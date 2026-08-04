// Package resolver looks up a hostname without trusting the machine's own DNS
// configuration.
//
// It backs tunnel hostname readiness, which asks the same question repeatedly
// while the answer is still changing: has this name been published yet? A
// recursive resolver answers that badly. Under RFC 2308 it caches the negative
// it got the first time, for as long as the zone's SOA allows — 30 minutes for
// the zones involved here — so a lookup made moments before publication decides
// the answer long after it stopped being true.
//
// The way around it is to ask something that does not cache: the zone's own
// nameservers. That works until the network will not carry the query, which is
// common enough — hotel and hotspot wifi, VPN exit nodes, and corporate
// resolvers all answer DNS on the machine's behalf. isHijacked detects that,
// and where it holds, lookups go out over DoH instead.
//
// The machine's resolver is not avoided, though — a caller connects through it,
// so readiness it cannot see is readiness a caller cannot use. It is asked
// last, and only once one of the above has shown the record exists, which is
// the difference between a query it can answer and one that poisons it. See
// confirmedResolver.
package resolver

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Records is a hostname's resolved address set. Empty means the name did not
// resolve — for a freshly minted tunnel hostname that is the ordinary state
// until the record is published, not a failure.
type Records struct {
	// A records are IPv4 addresses.
	A []netip.Addr
	// AAAA records are IPv6 addresses.
	AAAA []netip.Addr
	// CNAME is the canonical name for the queried hostname, if any.
	CNAME string
}

// Empty reports whether neither family resolved.
func (r Records) Empty() bool { return len(r.A) == 0 && len(r.AAAA) == 0 }

// Resolver looks up a hostname's addresses. Implementations differ in who they
// ask, which is the entire point: readiness polling needs an answer that is not
// a cached negative, and where that answer can be had from varies by network.
type Resolver interface {
	// Resolve returns the hostname's addresses, or empty Records if it does not
	// resolve. It does not report errors: a name that has not been published is
	// indistinguishable from one that never will be, and both mean "not yet".
	Resolve(hostname string) Records
}

// systemResolver resolves through the machine's own resolver — the one the
// calling process will use to reach the hostname. It is never asked first; see
// confirmedResolver for why the order is the whole design.
type systemResolver struct {
}

var _ Resolver = &systemResolver{}

// Resolve implements [Resolver] using the system resolver.
func (r *systemResolver) Resolve(hostname string) Records {
	records := Records{
		CNAME: hostname,
	}
	// The families are looked up independently: a host with only A records
	// fails the AAAA lookup, and that must not discard the A records.
	records.A = lookupVia(net.DefaultResolver, "ip4", hostname)
	records.AAAA = lookupVia(net.DefaultResolver, "ip6", hostname)
	return records
}

// lookupVia resolves one address family through r, returning nil for any
// failure — a name that does not resolve and a lookup that broke are the same
// answer to the caller: no records.
func lookupVia(r *net.Resolver, network, hostname string) []netip.Addr {
	// Bounded: the caller polls, and an unbounded lookup here would park the
	// readiness wait somewhere its own deadline cannot see.
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	ips, err := r.LookupIP(ctx, network, hostname)
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, ip := range ips {
		// Parsed rather than asserted: a malformed address is skipped instead
		// of panicking a caller's process.
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs
}

// confirmedResolver reports a hostname resolved only once the machine's own
// resolver resolves it too, and asks that resolver only after source has said
// the record exists.
//
// Both halves are load-bearing. Callers reach the hostname through the system
// resolver, so readiness that only a direct nameserver query can see is a
// readiness the caller cannot act on — it hands back a URL that does not
// resolve. And the system resolver is the one participant that caches, so a
// query made before the record exists fixes an NXDOMAIN in place for the length
// of the zone's SOA — 30 minutes for the zones here — which no amount of
// retrying afterwards can shorten. Asking it early is not a slow answer, it is
// a wrong one that outlives the truth.
//
// Ordering resolves the tension. source cannot cache anything, so it is free to
// ask as often as it likes; once it has records the name demonstrably exists,
// and a query to the system resolver then is one that can be answered rather
// than one that poisons. Until both agree the answer is empty Records, which
// the caller polls on.
type confirmedResolver struct {
	// source establishes that the record exists, without caching.
	source Resolver
	// system is the resolver the calling process will use.
	system Resolver
	// log reports which of the two is holding a wait up. The two failures want
	// opposite responses — an unpublished record resolves itself, a system
	// resolver that will not see a published one does not — and they are
	// indistinguishable from the empty Records both produce.
	log *slog.Logger
}

var _ Resolver = &confirmedResolver{}

// Resolve implements [Resolver], returning the addresses the machine's own
// resolver gives — the ones a caller will actually connect to.
func (c *confirmedResolver) Resolve(hostname string) Records {
	if c.source.Resolve(hostname).Empty() {
		// Not published yet. Asking the system resolver now is what would
		// poison it, so it is not asked.
		c.log.Debug("hostname not published yet", "hostname", hostname)
		return Records{CNAME: hostname}
	}
	records := c.system.Resolve(hostname)
	if records.Empty() {
		c.log.Debug("hostname published, but the system resolver does not see it yet",
			"hostname", hostname)
	}
	return records
}

// NewResolver returns the resolver best suited to the current network.
//
// Where DNS is trustworthy, nameservers are queried directly: their answers
// come from the zone itself and so cannot be a stale negative. Where it is not
// — see isHijacked — that path cannot be relied on, and lookups go out over
// DoH instead, which a network intercepting port 53 is not in a position to
// answer for. A direct walk that comes back with nothing falls through to DoH
// as well: the two fail for unrelated reasons, so one answering is worth more
// than either verdict alone.
//
// Whichever is chosen answers only the question "does this record exist yet",
// which is not the question a caller has: it connects through the system
// resolver. So the choice is wrapped in a confirmedResolver, which asks that
// resolver too — and, decisively, only once the record has been shown to exist.
// Where neither has the name, "not published yet" is the honest answer, and
// empty Records say exactly that.
//
// The choice is made per call rather than once, because a machine moves between
// networks and a resolver chosen for the previous one would be wrong.
//
// log reports, at debug, which half of a wait is unfinished — see
// confirmedResolver. It must not be nil.
func NewResolver(log *slog.Logger) Resolver {
	dohResolver := &dohResolver{
		servers: []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/dns-query",
			"https://dns.quad9.net/dns-query",
		},
	}

	netResolver := &netResolver{
		fallback: dohResolver,
		servers: []string{
			"a.gtld-servers.net",
			"b.gtld-servers.net",
			"c.gtld-servers.net",
			"d.gtld-servers.net",
			"e.gtld-servers.net",
			"f.gtld-servers.net",
			"g.gtld-servers.net",
			"h.gtld-servers.net",
			"i.gtld-servers.net",
			"j.gtld-servers.net",
			"k.gtld-servers.net",
			"l.gtld-servers.net",
			"m.gtld-servers.net",
		}}

	source := Resolver(netResolver)
	if isHijacked(netResolver.servers) {
		source = dohResolver
	}

	return &confirmedResolver{source: source, system: &systemResolver{}, log: log}
}

// shuffled returns a random permutation of servers, so no one server carries
// every lookup and a single bad one cannot decide every result. It copies:
// the caller's slice is left alone.
func shuffled(servers []string) []string {
	out := make([]string, len(servers))
	copy(out, servers)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// dnsName returns hostname as a fully qualified name, which is what the wire
// format expects.
func dnsName(hostname string) string {
	if strings.HasSuffix(hostname, ".") {
		return hostname
	}
	return hostname + "."
}

// isHijacked reports whether this network will not carry a query to one of
// servers and bring back that server's own answer. It decides between querying
// nameservers directly and going out over DoH.
//
// It asks the servers themselves — the ones netResolver would use, so the probe
// tests the actual path — for their zone's SOA with recursion disabled, and
// looks at one bit of the reply: AA. Those servers are authoritative for the
// zone and say so. Anything else answering in their place — a hotel's resolver,
// a VPN's, a captive portal's — cannot set that bit honestly, because it is not
// the zone's nameserver. So an authoritative reply proves the query reached the
// server it was addressed to.
//
// This measures the capability the caller depends on rather than inferring it
// from configuration. Across nine network configurations it agreed exactly with
// whether an RD=0 query to a tunnel zone's own nameserver came back
// authoritative.
//
// Anything else counts as hijacked, including a network that simply drops the
// query: if direct nameserver queries cannot be shown to work, DoH is the path
// that does.
//
// The result is not cached: a laptop changes networks, and a stale verdict
// would route every later lookup down the wrong path.
func isHijacked(servers []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), hijackProbeTimeout)
	defer cancel()
	ctx, cancel = context.WithCancel(ctx)
	defer cancel() // stop the slower probes once one has answered

	answered := make(chan bool, len(servers))
	for _, server := range servers {
		go func(server string) { answered <- answersAuthoritatively(ctx, server) }(server)
	}
	for range servers {
		if <-answered {
			return false
		}
	}
	return true
}

// hijackProbeTimeout bounds the whole check. The servers are anycast and answer
// in tens of milliseconds, so this is a ceiling on a stalled network rather
// than a cost normally paid.
const hijackProbeTimeout = 2 * time.Second

// probeZone is the zone the probe asks about. It must be one the configured
// servers are authoritative for — with the gTLD servers netResolver uses, that
// is com.
const probeZone = "com"

// answersAuthoritatively reports whether server replies to a nonrecursive query
// for probeZone with the AA bit set — the mark of the zone's own nameserver
// rather than something answering on its behalf.
func answersAuthoritatively(ctx context.Context, server string) bool {
	// Recursion is deliberately not requested: the question is whether this
	// server is authoritative for the zone, not whether it can look it up.
	query, err := buildQuery(probeZone, dnsmessage.TypeSOA, false)
	if err != nil {
		return false
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, maxUDPResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return false // dropped, refused, or timed out: not shown to work
	}
	var p dnsmessage.Parser
	header, err := p.Start(buf[:n])
	return err == nil && header.Authoritative
}

// maxUDPResponse bounds a DNS reply read from a datagram socket.
const maxUDPResponse = 1232
