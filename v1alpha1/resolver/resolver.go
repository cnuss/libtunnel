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
package resolver

import (
	"context"
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

// defaultResolver resolves through the system resolver. It is the last resort,
// used only when every other path has failed to produce records — its answers
// may come from any cache the machine is configured to use.
type defaultResolver struct {
}

var _ Resolver = &defaultResolver{}

// Resolve implements [Resolver] using the system resolver.
func (r *defaultResolver) Resolve(hostname string) Records {
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
	ips, err := r.LookupIP(context.Background(), network, hostname)
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

// NewResolver returns the resolver best suited to the current network.
//
// Where DNS is trustworthy, nameservers are queried directly: their answers
// come from the zone itself and so cannot be a stale negative. Where it is not
// — see isHijacked — that path cannot be relied on, and lookups go out over
// DoH instead, which a network intercepting port 53 is not in a position to
// answer for.
//
// The choice is made per call rather than once, because a machine moves between
// networks and a resolver chosen for the previous one would be wrong.
func NewResolver() Resolver {
	netResolver := &netResolver{
		fallback: &defaultResolver{},
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

	dohResolver := &dohResolver{
		fallback: netResolver,
		servers: []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/dns-query",
			"https://dns.quad9.net/dns-query",
		},
	}

	if isHijacked(netResolver.servers) {
		return dohResolver
	}

	return netResolver
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
