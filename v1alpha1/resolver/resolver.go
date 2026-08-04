// Package resolver waits for a hostname to resolve, asking only sources that
// cannot serve a cached negative.
//
// It backs tunnel hostname readiness: the edge publishes the record moments
// after the connection registers, and readiness wants the earliest honest yes.
// A recursive resolver answers that badly — under RFC 2308 it caches the
// negative it got before publication for as long as the zone's SOA allows, 30
// minutes for the zones here. The machine's own resolver is worst of all: one
// query about the not-yet-published name would fix that negative in place on
// the very resolver the calling process will use to connect. Nothing here asks
// it, ever.
//
// Two sources that cannot hold a stale negative are asked instead, together:
//
//   - The zone's own nameservers, found by following a TLD server's referral.
//     Only replies carrying the AA bit are trusted: on networks that intercept
//     port 53 — hotel and hotspot wifi, corporate proxies — whatever answers
//     in the nameserver's place is not authoritative for the zone, cannot set
//     that bit honestly, and is discarded.
//   - DoH endpoints (RFC 8484), which ride HTTPS and so pass through networks
//     that intercept port 53. They are recursive, but each is a different
//     operator and none is the resolver this machine will connect through, so
//     a stale negative on one neither decides the result nor poisons the
//     connection that follows.
//
// There are no timeouts here. Resolve keeps asking — a fresh round of queries
// every resolveInterval, rotating through servers — until an answer arrives or
// ctx ends. How long to wait is the caller's decision, expressed through ctx;
// a query the network never answers is abandoned when ctx is done, not before.
package resolver

import (
	"context"
	"log/slog"
	"math/rand"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Records is a hostname's resolved address set.
type Records struct {
	// A records are IPv4 addresses.
	A []netip.Addr
	// AAAA records are IPv6 addresses.
	AAAA []netip.Addr
}

// Empty reports whether the hostname resolved to an address the caller can
// expect to reach. That means IPv4: a quick tunnel's families are published
// independently and the AAAA half routinely lands first, so counting it would
// call a hostname ready on a host with no IPv6 route — a macOS runner, or
// anything behind IPv4-only NAT — that then cannot connect to it. AAAA alone is
// therefore still "not yet".
func (r Records) Empty() bool { return len(r.A) == 0 }

// Resolver looks up a hostname's addresses.
type Resolver interface {
	// Resolve blocks until hostname resolves, then returns its addresses.
	// Empty Records mean ctx ended first: the name was not published within
	// the time the caller was willing to wait.
	Resolve(ctx context.Context, hostname string) Records
}

// NewResolver returns a Resolver that races the delegation walk against DoH.
//
// log records, at debug, which source answered. A hostname that will not
// resolve looks identical from outside whichever way it fails, and these are
// the only lines that say which. It must not be nil.
func NewResolver(log *slog.Logger) Resolver {
	return &resolver{
		log: log,
		tlds: shuffled([]string{
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
		}),
		doh: shuffled([]string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/dns-query",
			"https://dns.quad9.net/dns-query",
		}),
	}
}

// resolver asks the zone's own nameservers and DoH endpoints side by side and
// takes whichever answers first. It holds no state between calls and caches
// nothing — the property the whole package exists for.
type resolver struct {
	// tlds are TLD nameservers the delegation walk starts from, one per round.
	// Shuffled at construction so no process favors the same server; must not
	// be empty.
	tlds []string
	// doh are RFC 8484 endpoints, one per round. Shuffled at construction;
	// must not be empty.
	doh []string
	// log records which source answered, at debug.
	log *slog.Logger
}

var _ Resolver = &resolver{}

// resolveInterval paces the rounds. It is not a timeout: a round's queries are
// never cut off by the next round starting — a slow answer from round one can
// still win during round three. Nothing asked here caches, so another round
// costs a handful of queries and can never fix a negative in place.
const resolveInterval = time.Second

// Resolve implements [Resolver]. Each round asks one TLD server (walking its
// referral to the zone's nameservers) and one DoH endpoint, in parallel, and
// the first source to produce an address wins. Rounds repeat, rotating through
// the configured servers, until ctx ends; every in-flight query is released
// when Resolve returns.
func (r *resolver) Resolve(ctx context.Context, hostname string) Records {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	found := make(chan Records, 1)
	pace := time.NewTicker(resolveInterval)
	defer pace.Stop()

	for round := 0; ; round++ {
		go r.direct(ctx, r.tlds[round%len(r.tlds)], hostname, found)
		go r.recursive(ctx, r.doh[round%len(r.doh)], hostname, found)

		select {
		case rec := <-found:
			return rec
		case <-ctx.Done():
			r.log.Debug("hostname did not resolve before ctx ended",
				"hostname", hostname, "rounds", round+1)
			return Records{}
		case <-pace.C:
		}
	}
}

// direct walks the delegation: it asks tld which nameservers hold the zone,
// then asks each of those, in parallel, trusting only authoritative answers.
// Neither step passes through a recursive resolver, so neither can return a
// cached negative, and the AA requirement means a middlebox answering in a
// nameserver's place is ignored rather than believed.
func (r *resolver) direct(ctx context.Context, tld, hostname string, found chan<- Records) {
	for _, ns := range delegation(ctx, tld, hostname) {
		go func() {
			a, authoritative := lookupUDP(ctx, ns, hostname, dnsmessage.TypeA)
			if !authoritative || len(a) == 0 {
				return
			}
			aaaa, _ := lookupUDP(ctx, ns, hostname, dnsmessage.TypeAAAA)
			if deliver(found, Records{A: a, AAAA: aaaa}) {
				r.log.Debug("authoritative nameserver serves the record",
					"hostname", hostname, "nameserver", ns)
			}
		}()
	}
}

// recursive asks one DoH endpoint. AA is not expected here — the endpoint is a
// recursive resolver; what protects this path is the transport, which a
// network intercepting port 53 cannot answer for.
func (r *resolver) recursive(ctx context.Context, endpoint, hostname string, found chan<- Records) {
	a := queryDoH(ctx, endpoint, hostname, dnsmessage.TypeA)
	if len(a) == 0 {
		return
	}
	aaaa := queryDoH(ctx, endpoint, hostname, dnsmessage.TypeAAAA)
	if deliver(found, Records{A: a, AAAA: aaaa}) {
		r.log.Debug("doh endpoint serves the record", "hostname", hostname, "endpoint", endpoint)
	}
}

// deliver offers rec as the answer, reporting whether it was taken. Exactly
// one answer is; later arrivals are dropped rather than blocking their
// goroutines.
func deliver(found chan<- Records, rec Records) bool {
	select {
	case found <- rec:
		return true
	default:
		return false
	}
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
