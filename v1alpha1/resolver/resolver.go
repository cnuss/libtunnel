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
// Two sources that cannot hold a stale negative are asked instead:
//
//   - The zone's own nameservers, found by following a TLD server's referral
//     and asked all at once. Only replies carrying the AA bit are trusted: on
//     networks that intercept port 53 — hotel and hotspot wifi, corporate
//     proxies — whatever answers in the nameserver's place is not
//     authoritative for the zone, cannot set that bit honestly, and is
//     discarded. Ready means consensus, not first sighting: the record
//     propagates across the zone's nameservers asynchronously, and a caller
//     told "ready" while one nameserver still lacks the record can ask its
//     own resolver, hit that nameserver, and cache the negative readiness
//     exists to avoid. So one authoritative "not yet" holds readiness open.
//   - DoH endpoints (RFC 8484), which ride HTTPS and so pass through networks
//     that intercept port 53. They are recursive, so they answer only where
//     no authoritative voice can be heard at all; an authoritative "not yet"
//     outranks a recursive resolver's yes, which may be exactly the kind of
//     cached answer consensus is waiting to make safe.
//
// There are no timeouts here. Resolve keeps asking — a fresh round of queries
// every resolveInterval, rotating through servers — until an answer arrives or
// ctx ends. How long to wait is the caller's decision, expressed through ctx;
// a query the network never answers is abandoned when ctx is done, not before.
// The one clock consensus needs — how long to wait for a nameserver that may
// never reply — is the pacing itself: a nameserver still silent when the next
// round begins forfeits its vote, rather than holding readiness hostage.
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
		port: "53",
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
	// port is where glue addresses are dialed. Glue carries an address and no
	// port, so it is always 53 in practice; it is a field only so tests can
	// point the walk at stubs.
	port string
	// log records which source answered, at debug.
	log *slog.Logger
}

var _ Resolver = &resolver{}

// resolveInterval paces the rounds. It is not a timeout: a round's queries are
// never cut off by the next round starting — a slow answer from round one can
// still win during round three. Nothing asked here caches, so another round
// costs a handful of queries and can never fix a negative in place.
const resolveInterval = time.Second

// Resolve implements [Resolver]. Each round asks one TLD server for the
// zone's delegation, then every nameserver in it at once, with one DoH lookup
// alongside as the fallback verdict; see round for how a round decides.
// Rounds repeat, rotating through the configured servers, until one delivers
// or ctx ends; every in-flight query is released when Resolve returns.
func (r *resolver) Resolve(ctx context.Context, hostname string) Records {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	found := make(chan Records, 1)
	pace := time.NewTicker(resolveInterval)
	defer pace.Stop()

	var supersede chan struct{}
	for round := 0; ; round++ {
		// Starting a round supersedes the previous one: whatever has not
		// answered it by now forfeits its vote (see round).
		if supersede != nil {
			close(supersede)
		}
		supersede = make(chan struct{})
		go r.round(ctx, r.tlds[round%len(r.tlds)], r.doh[round%len(r.doh)],
			hostname, supersede, found)

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

// round is one complete attempt to call the hostname resolved.
//
// It walks the delegation — ask tld which nameservers hold the zone, then ask
// all of them at once — and counts authoritative votes: an AA reply carrying
// the A record serves it, an AA reply without one is a nameserver the record
// has not reached yet. Anything else — unreachable, or a middlebox answering
// without the AA bit it cannot set honestly — has no vote, and a nameserver
// still silent when the next round supersedes this one forfeits its vote
// rather than stalling the verdict.
//
// The round delivers on consensus: someone serves the record and no
// authoritative voice says "not yet". A single dissent means the record is
// still propagating, and a caller released now could ask its own resolver,
// hit the lagging nameserver, and cache the very negative this package exists
// to avoid — so the round delivers nothing and lets a later round decide.
//
// doh is asked in parallel but its answer is used only when the walk heard no
// authoritative voice at all — a network where port 53 is intercepted or
// blocked. It is a recursive resolver: where the zone's own nameservers can
// be heard, their word outranks its cache.
func (r *resolver) round(ctx context.Context, tld, doh, hostname string, superseded <-chan struct{}, found chan<- Records) {
	dohCh := make(chan Records, 1)
	go func() { dohCh <- r.lookupDoH(ctx, doh, hostname) }()

	type vote struct {
		nameserver    string
		a             []netip.Addr
		authoritative bool
	}
	glue := delegation(ctx, tld, hostname, r.port)
	votes := make(chan vote, len(glue))
	for _, ns := range glue {
		go func() {
			a, authoritative := lookupUDP(ctx, ns, hostname, dnsmessage.TypeA)
			votes <- vote{nameserver: ns, a: a, authoritative: authoritative}
		}()
	}

	var served vote
	answered, lagging := 0, 0
collect:
	for range glue {
		select {
		case v := <-votes:
			if !v.authoritative {
				continue // unreachable, or not the zone's nameserver: no vote
			}
			answered++
			if len(v.a) == 0 {
				lagging++
			} else {
				served = v
			}
		case <-superseded:
			break collect // the still-silent forfeit their vote
		case <-ctx.Done():
			return
		}
	}

	switch {
	case lagging > 0:
		// No consensus: the record exists on some nameservers and not others
		// (or none yet). Deliver nothing — including DoH's answer, which
		// cannot outrank an authoritative "not yet" — and let a later round
		// find the fleet in agreement.
		r.log.Debug("authoritative nameservers lack consensus",
			"hostname", hostname, "answered", answered, "lagging", lagging)
	case answered > 0:
		aaaa, _ := lookupUDP(ctx, served.nameserver, hostname, dnsmessage.TypeAAAA)
		if deliver(found, Records{A: served.a, AAAA: aaaa}) {
			r.log.Debug("authoritative nameservers agree the record is served",
				"hostname", hostname, "answered", answered)
		}
	default:
		// No authoritative voice at all: intercepted or blocked port 53, or
		// a TLD referral this network would not carry. DoH decides.
		select {
		case rec := <-dohCh:
			if !rec.Empty() && deliver(found, rec) {
				r.log.Debug("doh endpoint serves the record",
					"hostname", hostname, "endpoint", doh)
			}
		case <-ctx.Done():
		}
	}
}

// lookupDoH asks one DoH endpoint for both address families. AA is not
// expected here — the endpoint is a recursive resolver; what protects this
// path is the transport, which a network intercepting port 53 cannot answer
// for.
func (r *resolver) lookupDoH(ctx context.Context, endpoint, hostname string) Records {
	a := queryDoH(ctx, endpoint, hostname, dnsmessage.TypeA)
	if len(a) == 0 {
		return Records{}
	}
	return Records{A: a, AAAA: queryDoH(ctx, endpoint, hostname, dnsmessage.TypeAAAA)}
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
