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
// Ready means consensus, not first sighting. The record propagates across the
// zone's nameservers — and across each nameserver's anycast nodes — over
// seconds, and a caller told "ready" during that spread can ask its own
// resolver, hit a node the record has not reached, and cache the negative for
// the zone's SOA. So every voice that can be heard votes, and readiness waits
// for agreement:
//
//   - The zone's own nameservers, found by following a TLD server's referral
//     and asked all at once. Only replies carrying the AA bit have a voice:
//     on networks that intercept port 53 — hotel and hotspot wifi, corporate
//     proxies — whatever answers in the nameserver's place is not
//     authoritative for the zone and cannot set that bit honestly.
//   - DoH endpoints (RFC 8484), which ride HTTPS and so pass through networks
//     that intercept port 53. They are recursive resolvers with anycast
//     fleets of their own — the vantage a visitor actually resolves from,
//     which the authoritative view alone cannot see. They join only after the
//     authoritative fleet agrees: asked earlier, they would recurse for a
//     name that does not exist yet and cache the negative — measured live as
//     all three endpoints flapping stale negatives, planted by this package's
//     own early rounds, for the rest of the wait.
//
// A round is ready when someone serves the record and nobody answers without
// it; one "not yet" from either kind of voice holds readiness open. Voices
// that cannot be heard at all — unreachable, blocked, intercepted — forfeit
// rather than veto, so consensus needs whoever can answer, not everyone. And
// consensus only ratchets forward: a voice that has served the record once
// has proven the record reached it, and an anycast node behind it flapping
// back to a stale view cannot take that vote away.
//
// Where no authoritative voice can be heard at all — port 53 intercepted or
// blocked — the DoH endpoints are the only voices left, and the first of them
// to serve the record decides. Unanimity there would measure nothing: the
// negatives their fleets may hold are indistinguishable from the ones this
// package's own pre-publication queries just planted.
//
// There are no timeouts here. Resolve keeps asking — a fresh round of queries
// every resolveInterval, rotating through servers — until an answer arrives or
// ctx ends. How long to wait is the caller's decision, expressed through ctx;
// a query the network never answers is abandoned when ctx is done, not before.
// The one clock consensus needs — how long to wait for a voice that may never
// reply — is the pacing itself: a voice still silent when the next round
// begins forfeits its vote, rather than holding readiness hostage.
package resolver

import (
	"context"
	"log/slog"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
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
	// doh are RFC 8484 endpoints, all asked every round. Shuffled at
	// construction; must not be empty.
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
// zone's delegation, then every nameserver in it and every DoH endpoint at
// once; see round for how the votes decide. Rounds repeat, rotating through
// the TLD servers, until one delivers or ctx ends; every in-flight query is
// released when Resolve returns.
func (r *resolver) Resolve(ctx context.Context, hostname string) Records {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	found := make(chan Records, 1)
	pace := time.NewTicker(resolveInterval)
	defer pace.Stop()

	tally := &tally{served: make(map[string]bool)}
	var supersede chan struct{}
	for round := 0; ; round++ {
		// Starting a round supersedes the previous one: whatever has not
		// answered it by now forfeits its vote (see round).
		if supersede != nil {
			close(supersede)
		}
		supersede = make(chan struct{})
		go r.round(ctx, r.tlds[round%len(r.tlds)], hostname, tally, supersede, found)

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

// vote is one voice's view of the hostname. A voice that answered with the A
// record serves it (and brings the AAAA half along for the caller); one that
// answered without it objects — the record has not reached it, and a visitor
// resolving through it would cache that negative. A voice that could not
// answer at all — unreachable, blocked, or a middlebox without the AA bit it
// cannot set honestly — casts no vote.
type vote struct {
	source  string
	a, aaaa []netip.Addr
	voiced  bool
	// recursive marks a DoH endpoint's vote, as opposed to a nameserver's.
	recursive bool
}

// tally is what one wait has established across its rounds. Rounds overlap,
// so it is shared under a lock; it lives and dies with a single Resolve call,
// so nothing here outlasts the wait — the package still caches nothing.
type tally struct {
	mu sync.Mutex
	// served holds every voice that has answered with the record. The record
	// provably reached these; a stale anycast node flapping back into view
	// cannot un-serve them, so their later objections are spent.
	served map[string]bool
	// askDoH opens the recursive polls: set once the authoritative fleet has
	// agreed — before that, a DoH query would recurse for a name that does
	// not exist yet and plant the very negative consensus is waiting out — or
	// once a round establishes there is no authoritative voice to hear.
	askDoH bool
	// authHeard records that some round got an authoritative reply. It
	// decides what DoH votes mean: confirmation on a network that can hear
	// the zone's nameservers, the only voice there is on one that cannot.
	authHeard bool
}

// round is one complete attempt to call the hostname resolved.
//
// The zone's nameservers, from the delegation tld hands back, are asked all
// at once — joined by every DoH endpoint once tally says their votes carry
// meaning. The round delivers on consensus: someone serves the record and
// nobody answers without it, spent objections excepted. A live objection
// means the record is still propagating somewhere a visitor might resolve
// from, so the round delivers nothing and lets a later round find agreement.
// Voices still silent when the next round supersedes this one forfeit their
// vote rather than stalling the verdict.
//
// The first round with authoritative consensus does not deliver; it opens the
// recursive polls, and delivery waits for a round where the DoH endpoints —
// the vantage a visitor resolves from — concur. Where no authoritative voice
// has ever been heard, the first DoH endpoint to serve the record decides
// alone.
func (r *resolver) round(ctx context.Context, tld, hostname string, tally *tally, superseded <-chan struct{}, found chan<- Records) {
	glue := delegation(ctx, tld, hostname, r.port)
	doh := tally.recursivePolls(r.doh)
	votes := make(chan vote, len(glue)+len(doh))
	for _, ns := range glue {
		go func() { votes <- lookupNameserver(ctx, ns, hostname) }()
	}
	for _, endpoint := range doh {
		go func() { votes <- lookupDoH(ctx, endpoint, hostname) }()
	}

	var served vote
	var objectors []string
	serving, authVoiced := 0, 0
collect:
	for range len(glue) + len(doh) {
		select {
		case v := <-votes:
			if !v.voiced {
				continue
			}
			if !v.recursive {
				authVoiced++
			}
			if len(v.a) > 0 {
				serving++
				served = v
				tally.serve(v.source)
			} else if !tally.hasServed(v.source) {
				objectors = append(objectors, v.source)
			}
		case <-superseded:
			break collect // the still-silent forfeit their vote
		case <-ctx.Done():
			return
		}
	}

	authHeard := tally.hearAuth(authVoiced)
	switch {
	case serving > 0 && !authHeard:
		// No authoritative voice exists on this network; the recursive
		// endpoints are the only voices, and one serving the record is the
		// best answer there is.
		if deliver(found, Records{A: served.a, AAAA: served.aaaa}) {
			r.log.Debug("doh endpoint serves the record", "hostname", hostname,
				"source", served.source)
		}
	case serving > 0 && len(objectors) == 0:
		if len(doh) == 0 {
			// Authoritative consensus. Not delivered on: it opens the
			// recursive polls, and a later round delivers once the visitor's
			// vantage concurs.
			tally.openPolls()
			r.log.Debug("authoritative nameservers agree, polling recursive endpoints",
				"hostname", hostname, "serving", serving)
			return
		}
		if deliver(found, Records{A: served.a, AAAA: served.aaaa}) {
			r.log.Debug("resolvers agree the record is served", "hostname", hostname,
				"serving", serving, "source", served.source)
		}
	case len(objectors) > 0:
		r.log.Debug("resolvers lack consensus", "hostname", hostname,
			"serving", serving, "objecting", objectors)
	default:
		// Nothing voiced anything. If there is no authoritative voice to
		// wait for, the recursive endpoints are the only ones left to ask.
		if !authHeard {
			tally.openPolls()
		}
	}
}

// recursivePolls returns the DoH endpoints to include in a round: none until
// askDoH opens them.
func (t *tally) recursivePolls(endpoints []string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.askDoH {
		return nil
	}
	return endpoints
}

// serve latches source as having served the record.
func (t *tally) serve(source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.served[source] = true
}

// hasServed reports whether source has ever served the record this wait.
func (t *tally) hasServed(source string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.served[source]
}

// hearAuth folds a round's count of authoritative voices into the tally and
// reports whether any round has heard one.
func (t *tally) hearAuth(voiced int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if voiced > 0 {
		t.authHeard = true
	}
	return t.authHeard
}

// openPolls admits the DoH endpoints to later rounds.
func (t *tally) openPolls() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.askDoH = true
}

// lookupNameserver casts one zone nameserver's vote. Only an AA reply is a
// voice: the nameserver answering for itself, not a middlebox in its place.
func lookupNameserver(ctx context.Context, ns, hostname string) vote {
	a, authoritative := lookupUDP(ctx, ns, hostname, dnsmessage.TypeA)
	v := vote{source: ns, a: a, voiced: authoritative}
	if v.voiced && len(a) > 0 {
		v.aaaa, _ = lookupUDP(ctx, ns, hostname, dnsmessage.TypeAAAA)
	}
	return v
}

// lookupDoH casts one DoH endpoint's vote. AA is not expected here — the
// endpoint is a recursive resolver; what makes its voice trustworthy is the
// transport, which a network intercepting port 53 cannot answer for.
func lookupDoH(ctx context.Context, endpoint, hostname string) vote {
	a, ok := queryDoH(ctx, endpoint, hostname, dnsmessage.TypeA)
	v := vote{source: endpoint, a: a, voiced: ok, recursive: true}
	if v.voiced && len(a) > 0 {
		v.aaaa, _ = queryDoH(ctx, endpoint, hostname, dnsmessage.TypeAAAA)
	}
	return v
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
