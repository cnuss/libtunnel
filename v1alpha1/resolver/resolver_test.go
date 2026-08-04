package resolver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// discard is the logger the resolvers under test write to: their debug lines are
// diagnostic detail for a live run, not behaviour to pin.
func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// stubResolver stands in for a Resolver in fallback chains, recording whether
// it was reached.
type stubResolver struct {
	called  bool
	records Records
}

func (s *stubResolver) Resolve(hostname string) Records {
	s.called = true
	s.records.CNAME = hostname
	return s.records
}

// answer builds a DNS reply carrying addrs of the question's type.
func answer(t *testing.T, query []byte, addrs []netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		t.Fatalf("parse query: %v", err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("read question: %v", err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	for _, addr := range addrs {
		var err error
		switch {
		case addr.Is4() && q.Type == dnsmessage.TypeA:
			err = b.AResource(h, dnsmessage.AResource{A: addr.As4()})
		case addr.Is6() && q.Type == dnsmessage.TypeAAAA:
			err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// serveDoH stands up a stub RFC 8484 endpoint. It records the requests it saw
// so a test can assert on method and headers.
func serveDoH(t *testing.T, addrs []netip.Addr) (endpoint string, seen *[]*http.Request) {
	t.Helper()
	var requests []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(context.Background()))
		query, err := io.ReadAll(io.LimitReader(r.Body, maxDNSMessage))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer(t, query, addrs))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &requests
}

func TestDoHResolvesBothFamilies(t *testing.T) {
	v4 := netip.MustParseAddr("104.16.230.132")
	v6 := netip.MustParseAddr("2606:4700::6810:e684")
	endpoint, _ := serveDoH(t, []netip.Addr{v4, v6})

	r := &dohResolver{servers: []string{endpoint}, log: discard()}

	rec := r.Resolve("demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{v4}) {
		t.Errorf("A = %v, want %v", rec.A, []netip.Addr{v4})
	}
	if !slices.Equal(rec.AAAA, []netip.Addr{v6}) {
		t.Errorf("AAAA = %v, want %v", rec.AAAA, []netip.Addr{v6})
	}
	if rec.CNAME != "demo.trycloudflare.com" {
		t.Errorf("CNAME = %q", rec.CNAME)
	}
}

// TestDoHRequestIsUncacheable pins the request shape. Readiness asks the same
// name repeatedly while it is still unpublished, so a reply that an HTTP cache
// may reuse is the one thing that must not happen: RFC 8484 responses to POST
// are not cached, and Cache-Control asks the endpoint for a fresh answer.
func TestDoHRequestIsUncacheable(t *testing.T) {
	endpoint, seen := serveDoH(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")})
	r := &dohResolver{servers: []string{endpoint}, log: discard()}
	r.Resolve("demo.trycloudflare.com")

	if len(*seen) == 0 {
		t.Fatal("no request reached the endpoint")
	}
	for _, req := range *seen {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST (a GET reply is cacheable)", req.Method)
		}
		if got := req.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q, want application/dns-message", got)
		}
		if got := req.Header.Get("Accept"); got != "application/dns-message" {
			t.Errorf("Accept = %q, want application/dns-message", got)
		}
		if got := req.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("Cache-Control = %q, want no-cache", got)
		}
	}
}

// TestDoHEndsTheChain pins DoH as terminal: when no server produces records the
// answer is empty Records, not a lookup through the machine's own resolver. That
// resolver is the only one that caches, and asking it about a name that is not
// published yet is what fixes a negative in place for the zone's SOA -- on the
// very resolver the calling process will use once the name does resolve.
func TestDoHEndsTheChain(t *testing.T) {
	endpoint, _ := serveDoH(t, nil) // answers, but with no records

	r := &dohResolver{servers: []string{endpoint}, log: discard()}

	if rec := r.Resolve("demo.trycloudflare.com"); !rec.Empty() {
		t.Errorf("Resolve() = %+v, want empty Records", rec)
	}
}

// TestDoHIgnoresUnreachableServer pins that a dead endpoint is skipped rather
// than failing the lookup — the reason more than one server is configured.
func TestDoHIgnoresUnreachableServer(t *testing.T) {
	want := netip.MustParseAddr("104.16.230.132")
	live, _ := serveDoH(t, []netip.Addr{want})

	r := &dohResolver{servers: []string{"http://127.0.0.1:1/dns-query", live}, log: discard()}

	rec := r.Resolve("demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{want}) {
		t.Errorf("A = %v, want %v from the reachable server", rec.A, want)
	}
}

func TestParseAnswerSkipsOtherTypes(t *testing.T) {
	v4 := netip.MustParseAddr("104.16.230.132")
	query, err := buildQuery("demo.trycloudflare.com", dnsmessage.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	wire := answer(t, query, []netip.Addr{v4})

	addrs, err := parseAnswer(wire, dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addrs, []netip.Addr{v4}) {
		t.Errorf("addrs = %v, want %v", addrs, []netip.Addr{v4})
	}

	// The same reply read as AAAA holds nothing of that family.
	addrs, err = parseAnswer(wire, dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 0 {
		t.Errorf("AAAA addrs = %v, want none", addrs)
	}
}

func TestParseAnswerRejectsMalformed(t *testing.T) {
	if _, err := parseAnswer([]byte{0x00, 0x01}, dnsmessage.TypeA); err == nil {
		t.Error("malformed response should error")
	}
}

// TestShuffledIsAPermutation guards a bug this replaced: writing each element
// to a random index drops roughly a third of them, leaving empty strings that
// are then dialed.
func TestShuffledIsAPermutation(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"}
	for range 50 {
		got := shuffled(in)
		if len(got) != len(in) {
			t.Fatalf("len = %d, want %d", len(got), len(in))
		}
		sorted := slices.Clone(got)
		slices.Sort(sorted)
		if !slices.Equal(sorted, in) {
			t.Fatalf("not a permutation: %v", got)
		}
	}
	// The input must not be reordered under the caller.
	if !slices.IsSorted(in) {
		t.Error("shuffled mutated its argument")
	}
}

func TestDNSName(t *testing.T) {
	for in, want := range map[string]string{
		"demo.trycloudflare.com":  "demo.trycloudflare.com.",
		"demo.trycloudflare.com.": "demo.trycloudflare.com.",
	} {
		if got := dnsName(in); got != want {
			t.Errorf("dnsName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecordsEmpty(t *testing.T) {
	if !(Records{}).Empty() {
		t.Error("zero Records should be empty")
	}
	if (Records{A: []netip.Addr{netip.MustParseAddr("1.2.3.4")}}).Empty() {
		t.Error("Records with an A record should not be empty")
	}
	if (Records{AAAA: []netip.Addr{netip.MustParseAddr("::1")}}).Empty() {
		t.Error("Records with an AAAA record should not be empty")
	}
}

// serveUDP stands up a UDP DNS server that replies with handler's wire
// response, and returns its host:port.
func serveUDP(t *testing.T, handler func(query []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := handler(buf[:n]); resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// referral builds the reply a TLD server sends for a name it does not hold:
// no answer, and the zone's nameserver addresses as glue in the additional
// section.
func referral(t *testing.T, query []byte, glue []netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	for _, addr := range glue {
		var err error
		if addr.Is4() {
			err = b.AResource(h, dnsmessage.AResource{A: addr.As4()})
		} else {
			err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// TestNetResolverWalksDelegation pins the two-step walk: a TLD server hands
// back glue, and the zone's own nameserver supplies the records. Neither step
// touches a recursive resolver, so neither can serve a cached negative.
func TestNetResolverWalksDelegation(t *testing.T) {
	v4 := netip.MustParseAddr("104.16.230.132")

	authoritative := serveUDP(t, func(query []byte) []byte {
		return answer(t, query, []netip.Addr{v4})
	})
	// Glue carries an address; the walk dials it on nameserverPort.
	authAddr, authPort := splitHostPort(t, authoritative)
	restore := nameserverPort
	nameserverPort = authPort
	t.Cleanup(func() { nameserverPort = restore })

	tld := serveUDP(t, func(query []byte) []byte {
		return referral(t, query, []netip.Addr{authAddr})
	})

	fallback := &stubResolver{}
	r := &netResolver{servers: []string{tld}, fallback: fallback, log: discard()}

	rec := r.Resolve("demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{v4}) {
		t.Errorf("A = %v, want %v from the zone's nameserver", rec.A, v4)
	}
	if fallback.called {
		t.Error("fallback used despite the walk succeeding")
	}
}

// TestNetResolverFallsBackWithoutGlue pins the chain: a referral carrying no
// usable glue leaves the walk nowhere to go, so the fallback decides.
func TestNetResolverFallsBackWithoutGlue(t *testing.T) {
	tld := serveUDP(t, func(query []byte) []byte {
		return referral(t, query, nil)
	})

	want := netip.MustParseAddr("9.9.9.9")
	fallback := &stubResolver{records: Records{A: []netip.Addr{want}}}
	r := &netResolver{servers: []string{tld}, fallback: fallback, log: discard()}

	rec := r.Resolve("demo.trycloudflare.com")
	if !fallback.called {
		t.Fatal("fallback not used when the referral carried no glue")
	}
	if !slices.Equal(rec.A, []netip.Addr{want}) {
		t.Errorf("A = %v, want the fallback's %v", rec.A, want)
	}
}

// TestNetResolverBudgetsTheWholeWalk pins walkBudget. Per-query timeouts do not
// bound a walk: a referral carries every nameserver the zone has, and asking
// each for two families costs len(glue) x 2 x queryTimeout when none of them
// answers. Measured on a CI runner that reached the TLD servers but not the
// zone's own nameservers, that was one Resolve taking sixty seconds and learning
// nothing, while the caller's readiness poll waited on it.
func TestNetResolverBudgetsTheWholeWalk(t *testing.T) {
	silent := serveUDP(t, func([]byte) []byte { return nil }) // never answers
	_, silentPort := splitHostPort(t, silent)
	restore := nameserverPort
	nameserverPort = silentPort
	t.Cleanup(func() { nameserverPort = restore })

	// Ten glue addresses, as the real zones carry — all pointing at the server
	// that never answers.
	glue := make([]netip.Addr, 10)
	for i := range glue {
		glue[i] = netip.MustParseAddr("127.0.0.1")
	}
	tld := serveUDP(t, func(query []byte) []byte { return referral(t, query, glue) })

	want := netip.MustParseAddr("9.9.9.9")
	fallback := &stubResolver{records: Records{A: []netip.Addr{want}}}
	r := &netResolver{servers: []string{tld}, fallback: fallback, log: discard()}

	start := time.Now()
	rec := r.Resolve("demo.trycloudflare.com")
	elapsed := time.Since(start)

	// Unbudgeted this is 10 x 2 x queryTimeout = 60s. The margin is wide on
	// purpose: the point is the order of magnitude, not the exact bound.
	if limit := 4 * walkBudget; elapsed > limit {
		t.Errorf("Resolve took %s, want under %s — the walk is not bounded as a whole", elapsed, limit)
	}
	if !fallback.called {
		t.Error("fallback not used once the walk ran out of budget")
	}
	if !slices.Equal(rec.A, []netip.Addr{want}) {
		t.Errorf("A = %v, want the fallback's %v", rec.A, want)
	}
}

// TestParseGlueSkipsNonAddressRecords pins that OPT — which every query now
// provokes, since EDNS0 is advertised — does not derail the glue scan.
func TestParseGlueSkipsNonAddressRecords(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.53")
	v6 := netip.MustParseAddr("2001:db8::53")
	query, err := buildQuery("demo.trycloudflare.com", dnsmessage.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}

	addrs, err := parseGlue(referral(t, query, []netip.Addr{v4, v6}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addrs, []netip.Addr{v4, v6}) {
		t.Errorf("glue = %v, want %v", addrs, []netip.Addr{v4, v6})
	}
}

// TestBuildQueryAdvertisesEDNS0 guards the buffer size. Without it a reply is
// capped at 512 bytes, and a delegation's glue is exactly what gets cut — one
// measured referral carried 20 addresses.
func TestBuildQueryAdvertisesEDNS0(t *testing.T) {
	query, err := buildQuery("demo.trycloudflare.com", dnsmessage.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatal(err)
	}
	h, err := p.AdditionalHeader()
	if err != nil {
		t.Fatalf("no additional section: EDNS0 not advertised")
	}
	if h.Type != dnsmessage.TypeOPT {
		t.Fatalf("additional record type = %v, want OPT", h.Type)
	}
	if got := h.DNSSECAllowed(); got {
		t.Error("DNSSEC OK should not be set")
	}
	// The OPT record's class carries the advertised UDP payload size.
	if uint16(h.Class) != maxUDPResponse {
		t.Errorf("advertised buffer = %d, want %d", uint16(h.Class), maxUDPResponse)
	}
}

// splitHostPort splits a host:port into a netip.Addr and the port string.
func splitHostPort(t *testing.T, hostport string) (netip.Addr, string) {
	t.Helper()
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	return ap.Addr(), strconv.Itoa(int(ap.Port()))
}

// serveNameserver stands up a UDP DNS server answering every query with the
// given AA bit and rcode — a root server when authoritative, a middlebox
// answering in its place when not.
func serveNameserver(t *testing.T, authoritative bool, rcode dnsmessage.RCode) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			if _, err := p.Start(buf[:n]); err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				Response:           true,
				Authoritative:      authoritative,
				RecursionAvailable: !authoritative, // a stand-in resolver advertises recursion
				RCode:              rcode,
			})
			if err := b.StartQuestions(); err != nil {
				continue
			}
			if err := b.Question(q); err != nil {
				continue
			}
			wire, err := b.Finish()
			if err != nil {
				continue
			}
			pc.WriteTo(wire, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// TestAnswersAuthoritativelyAcceptsTheRealServer pins the clean case: a server
// that sets AA proves the query reached the server it was addressed to.
func TestAnswersAuthoritativelyAcceptsTheRealServer(t *testing.T) {
	server := serveNameserver(t, true, dnsmessage.RCodeSuccess)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !answersAuthoritatively(ctx, server) {
		t.Error("an authoritative reply should count as reaching the nameserver")
	}
}

// TestAnswersAuthoritativelyRejectsAStandIn is the hijacked case, and the one
// that matters: something answered, and answered plausibly, but it is not the
// root and cannot honestly set AA. Measured on intercepting networks as
// NOERROR with records in one configuration and REFUSED in another, so both
// shapes are rejected.
func TestAnswersAuthoritativelyRejectsAStandIn(t *testing.T) {
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeRefused} {
		server := serveNameserver(t, false, rcode)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if answersAuthoritatively(ctx, server) {
			t.Errorf("a non-authoritative %v reply should not count as reaching the nameserver", rcode)
		}
		cancel()
	}
}

// TestAnswersAuthoritativelyRejectsSilence pins that a dropped query is not
// evidence the path works — DoH is used instead.
func TestAnswersAuthoritativelyRejectsSilence(t *testing.T) {
	// A closed loopback port: the send succeeds, the read does not.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if answersAuthoritatively(ctx, addr) {
		t.Error("silence should not be read as reaching the nameserver")
	}
}

// TestIsHijackedOneAuthoritativeServerSettlesIt pins that a single reachable
// server decides the verdict, so one unreachable nameserver cannot force the
// DoH path.
func TestIsHijackedOneAuthoritativeServerSettlesIt(t *testing.T) {
	live := serveNameserver(t, true, dnsmessage.RCodeSuccess)

	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	if isHijacked(discard(), []string{deadAddr, live}) {
		t.Error("one authoritative server should be enough to read as clean")
	}
}

// TestIsHijackedAllStandIns is the hijacked network: every server answers, and
// answers plausibly, but none authoritatively — measured as NOERROR with
// records on one intercepting network and REFUSED on another, so both shapes
// are covered.
func TestIsHijackedAllStandIns(t *testing.T) {
	servers := []string{
		serveNameserver(t, false, dnsmessage.RCodeSuccess),
		serveNameserver(t, false, dnsmessage.RCodeRefused),
	}
	if !isHijacked(discard(), servers) {
		t.Error("no authoritative reply should read as hijacked")
	}
}

// TestIsHijackedSilence pins that a network dropping the queries entirely reads
// as hijacked: the direct path was not shown to work, so DoH is used.
func TestIsHijackedSilence(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	if !isHijacked(discard(), []string{addr}) {
		t.Error("silence should read as hijacked")
	}
}
