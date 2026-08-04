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
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// discard is the logger the resolvers under test write to: their debug lines
// are diagnostic detail for a live run, not behaviour to pin.
func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// testCtx returns a context that outlives any healthy exchange but not a hung
// test.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// deadDoH is a DoH endpoint nothing listens on, for tests that exercise the
// direct path alone. The doh field must not be empty, but it may be useless.
const deadDoH = "http://127.0.0.1:1/dns-query"

// answer builds a DNS reply carrying addrs of the question's type, with the
// AA bit set as given — a zone's own nameserver when true, something
// answering in its place when false.
func answer(t *testing.T, query []byte, authoritative bool, addrs []netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		t.Fatalf("parse query: %v", err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("read question: %v", err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:           true,
		Authoritative:      authoritative,
		RecursionAvailable: !authoritative, // a stand-in resolver advertises recursion
	})
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
		w.Write(answer(t, query, false, addrs))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &requests
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

// glueTo repoints nameserverPort at hostport's port for the duration of the
// test and returns its address, so a referral can carry loopback glue that the
// walk then dials on the stub's port.
func glueTo(t *testing.T, hostport string) netip.Addr {
	t.Helper()
	addr, port := splitHostPort(t, hostport)
	restore := nameserverPort
	nameserverPort = port
	t.Cleanup(func() { nameserverPort = restore })
	return addr
}

// TestResolveWalksDelegation pins the direct path: a TLD server hands back
// glue, and the zone's own nameserver — answering authoritatively — supplies
// the records. Neither step touches a recursive resolver, so neither can serve
// a cached negative.
func TestResolveWalksDelegation(t *testing.T) {
	v4 := netip.MustParseAddr("104.16.230.132")
	v6 := netip.MustParseAddr("2606:4700::6810:e684")

	zone := serveUDP(t, func(query []byte) []byte {
		return answer(t, query, true, []netip.Addr{v4, v6})
	})
	zoneAddr := glueTo(t, zone)
	tld := serveUDP(t, func(query []byte) []byte {
		return referral(t, query, []netip.Addr{zoneAddr})
	})

	r := &resolver{tlds: []string{tld}, doh: []string{deadDoH}, log: discard()}

	rec := r.Resolve(testCtx(t), "demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{v4}) {
		t.Errorf("A = %v, want %v from the zone's nameserver", rec.A, v4)
	}
	if !slices.Equal(rec.AAAA, []netip.Addr{v6}) {
		t.Errorf("AAAA = %v, want %v", rec.AAAA, v6)
	}
}

// TestResolveDiscardsNonAuthoritativeAnswers is the intercepted network, and
// the case the AA requirement exists for: something answers in the zone
// nameserver's place, plausibly and with records — a captive portal resolves
// every name to itself — but it cannot set AA honestly, so its answer must not
// mark the hostname ready. DoH, which interception cannot touch, decides
// instead.
func TestResolveDiscardsNonAuthoritativeAnswers(t *testing.T) {
	poison := netip.MustParseAddr("192.0.2.1") // the portal's own address
	honest := netip.MustParseAddr("104.16.230.132")

	middlebox := serveUDP(t, func(query []byte) []byte {
		return answer(t, query, false, []netip.Addr{poison})
	})
	middleAddr := glueTo(t, middlebox)
	tld := serveUDP(t, func(query []byte) []byte {
		return referral(t, query, []netip.Addr{middleAddr})
	})
	doh, _ := serveDoH(t, []netip.Addr{honest})

	r := &resolver{tlds: []string{tld}, doh: []string{doh}, log: discard()}

	rec := r.Resolve(testCtx(t), "demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{honest}) {
		t.Errorf("A = %v, want DoH's %v — a non-authoritative answer was believed", rec.A, honest)
	}
}

// TestResolveViaDoHWhenWalkHasNowhereToGo pins the other interception shape: a
// network that answers the TLD query itself returns an answer, not a referral,
// so the walk finds no glue and DoH is the source that resolves.
func TestResolveViaDoHWhenWalkHasNowhereToGo(t *testing.T) {
	want := netip.MustParseAddr("104.16.230.132")

	tld := serveUDP(t, func(query []byte) []byte {
		return answer(t, query, false, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	})
	doh, _ := serveDoH(t, []netip.Addr{want})

	r := &resolver{tlds: []string{tld}, doh: []string{doh}, log: discard()}

	rec := r.Resolve(testCtx(t), "demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{want}) {
		t.Errorf("A = %v, want DoH's %v", rec.A, want)
	}
}

// TestResolveKeepsAskingUntilPublished pins the wait itself: a name that is
// not published on the first round is asked about again, and Resolve returns
// as soon as a round finds it. This is the readiness scenario — the record
// appears moments after the first query misses.
func TestResolveKeepsAskingUntilPublished(t *testing.T) {
	want := netip.MustParseAddr("104.16.230.132")
	var published atomic.Bool

	zone := serveUDP(t, func(query []byte) []byte {
		if !published.Load() {
			return answer(t, query, true, nil)
		}
		return answer(t, query, true, []netip.Addr{want})
	})
	zoneAddr := glueTo(t, zone)
	tld := serveUDP(t, func(query []byte) []byte {
		return referral(t, query, []netip.Addr{zoneAddr})
	})

	r := &resolver{tlds: []string{tld}, doh: []string{deadDoH}, log: discard()}

	time.AfterFunc(300*time.Millisecond, func() { published.Store(true) })
	rec := r.Resolve(testCtx(t), "demo.trycloudflare.com")
	if !slices.Equal(rec.A, []netip.Addr{want}) {
		t.Errorf("A = %v, want %v once published", rec.A, want)
	}
}

// TestResolveReturnsEmptyWhenCtxEnds pins the only way Resolve gives up: the
// caller's ctx. Nothing answers here — the network drops every query — and
// Resolve must come back empty when told to stop, not hang on the reads.
func TestResolveReturnsEmptyWhenCtxEnds(t *testing.T) {
	silent := serveUDP(t, func([]byte) []byte { return nil })

	r := &resolver{tlds: []string{silent}, doh: []string{deadDoH}, log: discard()}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	rec := r.Resolve(ctx, "demo.trycloudflare.com")
	if !rec.Empty() {
		t.Errorf("Resolve() = %+v, want empty Records when ctx ends first", rec)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Resolve returned %s after ctx ended — hung on unanswered queries", elapsed)
	}
}

// TestDoHRequestIsUncacheable pins the request shape. Readiness asks the same
// name repeatedly while it is still unpublished, so a reply that an HTTP cache
// may reuse is the one thing that must not happen: RFC 8484 responses to POST
// are not cached, and Cache-Control asks the endpoint for a fresh answer.
func TestDoHRequestIsUncacheable(t *testing.T) {
	endpoint, seen := serveDoH(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")})

	if addrs := queryDoH(testCtx(t), endpoint, "demo.trycloudflare.com", dnsmessage.TypeA); len(addrs) == 0 {
		t.Fatal("queryDoH returned nothing from a live stub")
	}
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

// TestParseAnswerReportsAuthority pins the AA bit's journey through the
// parser: the direct path trusts nothing without it.
func TestParseAnswerReportsAuthority(t *testing.T) {
	v4 := netip.MustParseAddr("104.16.230.132")
	query, err := buildQuery("demo.trycloudflare.com", dnsmessage.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, authoritative := range []bool{true, false} {
		addrs, aa, err := parseAnswer(answer(t, query, authoritative, []netip.Addr{v4}), dnsmessage.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if aa != authoritative {
			t.Errorf("authoritative = %v, want %v", aa, authoritative)
		}
		if !slices.Equal(addrs, []netip.Addr{v4}) {
			t.Errorf("addrs = %v, want %v", addrs, []netip.Addr{v4})
		}
	}
}

// TestParseAnswerSkipsOtherTypes pins that a reply read for one family yields
// nothing of the other.
func TestParseAnswerSkipsOtherTypes(t *testing.T) {
	query, err := buildQuery("demo.trycloudflare.com", dnsmessage.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	wire := answer(t, query, true, []netip.Addr{netip.MustParseAddr("104.16.230.132")})

	addrs, _, err := parseAnswer(wire, dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 0 {
		t.Errorf("AAAA addrs = %v, want none", addrs)
	}
}

func TestParseAnswerRejectsMalformed(t *testing.T) {
	if _, _, err := parseAnswer([]byte{0x00, 0x01}, dnsmessage.TypeA); err == nil {
		t.Error("malformed response should error")
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
	if !(Records{AAAA: []netip.Addr{netip.MustParseAddr("::1")}}).Empty() {
		t.Error("Records with only an AAAA record should be empty: IPv6 alone is not reachable everywhere")
	}
}
