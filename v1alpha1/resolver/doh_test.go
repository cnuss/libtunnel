package resolver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// dohServer is an httptest TLS server speaking just enough RFC 8484: it
// parses the POSTed wire-format query and lets answer build the response.
func dohServer(t *testing.T, answer func(q dnsmessage.Question) []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			t.Errorf("Content-Type = %q, want application/dns-message", ct)
		}
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)

		var p dnsmessage.Parser
		if _, err := p.Start(body[:n]); err != nil {
			t.Errorf("malformed query: %v", err)
			return
		}
		q, err := p.Question()
		if err != nil {
			t.Errorf("no question in query: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer(q))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// respond builds a wire-format response for q with the given rcode, answering
// A questions from v4 and AAAA questions from v6 (matching the question type,
// as a real resolver does).
func respond(t *testing.T, q dnsmessage.Question, rcode dnsmessage.RCode, v4 [][4]byte, v6 [][16]byte) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
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
	switch q.Type {
	case dnsmessage.TypeA:
		for _, a := range v4 {
			if err := b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a}); err != nil {
				t.Fatal(err)
			}
		}
	case dnsmessage.TypeAAAA:
		for _, a := range v6 {
			if err := b.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AAAAResource{AAAA: a}); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLookupSuccess(t *testing.T) {
	v4 := [4]byte{104, 16, 230, 132}
	v6 := [16]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0xe6, 0x84}
	srv := dohServer(t, func(q dnsmessage.Question) []byte {
		if got, want := q.Name.String(), "demo.trycloudflare.com."; got != want {
			t.Errorf("queried name = %q, want %q", got, want)
		}
		return respond(t, q, dnsmessage.RCodeSuccess, [][4]byte{v4}, [][16]byte{v6})
	})

	addrs, err := resolver.Lookup(context.Background(), srv.Client(), srv.URL, "demo.trycloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	// v4-first: the A record precedes the AAAA record, so a caller dialing in
	// order tries IPv4 before IPv6.
	want := []netip.Addr{netip.AddrFrom4(v4), netip.AddrFrom16(v6)}
	if len(addrs) != len(want) || addrs[0] != want[0] || addrs[1] != want[1] {
		t.Errorf("addrs = %v, want %v (v4 first)", addrs, want)
	}
}

func TestLookupNXDOMAINIsNotAnError(t *testing.T) {
	srv := dohServer(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeNameError, nil, nil)
	})

	addrs, err := resolver.Lookup(context.Background(), srv.Client(), srv.URL, "missing.trycloudflare.com")
	if err != nil {
		t.Fatalf("NXDOMAIN must read as not-yet-visible, got error: %v", err)
	}
	if len(addrs) != 0 {
		t.Errorf("addrs = %v, want none", addrs)
	}
}

func TestLookupServerFailureIsAnError(t *testing.T) {
	srv := dohServer(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeServerFailure, nil, nil)
	})

	if _, err := resolver.Lookup(context.Background(), srv.Client(), srv.URL, "demo.trycloudflare.com"); err == nil {
		t.Error("SERVFAIL returned no error")
	}
}

func TestLookupMalformedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write([]byte("<html>not dns</html>"))
	}))
	defer srv.Close()

	if _, err := resolver.Lookup(context.Background(), srv.Client(), srv.URL, "demo.trycloudflare.com"); err == nil {
		t.Error("malformed body returned no error")
	}
}

func TestLookupHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if _, err := resolver.Lookup(context.Background(), srv.Client(), srv.URL, "demo.trycloudflare.com"); err == nil {
		t.Error("HTTP 429 returned no error")
	}
}

func TestLookupTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	// LIFO: unblock the handler before srv.Close waits on it.
	defer close(block)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := resolver.Lookup(ctx, srv.Client(), srv.URL, "demo.trycloudflare.com"); err == nil {
		t.Error("slow endpoint returned no error before the context deadline")
	}
}
