package resolver_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// serveDNS starts a UDP DNS server on loopback that answers each query with
// handler's wire response, and returns its ip:port. The server stops on test
// cleanup.
func serveDNS(t *testing.T, handler func(dnsmessage.Question) []byte) string {
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
			var p dnsmessage.Parser
			if _, err := p.Start(buf[:n]); err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			if resp := handler(q); resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// respond builds a response to q with the given rcode and A/AAAA answers,
// echoing q's header ID via a fresh parse of nothing (the test server discards
// IDs; the resolver matches on question, not ID, for these single-shot tests).
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
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	if q.Type == dnsmessage.TypeA {
		for _, ip := range v4 {
			if err := b.AResource(rh, dnsmessage.AResource{A: ip}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if q.Type == dnsmessage.TypeAAAA {
		for _, ip := range v6 {
			if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip}); err != nil {
				t.Fatal(err)
			}
		}
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestQueryReturnsSortedRecords(t *testing.T) {
	v4 := [][4]byte{{104, 16, 231, 132}, {104, 16, 230, 132}}
	v6 := [][16]byte{{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0xe6, 0x84}}
	server := serveDNS(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeSuccess, v4, v6)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := resolver.Query(ctx, server, "demo.trycloudflare.com")
	if err != nil {
		t.Fatal(err)
	}

	wantA := []netip.Addr{netip.AddrFrom4([4]byte{104, 16, 230, 132}), netip.AddrFrom4([4]byte{104, 16, 231, 132})}
	if rec.A[0] != wantA[0] || rec.A[1] != wantA[1] {
		t.Errorf("A = %v, want sorted %v", rec.A, wantA)
	}
	if len(rec.AAAA) != 1 || rec.AAAA[0] != netip.AddrFrom16(v6[0]) {
		t.Errorf("AAAA = %v, want one address", rec.AAAA)
	}
	if rec.Empty() {
		t.Error("Empty() = true for a populated record set")
	}
}

func TestQueryNXDOMAINIsEmptyNotError(t *testing.T) {
	server := serveDNS(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeNameError, nil, nil)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := resolver.Query(ctx, server, "missing.trycloudflare.com")
	if err != nil {
		t.Fatalf("NXDOMAIN should not error: %v", err)
	}
	if !rec.Empty() {
		t.Errorf("records = %+v, want empty for NXDOMAIN", rec)
	}
}

func TestQueryServerFailureIsError(t *testing.T) {
	server := serveDNS(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeServerFailure, nil, nil)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := resolver.Query(ctx, server, "demo.trycloudflare.com"); err == nil {
		t.Error("SERVFAIL should be an error")
	}
}

func TestRecordsEqual(t *testing.T) {
	a := resolver.Records{
		A:    []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
		AAAA: []netip.Addr{netip.AddrFrom16([16]byte{0x20, 0x01})},
	}
	same := resolver.Records{
		A:    []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
		AAAA: []netip.Addr{netip.AddrFrom16([16]byte{0x20, 0x01})},
	}
	diff := resolver.Records{A: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 2})}}

	if !a.Equal(same) {
		t.Error("Equal = false for identical records")
	}
	if a.Equal(diff) {
		t.Error("Equal = true for differing records")
	}
}

// TestNewResolverDialsPacketConn guards the framing seam: Go's resolver
// type-asserts the dialed conn to net.PacketConn to choose datagram (bare) over
// stream (length-prefixed) framing. The NXDOMAIN/timeout repair parses bare
// messages, so the wrapper must keep presenting as a PacketConn on the UDP path.
// If a future edit drops that interface, framing silently flips to stream and
// the 2-byte length prefix desyncs every parse — this test fails first.
func TestNewResolverDialsPacketConn(t *testing.T) {
	server := serveDNS(t, func(q dnsmessage.Question) []byte {
		return respond(t, q, dnsmessage.RCodeSuccess, [][4]byte{{1, 2, 3, 4}}, nil)
	})

	r := resolver.NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := r.Dial(ctx, "udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatalf("UDP conn %T does not implement net.PacketConn: Go will use stream framing and the repair parser will desync", conn)
	}
}
