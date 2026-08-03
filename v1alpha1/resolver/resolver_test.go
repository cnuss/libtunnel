package resolver_test

import (
	"context"
	"encoding/binary"
	"io"
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
	// Authoritative: these stand in for the zone's own nameservers, which set AA
	// on RD=0 answers — what query now requires to accept a response.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true, RCode: rcode})
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

// parseQ extracts the question from a raw DNS message.
func parseQ(b []byte) (dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(b); err != nil {
		return dnsmessage.Question{}, false
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Question{}, false
	}
	return q, true
}

// serveDNSSplit listens for DNS on both UDP and TCP at one loopback ip:port,
// answering each transport from its own handler — so a test can simulate a
// network where UDP/53 is intercepted but TCP reaches the real server. Returns
// the shared ip:port.
func serveDNSSplit(t *testing.T, udp, tcp func(dnsmessage.Question) []byte) string {
	t.Helper()
	tcpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcpL.Close() })
	addr := tcpL.Addr().String()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1024)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if q, ok := parseQ(buf[:n]); ok {
				if resp := udp(q); resp != nil {
					pc.WriteTo(resp, raddr)
				}
			}
		}
	}()
	go func() {
		for {
			conn, err := tcpL.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var length uint16
				if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
					return
				}
				msg := make([]byte, length)
				if _, err := io.ReadFull(conn, msg); err != nil {
					return
				}
				q, ok := parseQ(msg)
				if !ok {
					return
				}
				resp := tcp(q)
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				conn.Write(out)
			}()
		}
	}()
	return addr
}

// nonAuthRefused mimics an intercepting recursive resolver answering an RD=0
// query for a zone it is not authoritative for: RA set, no AA, REFUSED.
func nonAuthRefused(t *testing.T, q dnsmessage.Question) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeRefused})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// TestQueryRacesTCPWhenUDPIntercepted pins the #123 fix: UDP/53 answers with a
// hijacked non-authoritative REFUSED, TCP with the real authoritative record.
// The race must take the TCP answer instead of hanging on the UDP REFUSED.
func TestQueryRacesTCPWhenUDPIntercepted(t *testing.T) {
	v4 := [][4]byte{{104, 16, 230, 132}}
	server := serveDNSSplit(t,
		func(q dnsmessage.Question) []byte { return nonAuthRefused(t, q) },
		func(q dnsmessage.Question) []byte { return respond(t, q, dnsmessage.RCodeSuccess, v4, nil) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := resolver.Query(ctx, server, "demo.trycloudflare.com")
	if err != nil {
		t.Fatalf("race should resolve over TCP when UDP is intercepted: %v", err)
	}
	if len(rec.A) != 1 || rec.A[0] != netip.AddrFrom4(v4[0]) {
		t.Errorf("A = %v, want the TCP authoritative answer %v", rec.A, v4[0])
	}
}

// nonAuthAnswer mimics a transparent recursive resolver that answers CORRECTLY
// but does not set AA: RA set, NOERROR, real records. Common on home and
// corporate networks.
func nonAuthAnswer(t *testing.T, q dnsmessage.Question, v4 [][4]byte) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true})
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
	if q.Type == dnsmessage.TypeA {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		for _, ip := range v4 {
			if err := b.AResource(rh, dnsmessage.AResource{A: ip}); err != nil {
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

// TestQueryAcceptsNonAuthoritativeRecords is the regression guard for the AA
// requirement that shipped in v0.0.39: a transparent resolver that answers
// correctly without setting AA must still be believed. Requiring AA made every
// probe fail on such networks, so hostname readiness never fired and the tunnel
// hung at "waiting for DNS" forever. Records are the readiness signal — trust
// them whether or not AA is set.
func TestQueryAcceptsNonAuthoritativeRecords(t *testing.T) {
	v4 := [][4]byte{{104, 16, 230, 132}}
	server := serveDNSSplit(t,
		func(q dnsmessage.Question) []byte { return nonAuthAnswer(t, q, v4) },
		func(q dnsmessage.Question) []byte { return nonAuthAnswer(t, q, v4) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := resolver.Query(ctx, server, "demo.trycloudflare.com")
	if err != nil {
		t.Fatalf("a correct answer without AA must be accepted, got error: %v", err)
	}
	if len(rec.A) != 1 || rec.A[0] != netip.AddrFrom4(v4[0]) {
		t.Errorf("A = %v, want %v from the non-authoritative answer", rec.A, v4[0])
	}
}

// TestQueryNonAuthoritativeIsRejected pins that a non-authoritative NEGATIVE is
// never trusted: when both transports return a hijacked (no-AA, no records)
// response, Query errors rather than accepting it as "not published" or hanging.
func TestQueryNonAuthoritativeIsRejected(t *testing.T) {
	server := serveDNSSplit(t,
		func(q dnsmessage.Question) []byte { return nonAuthRefused(t, q) },
		func(q dnsmessage.Question) []byte { return nonAuthRefused(t, q) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := resolver.Query(ctx, server, "demo.trycloudflare.com"); err == nil {
		t.Error("both transports non-authoritative should error, not succeed")
	}
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
