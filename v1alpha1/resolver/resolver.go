// Package resolver does direct DNS lookups against a specific server — the
// dig(1) equivalent: build the query with golang.org/x/net/dns/dnsmessage, send
// it over UDP (retrying over TCP when the answer is truncated), and parse the
// reply. It backs hostname-readiness polling, which queries a zone's
// authoritative nameservers directly so a recursive resolver's negative cache
// never delays readiness.
//
// Queries are nonrecursive (RD=0): they target the zone's authoritative
// nameservers, which answer in-zone names authoritatively (the AA bit) whether
// or not recursion is requested, so RD is unnecessary — and a nonrecursive
// query can't be served from any recursive cache.
package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// NewResolver returns a *net.Resolver that transparently repairs a flaky system
// resolver: every lookup runs through the system path first, and any UDP answer
// that comes back NXDOMAIN is retried against the zone's authoritative
// nameservers, the result spliced back in as if the system had answered. It
// exists because a fresh record (e.g. a just-minted trycloudflare hostname) can
// be live on the authoritative servers while a recursive resolver still serves a
// stale negative cache — exactly the "no such host" a caller hits dialing the
// tunnel URL the moment readiness reports green.
//
// PreferGo is mandatory: only Go's pure resolver consults Dial, so without it
// (notably on macOS, where cgo is the default) the interception never runs.
func NewResolver() *net.Resolver {
	dialFn := net.DefaultResolver.Dial
	if dialFn == nil {
		var d net.Dialer
		dialFn = d.DialContext
	}

	// clean is the un-patched path used for the fallback's own NS/A lookups, so
	// resolving a zone's nameservers can't re-enter the wrapper and recurse.
	clean := &net.Resolver{PreferGo: true, Dial: dialFn}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialFn(ctx, network, address)
			if err != nil {
				return nil, err
			}
			// Only the UDP path is wrapped, and the wrapper must keep presenting
			// as a net.PacketConn (see ResolverConn): Go's resolver type-asserts
			// the conn to choose datagram vs stream framing, and a stream-framed
			// conn prepends a 2-byte length our bare-message parsing doesn't
			// expect. A TCP conn is returned unwrapped — its single-name answers
			// never need repair.
			pc, ok := conn.(net.PacketConn)
			if network != "udp" || !ok {
				return conn, nil
			}
			return &ResolverConn{conn: conn, pc: pc, network: network, ctx: ctx, clean: clean}, nil
		},
	}
}

// ResolverConn wraps a DNS-server connection so it can watch answers flow back
// and substitute an authoritative result when the upstream fails a fresh name.
// ctx is captured at dial time because Read carries none; clean is the
// un-patched resolver used for the fallback lookups; query holds the last
// outbound message so a silent (dropped/timed-out) upstream — which yields no
// response to read the question from — can still be recovered and re-resolved.
type ResolverConn struct {
	conn    net.Conn
	pc      net.PacketConn
	network string
	ctx     context.Context
	clean   *net.Resolver
	query   []byte
}

// ResolverConn must satisfy net.PacketConn, not just net.Conn: Go's resolver
// type-asserts the dialed conn to net.PacketConn to select datagram (bare)
// framing over stream (length-prefixed) framing. Hiding the underlying
// *net.UDPConn's PacketConn methods would silently flip it to stream framing.
var _ net.PacketConn = &ResolverConn{}

// ReadFrom implements [net.PacketConn], delegating to the underlying conn. It
// exists to preserve the PacketConn identity; Go's connected-UDP DNS path reads
// via Read, so this is not on the hot path.
func (r *ResolverConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return r.pc.ReadFrom(p)
}

// WriteTo implements [net.PacketConn], delegating to the underlying conn.
func (r *ResolverConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return r.pc.WriteTo(p, addr)
}

// Close implements [net.Conn].
func (r *ResolverConn) Close() error {
	return r.conn.Close()
}

// LocalAddr implements [net.Conn].
func (r *ResolverConn) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

// Write implements [net.Conn]. It stashes the outbound query so Read can recover
// the question when the upstream answers with silence (a drop/timeout) rather
// than a packet.
func (r *ResolverConn) Write(b []byte) (int, error) {
	r.query = append(r.query[:0], b...)
	return r.conn.Write(b)
}

// Read implements [net.Conn]. It reads one DNS answer from the upstream server
// and, when the upstream fails a name two ways a fresh record provokes — an
// NXDOMAIN response, or a silent drop that surfaces as a read timeout — replaces
// it with an authoritative answer if one exists. This is the wire-level seam
// where "no such host" is caught and repaired.
func (r *ResolverConn) Read(b []byte) (n int, err error) {
	n, err = r.conn.Read(b)
	// Only UDP is rewritten: TCP frames a 2-byte length prefix Go reads
	// separately, and a single-name A/AAAA answer never truncates onto TCP.
	if r.network != "udp" || !r.shouldRepair(b[:n], err) {
		return n, err
	}
	// On NXDOMAIN the response echoes the question; on a timeout there is no
	// response at all. Either way the stashed outbound query carries the ID and
	// question to re-resolve.
	id, q, ok := parseQuestion(r.query)
	if !ok {
		return n, err
	}
	repl, ok := r.fallback(id, q)
	if !ok {
		return n, err // authoritative path found nothing: keep the upstream failure
	}
	return copy(b, repl), nil
}

// shouldRepair reports whether a UDP read is a failure worth retrying against
// authoritative nameservers: an NXDOMAIN response, or a timeout (the upstream
// dropped the query — some flaky resolvers stay silent instead of answering
// NXDOMAIN). Other read errors and successful responses pass through untouched.
func (r *ResolverConn) shouldRepair(resp []byte, readErr error) bool {
	if readErr != nil {
		var ne net.Error
		return errors.As(readErr, &ne) && ne.Timeout()
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	return err == nil && h.RCode == dnsmessage.RCodeNameError
}

// parseQuestion pulls the transaction ID and the (single) question out of a DNS
// message — used on the stashed outbound query to learn what to re-resolve.
func parseQuestion(msg []byte) (uint16, dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return 0, dnsmessage.Question{}, false
	}
	q, err := p.Question()
	if err != nil {
		return 0, dnsmessage.Question{}, false
	}
	return h.ID, q, true
}

// fallback re-resolves q against the zone's authoritative nameservers and, on a
// hit, returns a wire response (echoing id and the question) to splice in for
// the failed upstream answer. ok is false when nothing resolves, leaving the
// upstream failure intact.
func (r *ResolverConn) fallback(id uint16, q dnsmessage.Question) ([]byte, bool) {
	name := strings.TrimSuffix(q.Name.String(), ".")
	_, zone, found := strings.Cut(name, ".")
	if !found {
		return nil, false // apex/single-label name has no parent zone to query
	}

	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()

	servers, err := NameserverIPs(ctx, zone, r.clean)
	if err != nil || len(servers) == 0 {
		return nil, false
	}
	for _, server := range servers {
		rec, err := Query(ctx, server, name)
		if err != nil || rec.Empty() {
			continue
		}
		if repl, err := buildResponse(id, q, rec); err == nil {
			return repl, true
		}
	}
	return nil, false
}

// buildResponse encodes a DNS response answering q from rec: it echoes id and
// the question, sets the response/recursion-available flags with RCode success,
// and appends the A or AAAA records matching q.Type. It is the inverse of
// buildQuery — what a nameserver would have returned had the upstream not
// NXDOMAIN'd.
func buildResponse(id uint16, q dnsmessage.Question, rec Records) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	// TTL is short: these are freshly-propagated records, and we don't want a
	// downstream cache holding them past their real lifetime.
	hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}
	switch q.Type {
	case dnsmessage.TypeA:
		for _, addr := range rec.A {
			if err := b.AResource(hdr, dnsmessage.AResource{A: addr.As4()}); err != nil {
				return nil, err
			}
		}
	case dnsmessage.TypeAAAA:
		for _, addr := range rec.AAAA {
			if err := b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: addr.As16()}); err != nil {
				return nil, err
			}
		}
	}
	return b.Finish()
}

// RemoteAddr implements [net.Conn].
func (r *ResolverConn) RemoteAddr() net.Addr {
	return r.conn.RemoteAddr()
}

// SetDeadline implements [net.Conn].
func (r *ResolverConn) SetDeadline(t time.Time) error {
	return r.conn.SetDeadline(t)
}

// SetReadDeadline implements [net.Conn].
func (r *ResolverConn) SetReadDeadline(t time.Time) error {
	return r.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements [net.Conn].
func (r *ResolverConn) SetWriteDeadline(t time.Time) error {
	return r.conn.SetWriteDeadline(t)
}

// maxResponse bounds a single DNS reply read; an A/AAAA answer for one name is
// far smaller.
const maxResponse = 64 << 10

// Records is a name's resolved address set — A and AAAA, each sorted so two
// servers' answers compare by value.
type Records struct {
	A    []netip.Addr
	AAAA []netip.Addr
}

// Empty reports whether neither family resolved.
func (r Records) Empty() bool { return len(r.A) == 0 && len(r.AAAA) == 0 }

// Equal reports whether r and o hold the same addresses in both families.
func (r Records) Equal(o Records) bool {
	return slices.Equal(r.A, o.A) && slices.Equal(r.AAAA, o.AAAA)
}

// Query asks server (an ip:port DNS endpoint) for hostname's A and AAAA records
// with recursion desired, returning both families sorted. It queries over UDP
// and retries over TCP if the answer is truncated. A name that does not (yet)
// resolve comes back as empty Records with a nil error (the "keep polling"
// signal); transport and DNS-level failures return an error.
func Query(ctx context.Context, server, hostname string) (Records, error) {
	a, err := query(ctx, server, hostname, dnsmessage.TypeA)
	if err != nil {
		return Records{}, err
	}
	aaaa, err := query(ctx, server, hostname, dnsmessage.TypeAAAA)
	if err != nil {
		return Records{}, err
	}
	return Records{A: a, AAAA: aaaa}, nil
}

func query(ctx context.Context, server, hostname string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	wire, err := buildQuery(hostname, qtype)
	if err != nil {
		return nil, err
	}

	resp, err := exchangeUDP(ctx, server, wire)
	if err != nil {
		return nil, err
	}
	truncated, addrs, err := parse(resp, qtype)
	if err != nil {
		return nil, err
	}
	if truncated {
		if resp, err = exchangeTCP(ctx, server, wire); err != nil {
			return nil, err
		}
		if _, addrs, err = parse(resp, qtype); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return addrs, nil
}

func buildQuery(hostname string, qtype dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}
	// RD=0: these queries go straight to the zone's authoritative nameservers,
	// which answer in-zone names authoritatively regardless, so recursion is
	// neither needed nor wanted. (Authoritative/AA is a response flag the server
	// sets — pointless on an outbound query.)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: false})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func exchangeUDP(ctx context.Context, server string, wire []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, maxResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, wire []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// RFC 1035: TCP DNS messages are prefixed with a two-byte length.
	msg := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(msg, uint16(len(wire)))
	copy(msg[2:], wire)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parse(resp []byte, qtype dnsmessage.Type) (truncated bool, addrs []netip.Addr, err error) {
	var p dnsmessage.Parser
	header, err := p.Start(resp)
	if err != nil {
		return false, nil, fmt.Errorf("malformed DNS response: %w", err)
	}
	if header.Truncated {
		return true, nil, nil
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return false, nil, nil // NXDOMAIN: not visible yet
	default:
		return false, nil, fmt.Errorf("server returned rcode %v", header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false, nil, err
	}

	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return false, nil, err
		}
		if rh.Type != qtype {
			// CNAME links and other-family records in the chain: skip.
			if err := p.SkipAnswer(); err != nil {
				return false, nil, err
			}
			continue
		}
		switch qtype {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return false, nil, err
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return false, nil, err
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
		}
	}
	return false, addrs, nil
}

// NameserverIPs resolves the zone's NS records to IPv4 ip:53 endpoints via the
// system resolver. NS records are stable and are not the propagation target, so
// the system resolver is fine here — the record we wait on is queried at these
// servers directly. Any :port on domain is stripped (DNS queries take bare
// names, which the v1 contract allows GetHostname to carry).
//
// Only IPv4 endpoints are kept: an IPv6 NS anycast address on an IPv4-only host
// (e.g. a GitHub Actions runner) yields "connect: no route to host", burning a
// 5s query timeout each round for nothing. Every Cloudflare NS has an IPv4
// anycast address, so v4-only loses no nameserver.
func NameserverIPs(ctx context.Context, domain string, resolver *net.Resolver) ([]string, error) {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	ns, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("authoritative NS lookup failed for %q: %w", domain, err)
	}
	var servers []string
	for _, record := range ns {
		ips, err := resolver.LookupIP(ctx, "ip4", record.Host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return servers, nil
}
