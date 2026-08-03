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
// directly (RD=0), returning both families sorted. Each family is raced over UDP
// and TCP, preferring but not requiring an authoritative (AA) answer, so a
// network intercepting port 53 cannot stall the result (see query). A name that
// does not (yet) resolve comes back as empty Records with a nil error (the "keep
// polling" signal); transport and DNS-level failures return an error.
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

// query races the question over UDP and TCP against server and returns the
// addresses from the first usable answer. Racing both transports defeats a
// network that intercepts port 53: an interceptor stands in for the zone's
// nameserver, and for an RD=0 query it is not authoritative for it typically
// REFUSEs — while the other transport (interceptors usually target UDP) reaches
// the real server.
//
// The AA bit is NOT required — only consulted to judge a refusal:
//
//   - Any response CARRYING RECORDS is accepted. Records are the readiness
//     signal, and plenty of benign middleboxes answer correctly without setting
//     AA (a transparent recursive resolver on a home or corporate network).
//     Requiring AA here hangs the poll on those networks.
//   - A well-formed negative — NOERROR with no records, or NXDOMAIN — is "not
//     published yet": empty addrs, nil error, keep polling. Believed with or
//     without AA, since an empty family (an A-only host's AAAA) is routine.
//   - A REFUSED/SERVFAIL-class failure is judged by AA: from the zone's own
//     nameserver it is a real error; from anything else it is likely an
//     interceptor rejecting the RD=0 query, so it is set aside to let the other
//     transport speak. If neither transport produces anything usable, that
//     failure is returned — naming the likely interception — rather than
//     silently polling on a lie.
func query(ctx context.Context, server, hostname string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	wire, err := buildQuery(hostname, qtype)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stop the slower transport once one answers authoritatively

	type result struct {
		transport string
		ans       answer
		err       error
	}
	results := make(chan result, 2) // buffered: the loser never blocks on send
	race := func(transport string, exchange func(context.Context, string, []byte) ([]byte, error)) {
		resp, err := exchange(ctx, server, wire)
		if err != nil {
			results <- result{transport: transport, err: err}
			return
		}
		ans, err := parse(resp, qtype)
		results <- result{transport: transport, ans: ans, err: err}
	}
	go race("udp", exchangeUDP)
	go race("tcp", exchangeTCP)

	var lastErr error
	for range 2 {
		r := <-results
		switch {
		case r.err != nil:
			lastErr = fmt.Errorf("%s: %w", r.transport, r.err)
		case r.ans.truncated:
			// UDP hit the 512-byte limit; the TCP leg carries the full message.
		case len(r.ans.addrs) > 0:
			// Records answer the question, authoritative or not.
			addrs := r.ans.addrs
			slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
			return addrs, nil
		case r.ans.rcode == dnsmessage.RCodeSuccess, r.ans.rcode == dnsmessage.RCodeNameError:
			// A well-formed negative: the name has no record of this family yet
			// (NOERROR) or does not exist yet (NXDOMAIN). Both mean keep polling,
			// and both are believable without AA — a family with no records is the
			// normal answer for, say, an A-only hostname's AAAA query.
			return nil, nil
		case !r.ans.authoritative:
			// A refusal or failure from something that is not the zone's
			// nameserver: likely an interceptor rejecting the RD=0 query rather
			// than the zone answering. Set aside so the other transport can speak.
			lastErr = fmt.Errorf("%s: non-authoritative %v (port 53 may be intercepted)", r.transport, r.ans.rcode)
		default:
			return nil, fmt.Errorf("%s: authoritative server returned rcode %v", r.transport, r.ans.rcode)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable DNS answer for %s", hostname)
	}
	return nil, lastErr
}

func buildQuery(hostname string, qtype dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}
	// RD=0: these queries go straight to the zone's authoritative nameservers,
	// which answer in-zone names authoritatively regardless, so recursion is
	// neither needed nor wanted. (Authoritative/AA is a response flag the server
	// sets — pointless on an outbound query.) RD=0 is also what makes an
	// intercepting recursive resolver REFUSE rather than answer — the signal
	// query keys on — but only if the packet reaches the real nameserver at all,
	// which is why query races TCP alongside UDP.
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

// answer is a parsed DNS response: the header bits query needs to judge it plus
// any A/AAAA addresses (populated only on an RCodeSuccess, non-truncated reply).
// A malformed response is the only error — rcode and the AA/TC flags are data
// the caller interprets, not failures.
type answer struct {
	authoritative bool // AA: the responder is the zone's own nameserver
	truncated     bool // TC: retry over TCP for the full message
	rcode         dnsmessage.RCode
	addrs         []netip.Addr
}

func parse(resp []byte, qtype dnsmessage.Type) (answer, error) {
	var p dnsmessage.Parser
	header, err := p.Start(resp)
	if err != nil {
		return answer{}, fmt.Errorf("malformed DNS response: %w", err)
	}
	ans := answer{authoritative: header.Authoritative, truncated: header.Truncated, rcode: header.RCode}
	if header.Truncated || header.RCode != dnsmessage.RCodeSuccess {
		return ans, nil // nothing to parse; query decides on the flags/rcode
	}
	if err := p.SkipAllQuestions(); err != nil {
		return answer{}, err
	}

	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return answer{}, err
		}
		if rh.Type != qtype {
			// CNAME links and other-family records in the chain: skip.
			if err := p.SkipAnswer(); err != nil {
				return answer{}, err
			}
			continue
		}
		switch qtype {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return answer{}, err
			}
			ans.addrs = append(ans.addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return answer{}, err
			}
			ans.addrs = append(ans.addrs, netip.AddrFrom16(r.AAAA))
		}
	}
	return ans, nil
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
