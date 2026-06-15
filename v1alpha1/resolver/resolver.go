// Package resolver does direct DNS lookups against a specific server — the
// dig(1) equivalent: build the query with golang.org/x/net/dns/dnsmessage, send
// it over UDP (retrying over TCP when the answer is truncated), and parse the
// reply. It backs hostname-readiness polling, which queries a zone's
// authoritative nameservers directly so a recursive resolver's negative cache
// never delays readiness.
//
// Queries set RD=1 (recursion desired): Cloudflare's quick-tunnel nameservers
// REFUSE nonrecursive (RD=0) queries, so a "nonrecursive" lookup is not an
// option against them.
package resolver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"

	"golang.org/x/net/dns/dnsmessage"
)

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
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
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
