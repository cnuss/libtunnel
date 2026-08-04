package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxUDPResponse bounds a DNS reply read from a datagram socket, and is the
// buffer size EDNS0 advertises.
const maxUDPResponse = 1232

// maxDNSMessage bounds a DNS reply read over HTTPS. The wire format caps a
// message at 64 KiB, so nothing larger is a DNS message.
const maxDNSMessage = 1 << 16

// nameserverPort is where glue addresses are dialed. Glue carries an address
// and no port, so it is always 53 in practice; it is a variable only so tests
// can point the walk at a stub.
var nameserverPort = "53"

// delegation asks server which nameservers hold hostname's zone and returns
// their addresses, taken from the glue the referral carries.
//
// The glue is used rather than the nameserver names: resolving those names
// would mean asking a recursive resolver, which is the thing this path exists
// to avoid.
func delegation(ctx context.Context, server, hostname string) []string {
	query, err := buildQuery(hostname, dnsmessage.TypeA, false)
	if err != nil {
		return nil
	}
	wire, err := exchangeUDP(ctx, server, query)
	if err != nil {
		return nil
	}
	addrs, err := parseGlue(wire)
	if err != nil {
		return nil
	}

	servers := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		servers = append(servers, net.JoinHostPort(addr.String(), nameserverPort))
	}
	// Randomized so one nameserver does not carry every lookup.
	return shuffled(servers)
}

// lookupUDP asks one nameserver directly for hostname's records of type qtype,
// reporting the addresses and whether the reply carried the AA bit. A server
// that does not answer, or answers with garbage, yields nothing.
func lookupUDP(ctx context.Context, server, hostname string, qtype dnsmessage.Type) ([]netip.Addr, bool) {
	query, err := buildQuery(hostname, qtype, false)
	if err != nil {
		return nil, false
	}
	wire, err := exchangeUDP(ctx, server, query)
	if err != nil {
		return nil, false
	}
	addrs, authoritative, err := parseAnswer(wire, qtype)
	if err != nil {
		return nil, false
	}
	return addrs, authoritative
}

// exchangeUDP sends one query to server and returns the reply. server may omit
// the port, in which case 53 is assumed. The exchange has no timeout of its
// own: it is released by ctx — canceled or past its deadline — and not before.
func exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The read below cannot watch ctx itself; this unblocks it when ctx ends.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// queryDoH asks one DoH endpoint for hostname's records of type qtype,
// returning nil for any failure — a caller distinguishes sources by whether
// they produced records, not by why they did not.
func queryDoH(ctx context.Context, endpoint, hostname string, qtype dnsmessage.Type) []netip.Addr {
	// Recursion is desired: a DoH endpoint is a recursive resolver, and asking
	// it not to recurse leaves it able to answer only from its own cache.
	query, err := buildQuery(hostname, qtype, true)
	if err != nil {
		return nil
	}

	// POST carries the query as the body, so it needs neither the base64url
	// wrapping of the GET form nor a cache-buster: RFC 8484 responses to POST
	// are not cached by HTTP intermediaries. Cache-Control asks the endpoint
	// itself for a fresh answer.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	wire, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage))
	if err != nil {
		return nil
	}
	addrs, _, err := parseAnswer(wire, qtype)
	if err != nil {
		return nil
	}
	return addrs
}

// buildQuery encodes a single A or AAAA question in DNS wire format.
// recursionDesired sets the RD bit, which a recursive resolver needs and an
// authoritative server ignores.
func buildQuery(hostname string, qtype dnsmessage.Type, recursionDesired bool) ([]byte, error) {
	name, err := dnsmessage.NewName(dnsName(hostname))
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: recursionDesired})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}

	// EDNS0 advertises a reply buffer past the 512 bytes a bare DNS message is
	// limited to. A referral carries a zone's nameservers and their addresses,
	// which readily exceeds that, and the addresses are the part that would be
	// cut — leaving names that could only be resolved by asking a recursive
	// resolver.
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(maxUDPResponse, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parseAnswer extracts the addresses of type qtype from a DNS reply, and
// reports whether the reply carried the AA bit — the mark of the zone's own
// nameserver, which anything answering in its place cannot set honestly.
// Records of other types in the answer — the CNAME links of a chain — are
// skipped. A reply that resolves to nothing yields no addresses and no error:
// a name that is not published yet is a legitimate answer, not a failure.
func parseAnswer(wire []byte, qtype dnsmessage.Type) ([]netip.Addr, bool, error) {
	var p dnsmessage.Parser
	header, err := p.Start(wire)
	if err != nil {
		return nil, false, fmt.Errorf("malformed DNS response: %w", err)
	}
	if header.RCode != dnsmessage.RCodeSuccess && header.RCode != dnsmessage.RCodeNameError {
		return nil, false, fmt.Errorf("server returned rcode %v", header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false, err
	}

	var addrs []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return addrs, header.Authoritative, nil
		}
		if err != nil {
			return nil, false, err
		}
		if h.Type != qtype {
			if err := p.SkipAnswer(); err != nil {
				return nil, false, err
			}
			continue
		}
		switch qtype {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return nil, false, err
			}
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return nil, false, err
			}
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, false, err
			}
		}
	}
}

// parseGlue extracts the nameserver addresses from a referral's additional
// section. A reply that runs out mid-section is read for whatever it did carry:
// one usable address is enough to continue the walk.
func parseGlue(wire []byte) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		return nil, fmt.Errorf("malformed DNS response: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return nil, err
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return addrs, nil // section done, or truncated: keep what was read
		}
		switch h.Type {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return addrs, nil
			}
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return addrs, nil
			}
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		default:
			if err := p.SkipAdditional(); err != nil {
				return addrs, nil
			}
		}
	}
}
