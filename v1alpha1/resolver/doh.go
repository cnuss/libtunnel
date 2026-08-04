package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohResolver resolves over DNS-over-HTTPS. It exists for networks where port
// 53 cannot be trusted — a middlebox answering in a nameserver's place, or a
// resolver the machine was handed and whose cache it cannot flush. DoH rides
// HTTPS, which such a network is not in a position to answer for.
//
// Its answers still come from a recursive resolver, so they can be served from
// that resolver's cache. That is a real cost, accepted only because the
// alternative on these networks is an answer from something worse. servers are
// tried in a random order and each is a different operator, so a stale negative
// held by one does not decide the result.
type dohResolver struct {
	// servers are RFC 8484 endpoints, tried in random order.
	servers []string
	// fallback resolves the hostname when no server returns records.
	fallback Resolver
}

var _ Resolver = &dohResolver{}

// dohTimeout bounds a single request. Three servers are tried, so this is the
// per-attempt budget rather than the total.
const dohTimeout = 5 * time.Second

// Resolve implements [Resolver]. It asks each server in turn for A and AAAA
// records and returns the first non-empty answer, falling back when none of
// them resolves the hostname.
func (r *dohResolver) Resolve(hostname string) Records {
	records := Records{
		CNAME: hostname,
	}

	for _, server := range shuffled(r.servers) {
		records.A = queryDoH(server, hostname, dnsmessage.TypeA)
		records.AAAA = queryDoH(server, hostname, dnsmessage.TypeAAAA)

		if len(records.A) > 0 || len(records.AAAA) > 0 {
			return records
		}

		// If we didn't get any records, wait a second before trying the next server
		time.Sleep(1 * time.Second)
	}

	return r.fallback.Resolve(hostname)
}

// queryDoH asks one DoH endpoint for hostname's records of type qtype,
// returning nil for any failure — a caller distinguishes servers by whether
// they produced records, not by why they did not.
func queryDoH(endpoint, hostname string, qtype dnsmessage.Type) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
	defer cancel()

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
	addrs, err := parseAnswer(wire, qtype)
	if err != nil {
		return nil
	}
	return addrs
}

// maxDNSMessage bounds a DNS reply read over HTTPS. The wire format caps a
// message at 64 KiB, so nothing larger is a DNS message.
const maxDNSMessage = 1 << 16

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

// parseAnswer extracts the addresses of type qtype from a DNS reply. Records of
// other types in the answer — the CNAME links of a chain — are skipped. A reply
// that resolves to nothing yields no addresses and no error: a name that is not
// published yet is a legitimate answer, not a failure.
func parseAnswer(wire []byte, qtype dnsmessage.Type) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	header, err := p.Start(wire)
	if err != nil {
		return nil, fmt.Errorf("malformed DNS response: %w", err)
	}
	if header.RCode != dnsmessage.RCodeSuccess && header.RCode != dnsmessage.RCodeNameError {
		return nil, fmt.Errorf("server returned rcode %v", header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return addrs, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Type != qtype {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		switch qtype {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
}
