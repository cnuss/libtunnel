// Package resolver provides DNS-over-HTTPS readiness queries for the tunnel
// core. The HostnameReady poller's plain :53 queries are useless on networks
// that intercept or block port 53 (VPN exit nodes forcing their own resolver,
// many corporate networks) — every "different" resolver is silently the same
// interceptor. DoH rides ordinary HTTPS, which is interception-proof in
// exactly those situations.
package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// Endpoints is the RFC 8484 fleet the readiness poller cycles through, one
// query per attempt. The IP-literal entries matter: hostname-based endpoints
// need DNS themselves, so without them resolving the resolver could deadlock
// on the very networks this package exists for (the TLS certificates
// Cloudflare and Google ship carry the IP SANs, so verification still holds).
var Endpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://1.1.1.1/dns-query",
	"https://dns.google/dns-query",
	"https://8.8.8.8/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://doh.opendns.com/dns-query",
	"https://dns.adguard-dns.com/dns-query",
	"https://freedns.controld.com/p0",
}

// maxResponse bounds how much of a DoH response is read; a well-formed
// answer for one name is far smaller.
const maxResponse = 64 << 10

// Lookup queries endpoint for hostname's A and AAAA records per RFC 8484: each
// wire-format query is POSTed as application/dns-message and the wire-format
// response parsed back. Addresses come back v4-first, so a caller dialing them
// in order falls back from an unroutable IPv6 to IPv4 without waiting on a v6
// timeout. A name that does not (yet) resolve in either family returns
// (nil, nil) — the "keep polling" signal — while transport, HTTP, and
// DNS-level failures return errors. client supplies timeouts and TLS
// configuration.
func Lookup(ctx context.Context, client *http.Client, endpoint, hostname string) ([]netip.Addr, error) {
	v4, err := query(ctx, client, endpoint, hostname, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	v6, err := query(ctx, client, endpoint, hostname, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

// query runs one RFC 8484 lookup of qtype (A or AAAA) for hostname against
// endpoint and returns the addresses of that family. NXDOMAIN reads as
// (nil, nil); transport, HTTP, and DNS-level failures return errors.
func query(ctx context.Context, client *http.Client, endpoint, hostname string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}

	// RFC 8484 wants ID 0 so responses are cache-friendly.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	wire, err := b.Finish()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	header, err := p.Start(body)
	if err != nil {
		return nil, fmt.Errorf("%s answered a malformed DNS message: %w", endpoint, err)
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil // NXDOMAIN: not visible from this endpoint yet
	default:
		return nil, fmt.Errorf("%s answered rcode %v", endpoint, header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if rh.Type != qtype {
			// CNAME links and the other family's records in the chain: skip.
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		switch qtype {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
		}
	}
	return addrs, nil
}
