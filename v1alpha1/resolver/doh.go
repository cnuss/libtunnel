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

// LookupA queries endpoint for hostname's A records per RFC 8484: the
// wire-format query is POSTed as application/dns-message and the wire-format
// response parsed back. A name that does not (yet) resolve returns (nil, nil)
// — that is the "keep polling" signal — while transport, HTTP, and DNS-level
// failures return errors. client supplies timeouts and TLS configuration.
func LookupA(ctx context.Context, client *http.Client, endpoint, hostname string) ([]netip.Addr, error) {
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
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	query, err := b.Finish()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
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
		if rh.Type != dnsmessage.TypeA {
			// CNAME links and anything else in the chain: not addresses.
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		r, err := p.AResource()
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, netip.AddrFrom4(r.A))
	}
	return addrs, nil
}
