package resolver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// fleetClient is the short-timeout HTTP client the fleet walk uses for its own
// DoH round-trips. It is independent of the dualstack client below: resolving
// the resolver must not recurse.
var fleetClient = &http.Client{Timeout: 5 * time.Second}

// Resolve walks the DoH fleet until an endpoint answers with addresses for
// hostname, returning them v4-first. It exists because CI runners and
// captive-portal resolvers answer AAAA-only on hosts with no IPv6 egress (and
// negative-cache fresh A records for the zone's SOA minimum); the DoH fleet —
// the same machinery HostnameReady trusts — sidesteps both.
func Resolve(ctx context.Context, hostname string) ([]netip.Addr, error) {
	var lastErr error
	for _, endpoint := range Endpoints {
		addrs, err := Lookup(ctx, fleetClient, endpoint, hostname)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = fmt.Errorf("%s has no records for %s yet", endpoint, hostname)
	}
	return nil, fmt.Errorf("DoH fleet exhausted resolving %s: %w", hostname, lastErr)
}

// DialContext resolves the address's host over the DoH fleet (both families)
// and dials each candidate in turn, returning the first connection. A v6
// candidate with no route fails fast and the v4 candidate wins — dualstack
// behavior independent of the system resolver. An address already given as an
// IP literal is dialed straight through.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}

	addrs, err := Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("every address for %s failed (last %v)", host, lastErr)
}

// HTTPClient returns an *http.Client that resolves hostnames over the DoH fleet
// and dials dualstack via DialContext. TLS SNI and certificate verification
// still use the URL hostname; only the TCP dial target changes. Use it to reach
// a host from a network whose own resolver is unreliable — CI runners that
// answer AAAA-only with no IPv6 egress, captive portals — where the default
// client can stall or fail.
func HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{DialContext: DialContext},
	}
}
