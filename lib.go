// Package libtunnel exposes a local listener to the public internet through a
// tunnel backend (Cloudflare quick tunnels first), behind a thin, stable
// façade over stable/alpha versioned packages.
//
// The package is split into these pieces:
//
//   - libtunnel (this package) — thin façade exposing New and the backend
//     constructors. Stable surface for application code.
//   - github.com/cnuss/libtunnel/v1 — the stable Tunnel/Tunneled/Provider/
//     Backend interfaces and spec types. Application code that wants to
//     declare types against the contract imports this.
//   - github.com/cnuss/libtunnel/v1alpha1 — the current implementation: the
//     lazy tunnel core plus generic providers, with backend engines in
//     subpackages (v1alpha1/cloudflare). Internals may change between alpha
//     revisions.
//
// Everything is lazy: New returns immediately, and WithListener is the
// trigger that starts the edge connection.
//
//	l, _ := net.Listen("tcp", "127.0.0.1:0")
//	conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
//	go server.Serve(conn.Listener())
//	select {
//	case <-conn.TunnelReady():
//		fmt.Println(conn.URL()) // public https://<hostname>/
//	case <-conn.Done():
//		log.Fatal(conn.Err()) // TunnelReady never closes on failure
//	}
package libtunnel

import (
	"net/http"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// TunnelV1 is the configurable phase returned by New: a non-generic alias for
// v1.Tunnel, re-exported so callers can name the type without importing v1.
// Mutators (With*) chain until WithListener narrows it to TunneledV1.
type TunnelV1 = v1.Tunnel

// TunneledV1 is the post-WithListener phase: a non-generic alias for
// v1.Tunneled (observers and lifecycle, no mutators). Storable as a plain
// field — the backend spec type does not appear in it.
type TunneledV1 = v1.Tunneled

// CloudflareV1 is the backend type returned by Cloudflare: an alias for
// v1.Backend[*cloudflare.Spec], re-exported so callers can name it without
// importing v1 or the cloudflare package.
type CloudflareV1 = v1.Backend[*cloudflare.Spec]

// New returns an unstarted tunnel on the given backend, which also supplies
// the credential chain. T is the backend's spec type, inferred from the
// backend and used only to wire the credential chain — it does not appear in
// the returned type, so the tunnel reference is non-generic and storable
// without threading the spec type through caller code:
//
//	libtunnel.New(libtunnel.Cloudflare())
//
// Configure the result with With* methods; WithListener starts the
// connection.
func New[T v1.Spec](backend v1.Backend[T]) TunnelV1 {
	return v1alpha1.New(backend)
}

// Cloudflare returns the Cloudflare backend: an in-process cloudflared
// quick-tunnel engine (no cloudflared binary required). Its credential chain
// adopts a spec from the TUNNEL_SPEC environment variable when a parent
// process handed one off, mints an anonymous *.trycloudflare.com quick
// tunnel otherwise, and exports a freshly minted spec back into the
// environment so spawned children inherit the same tunnel identity. A spec
// this process exported itself is never re-adopted: a second in-process
// tunnel mints its own identity.
func Cloudflare() CloudflareV1 {
	return cloudflare.New()
}

// HTTPClient returns an http.Client that resolves hostnames over DNS-over-HTTPS
// and dials dualstack — both IPv4 and IPv6, first address to connect wins.
// Reach a tunnel's public URL with it from a network whose own resolver is
// unreliable: CI runners that answer AAAA-only with no IPv6 egress, captive
// portals, anywhere the default client can stall or fail on a fresh hostname.
// TLS verification is unchanged — only the dial target is resolved over DoH.
func HTTPClient() *http.Client {
	return resolver.HTTPClient()
}
