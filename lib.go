// Package libtunnel exposes a local listener to the public internet through a
// tunnel backend (Cloudflare quick tunnels first), behind a thin, stable
// façade over stable/alpha versioned packages.
//
// The package is split into these pieces:
//
//   - libtunnel (this package) — thin façade exposing New and the backend
//     constructors. Stable surface for application code.
//   - github.com/cnuss/libtunnel/v1 — the stable Tunnel/Connected/Provider/
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
	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// New returns an unstarted tunnel on the given backend, which also supplies
// the credential chain. T is the backend's spec type and is inferred:
//
//	libtunnel.New(libtunnel.Cloudflare())
//
// Configure the result with With* methods; WithListener starts the
// connection.
func New[T v1.Spec](backend v1.Backend[T]) v1.Tunnel[T] {
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
func Cloudflare() v1.Backend[*cloudflare.Spec] {
	return cloudflare.New()
}
