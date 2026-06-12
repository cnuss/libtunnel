// Package libtunnel exposes a local listener to the public internet through a
// tunnel backend (Cloudflare quick tunnels first), behind a thin, stable
// façade over stable/alpha versioned packages.
//
// The package is split into these pieces:
//
//   - libtunnel (this package) — thin façade exposing New, the backend and
//     provider constructors, and the spec↔environment handoff helpers. Stable
//     surface for application code.
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
//	conn := libtunnel.New(libtunnel.Cloudflare(), libtunnel.QuickTunnel()).WithListener(l)
//	go server.Serve(conn.Listener())
//	<-conn.TunnelReady()
//	fmt.Println(conn.URL()) // public https://<hostname>/
package libtunnel

import (
	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// New returns an unstarted tunnel on the given backend, drawing credentials
// from the given provider. T is the backend's spec type and is inferred:
//
//	libtunnel.New(libtunnel.Cloudflare(), libtunnel.QuickTunnel())
//
// Configure the result with With* methods; WithListener starts the
// connection.
func New[T v1.Spec](backend v1.Backend[T], provider v1.Provider[T]) v1.Tunnel[T] {
	return v1alpha1.New(backend, provider)
}

// Cloudflare returns the Cloudflare backend: an in-process cloudflared
// quick-tunnel engine (no cloudflared binary required).
func Cloudflare() v1.Backend[*v1.CloudflareSpec] {
	return cloudflare.New()
}

// QuickTunnel returns a provider that mints an anonymous *.trycloudflare.com
// tunnel, retrying with linear backoff until its context is done. Set Log on
// the returned provider to surface retry warnings.
func QuickTunnel() *cloudflare.QuickTunnelProvider {
	return cloudflare.QuickTunnel()
}

// Env wraps a provider with TUNNEL_SPEC adoption: when the environment
// carries a spec (a parent process exported one), it wins; otherwise the
// wrapped provider resolves a fresh one. This is the child side of the
// parent→child handoff:
//
//	libtunnel.New(libtunnel.Cloudflare(), libtunnel.Env(libtunnel.QuickTunnel()))
func Env[E any, T interface {
	*E
	v1.Spec
}](next v1.Provider[T]) v1.Provider[T] {
	return v1alpha1.Env(next)
}

// Static returns a provider that yields the given spec verbatim.
func Static[T v1.Spec](spec T) v1.Provider[T] {
	return v1alpha1.Static(spec)
}

// SpecEnv is the environment variable carrying a JSON-encoded spec across a
// process boundary — the parent→child handoff channel.
const SpecEnv = v1alpha1.SpecEnv

// ExportSpec publishes spec into this process's own environment so re-exec'd
// or spawned children inherit it and Env-wrapped providers adopt it.
func ExportSpec[T v1.Spec](spec T) error {
	return v1alpha1.ExportSpec(spec)
}

// SpecEnviron encodes spec as a "TUNNEL_SPEC=<json>" entry for a child
// process's exec.Cmd.Env.
func SpecEnviron[T v1.Spec](spec T) (string, error) {
	return v1alpha1.SpecEnviron(spec)
}

// SpecFromEnv decodes TUNNEL_SPEC into the caller-allocated spec, reporting
// whether the variable was present.
func SpecFromEnv[T v1.Spec](spec T) (bool, error) {
	return v1alpha1.SpecFromEnv(spec)
}
