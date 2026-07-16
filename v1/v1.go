// Package v1 is the stable public surface for libtunnel. The interfaces here
// are the contract callers depend on across releases; the implementation lives
// in v1alpha1 and may change between alpha revisions.
//
// A tunnel exposes a local origin to the public internet through a backend
// transport (Cloudflare quick tunnels first). The API is pure-lazy: every
// getter resolves on first use, and the edge connection starts on first
// demand — WithListener provides the origin listener explicitly, WithLocalURL
// points at an already-running local origin instead, and Listener, URL, and
// TunnelReady mint a loopback listener if no origin was provided.
package v1

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/url"
)

// ErrClosed is the Err result of a tunnel shut down deliberately — by
// closing the listener returned from Tunnel.Listener.
var ErrClosed = errors.New("tunnel closed")

// Spec is the credential/identity set a Provider yields. Each backend defines
// a concrete spec type (cloudflare.Spec for the Cloudflare backend); the core
// only needs the public hostname the spec encodes — everything else is
// backend-internal.
type Spec interface {
	// GetHostname returns the public hostname (host or host:port) the tunnel
	// serves under.
	GetHostname() string
	// Serialize returns the spec as a tagged-envelope JSON string — the same
	// form carried by LIBTUNNEL_SPEC. The result round-trips through
	// libtunnel.From and can be dropped straight into the env var.
	Serialize() string
}

// Provider supplies a tunnel spec. Implementations may mint fresh credentials
// (a quick-tunnel API call) or replay existing ones (a static spec, a spec
// inherited from the environment). Spec blocks until credentials are
// available or ctx is done.
type Provider[T Spec] interface {
	Spec(ctx context.Context) (T, error)
}

// Backend selects the tunnel transport engine, fixes the spec type T, and
// supplies the credential chain specs are drawn from. Backends are opaque:
// obtain one from a façade constructor (libtunnel.Cloudflare()). The engine
// contract beyond these methods is alpha-internal — v1alpha1 type-asserts for
// its real interface — so custom Backend implementations outside this module
// are not supported.
type Backend[T Spec] interface {
	// Name identifies the backend (e.g. "cloudflare").
	Name() string
	// Provider is the credential chain this backend draws specs from. For
	// Cloudflare: adopt LIBTUNNEL_SPEC from the environment when present,
	// otherwise mint an anonymous quick tunnel.
	Provider() Provider[T]
	// WithTLS declares whether the local origin terminates TLS. True dials the
	// listener over https (verification is off, so a self-signed cert is fine);
	// false over http. Default false. Chainable:
	// libtunnel.Cloudflare().WithTLS(true).
	WithTLS(bool) Backend[T]
	// WithHTTP2 declares whether the origin is dialed over HTTP/2 rather than
	// HTTP/1.1. Independent of WithTLS, though a stdlib http.Server only
	// negotiates HTTP/2 over TLS. Default false. Chainable.
	WithHTTP2(bool) Backend[T]
}

// Tunnel is the lazy tunnel handle returned by libtunnel.New. All getters
// resolve on first use; getters that need state that is not yet available
// block until it is (or until the tunnel is canceled), in which case they
// return zero values. The edge connection starts on first demand: the origin
// is provided exactly once — WithListener provides it as a listener,
// WithLocalURL as the URL of an already-running local service, and the start
// triggers — Listener, URL, TunnelReady — mint a loopback listener if no
// origin was provided. Providing an origin twice, by any combination of
// those, cancels the tunnel (Err reports "origin already provided").
//
// Configuration is write-once: each With* mutator takes effect at most once
// and is a no-op after its value is fixed, whether by an earlier call or by
// the tunnel's first use of the default.
//
// It is non-generic: the backend spec type is a construction-time detail that
// does not outlive New, so callers can store a tunnel reference without
// threading the spec type through their own code.
type Tunnel interface {
	// LocalPort is the origin's local port: the listener's bound port, or for
	// a URL origin (WithLocalURL) the URL's port — 443 for https and 80 for
	// http when the URL has none. Blocks until an origin is provided.
	LocalPort() int
	// LocalIP is the origin's local IP: the listener's bound IP, or for a URL
	// origin the URL's host, parsed as an IP or resolved. A listener bound to
	// an unspecified address (0.0.0.0 / ::) falls back to the outbound-route
	// IP, discovered with a UDP dial that sends no packets. Blocks until an
	// origin is provided.
	LocalIP() net.IP
	// LocalHost is the machine's hostname, truncated at the first dot.
	LocalHost() string
	// LocalURL is the local origin's URL: http://<LocalIP>:<LocalPort>/ for a
	// listener origin (always http — the origin's scheme is a backend
	// setting, WithTLS, and the public URL carries the real scheme), or the
	// provided URL itself for a URL origin, scheme intact. Blocks until an
	// origin is provided.
	LocalURL() *url.URL

	// Host is the first label of Hostname.
	Host() string
	// Hostname is the public hostname from the spec.
	Hostname() string
	// Domain is Hostname with the first label removed.
	Domain() string
	// Port is the port encoded in Hostname, or 443 when absent.
	Port() int
	// CACerts returns the trust roots the backend uses for its edge
	// connections.
	CACerts() []*x509.Certificate

	// Listener returns a tunnel-owned listener to serve on, starting the edge
	// connection on first use. With a listener provided via WithListener it
	// returns a tunnel-owned view of that one; with no origin provided it
	// mints a loopback listener (127.0.0.1:0) and adopts it, so
	// http.Serve(tun.Listener(), h) needs no net.Listen of your own.
	// Idempotent: repeated calls return the same listener. A URL origin
	// (WithLocalURL) has no listener: calling Listener then cancels the
	// tunnel and returns nil.
	//
	// Closing it closes the tunnel (Done fires, Err reports ErrClosed) — so an
	// http.Server serving on it tears the tunnel down on Shutdown/Close. To
	// restart the origin while the tunnel persists, close the original
	// listener handed to WithListener instead and rebind the same address; a
	// minted listener has no separate owner, so closing it is terminal.
	Listener() net.Listener
	// URL is https://<Hostname>/. It blocks until the hostname resolves on
	// the zone's authoritative nameservers (see HostnameReady). URL demands
	// public reachability, so like Listener it is a start trigger: with no
	// origin provided it mints a loopback listener and starts the edge
	// connection, instead of waiting on readiness that could never arrive.
	URL() *url.URL

	// HostnameReady is closed when the hostname resolves on the zone's
	// authoritative nameservers — polled directly, so recursive resolvers'
	// negative caches never delay readiness.
	HostnameReady() <-chan struct{}
	// TunnelReady is closed when the edge connection is up and the hostname
	// resolves publicly — the tunnel is reachable end to end. It is never
	// closed on failure: select on Done alongside it. Like URL it is a start
	// trigger: with no origin provided it mints a loopback listener and
	// starts the edge connection before handing back the channel.
	TunnelReady() <-chan struct{}
	// Done is closed when the tunnel fails or shuts down. Waits on TunnelReady
	// or HostnameReady should select on Done too, or a failed tunnel blocks
	// them forever.
	Done() <-chan struct{}
	// Err reports why the tunnel ended (nil while it is alive).
	Err() error

	// WithLogger sets the logger, once. Unset, the tunnel is silent.
	WithLogger(log *slog.Logger) Tunnel
	// WithContext threads a caller context into URL, once: set, URL waits for
	// the tunnel to be reachable end to end (TunnelReady), honoring the
	// context, instead of only for the hostname to resolve — and returns nil
	// if the context is done first. Unset (or nil), URL waits on DNS alone.
	WithContext(ctx context.Context) Tunnel
	// WithListener provides the local origin as a listener and lazily starts
	// the edge connection. The origin scheme is not inferred from the
	// listener — declare it on the backend with WithTLS / WithHTTP2 (both
	// default false).
	//
	// The origin is provided exactly once, shared with WithLocalURL and the
	// start-trigger mint. Providing it again — a second WithListener or
	// WithLocalURL, or either after a start trigger (Listener, URL,
	// TunnelReady) minted a listener — cancels the tunnel (Err reports
	// "origin already provided"). To let the tunnel supply the listener
	// instead, skip WithListener and call Listener().
	WithListener(l net.Listener) Tunnel
	// WithLocalURL provides the local origin as the URL of an already-running
	// local service (e.g. http://localhost:1234) and lazily starts the edge
	// connection — the cloudflared `tunnel --url` shape. Only the scheme and
	// host are used: the scheme (http or https) declares how the origin is
	// dialed, superseding the backend's WithTLS (which applies to listener
	// origins only), and anything else (path, query, user info) is dropped. A
	// nil URL, a scheme other than http/https, or an empty host cancels the
	// tunnel.
	//
	// The origin is provided exactly once — see WithListener. A URL origin
	// has no tunnel-owned listener: Listener must not be called (it cancels
	// the tunnel), and there is no handle whose Close shuts the tunnel down,
	// so the tunnel runs until the process exits or the tunnel fails.
	WithLocalURL(u *url.URL) Tunnel
}
