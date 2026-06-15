// Package v1 is the stable public surface for libtunnel. The interfaces here
// are the contract callers depend on across releases; the implementation lives
// in v1alpha1 and may change between alpha revisions.
//
// A tunnel exposes a local listener to the public internet through a backend
// transport (Cloudflare quick tunnels first). The API is pure-lazy: every
// getter resolves on first use, and WithListener is the trigger that starts
// the edge connection.
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
// closing the listener returned from Tunneled.Listener.
var ErrClosed = errors.New("tunnel closed")

// Spec is the credential/identity set a Provider yields. Each backend defines
// a concrete spec type (cloudflare.Spec for the Cloudflare backend); the core
// only needs the public hostname the spec encodes — everything else is
// backend-internal.
type Spec interface {
	// GetHostname returns the public hostname (host or host:port) the tunnel
	// serves under.
	GetHostname() string
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
	// Cloudflare: adopt TUNNEL_SPEC from the environment when present,
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

// Tunneled is the post-WithListener phase of a tunnel: the edge connection is
// starting (or up). It is the running-handle surface — how to reach the tunnel
// (LocalURL, Listener, URL) and how to watch it (TunnelReady, Done, Err). Spec
// introspection (Host, Hostname, Domain, Port, CACerts), the local-address
// getters (LocalIP, LocalHost), and the HostnameReady probe describe the
// tunnel before it starts and live on Tunnel, the pre-WithListener phase.
//
// All getters are lazy and resolve on first use; getters that need state that
// is not yet available block until it is (or until the tunnel's context is
// canceled), in which case they return zero values.
//
// It is non-generic: the backend spec type is a construction-time detail that
// does not outlive New, so callers can store a tunnel reference without
// threading the spec type through their own code.
type Tunneled interface {
	// LocalPort is the listener's bound port. Blocks until a listener is
	// provided.
	LocalPort() int
	// LocalURL is <scheme>://<LocalIP>:<LocalPort>/, where the scheme follows
	// the backend's WithTLS (https when the origin terminates TLS, http
	// otherwise). Blocks until a listener is provided.
	LocalURL() *url.URL
	// Listener returns a tunnel-owned view of the listener provided via
	// WithListener, blocking until one arrives. Closing it closes the tunnel
	// too (Done fires, Err reports ErrClosed) — so an http.Server serving on
	// it tears the tunnel down on Shutdown/Close. To restart the origin
	// while the tunnel persists, close the original listener handed to
	// WithListener instead and rebind the same address.
	Listener() net.Listener

	// URL is https://<Hostname>/. It blocks until the hostname resolves on
	// the zone's authoritative nameservers (see Tunnel.HostnameReady).
	URL() *url.URL

	// TunnelReady is closed when the edge connection is up and the hostname
	// resolves publicly — the tunnel is reachable end to end. It is never
	// closed on failure: select on Done alongside it.
	TunnelReady() <-chan struct{}
	// Done is closed when the tunnel fails or shuts down. Waits on TunnelReady
	// or Tunnel.HostnameReady should select on Done too, or a failed tunnel
	// blocks them forever.
	Done() <-chan struct{}
	// Err reports why the tunnel ended (nil while it is alive).
	Err() error
}

// Tunnel is the configurable phase returned by libtunnel.New. It carries the
// running-handle surface (the embedded Tunneled), plus the spec introspection,
// local-address getters, and HostnameReady probe that describe the tunnel
// before it starts, and the mutators that disappear once WithListener narrows
// the type to Tunneled. All getters are lazy and resolve on first use. Like
// Tunneled, it is non-generic — the spec type does not outlive construction.
type Tunnel interface {
	Tunneled

	// LocalIP is the listener's bound IP. A listener bound to an unspecified
	// address (0.0.0.0 / ::) falls back to the outbound-route IP, discovered
	// with a UDP dial that sends no packets. Blocks until a listener is
	// provided.
	LocalIP() net.IP
	// LocalHost is the machine's hostname, truncated at the first dot.
	LocalHost() string

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
	// HostnameReady is closed when the hostname resolves on the zone's
	// authoritative nameservers — polled directly, so recursive resolvers'
	// negative caches never delay readiness.
	HostnameReady() <-chan struct{}

	// WithLogger sets the logger. Unset, the tunnel is silent.
	WithLogger(log *slog.Logger) Tunnel
	// WithContext threads a caller context into URL: once set, URL waits for
	// the tunnel to be reachable end to end (TunnelReady), honoring the
	// context, instead of only for the hostname to resolve — and returns nil
	// if the context is done first. Unset (or nil), URL waits on DNS alone.
	WithContext(ctx context.Context) Tunnel
	// WithListener provides the local listener and lazily starts the edge
	// connection. It is the terminal mutator: the returned Tunneled carries
	// no further configuration surface. The origin scheme is not inferred from
	// the listener — declare it on the backend with WithTLS / WithHTTP2 (both
	// default false).
	WithListener(l net.Listener) Tunneled
}
