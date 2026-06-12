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
	"log/slog"
	"net"
	"net/url"
)

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
}

// Connected is the post-WithListener phase of a tunnel: the edge connection
// is starting (or up), and only observers and lifecycle remain — no mutators.
// All getters are lazy and resolve on first use; getters that need state that
// is not yet available block until it is (or until the tunnel's context is
// canceled), in which case they return zero values.
type Connected[T Spec] interface {
	// LocalIP is the listener's bound IP. A listener bound to an unspecified
	// address (0.0.0.0 / ::) falls back to the outbound-route IP, discovered
	// with a UDP dial that sends no packets. Blocks until a listener is
	// provided.
	LocalIP() net.IP
	// LocalPort is the listener's bound port. Blocks until a listener is
	// provided.
	LocalPort() int
	// LocalHost is the machine's hostname, truncated at the first dot.
	LocalHost() string
	// LocalURL is <scheme>://<LocalIP>:<LocalPort>/, where the scheme follows
	// the listener (https when it terminates TLS, http otherwise). Blocks
	// until a listener is provided.
	LocalURL() *url.URL
	// Listener returns the listener provided via WithListener, blocking until
	// one arrives.
	Listener() net.Listener

	// Host is the first label of Hostname.
	Host() string
	// Hostname is the public hostname from the spec.
	Hostname() string
	// Domain is Hostname with the first label removed.
	Domain() string
	// Port is the port encoded in Hostname, or 443 when absent.
	Port() int
	// URL is https://<Hostname>/. It blocks until the hostname resolves on
	// the zone's authoritative nameservers (see HostnameReady).
	URL() *url.URL
	// CACerts returns the trust roots the backend uses for its edge
	// connections.
	CACerts() []*x509.Certificate
	// Spec returns the resolved tunnel spec, fetching it from the Provider on
	// first use.
	Spec() T

	// TunnelReady is closed when the edge connection is up and the hostname
	// resolves publicly — the tunnel is reachable end to end. It is never
	// closed on failure: select on Done alongside it.
	TunnelReady() <-chan struct{}
	// Done is closed when the tunnel fails or shuts down. Waits on
	// TunnelReady/HostnameReady should select on Done too, or a failed
	// tunnel blocks them forever.
	Done() <-chan struct{}
	// Err reports why the tunnel ended (nil while it is alive).
	Err() error
	// HostnameReady is closed when the hostname resolves on the zone's
	// authoritative nameservers — polled directly, so recursive resolvers'
	// negative caches never delay readiness.
	HostnameReady() <-chan struct{}
}

// Tunnel is the configurable phase returned by libtunnel.New. All Connected
// observers work here too (they resolve lazily); the mutators disappear once
// WithListener narrows the type to Connected.
type Tunnel[T Spec] interface {
	Connected[T]

	// WithLogger sets the logger. Unset, the tunnel is silent.
	WithLogger(log *slog.Logger) Tunnel[T]
	// WithListener provides the local listener and lazily starts the edge
	// connection. It is the terminal mutator: the returned Connected carries
	// no further configuration surface. The tunnel infers the origin scheme
	// from the listener: TLS listeners (tls.Listen, or any listener with a
	// TLS() bool method reporting true) are dialed over https, plain ones
	// over http.
	WithListener(l net.Listener) Connected[T]
}
