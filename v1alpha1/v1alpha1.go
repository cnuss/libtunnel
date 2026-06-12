// Package v1alpha1 is the current implementation behind the v1 tunnel
// interfaces: the backend-agnostic lazy core plus generic providers. Backend
// engines live in subpackages (v1alpha1/cloudflare). The root libtunnel
// façade wraps this; callers reaching directly into v1alpha1 use it for the
// concrete structs and providers. Anything here may change between alpha
// revisions — depend on the v1 contract, not these internals.
package v1alpha1

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/url"
	"sync"

	v1 "github.com/cnuss/libtunnel/v1"
)

// Engine is the alpha-internal contract behind v1.Backend: what the tunnel
// core needs from a transport implementation. It extends the opaque
// v1.Backend so a backend value flows through the stable surface and is
// asserted back here.
type Engine[T v1.Spec] interface {
	v1.Backend[T]

	// CACerts returns the trust roots for this backend's edge connections.
	CACerts() []*x509.Certificate
	// WithListener mirrors the top-level mutator: the core hands the provided
	// listener down when the tunnel's WithListener fires. It is invoked once,
	// in its own goroutine, and blocks until the edge connection is up
	// (returning any setup failure). Runtime failures after that are reported
	// through t.Cancel. The core closes TunnelReady once WithListener returns
	// nil and the hostname resolves publicly.
	WithListener(t *TunnelImpl[T], l net.Listener) error
}

// New returns an unstarted tunnel for the given backend, which also supplies
// the credential provider. The root libtunnel.New façade wraps this and
// returns the v1.Tunnel[T] interface.
//
// The backend must implement this package's Engine contract (backends from
// façade constructors such as libtunnel.Cloudflare() do); a foreign Backend
// cancels the tunnel on first use.
func New[T v1.Spec](backend v1.Backend[T]) *TunnelImpl[T] {
	ctx, cancel := context.WithCancelCause(context.Background())

	t := &TunnelImpl[T]{
		ctx:              ctx,
		cancel:           cancel,
		log:              slog.New(slog.DiscardHandler),
		backend:          backend,
		listenerProvided: make(chan struct{}),
		tunnelReady:      make(chan struct{}),
		hostnameReady:    make(chan struct{}),
	}

	// Surface why the tunnel context was canceled. cancel is a
	// CancelCauseFunc, so every t.Cancel(err) records a cause that
	// context.Cause reports here when Done fires.
	go func() {
		<-ctx.Done()
		t.log.Warn("tunnel context canceled", "cause", context.Cause(ctx))
	}()

	return t
}

// TunnelImpl is the lazy tunnel core. Every getter resolves through a
// sync.Once on first use; getters whose input is not yet available block on
// the tunnel context. One TunnelImpl serves as both v1.Tunnel (configurable
// phase) and v1.Connected (post-WithListener phase) — the narrowing at
// WithListener is purely compile-time.
type TunnelImpl[T v1.Spec] struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	log     *slog.Logger
	backend v1.Backend[T]

	listenerOnce     sync.Once
	listener         net.Listener
	listenerProvided chan struct{}

	localIPOnce   sync.Once
	localIP       net.IP
	localHostOnce sync.Once
	localHost     string
	localURLOnce  sync.Once
	localURL      *url.URL

	specOnce sync.Once
	spec     T

	hostnameOnce sync.Once
	hostname     string

	urlOnce sync.Once
	url     *url.URL

	caCertsOnce sync.Once
	caCerts     []*x509.Certificate

	hostnameReadyOnce sync.Once
	hostnameReady     chan struct{}

	tunnelReady chan struct{}
}

var (
	_ v1.Tunnel[*v1.CloudflareSpec]    = (*TunnelImpl[*v1.CloudflareSpec])(nil)
	_ v1.Connected[*v1.CloudflareSpec] = (*TunnelImpl[*v1.CloudflareSpec])(nil)
)

// Context is the tunnel's lifetime context, canceled (with cause) on any
// fatal tunnel error. Exposed for Engine implementations in subpackages.
func (t *TunnelImpl[T]) Context() context.Context {
	return t.ctx
}

// Cancel records cause and cancels the tunnel's context. Exposed for Engine
// implementations in subpackages.
func (t *TunnelImpl[T]) Cancel(cause error) {
	t.cancel(cause)
}

// Logger is the tunnel's logger (never nil; silent by default). Exposed for
// Engine implementations in subpackages.
func (t *TunnelImpl[T]) Logger() *slog.Logger {
	return t.log
}
