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
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

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
// returns the non-generic v1.Tunnel interface.
//
// The backend must implement this package's Engine contract (backends from
// façade constructors such as libtunnel.Cloudflare() do); a foreign Backend
// cancels the tunnel on first use.
// newImpl builds a fresh TunnelImpl with its channels and default (silent)
// logger — the shared core of New and Failed, minus the engine wiring.
func newImpl[T v1.Spec](backend v1.Backend[T]) *TunnelImpl[T] {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &TunnelImpl[T]{
		ctx:              ctx,
		cancel:           cancel,
		backend:          backend,
		listenerProvided: make(chan struct{}),
		hostnameProvided: make(chan struct{}),
		tunnelReady:      make(chan struct{}),
		hostnameReady:    make(chan struct{}),
	}
	t.log.Store(slog.New(slog.DiscardHandler))
	return t
}

func New[T v1.Spec](backend v1.Backend[T]) *TunnelImpl[T] {
	t := newImpl(backend)

	// Establish the backend→engine relationship once, here, instead of
	// re-asserting at every engine-touching getter: a foreign backend cancels
	// the tunnel immediately with one consistent cause, and everything else
	// just checks t.engine.
	if engine, ok := backend.(Engine[T]); ok {
		t.engine = engine
	} else {
		t.cancel(fmt.Errorf("backend %q does not implement the v1alpha1 engine contract", backend.Name()))
	}

	// Surface why the tunnel context was canceled. cancel is a
	// CancelCauseFunc, so every t.Cancel(err) records a cause that
	// context.Cause reports here when Done fires.
	go func() {
		<-t.ctx.Done()
		t.Logger().Warn("tunnel context canceled", "cause", context.Cause(t.ctx))
	}()

	return t
}

// TunnelImpl is the lazy tunnel core. Every getter resolves through a
// sync.Once on first use; getters whose input is not yet available block on
// the tunnel context. One TunnelImpl serves as both v1.Tunnel (configurable
// phase) and v1.Tunneled (post-WithListener phase) — the narrowing at
// WithListener is purely compile-time.
type TunnelImpl[T v1.Spec] struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	// log is atomic: WithLogger can race the goroutines New and WithListener
	// spawn, which read it through Logger.
	log     atomic.Pointer[slog.Logger]
	backend v1.Backend[T]
	// engine is backend asserted to the alpha contract, established once in
	// New. Nil means a foreign backend — the tunnel is born canceled.
	engine Engine[T]

	// listenerSet guards the one-time provide: the first WithListener or
	// Listener-mint wins the CAS and sets listener; a later WithListener that
	// loses is a double-provide and cancels the tunnel.
	listenerSet      atomic.Bool
	listener         net.Listener
	listenerProvided chan struct{}

	// userCtx is an optional caller context set via WithContext, read by URL.
	// Atomic because WithContext can race the goroutines that reach URL. Nil
	// (unset) means URL waits on DNS alone; set, URL waits for full readiness.
	userCtx atomic.Pointer[context.Context]

	localIPOnce   sync.Once
	localIP       net.IP
	localHostOnce sync.Once
	localHost     string

	specOnce sync.Once
	spec     T
	// hostnameProvided is closed once Spec resolves the public hostname. It
	// starts the authoritative DNS poll (mirrors listenerProvided), so polling
	// begins at mint time rather than when a caller first asks HostnameReady.
	hostnameProvided chan struct{}

	caCertsOnce sync.Once
	caCerts     []*x509.Certificate

	hostnameReady chan struct{}

	tunnelReady chan struct{}
}

// Context is the tunnel's lifetime context, canceled (with cause) on any
// fatal tunnel error. Exposed for Engine implementations in subpackages.
func (t *TunnelImpl[T]) Context() context.Context {
	return t.ctx
}

// Done implements v1.Tunneled: closed when the tunnel fails or shuts down.
func (t *TunnelImpl[T]) Done() <-chan struct{} {
	return t.ctx.Done()
}

// Err implements v1.Tunneled: the cancellation cause, nil while alive.
func (t *TunnelImpl[T]) Err() error {
	return context.Cause(t.ctx)
}

// Cancel records cause and cancels the tunnel's context. Exposed for Engine
// implementations in subpackages.
func (t *TunnelImpl[T]) Cancel(cause error) {
	t.cancel(cause)
}

// Logger is the tunnel's logger (never nil; silent by default). Exposed for
// Engine implementations in subpackages.
func (t *TunnelImpl[T]) Logger() *slog.Logger {
	return t.log.Load()
}
