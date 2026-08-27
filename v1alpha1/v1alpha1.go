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
	"math"
	"net"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	// Proxy is the in-process reverse proxy that fronts the origin, live once
	// the tunnel has connected. NewInterceptCtx seeds an interception's default
	// handler from it (proxy the request to the origin). Nil before connect.
	Proxy() *httputil.ReverseProxy
	// Listener is the loopback listener the engine dials to reach Proxy — the
	// proxy's own accept socket, not the origin. Surfaced to interceptors as
	// InterceptCtx.Target. Nil before connect.
	Listener() net.Listener
	// WithListener mirrors the top-level mutator: the core hands the provided
	// listener down when the tunnel's WithListener fires. It is invoked once,
	// in its own goroutine, and blocks until the edge connection is up
	// (returning any setup failure). Runtime failures after that are reported
	// through t.Cancel. The core closes TunnelReady once WithListener returns
	// nil and the hostname resolves publicly.
	WithListener(t *TunnelImpl[T], l net.Listener) error
	// WithLocalURL is WithListener's counterpart for URL origins: the core
	// hands down the validated origin URLs (each scheme http/https, host set,
	// path "/", at least one) when the tunnel's WithLocalURL fires. urls[0]
	// is the default origin; more than one URL asks the engine for per-request
	// routing (see v1.Tunnel.WithLocalURL). Same contract — invoked once, in
	// its own goroutine, blocking until the edge connection is up.
	WithLocalURL(t *TunnelImpl[T], urls []*url.URL) error
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
		ctx:            ctx,
		cancel:         cancel,
		backend:        backend,
		originProvided: make(chan struct{}),
		tunnelReady:    make(chan struct{}),
		hostnameReady:  make(chan struct{}),
	}
	// Auto-assigned interceptor Priorities count down from the top of the range.
	t.autoPriority.Store(math.MaxUint16)
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
	// context.Cause reports here when Done fires. Logged at Info: a cancel is
	// as often a clean shutdown (a signal, a caller context) as a failure, so
	// it is not inherently a warning.
	go func() {
		<-t.ctx.Done()
		t.Logger().Info("tunnel context canceled", "cause", context.Cause(t.ctx))
	}()

	return t
}

// TunnelImpl is the lazy tunnel core behind v1.Tunnel. Every getter resolves
// through a sync.Once on first use; getters whose input is not yet available
// block on the tunnel context. The configurable fields are write-once for the
// same reason — each is guarded by its own sync.Once, fixed by the first
// mutator call or the first internal use, so a fixed value never mutates
// under a goroutine that already read it.
type TunnelImpl[T v1.Spec] struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	// logOnce fixes log: the first WithLogger wins; a Logger read before any
	// WithLogger fixes the silent default.
	logOnce sync.Once
	log     *slog.Logger
	backend v1.Backend[T]
	// engine is backend asserted to the alpha contract, established once in
	// New. Nil means a foreign backend — the tunnel is born canceled.
	engine Engine[T]

	// originOnce guards the one-time origin provide: the first WithListener,
	// WithLocalURL, or start-trigger mint wins and sets exactly one of
	// listener / localURLs; a later provide of either kind is a double-provide
	// and cancels the tunnel. The originProvided close is the happens-before
	// edge for reading both fields.
	originOnce     sync.Once
	listener       net.Listener
	localURLs      []*url.URL
	originProvided chan struct{}

	// userCtxOnce fixes userCtx: the first WithContext wins; a URL read
	// before any WithContext fixes it to nil (unset). Nil means URL waits on
	// DNS alone; set, URL waits for full readiness.
	userCtxOnce sync.Once
	userCtx     context.Context

	localIPOnce   sync.Once
	localIP       net.IP
	localHostOnce sync.Once
	localHost     string

	specOnce sync.Once
	spec     T

	caCertsOnce sync.Once
	caCerts     []*x509.Certificate

	interceptorsMu sync.Mutex
	interceptors   v1.Interceptors
	// autoPriority hands out Priorities to interceptors registered with Priority
	// 0 (unset). It starts at math.MaxUint16 and steps down, so an unprioritized
	// interceptor sits at the low-precedence end (highest number) and a
	// later-registered one steps toward higher precedence — later wins — while
	// any explicit small Priority outranks them all. Lower Priority = higher
	// precedence (evaluated first), AWS-ALB style. uint32 holds the uint16 range
	// with headroom for the step-down arithmetic; it saturates at 0.
	autoPriority atomic.Uint32

	hostnameReady chan struct{}

	tunnelReady chan struct{}
}

// Context is the tunnel's lifetime context, canceled (with cause) on any
// fatal tunnel error. Exposed for Engine implementations in subpackages.
func (t *TunnelImpl[T]) Context() context.Context {
	return t.ctx
}

// Done implements v1.Tunnel: closed when the tunnel fails or shuts down.
func (t *TunnelImpl[T]) Done() <-chan struct{} {
	return t.ctx.Done()
}

// Err implements v1.Tunnel: the cancellation cause, nil while alive.
func (t *TunnelImpl[T]) Err() error {
	return context.Cause(t.ctx)
}

// Cancel records cause and cancels the tunnel's context. Exposed for Engine
// implementations in subpackages.
func (t *TunnelImpl[T]) Cancel(cause error) {
	t.cancel(cause)
}

// Logger is the tunnel's logger (never nil; silent by default). Exposed for
// Engine implementations in subpackages. The first read without a prior
// WithLogger fixes the default — the log field is write-once. The default is
// silent unless v1.LogEnv names a level; then it is a stderr text logger at that
// level.
func (t *TunnelImpl[T]) Logger() *slog.Logger {
	t.logOnce.Do(func() {
		t.log = defaultLogger()
	})
	return t.log
}

// defaultLogger builds the logger used when no WithLogger call fixed one:
// silent, unless v1.LogEnv names a level — then a stderr text logger at that
// level. An unknown value gets info plus a warning, so a typo surfaces
// instead of silencing logs.
func defaultLogger() *slog.Logger {
	env, ok := os.LookupEnv(v1.LogEnv)
	if !ok || env == "" {
		return slog.New(slog.DiscardHandler)
	}
	var level slog.Level
	err := level.UnmarshalText([]byte(env))
	if err != nil {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err != nil {
		log.Warn("unknown log level, defaulting to info", "var", v1.LogEnv, "value", env)
	}
	return log
}

// EnvBool reads an env-fixed boolean knob for a backend: fixed reports
// whether name is set (its value then overrides code), and err carries an
// unparsable value for the backend to surface at connect — loud beats a
// silently ignored override.
func EnvBool(name string) (value, fixed bool, err error) {
	env, ok := os.LookupEnv(name)
	if !ok || env == "" {
		return false, false, nil
	}
	v, err := strconv.ParseBool(env)
	if err != nil {
		return false, true, fmt.Errorf("%s: %w", name, err)
	}
	return v, true, nil
}

// EnvDuration reads an env-fixed duration knob for a backend, the sibling of
// EnvBool: fixed reports whether name is set (its value then overrides code),
// and err carries an unparsable value for the backend to surface at connect.
// The value uses time.ParseDuration syntax (e.g. "1s", "500ms").
func EnvDuration(name string) (value time.Duration, fixed bool, err error) {
	env, ok := os.LookupEnv(name)
	if !ok || env == "" {
		return 0, false, nil
	}
	v, err := time.ParseDuration(env)
	if err != nil {
		return 0, true, fmt.Errorf("%s: %w", name, err)
	}
	return v, true, nil
}
