package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// fakeEngine satisfies the Engine contract without dialing anything: it
// records the origin it was handed (listener or URL) and reports success
// immediately.
type fakeEngine struct {
	got         chan net.Listener
	gotURL      chan *url.URL
	spec        *cloudflare.Spec
	proxy       *httputil.ReverseProxy
	listener    net.Listener
	reconnected bool
}

func newFakeEngine(spec *cloudflare.Spec) *fakeEngine {
	return &fakeEngine{got: make(chan net.Listener, 1), gotURL: make(chan *url.URL, 1), spec: spec}
}

func (e *fakeEngine) Name() string                                { return "fake" }
func (e *fakeEngine) Provider() v1.Provider[*cloudflare.Spec]     { return v1alpha1.Static(e.spec) }
func (e *fakeEngine) CACerts() []*x509.Certificate                { return []*x509.Certificate{} }
func (e *fakeEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e *fakeEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (e *fakeEngine) Reconnect(context.Context) error             { e.reconnected = true; return nil }
func (e *fakeEngine) Proxy() *httputil.ReverseProxy               { return e.proxy }
func (e *fakeEngine) Listener() net.Listener                      { return e.listener }
func (e *fakeEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	e.got <- l
	return nil
}
func (e *fakeEngine) WithLocalURL(t *v1alpha1.TunnelImpl[*cloudflare.Spec], u *url.URL) error {
	e.gotURL <- u
	return nil
}

// foreignBackend implements v1.Backend but not Engine.
type foreignBackend struct{}

func (foreignBackend) Name() string { return "foreign" }
func (foreignBackend) Provider() v1.Provider[*cloudflare.Spec] {
	return v1alpha1.Static(&cloudflare.Spec{})
}
func (f foreignBackend) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return f }
func (f foreignBackend) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return f }
func (foreignBackend) Reconnect(context.Context) error               { return nil }

var (
	_ v1alpha1.Engine[*cloudflare.Spec] = (*fakeEngine)(nil)
	_ v1.Backend[*cloudflare.Spec]      = foreignBackend{}
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestLocalGettersDeriveFromListener(t *testing.T) {
	l := listen(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	conn := tun.WithListener(l)

	addr := l.Addr().(*net.TCPAddr)
	if got := conn.LocalPort(); got != addr.Port {
		t.Errorf("LocalPort() = %d, want %d (the listener's port)", got, addr.Port)
	}
	if got := tun.LocalIP(); !got.Equal(addr.IP) {
		t.Errorf("LocalIP() = %v, want %v (the listener's IP)", got, addr.IP)
	}
	wantHost := net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
	if got := conn.LocalURL(); got.Host != wantHost || got.Scheme != "http" {
		t.Errorf("LocalURL() = %v, want http://%s/ (plain listener => http)", got, wantHost)
	}
	if got := conn.Listener(); got.Addr().String() != l.Addr().String() {
		t.Errorf("Listener().Addr() = %v, want %v", got.Addr(), l.Addr())
	}
}

func TestLocalGettersBlockUntilListener(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{}))

	port := make(chan int, 1)
	go func() { port <- tun.LocalPort() }()

	select {
	case p := <-port:
		t.Fatalf("LocalPort() = %d before any listener was provided; want it to block", p)
	case <-time.After(50 * time.Millisecond):
	}

	l := listen(t)
	tun.WithListener(l)

	select {
	case p := <-port:
		if want := l.Addr().(*net.TCPAddr).Port; p != want {
			t.Errorf("LocalPort() = %d, want %d", p, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LocalPort() still blocked after WithListener")
	}
}

func TestUnspecifiedBindFallsBackToOutboundRouteIP(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{}))
	tun.WithListener(l)

	ip := tun.LocalIP()
	if ip == nil {
		t.Skip("no outbound route available")
	}
	if ip.IsUnspecified() {
		t.Errorf("LocalIP() = %v; want a concrete IP for an unspecified bind", ip)
	}
}

func TestSpecGettersDeriveFromProvider(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))

	if got := tun.Hostname(); got != "demo.trycloudflare.com" {
		t.Errorf("Hostname() = %q", got)
	}
	if got := tun.Host(); got != "demo" {
		t.Errorf("Host() = %q, want %q", got, "demo")
	}
	if got := tun.Domain(); got != "trycloudflare.com" {
		t.Errorf("Domain() = %q, want %q", got, "trycloudflare.com")
	}
	if got := tun.Port(); got != 443 {
		t.Errorf("Port() = %d, want 443", got)
	}
}

// TestListenerCloseClosesTunnel pins the implicit-close contract: closing
// the tunnel-owned listener (what an http.Server does on Shutdown) closes
// the tunnel, with ErrClosed as the cause. The caller's original listener
// dies with it.
func TestListenerCloseClosesTunnel(t *testing.T) {
	l := listen(t)
	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{})).WithListener(l)

	if err := conn.Listener().Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-conn.Done():
		if !errors.Is(conn.Err(), v1.ErrClosed) {
			t.Errorf("Err() = %v, want ErrClosed", conn.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after the listener was closed")
	}

	if _, err := l.Accept(); err == nil {
		t.Error("original listener still accepting after the tunnel-owned handle was closed")
	}
}

func TestEngineReceivesListener(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{})
	l := listen(t)
	v1alpha1.New(engine).WithListener(l)

	select {
	case got := <-engine.got:
		if got != l {
			t.Errorf("engine received listener %v, want %v", got, l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never received the listener")
	}
}

// TestListenerMintsWhenNoneProvided pins the lazy path: Listener() with no
// prior WithListener binds a loopback listener, adopts it, and hands it to the
// engine — so http.Serve(tun.Listener(), h) needs no net.Listen of its own.
func TestListenerMintsWhenNoneProvided(t *testing.T) {
	stubReady(t)
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})
	tun := v1alpha1.New(engine)

	l := tun.Listener()
	if l == nil {
		t.Fatal("Listener() = nil; want a minted loopback listener")
	}
	if addr, ok := l.Addr().(*net.TCPAddr); !ok || !addr.IP.IsLoopback() {
		t.Fatalf("minted listener addr = %v, want loopback", l.Addr())
	}
	select {
	case got := <-engine.got:
		if got.Addr().String() != l.Addr().String() {
			t.Errorf("engine got %v, want the minted %v", got.Addr(), l.Addr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never received the minted listener")
	}
}

// TestURLMintsListenerWhenNoneProvided pins URL as a start trigger: called
// with no listener provided, it must mint a loopback listener and start the
// tunnel — not block on readiness that could never arrive (#82).
func TestURLMintsListenerWhenNoneProvided(t *testing.T) {
	stubReady(t)
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})
	tun := v1alpha1.New(engine)

	u := tun.URL()
	if u == nil || u.String() != "https://demo.trycloudflare.com/" {
		t.Fatalf("URL() = %v, want https://demo.trycloudflare.com/", u)
	}
	select {
	case got := <-engine.got:
		if addr, ok := got.Addr().(*net.TCPAddr); !ok || !addr.IP.IsLoopback() {
			t.Errorf("engine got %v, want a minted loopback listener", got.Addr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never received a listener — URL() did not start the tunnel")
	}
}

// TestTunnelReadyStartsTunnelWhenNoneProvided pins TunnelReady as a start
// trigger: waiting on it with no listener provided must start the tunnel and
// eventually fire, not block forever.
func TestTunnelReadyStartsTunnelWhenNoneProvided(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))

	select {
	case <-tun.TunnelReady():
	case <-tun.Done():
		t.Fatalf("tunnel died instead of becoming ready: %v", tun.Err())
	case <-time.After(5 * time.Second):
		t.Fatal("TunnelReady never closed — it did not start the tunnel")
	}
}

// TestSecondWithListenerCancels pins the one-provide rule: a second
// WithListener cancels the tunnel rather than silently dropping the listener.
func TestSecondWithListenerCancels(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithListener(listen(t))
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "origin already provided") {
			t.Errorf("Err() = %v, want 'origin already provided'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after a second WithListener")
	}
}

// TestListenerMintThenWithListenerCancels pins that a minted listener also
// counts as provided: a following WithListener is a double-provide.
func TestListenerMintThenWithListenerCancels(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.Listener()
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "origin already provided") {
			t.Errorf("Err() = %v, want 'origin already provided'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after WithListener following a mint")
	}
}

// TestWithListenerThenListenerReturnsProvided pins the benign order: Listener()
// after WithListener returns a view of the provided listener and never mints or
// cancels.
func TestWithListenerThenListenerReturnsProvided(t *testing.T) {
	stubReady(t)
	l := listen(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithListener(l)

	got := tun.Listener()
	if got == nil || got.Addr().String() != l.Addr().String() {
		t.Errorf("Listener() = %v, want a view of the provided %v", got, l.Addr())
	}
	if err := tun.Err(); err != nil {
		t.Errorf("Err() = %v, want nil (Listener after WithListener is fine)", err)
	}
}

// TestWithLocalURLGettersDeriveFromURL pins the URL-origin local side: the
// local getters derive from the provided URL, and the engine receives the
// URL — never a listener.
func TestWithLocalURLGettersDeriveFromURL(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})
	conn := v1alpha1.New(engine).WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	if got := conn.LocalPort(); got != 1234 {
		t.Errorf("LocalPort() = %d, want 1234 (the URL's port)", got)
	}
	if got := conn.LocalIP(); !got.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("LocalIP() = %v, want 127.0.0.1 (the URL's host)", got)
	}
	if got := conn.LocalURL(); got.String() != "http://127.0.0.1:1234/" {
		t.Errorf("LocalURL() = %v, want http://127.0.0.1:1234/ (the provided URL)", got)
	}

	select {
	case got := <-engine.gotURL:
		if got.String() != "http://127.0.0.1:1234/" {
			t.Errorf("engine received %v, want http://127.0.0.1:1234/", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never received the origin URL")
	}
	select {
	case l := <-engine.got:
		t.Errorf("engine received listener %v for a URL origin", l.Addr())
	default:
	}
}

// TestWithLocalURLDefaultPorts pins the port default for host-only URLs: 443
// for https, 80 for http.
func TestWithLocalURLDefaultPorts(t *testing.T) {
	for scheme, want := range map[string]int{"http": 80, "https": 443} {
		conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})).
			WithLocalURL(&url.URL{Scheme: scheme, Host: "127.0.0.1"})
		if got := conn.LocalPort(); got != want {
			t.Errorf("LocalPort() = %d for a portless %s URL, want %d", got, scheme, want)
		}
	}
}

// TestWithLocalURLResolvesHost pins LocalIP for a non-IP URL host: the name
// is resolved (localhost ⇒ a loopback address).
func TestWithLocalURLResolvesHost(t *testing.T) {
	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})).
		WithLocalURL(&url.URL{Scheme: "http", Host: "localhost:8080"})

	if got := conn.LocalIP(); got == nil || !got.IsLoopback() {
		t.Errorf("LocalIP() = %v for localhost, want a loopback address", got)
	}
}

// TestWithLocalURLInvalidCancels pins eager validation: a nil URL, a non-http
// scheme, or a hostless URL cancels the tunnel instead of confusing the
// backend later.
func TestWithLocalURLInvalidCancels(t *testing.T) {
	for name, u := range map[string]*url.URL{
		"nil":       nil,
		"badScheme": {Scheme: "ftp", Host: "127.0.0.1:21"},
		"noHost":    {Scheme: "http"},
	} {
		t.Run(name, func(t *testing.T) {
			tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
			tun.WithLocalURL(u)

			select {
			case <-tun.Done():
				if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "http(s) URL") {
					t.Errorf("Err() = %v, want the URL validation failure", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Done never closed for an invalid origin URL")
			}
		})
	}
}

// TestWithLocalURLThenWithListenerCancels pins the one-provide rule across
// origin kinds: a listener after a URL origin is a double-provide.
func TestWithLocalURLThenWithListenerCancels(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "origin already provided") {
			t.Errorf("Err() = %v, want 'origin already provided'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after WithListener following WithLocalURL")
	}
}

// TestWithListenerThenWithLocalURLCancels pins the reverse order: a URL
// origin after a listener is a double-provide.
func TestWithListenerThenWithLocalURLCancels(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithListener(listen(t))
	tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "origin already provided") {
			t.Errorf("Err() = %v, want 'origin already provided'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after WithLocalURL following WithListener")
	}
}

// TestListenerAfterWithLocalURLCancels pins the contract violation: a URL
// origin has no listener, so Listener() cancels the tunnel and returns nil
// instead of blocking forever or minting a second origin.
func TestListenerAfterWithLocalURLCancels(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	if l := tun.Listener(); l != nil {
		t.Errorf("Listener() = %v for a URL origin, want nil", l)
	}
	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "no listener exists") {
			t.Errorf("Err() = %v, want 'no listener exists'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after Listener() on a URL origin")
	}
}

// TestWithLocalURLReadiness pins the start triggers for a URL origin: URL and
// TunnelReady must not mint a listener (the origin is already provided) and
// must complete once the engine connects and the hostname resolves.
func TestWithLocalURLReadiness(t *testing.T) {
	stubReady(t)
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})
	tun := v1alpha1.New(engine)
	conn := tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	if u := conn.URL(); u == nil || u.String() != "https://demo.trycloudflare.com/" {
		t.Fatalf("URL() = %v, want https://demo.trycloudflare.com/", u)
	}
	select {
	case <-conn.TunnelReady():
	case <-conn.Done():
		t.Fatalf("tunnel died instead of becoming ready: %v", conn.Err())
	case <-time.After(5 * time.Second):
		t.Fatal("TunnelReady never closed for a URL origin")
	}
	select {
	case l := <-engine.got:
		t.Errorf("a start trigger minted listener %v despite the URL origin", l.Addr())
	default:
	}
	if err := conn.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

// TestEnvLocalURLOverridesProvides pins the LIBTUNNEL_LOCAL_URL env-beats-code
// rule at every origin-provide path: the env URL supersedes a WithListener
// listener, a WithLocalURL argument, and the start-trigger mint — the engine
// receives the env URL and never a listener.
func TestEnvLocalURLOverridesProvides(t *testing.T) {
	for name, provide := range map[string]func(v1.Tunnel, net.Listener){
		"WithListener": func(tun v1.Tunnel, l net.Listener) { tun.WithListener(l) },
		"WithLocalURL": func(tun v1.Tunnel, _ net.Listener) {
			tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:9"})
		},
		"StartTriggerMint": func(tun v1.Tunnel, _ net.Listener) { tun.TunnelReady() },
	} {
		t.Run(name, func(t *testing.T) {
			stubReady(t)
			t.Setenv(v1.LocalURLEnv, "http://127.0.0.1:4321")
			engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})
			tun := v1alpha1.New(engine)

			provide(tun, listen(t))

			select {
			case got := <-engine.gotURL:
				if got.String() != "http://127.0.0.1:4321/" {
					t.Errorf("engine received %v, want the env override http://127.0.0.1:4321/", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("engine never received the env origin URL")
			}
			select {
			case l := <-engine.got:
				t.Errorf("engine received listener %v despite the env override", l.Addr())
			default:
			}
			if got := tun.LocalPort(); got != 4321 {
				t.Errorf("LocalPort() = %d, want 4321 (the env URL's port)", got)
			}
		})
	}
}

// TestEnvLocalURLInvalidCancels pins loud failure for a bad override: the
// provide slot is spent and the tunnel dies with the variable named.
func TestEnvLocalURLInvalidCancels(t *testing.T) {
	t.Setenv(v1.LocalURLEnv, "ftp://127.0.0.1:21")
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), v1.LocalURLEnv) {
			t.Errorf("Err() = %v, want a %s cause", err, v1.LocalURLEnv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed for an invalid LIBTUNNEL_LOCAL_URL")
	}
}

// TestEnvLogSetsDefaultLevel pins LIBTUNNEL_LOG: the default logger stops
// being silent and enables the named level — while an explicit WithLogger
// keeps its handler (env carries a level, not a sink).
func TestEnvLogSetsDefaultLevel(t *testing.T) {
	t.Setenv(v1.LogEnv, "debug")

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	if !tun.Logger().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Logger() does not enable debug with LIBTUNNEL_LOG=debug")
	}

	own := slog.New(slog.DiscardHandler)
	tun2 := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun2.WithLogger(own)
	if got := tun2.Logger(); got != own {
		t.Errorf("Logger() = %p with WithLogger set, want the explicit logger %p (env must not replace a sink)", got, own)
	}
}

// TestWithLoggerWriteOnce pins the write-once mutator contract: the first
// WithLogger fixes the logger; a later call is a no-op, not a mutation.
func TestWithLoggerWriteOnce(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	first := slog.New(slog.DiscardHandler)
	second := slog.New(slog.DiscardHandler)

	tun.WithLogger(first)
	if got := tun.Logger(); got != first {
		t.Fatalf("Logger() = %p, want the first WithLogger value %p", got, first)
	}
	tun.WithLogger(second)
	if got := tun.Logger(); got != first {
		t.Errorf("Logger() = %p after a second WithLogger, want the first value %p to stick", got, first)
	}
}

// TestWithContextWriteOnce pins the write-once mutator contract for
// WithContext: the first context sticks, so URL honors it even when a later
// WithContext tries to replace it. The readiness probe never fires here, so
// URL can only return via the first (already canceled) context — if the
// second context won, URL would hang past the test timeout.
func TestWithContextWriteOnce(t *testing.T) {
	stubNeverReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tun.WithContext(canceled)
	tun.WithContext(context.Background()) // loses: the first WithContext fixed the field

	done := make(chan *url.URL, 1)
	go func() { done <- tun.URL() }()
	select {
	case u := <-done:
		if u != nil {
			t.Errorf("URL() = %v, want nil (first WithContext context is canceled)", u)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("URL() hung — the second WithContext must not replace the first")
	}
}

// fakeResolver resolves every hostname to a fixed address without touching the
// network.
type fakeResolver struct{}

func (fakeResolver) Resolve(context.Context, string) resolver.Records {
	return resolver.Records{A: []netip.Addr{netip.MustParseAddr("104.16.230.132")}}
}

// unpublishedResolver answers once publish is closed — a hostname whose record
// is published a moment after the tunnel connects, which is the ordinary case.
// Like the real resolver, it comes back empty only when ctx ends first.
type unpublishedResolver struct{ publish chan struct{} }

func (u *unpublishedResolver) Resolve(ctx context.Context, _ string) resolver.Records {
	select {
	case <-u.publish:
		return resolver.Records{A: []netip.Addr{netip.MustParseAddr("104.16.230.132")}}
	case <-ctx.Done():
		return resolver.Records{}
	}
}

// neverResolver never answers, so hostname readiness never fires. It returns
// empty on release — closed at test cleanup, so the tunnel's goroutine is not
// left parked — or when ctx ends, whichever comes first.
type neverResolver struct{ release <-chan struct{} }

func (n neverResolver) Resolve(ctx context.Context, _ string) resolver.Records {
	select {
	case <-n.release:
	case <-ctx.Done():
	}
	return resolver.Records{}
}

// stubNeverReady holds hostname readiness open for the duration of a test, for
// the cases that need to observe what happens while a tunnel is not yet ready.
func stubNeverReady(t *testing.T) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(v1alpha1.SetResolver(neverResolver{release: release}))
	t.Cleanup(func() { close(release) })
}

// stubReady makes hostname readiness resolve immediately so these tests
// exercise the readiness plumbing (channel close, URL unblock) deterministically
// without live DNS — the real resolvers are covered by the resolver package's
// own tests and the live e2e suite.
func stubReady(t *testing.T) {
	t.Helper()
	t.Cleanup(v1alpha1.SetResolver(fakeResolver{}))
}

// TestTunnelReadyAfterEngineConnects pins that TunnelReady closes once the
// engine connects and the hostname resolves — the fake engine supplies the
// connection half, stubReady the resolution half.
func TestTunnelReadyAfterEngineConnects(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"}))

	conn := tun.WithListener(listen(t))

	select {
	case <-conn.TunnelReady():
	case <-time.After(15 * time.Second):
		t.Fatal("TunnelReady never closed after the engine connected")
	}
}

// TestHostnameReadyWaitsForRecords pins that readiness means the record
// exists. The edge publishes it moments after the connection registers, so the
// resolver ordinarily waits out that gap; readiness firing before the record
// is published would hand the caller a URL that does not resolve.
func TestHostnameReadyWaitsForRecords(t *testing.T) {
	r := &unpublishedResolver{publish: make(chan struct{})}
	t.Cleanup(v1alpha1.SetResolver(r))

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"}))
	conn := tun.WithListener(listen(t))

	select {
	case <-conn.HostnameReady():
		t.Fatal("HostnameReady closed before the record was published")
	case <-time.After(200 * time.Millisecond):
	}

	close(r.publish)
	select {
	case <-conn.HostnameReady():
	case <-time.After(30 * time.Second):
		t.Fatal("HostnameReady never closed once the record was published")
	}
}

// TestHostnameNeverResolvesFailsTunnel pins that the wait is bounded. A
// resolver that answered for the name before the record was published holds
// that negative for the zone's SOA, so waiting cannot fix it — and a caller
// that set no deadline of its own would otherwise block forever, which is a
// hang rather than patience.
func TestHostnameNeverResolvesFailsTunnel(t *testing.T) {
	stubNeverReady(t)
	t.Cleanup(v1alpha1.SetResolveTimeout(100 * time.Millisecond))

	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"})).
		WithListener(listen(t))

	select {
	case <-conn.Done():
	case <-conn.HostnameReady():
		t.Fatal("HostnameReady closed though the hostname never resolved")
	case <-time.After(15 * time.Second):
		t.Fatal("tunnel neither resolved nor failed — readiness is unbounded")
	}
	if err := conn.Err(); !errors.Is(err, v1.ErrHostnameUnresolved) {
		t.Errorf("Err() = %v, want ErrHostnameUnresolved", err)
	}
}

// TestWithContextURLWaitsForTunnelReady pins WithContext's upgrade: with a
// caller context set, URL blocks until TunnelReady (not DNS alone) and then
// returns the public URL.
func TestWithContextURLWaitsForTunnelReady(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"})).
		WithContext(context.Background())
	conn := tun.WithListener(listen(t))

	got := make(chan string, 1)
	go func() {
		if u := conn.URL(); u != nil {
			got <- u.String()
		} else {
			got <- ""
		}
	}()

	select {
	case u := <-got:
		if u != "https://www.cloudflare.com/" {
			t.Errorf("URL() = %q, want https://www.cloudflare.com/", u)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("URL never returned after the engine connected")
	}
}

// TestWithContextCancelReturnsNilURLAndTearsDown pins the WithContext
// shutdown contract (#97): canceling the caller's context both unblocks URL
// (returning nil) and tears the tunnel down — Done fires and Err reports the
// context's cause. The .invalid hostname never resolves, so only the canceled
// context can end the wait, making the outcome deterministic.
func TestWithContextCancelReturnsNilURLAndTearsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller gives up immediately; the tunnel is still coming up

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "never.resolves.invalid"})).
		WithContext(ctx)
	conn := tun.WithListener(listen(t))

	if u := conn.URL(); u != nil {
		t.Errorf("URL() = %v with a canceled context, want nil", u)
	}
	select {
	case <-tun.Done():
		if err := tun.Err(); !errors.Is(err, context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled (the caller's context is the shutdown handle)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never fired after the caller's context was canceled")
	}
}

// TestWithContextCancelTearsDownURLOrigin pins the motivating case (#97): a
// WithLocalURL origin has no listener and no Close, so the caller's context
// is its only teardown. Canceling it after the tunnel is up must retire the
// tunnel, not leak it until process exit.
func TestWithContextCancelTearsDownURLOrigin(t *testing.T) {
	stubReady(t)
	ctx, cancel := context.WithCancelCause(context.Background())

	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"})).
		WithContext(ctx).
		WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	select {
	case <-conn.TunnelReady():
	case <-conn.Done():
		t.Fatalf("tunnel died before becoming ready: %v", conn.Err())
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel never became ready")
	}

	wantErr := errors.New("caller done")
	cancel(wantErr)

	select {
	case <-conn.Done():
		if err := conn.Err(); !errors.Is(err, wantErr) {
			t.Errorf("Err() = %v, want the context cause %v", err, wantErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never fired after the caller canceled the context — URL origin leaked")
	}
}

func TestForeignBackendCancels(t *testing.T) {
	tun := v1alpha1.New(foreignBackend{})
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if tun.Err() == nil {
			t.Error("Done closed but Err() is nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreign backend did not cancel the tunnel")
	}
}

// TestDoneSurfacesSpecFailure pins the deadlock fix: a tunnel whose spec can
// never resolve must report through Done/Err — callers select on Done next
// to TunnelReady instead of blocking forever.
func TestDoneSurfacesSpecFailure(t *testing.T) {
	tun := v1alpha1.New(failingEngine{})

	if err := tun.Err(); err != nil {
		t.Fatalf("Err() = %v before any failure, want nil", err)
	}

	tun.Hostname() // forces the spec fetch, which fails

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("Err() = %v, want the provider failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after the spec fetch failed")
	}

	select {
	case <-tun.TunnelReady():
		t.Error("TunnelReady closed on a failed tunnel")
	default:
	}
}

// TestURLReturnsNilWhenCanceled pins the v1 zero-value-on-cancel contract for
// URL: a tunnel canceled before the hostname resolves must yield nil, not a
// non-nil URL with an empty host that defeats callers' nil checks.
func TestURLReturnsNilWhenCanceled(t *testing.T) {
	tun := v1alpha1.New(failingEngine{})

	if u := tun.URL(); u != nil {
		t.Errorf("URL() = %v after the spec fetch failed, want nil", u)
	}
	if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("Err() = %v, want the provider failure", err)
	}
}

// failingEngine's provider always errors.
type failingEngine struct{}

func (failingEngine) Name() string { return "failing" }
func (failingEngine) Provider() v1.Provider[*cloudflare.Spec] {
	return failingProvider{}
}
func (failingEngine) CACerts() []*x509.Certificate                  { return nil }
func (failingEngine) Proxy() *httputil.ReverseProxy                 { return nil }
func (failingEngine) Listener() net.Listener                        { return nil }
func (e failingEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e failingEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (failingEngine) Reconnect(context.Context) error               { return nil }
func (failingEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	return nil
}
func (failingEngine) WithLocalURL(t *v1alpha1.TunnelImpl[*cloudflare.Spec], u *url.URL) error {
	return nil
}

type failingProvider struct{}

func (failingProvider) Spec(context.Context) (*cloudflare.Spec, error) {
	return nil, errors.New("boom")
}

// FuzzHostnameParsing checks the Host/Domain/Port derivation invariants over
// arbitrary spec hostnames, through the public getters: the first label plus
// the remainder reassemble the input, and the port is 443 unless the
// hostname encodes a valid one.
func FuzzHostnameParsing(f *testing.F) {
	f.Add("demo.trycloudflare.com")
	f.Add("localhost")
	f.Add("example.com:8443")
	f.Add("")
	f.Add(".")

	f.Fuzz(func(t *testing.T, hostname string) {
		tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: hostname}))
		defer tun.Cancel(errors.New("fuzz iteration done")) // reap the ctx watcher

		host, domain, port := tun.Host(), tun.Domain(), tun.Port()

		if strings.Contains(hostname, ".") {
			if host+"."+domain != hostname {
				t.Errorf("Host/Domain lost data: host=%q domain=%q from %q", host, domain, hostname)
			}
		} else if host != hostname {
			t.Errorf("Host() = %q; want the input when it has no dot", host)
		}
		if port < 1 || port > 65535 {
			t.Errorf("Port() = %d, out of range", port)
		}
	})
}

// --- interceptors ---

// proxyEngine returns a fake engine whose Proxy serves a fixed body, so the
// default (fall-through) handler NewInterceptCtx seeds has a real origin to hit.
func proxyEngine(t *testing.T, body string) *fakeEngine {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	u, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	e := newFakeEngine(&cloudflare.Spec{})
	e.proxy = httputil.NewSingleHostReverseProxy(u)
	return e
}

// serveIntercept resolves req through tun's interceptor pipeline (built over
// engine's InterceptCtx) and serves it, returning the recorded response.
func serveIntercept(tun *v1alpha1.TunnelImpl[*cloudflare.Spec], engine *fakeEngine, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	tun.Intercept(v1alpha1.NewInterceptCtx(engine, rr, req))(rr, req)
	return rr
}

func TestInterceptFallsThroughToProxy(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)

	rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil))
	if rr.Body.String() != "origin" {
		t.Fatalf("body = %q, want %q (no interceptor → proxy)", rr.Body.String(), "origin")
	}
}

func intercMark(s string) v1.InterceptFn {
	return func(ctx v1.InterceptCtx) v1.InterceptCtx {
		return ctx.WithHandler(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, s) })
	}
}

// TestInterceptLaterDefaultWins: two Priority-0 interceptors are auto-assigned
// from the top of the range downward, so the later-registered one has the lower
// (higher-precedence) Priority and wins.
func TestInterceptLaterDefaultWins(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	always := func(*http.Request) bool { return true }
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("first")})
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("second")})

	rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil))
	if rr.Body.String() != "second" {
		t.Fatalf("body = %q, want %q (later default wins via auto Priority)", rr.Body.String(), "second")
	}
}

// TestInterceptLowerPriorityWins: with ALB ordering the lowest Priority wins,
// regardless of registration order.
func TestInterceptLowerPriorityWins(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	always := func(*http.Request) bool { return true }
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("low-prec"), Priority: 50})
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("high-prec"), Priority: 5})

	if rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil)); rr.Body.String() != "high-prec" {
		t.Fatalf("body = %q, want %q (lower Priority = higher precedence wins)", rr.Body.String(), "high-prec")
	}
}

// TestInterceptExplicitBeatsDefault: any explicit Priority outranks an
// auto-assigned default (which sits at the top of the range).
func TestInterceptExplicitBeatsDefault(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	always := func(*http.Request) bool { return true }
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("default")})                    // auto ~MaxUint16
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("explicit"), Priority: 40_000}) // still far below auto

	if rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil)); rr.Body.String() != "explicit" {
		t.Fatalf("body = %q, want %q (explicit Priority outranks an auto default)", rr.Body.String(), "explicit")
	}
}

// TestInterceptorsAccessor: Interceptors() exposes the registry in precedence
// order (ascending Priority), with auto-assigned Priorities resolved.
func TestInterceptorsAccessor(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	always := func(*http.Request) bool { return true }
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("d1")})                 // auto, top-down
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("mid"), Priority: 100}) // explicit mid
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("top"), Priority: 1})   // explicit top
	tun.WithInterceptor(v1.Interceptor{Match: always, Handler: intercMark("d2")})                 // auto, below d1

	got := tun.Interceptors()
	if len(got) != 4 {
		t.Fatalf("Interceptors() len = %d, want 4", len(got))
	}
	// Ascending Priority: top(1) < mid(100) < d2(auto) < d1(auto).
	for i := 1; i < len(got); i++ {
		if got[i-1].Priority > got[i].Priority {
			t.Fatalf("Interceptors() not in ascending Priority order: %d then %d", got[i-1].Priority, got[i].Priority)
		}
	}
	if got[0].Priority != 1 {
		t.Errorf("first Priority = %d, want the explicit 1 (highest precedence)", got[0].Priority)
	}
	if got[0].Priority == 0 || got[len(got)-1].Priority == 0 {
		t.Error("auto-assigned Priority should be resolved (non-zero) in the snapshot")
	}
}

// TestInterceptWrapsDefaultHandler pins the README's middleware pattern: wrap
// ctx.Handler() (the origin proxy) to add a response header, then serve it —
// the header lands AND the origin body is relayed.
func TestInterceptWrapsDefaultHandler(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	tun.WithInterceptor(v1.Interceptor{
		Match: func(*http.Request) bool { return true },
		Handler: func(ctx v1.InterceptCtx) v1.InterceptCtx {
			next := ctx.Handler()
			return ctx.WithHandler(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Served-By", "libtunnel")
				next(w, r)
			})
		},
	})

	rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil))
	if got := rr.Header().Get("X-Served-By"); got != "libtunnel" {
		t.Errorf("X-Served-By = %q, want the injected header", got)
	}
	if rr.Body.String() != "origin" {
		t.Errorf("body = %q, want the origin body relayed through the wrapper", rr.Body.String())
	}
}

func TestInterceptMatchPredicate(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	tun.WithInterceptor(v1.Interceptor{
		Match: func(r *http.Request) bool { return r.URL.Path == "/hooked" },
		Handler: func(ctx v1.InterceptCtx) v1.InterceptCtx {
			return ctx.WithHandler(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hooked") })
		},
	})

	if rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/hooked", nil)); rr.Body.String() != "hooked" {
		t.Errorf("matching path body = %q, want %q", rr.Body.String(), "hooked")
	}
	if rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/other", nil)); rr.Body.String() != "origin" {
		t.Errorf("non-matching path body = %q, want %q (fall-through)", rr.Body.String(), "origin")
	}
}

// TestInterceptDeclineFallsThrough: a matched interceptor that inspects but
// never calls WithHandler leaves the default (origin) handler in place.
func TestInterceptDeclineFallsThrough(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)

	inspected := false
	tun.WithInterceptor(v1.Interceptor{
		Match: func(*http.Request) bool { return true },
		Handler: func(ctx v1.InterceptCtx) v1.InterceptCtx {
			inspected = true
			return ctx // no WithHandler → default stands
		},
	})

	rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil))
	if !inspected {
		t.Fatal("interceptor never ran")
	}
	if rr.Body.String() != "origin" {
		t.Fatalf("body = %q, want %q (decline → fall through)", rr.Body.String(), "origin")
	}
}

// TestInterceptNilReturnFallsThrough: returning nil is equivalent to declining.
func TestInterceptNilReturnFallsThrough(t *testing.T) {
	engine := proxyEngine(t, "origin")
	tun := v1alpha1.New(engine)
	tun.WithInterceptor(v1.Interceptor{
		Match:   func(*http.Request) bool { return true },
		Handler: func(v1.InterceptCtx) v1.InterceptCtx { return nil },
	})

	if rr := serveIntercept(tun, engine, httptest.NewRequest("GET", "/", nil)); rr.Body.String() != "origin" {
		t.Fatalf("body = %q, want %q (nil return → fall through)", rr.Body.String(), "origin")
	}
}

// TestInterceptCtxExposesLevers: the ctx surfaces the request, the proxy
// listener via Target, and reaches the engine's Reconnect.
func TestInterceptCtxExposesLevers(t *testing.T) {
	engine := proxyEngine(t, "origin")
	l := listen(t)
	engine.listener = l
	tun := v1alpha1.New(engine)

	var gotTarget net.Listener
	var gotReq *http.Request
	tun.WithInterceptor(v1.Interceptor{
		Match: func(*http.Request) bool { return true },
		Handler: func(ctx v1.InterceptCtx) v1.InterceptCtx {
			gotTarget = ctx.Target()
			gotReq = ctx.Request()
			_ = ctx.Reconnect(ctx)
			return ctx.WithHandler(func(http.ResponseWriter, *http.Request) {})
		},
	})

	req := httptest.NewRequest("GET", "/x", nil)
	serveIntercept(tun, engine, req)
	if gotTarget != l {
		t.Error("InterceptCtx.Target did not return the engine listener")
	}
	if gotReq != req {
		t.Error("InterceptCtx.Request did not return the inbound request")
	}
	if !engine.reconnected {
		t.Error("InterceptCtx.Reconnect did not reach the engine")
	}
}
