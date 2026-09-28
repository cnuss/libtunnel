package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// fakeEngine satisfies the Engine contract without dialing anything: it
// records the origin it was handed (listener or URL) and reports success
// immediately.
type fakeEngine struct {
	got         chan net.Listener
	gotURL      chan *url.URL
	spec        *cloudflare.Spec
	reconnected bool
	// tokens records every WithToken the tunnel forwarded, in order.
	tokens []string
	// headers records every WithHeader the tunnel forwarded, in order, as
	// "key: value".
	headers []string
	// manual leaves EventEstablished to the test instead of firing it on
	// connect, for the cases that observe the gap between the two.
	manual bool
	// stopped is what Stopped reports: nil, the default, is an engine that
	// holds nothing at the edge; a channel is one that lets go when the
	// test closes it.
	stopped chan struct{}
}

func newFakeEngine(spec *cloudflare.Spec) *fakeEngine {
	return &fakeEngine{got: make(chan net.Listener, 1), gotURL: make(chan *url.URL, 1), spec: spec}
}

func (e *fakeEngine) Name() string                                { return "fake" }
func (e *fakeEngine) Provider() v1.Provider[*cloudflare.Spec]     { return v1alpha1.Static(e.spec) }
func (e *fakeEngine) CACerts() []*x509.Certificate                { return []*x509.Certificate{} }
func (e *fakeEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e *fakeEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (e *fakeEngine) WithToken(token string) v1.Backend[*cloudflare.Spec] {
	e.tokens = append(e.tokens, token)
	return e
}
func (e *fakeEngine) Reconnect(context.Context) error { e.reconnected = true; return nil }
func (e *fakeEngine) Stopped() <-chan struct{}        { return e.stopped }
func (e *fakeEngine) AddHeader(key, value string)     { e.headers = append(e.headers, key+": "+value) }
func (e *fakeEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	e.got <- l
	if !e.manual {
		t.Emit(v1.Event{Kind: v1.EventEstablished})
	}
	return nil
}
func (e *fakeEngine) WithLocalURL(t *v1alpha1.TunnelImpl[*cloudflare.Spec], u *url.URL) error {
	e.gotURL <- u
	if !e.manual {
		t.Emit(v1.Event{Kind: v1.EventEstablished})
	}
	return nil
}

// stuckEngine is a fakeEngine whose connect never returns within the test,
// for the cases that observe a tunnel that is not yet ready. With readiness
// following edge registration directly (no settle delay to inflate), an
// engine that never registers is the way to hold readiness open.
type stuckEngine struct {
	*fakeEngine
	hold chan struct{}
}

func newStuckEngine(t *testing.T, spec *cloudflare.Spec) *stuckEngine {
	t.Helper()
	e := &stuckEngine{fakeEngine: newFakeEngine(spec), hold: make(chan struct{})}
	t.Cleanup(func() { close(e.hold) })
	return e
}

func (e *stuckEngine) WithListener(*v1alpha1.TunnelImpl[*cloudflare.Spec], net.Listener) error {
	<-e.hold
	return nil
}

// foreignBackend implements v1.Backend but not Engine.
type foreignBackend struct{}

func (foreignBackend) Name() string { return "foreign" }
func (foreignBackend) Provider() v1.Provider[*cloudflare.Spec] {
	return v1alpha1.Static(&cloudflare.Spec{})
}
func (f foreignBackend) WithTLS(bool) v1.Backend[*cloudflare.Spec]     { return f }
func (f foreignBackend) WithHTTP2(bool) v1.Backend[*cloudflare.Spec]   { return f }
func (f foreignBackend) WithToken(string) v1.Backend[*cloudflare.Spec] { return f }
func (foreignBackend) Reconnect(context.Context) error                 { return nil }

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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))

	if got := tun.Hostname(); got != "demo.tunneled.pizza" {
		t.Errorf("Hostname() = %q", got)
	}
	if got := tun.Host(); got != "demo" {
		t.Errorf("Host() = %q, want %q", got, "demo")
	}
	if got := tun.Domain(); got != "tunneled.pizza" {
		t.Errorf("Domain() = %q, want %q", got, "tunneled.pizza")
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
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
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
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	tun := v1alpha1.New(engine)

	u := tun.URL()
	if u == nil || u.String() != "https://demo.tunneled.pizza/" {
		t.Fatalf("URL() = %v, want https://demo.tunneled.pizza/", u)
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

// TestReadyStartsTunnelWhenNoneProvided pins Ready as a start trigger:
// waiting on it with no listener provided must start the tunnel and
// eventually deliver, not block forever.
func TestReadyStartsTunnelWhenNoneProvided(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))

	select {
	case _, ok := <-tun.Ready():
		if !ok {
			t.Fatalf("tunnel died instead of becoming ready: %v", tun.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready never delivered — it did not start the tunnel")
	}
}

// TestSecondWithListenerCancels pins the one-provide rule: a second
// WithListener cancels the tunnel rather than silently dropping the listener.
func TestSecondWithListenerCancels(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	l := listen(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
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
		conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})).
			WithLocalURL(&url.URL{Scheme: scheme, Host: "127.0.0.1"})
		if got := conn.LocalPort(); got != want {
			t.Errorf("LocalPort() = %d for a portless %s URL, want %d", got, scheme, want)
		}
	}
}

// TestWithLocalURLResolvesHost pins LocalIP for a non-IP URL host: the name
// is resolved (localhost ⇒ a loopback address).
func TestWithLocalURLResolvesHost(t *testing.T) {
	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})).
		WithLocalURL(&url.URL{Scheme: "http", Host: "localhost:8080"})

	if got := conn.LocalIP(); got == nil || !got.IsLoopback() {
		t.Errorf("LocalIP() = %v for localhost, want a loopback address", got)
	}
}

// TestWithLocalURLInvalidCancels pins eager validation: a nil URL, a non-http
// scheme, or a hostless URL cancels the tunnel instead of confusing the
// backend later. A scheme is http or https exactly, so one carrying a suffix
// (http+ws) fails the same check.
func TestWithLocalURLInvalidCancels(t *testing.T) {
	for name, u := range map[string]*url.URL{
		"nil":          nil,
		"badScheme":    {Scheme: "ftp", Host: "127.0.0.1:21"},
		"noHost":       {Scheme: "http"},
		"wsMarker":     {Scheme: "http+ws", Host: "127.0.0.1:5173"},
		"wssMarkerTLS": {Scheme: "https+wss", Host: "127.0.0.1:5173"},
	} {
		t.Run(name, func(t *testing.T) {
			tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
// Ready must not mint a listener (the origin is already provided) and must
// complete once the tunnel is established.
func TestWithLocalURLReadiness(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	tun := v1alpha1.New(engine)
	conn := tun.WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	if u := conn.URL(); u == nil || u.String() != "https://demo.tunneled.pizza/" {
		t.Fatalf("URL() = %v, want https://demo.tunneled.pizza/", u)
	}
	select {
	case _, ok := <-conn.Ready():
		if !ok {
			t.Fatalf("tunnel died instead of becoming ready: %v", conn.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready never delivered for a URL origin")
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
		"StartTriggerMint": func(tun v1.Tunnel, _ net.Listener) { tun.Ready() },
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(v1.LocalURLEnv, "http://127.0.0.1:4321")
			engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
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
// provide slot is spent and the tunnel dies with the variable named, and with
// the scheme it refused. The override is validated by the same check as a
// WithLocalURL argument, so a suffixed scheme fails here as it does there.
func TestEnvLocalURLInvalidCancels(t *testing.T) {
	for name, env := range map[string]string{
		"badScheme": "ftp://127.0.0.1:21",
		"wsSuffix":  "http+ws://localhost:5173",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(v1.LocalURLEnv, env)
			tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
			tun.WithListener(listen(t))

			select {
			case <-tun.Done():
				err := tun.Err()
				if err == nil || !strings.Contains(err.Error(), v1.LocalURLEnv) {
					t.Errorf("Err() = %v, want a %s cause", err, v1.LocalURLEnv)
				}
				scheme, _, _ := strings.Cut(env, ":")
				if err == nil || !strings.Contains(err.Error(), strconv.Quote(scheme)) {
					t.Errorf("Err() = %v, want it to name the scheme %q", err, scheme)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Done never closed for an invalid LIBTUNNEL_LOCAL_URL")
			}
		})
	}
}

// TestEnvLogSetsDefaultLevel pins LIBTUNNEL_LOG: the default logger stops
// being silent and enables the named level — while an explicit WithLogger
// keeps its handler (env carries a level, not a sink).
func TestEnvLogSetsDefaultLevel(t *testing.T) {
	t.Setenv(v1.LogEnv, "debug")

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
	if !tun.Logger().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Logger() does not enable debug with LIBTUNNEL_LOG=debug")
	}

	own := slog.New(slog.DiscardHandler)
	tun2 := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
	tun2.WithLogger(own)
	if got := tun2.Logger(); got != own {
		t.Errorf("Logger() = %p with WithLogger set, want the explicit logger %p (env must not replace a sink)", got, own)
	}
}

// TestWithLoggerWriteOnce pins the write-once mutator contract: the first
// WithLogger fixes the logger; a later call is a no-op, not a mutation.
func TestWithLoggerWriteOnce(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))
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
// WithContext tries to replace it. The engine never connects here (stuck), so
// readiness never fires and URL can only return via the first (already
// canceled) context — if the second context won, URL would hang past the
// test timeout.
func TestWithContextWriteOnce(t *testing.T) {
	tun := v1alpha1.New(newStuckEngine(t, &cloudflare.Spec{Hostname: "demo.tunneled.pizza"}))

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

// TestLifecycleDeliversTheTunnel pins the payload: Ready and Done each hand
// back the tunnel itself, to every waiter — a closed channel would broadcast,
// but carry nil.
func TestLifecycleDeliversTheTunnel(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"}))
	conn := tun.WithListener(listen(t))

	// Lifecycle alone, no Tunnel: what a supervisor holding mixed values sees.
	var life v1.Lifecycle[v1.Tunnel] = conn

	// Two waiters, taken before readiness, so neither is the fast path.
	first, second := life.Ready(), life.Ready()
	for i, ch := range []<-chan v1.Tunnel{first, second} {
		select {
		case got, ok := <-ch:
			if !ok || got != v1.Tunnel(conn) {
				t.Fatalf("waiter %d: Ready delivered (%v, %v), want the tunnel", i, got, ok)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("waiter %d: Ready never delivered after the engine connected", i)
		}
	}
	// And after the fact, without a goroutine behind it.
	if got, ok := <-life.Ready(); !ok || got != v1.Tunnel(conn) {
		t.Fatalf("late Ready delivered (%v, %v), want the tunnel", got, ok)
	}
	if err := life.Err(); err != nil {
		t.Fatalf("Err = %v while the tunnel is alive, want nil", err)
	}

	life.Cancel()
	select {
	case got, ok := <-life.Done():
		if !ok || got != v1.Tunnel(conn) {
			t.Fatalf("Done delivered (%v, %v), want the tunnel", got, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done never delivered after Cancel")
	}
}

// TestReadyClosesEmptyOnFailure pins that a waiter on a tunnel that never
// comes up is released, not stranded: the channel closes without a value, and
// ok == false is how the receiver learns it.
func TestReadyClosesEmptyOnFailure(t *testing.T) {
	tun := v1alpha1.New(failingEngine{})
	ready := tun.Ready() // start trigger; the spec fetch fails behind it

	select {
	case got, ok := <-ready:
		if ok || got != nil {
			t.Fatalf("Ready delivered (%v, %v) on a failed tunnel, want a bare close", got, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready stayed open on a failed tunnel")
	}
	if err := tun.Err(); err == nil {
		t.Fatal("Err = nil after the failure, want the cause")
	}
}

// TestHostnameReadyAtRegistration pins that the hostname is reported at edge
// registration with no client-side settle: the mint provider waits out the
// record's spread before returning credentials, so holding the caller after
// connect would be a second wait for the same propagation.
func TestHostnameReadyAtRegistration(t *testing.T) {
	ready := make(chan string, 1)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "www.cloudflare.com"})).
		WithEventListener(func(e v1.Event) {
			if e.Kind == v1.EventHostnameReady {
				ready <- e.Hostname
			}
		})
	tun.WithListener(listen(t))

	select {
	case host := <-ready:
		if host != "www.cloudflare.com" {
			t.Errorf("EventHostnameReady carried %q, want the spec's hostname", host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EventHostnameReady not fired promptly after the engine connected — is a settle wait back?")
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
	ctx, cancel := context.WithCancelCause(context.Background())

	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})).
		WithContext(ctx).
		WithLocalURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1234"})

	select {
	case _, ok := <-conn.Ready():
		if !ok {
			t.Fatalf("tunnel died before becoming ready: %v", conn.Err())
		}
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
// never resolve must report through Done/Err, and Ready must close empty
// rather than strand a waiter.
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

	if got, ok := <-tun.Ready(); ok {
		t.Errorf("Ready delivered %v on a failed tunnel, want closed empty", got)
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
func (failingEngine) CACerts() []*x509.Certificate                    { return nil }
func (failingEngine) Stopped() <-chan struct{}                        { return nil }
func (failingEngine) AddHeader(string, string)                        {}
func (e failingEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]     { return e }
func (e failingEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e failingEngine) WithToken(string) v1.Backend[*cloudflare.Spec] { return e }
func (failingEngine) Reconnect(context.Context) error                 { return nil }
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
	f.Add("demo.tunneled.pizza")
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

// TestWithContextAlreadyCanceledCancelsSynchronously pins the fix for #153: a
// context that is already done when WithContext receives it cancels the tunnel
// before WithContext returns, rather than whenever a watcher goroutine happens
// to be scheduled. The ordering is what start's post-connect guard depends on
// to keep a dead tunnel from ever reporting ready — and, through that, what
// keeps URL from handing a URL to a caller who gave up before asking.
func TestWithContextAlreadyCanceledCancelsSynchronously(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})).
		WithContext(ctx)

	select {
	case <-tun.Done():
	default:
		t.Fatal("Done() not closed when WithContext returned; a dead context must take effect immediately")
	}
	if err := tun.Err(); !errors.Is(err, context.Canceled) {
		t.Errorf("Err() = %v, want context.Canceled", err)
	}
}

// TestWithContextAlreadyCanceledNeverReportsReady is the consequence that
// matters (#153): with the cancel applied before the tunnel starts, the engine
// may still "connect" — a fake one does so instantly — but the tunnel must
// never mark itself ready, so URL has no readiness to race against.
func TestWithContextAlreadyCanceledNeverReportsReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})).
		WithContext(ctx)
	conn := tun.WithListener(listen(t))

	// The start goroutine runs Spec, connect, and its guard; give it room to
	// finish before asserting it reported nothing.
	time.Sleep(100 * time.Millisecond)
	if got, ok := <-conn.Ready(); ok {
		t.Errorf("Ready delivered %v despite a context canceled before the tunnel started", got)
	}
	if u := conn.URL(); u != nil {
		t.Errorf("URL() = %v, want nil", u)
	}
}

// TestEventListenersAreLayered pins that registering is additive, not
// write-once: an observation is not a conflict, so every listener hears
// everything, in the order it registered.
func TestEventListenersAreLayered(t *testing.T) {
	tun := v1alpha1.New[*cloudflare.Spec](cloudflare.New())

	var order []string
	tun.WithEventListener(func(v1.Event) { order = append(order, "first") })
	tun.WithEventListener(func(v1.Event) { order = append(order, "second") })
	tun.WithEventListener(nil) // ignored rather than panicking later

	tun.Emit(v1.Event{Kind: v1.EventServing})
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("listeners ran %v, want [first second]", order)
	}
}

// TestEventListenerPanicIsContained pins that a caller's bad callback cannot
// take a working tunnel down, and does not stop the listeners behind it.
func TestEventListenerPanicIsContained(t *testing.T) {
	tun := v1alpha1.New[*cloudflare.Spec](cloudflare.New())

	reached := false
	tun.WithEventListener(func(v1.Event) { panic("listener blew up") })
	tun.WithEventListener(func(v1.Event) { reached = true })

	tun.Emit(v1.Event{Kind: v1.EventServing})
	if !reached {
		t.Error("a panicking listener stopped the ones after it")
	}
}

// TestFailedTunnelEmitsErrorThenDone pins the terminal pair and their order: a
// listener watching only for failure hears it before the tunnel is reported
// finished.
func TestFailedTunnelEmitsErrorThenDone(t *testing.T) {
	var kinds []v1.EventKind
	var seen []error
	done := make(chan struct{})

	// Registered before the cancel: the contract is that events are a
	// notification channel, so a listener attached after the fact hears
	// nothing — Failed() tunnels are already over by the time you hold one.
	tun := v1alpha1.New[*cloudflare.Spec](cloudflare.New())
	tun.WithEventListener(func(e v1.Event) {
		kinds = append(kinds, e.Kind)
		seen = append(seen, e.Err)
		if e.Kind == v1.EventDone {
			close(done)
		}
	})

	tun.Cancel(v1.ErrCertificate)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no done event; got %v", kinds)
	}
	if len(kinds) != 2 || kinds[0] != v1.EventError || kinds[1] != v1.EventDone {
		t.Fatalf("kinds = %v, want [error done]", kinds)
	}
	for i, err := range seen {
		if !errors.Is(err, v1.ErrCertificate) {
			t.Errorf("event %d carried %v, want the cause", i, err)
		}
	}
}

// TestWithTokenForwardsOnce pins the Tunnel-level knob: the first non-empty
// WithToken reaches the backend, a repeat is a no-op, and once the spec has
// been fetched — the provider built from the backend's knobs — a later call
// has nothing to land on and forwards nothing.
func TestWithTokenForwardsOnce(t *testing.T) {
	eng := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	tun := v1alpha1.New(eng)

	tun.WithToken("").WithToken("first").WithToken("second")
	if got := eng.tokens; len(got) != 1 || got[0] != "first" {
		t.Fatalf("backend saw tokens %v, want exactly [first]", got)
	}

	late := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	lateTun := v1alpha1.New(late)
	if got := lateTun.Hostname(); got != "demo.tunneled.pizza" {
		t.Fatalf("Hostname = %q", got)
	}
	lateTun.WithToken("too-late")
	if got := late.tokens; len(got) != 0 {
		t.Errorf("backend saw tokens %v after the spec fetch, want none", got)
	}
}

// TestWithHeaderForwardsUntilTheSpecFetch pins the Tunnel-level header knob:
// every WithHeader reaches the backend, in order and repeats included, until
// the spec is fetched — the provider built from the backend's knobs — after
// which a call has nothing to land on and forwards nothing. A tunnel with no
// engine (a foreign backend, or From's failed placeholder) takes the call and
// does nothing.
func TestWithHeaderForwardsUntilTheSpecFetch(t *testing.T) {
	eng := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	tun := v1alpha1.New(eng)
	tun.WithHeader("User-Agent", "tunneld/v1").WithHeader("X-Opaque", "true").WithHeader("X-Opaque", "again")
	want := []string{"User-Agent: tunneld/v1", "X-Opaque: true", "X-Opaque: again"}
	if got := eng.headers; !slices.Equal(got, want) {
		t.Fatalf("backend saw headers %q, want %q", got, want)
	}

	if got := tun.Hostname(); got != "demo.tunneled.pizza" {
		t.Fatalf("Hostname = %q", got)
	}
	tun.WithHeader("X-Late", "true")
	if got := eng.headers; !slices.Equal(got, want) {
		t.Errorf("backend saw headers %q after the spec fetch, want still %q", got, want)
	}

	v1alpha1.Failed(errors.New("no backend")).WithHeader("User-Agent", "x")
}

// TestCancelIsDeliberate pins Cancel as the caller's clean shutdown: Done
// delivers, Err reports ErrClosed, and no EventError fires — the same
// shape as closing the tunnel-owned listener.
func TestCancelIsDeliberate(t *testing.T) {
	var mu sync.Mutex
	var kinds []v1.EventKind
	done := make(chan struct{})
	conn := v1alpha1.New(newFakeEngine(&cloudflare.Spec{})).WithEventListener(func(e v1.Event) {
		mu.Lock()
		kinds = append(kinds, e.Kind)
		mu.Unlock()
		if e.Kind == v1.EventDone {
			close(done)
		}
	})

	conn.Cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("EventDone never fired after Cancel")
	}
	if !errors.Is(conn.Err(), v1.ErrClosed) {
		t.Errorf("Err() = %v, want ErrClosed", conn.Err())
	}
	if errors.Is(conn.Err(), v1.ErrFailed) {
		t.Errorf("Err() = %v reads as a failure; a deliberate cancel is not one", conn.Err())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(kinds) != 1 || kinds[0] != v1.EventDone {
		t.Errorf("events = %v, want [done] only", kinds)
	}
}

// TestCancelWithCauseIsAFailure pins the other half: a cause carries through
// to Err and Done, the way an engine reports the edge dying under it.
func TestCancelWithCauseIsAFailure(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{}))
	want := errors.New("edge went away")
	tun.Cancel(want)
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done never delivered after Cancel(cause)")
	}
	if !errors.Is(tun.Err(), want) {
		t.Errorf("Err() = %v, want the cause", tun.Err())
	}
}

// TestSerializeResolvesSpec pins Serialize as a getter like the rest: it
// resolves the spec on first use rather than reading a field that nothing
// has filled yet.
func TestSerializeResolvesSpec(t *testing.T) {
	spec := &cloudflare.Spec{ID: "id-1", Hostname: "ser.tunneled.pizza", AccountTag: "tag", Secret: []byte("s")}
	conn := v1alpha1.New(newFakeEngine(spec))
	if got, want := conn.Serialize(), spec.Serialize(); got != want {
		t.Errorf("Serialize() = %q, want %q", got, want)
	}
}

// TestURLWaitsForEstablished pins what URL means: the public URL verified to
// work from here, not an edge connection registered. With or without a
// caller context — WithContext adds a cancellation source, not a different
// wait.
func TestURLWaitsForEstablished(t *testing.T) {
	for _, tc := range []struct {
		name string
		with func(v1.Tunnel) v1.Tunnel
	}{
		{"without WithContext", func(tun v1.Tunnel) v1.Tunnel { return tun }},
		{"with WithContext", func(tun v1.Tunnel) v1.Tunnel { return tun.WithContext(context.Background()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
			engine.manual = true
			tun := v1alpha1.New(engine)
			conn := tc.with(tun).WithListener(listen(t))

			got := make(chan *url.URL, 1)
			go func() { got <- conn.URL() }()

			<-engine.got // connected; not yet established
			select {
			case u := <-got:
				t.Fatalf("URL() = %v before EventEstablished", u)
			case <-time.After(200 * time.Millisecond):
			}

			tun.Emit(v1.Event{Kind: v1.EventEstablished})
			select {
			case u := <-got:
				if u == nil || u.String() != "https://demo.tunneled.pizza/" {
					t.Errorf("URL() = %v, want https://demo.tunneled.pizza/", u)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("URL never returned after EventEstablished")
			}
		})
	}
}

// TestReadyDeliversOnEstablished pins Ready to the same moment as URL.
func TestReadyDeliversOnEstablished(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	engine.manual = true
	tun := v1alpha1.New(engine)
	conn := tun.WithListener(listen(t))

	ready := conn.Ready()
	<-engine.got
	select {
	case got, ok := <-ready:
		t.Fatalf("Ready delivered (%v, %v) before EventEstablished", got, ok)
	case <-time.After(200 * time.Millisecond):
	}

	tun.Emit(v1.Event{Kind: v1.EventEstablished})
	select {
	case got, ok := <-ready:
		if !ok || got != v1.Tunnel(conn) {
			t.Errorf("Ready delivered (%v, %v), want the tunnel", got, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready never delivered after EventEstablished")
	}
}

// TestEstablishedAfterCancelIsIgnored pins that a dead tunnel never reports
// ready: an engine whose verification lands after the cancel changes
// nothing.
func TestEstablishedAfterCancelIsIgnored(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	engine.manual = true
	tun := v1alpha1.New(engine)
	conn := tun.WithListener(listen(t))
	<-engine.got

	tun.Cancel()
	<-conn.Done()
	tun.Emit(v1.Event{Kind: v1.EventEstablished})

	if u := conn.URL(); u != nil {
		t.Errorf("URL() = %v on a canceled tunnel, want nil", u)
	}
	if got, ok := <-conn.Ready(); ok {
		t.Errorf("Ready delivered %v on a canceled tunnel, want closed empty", got)
	}
}

// TestDoneWaitsForTheEngineToLetGo pins what Done means: not the context
// ending, but the engine having let go of the edge after it. A process that
// exits on Done then leaves nothing registered for the edge to route to; one
// that exited on the context alone left its connections behind, and the next
// connector on the same tunnel answered 502 until the edge noticed.
func TestDoneWaitsForTheEngineToLetGo(t *testing.T) {
	engine := newFakeEngine(&cloudflare.Spec{Hostname: "demo.tunneled.pizza"})
	engine.stopped = make(chan struct{})
	var events []v1.EventKind
	var mu sync.Mutex
	tun := v1alpha1.New(engine).WithEventListener(func(e v1.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e.Kind)
	})

	done := tun.Done()
	tun.Cancel()
	if err := tun.Err(); !errors.Is(err, v1.ErrClosed) {
		t.Fatalf("Err() = %v after Cancel, want ErrClosed", err)
	}
	select {
	case <-done:
		t.Fatal("Done delivered with the engine still holding the edge")
	case <-time.After(50 * time.Millisecond):
	}
	mu.Lock()
	if slices.Contains(events, v1.EventDone) {
		t.Error("EventDone fired with the engine still holding the edge")
	}
	mu.Unlock()

	close(engine.stopped)
	select {
	case got, ok := <-done:
		if !ok || got != tun {
			t.Errorf("Done delivered (%v, %v), want the tunnel", got, ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Done not delivered once the engine let go")
	}
}

// TestMessagesComeOffTheSpec pins the accessor: what the provider said with
// the spec is read off the tunnel as sent, and resolving the spec is what
// the first call does, like Hostname.
func TestMessagesComeOffTheSpec(t *testing.T) {
	spec := &cloudflare.Spec{Hostname: "demo.tunneled.pizza"}
	spec.WithMessage("data:text/markdown;base64,PiBbIW5vdGVdIGhp")
	tun := v1alpha1.New(newFakeEngine(spec))
	if got := tun.Messages(); len(got) != 1 || got[0] != spec.Messages()[0] {
		t.Errorf("Messages = %q, want the spec's, as sent", got)
	}
	if got := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "quiet.tunneled.pizza"})).Messages(); got != nil {
		t.Errorf("Messages = %v with nothing said, want nil", got)
	}
}
