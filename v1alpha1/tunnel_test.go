package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"
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
// records the listener it was handed and reports success immediately.
type fakeEngine struct {
	got  chan net.Listener
	spec *cloudflare.Spec
}

func newFakeEngine(spec *cloudflare.Spec) *fakeEngine {
	return &fakeEngine{got: make(chan net.Listener, 1), spec: spec}
}

func (e *fakeEngine) Name() string                                { return "fake" }
func (e *fakeEngine) Provider() v1.Provider[*cloudflare.Spec]     { return v1alpha1.Static(e.spec) }
func (e *fakeEngine) CACerts() []*x509.Certificate                { return []*x509.Certificate{} }
func (e *fakeEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e *fakeEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (e *fakeEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	e.got <- l
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

// TestSecondWithListenerCancels pins the one-provide rule: a second
// WithListener cancels the tunnel rather than silently dropping the listener.
func TestSecondWithListenerCancels(t *testing.T) {
	stubReady(t)
	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "demo.trycloudflare.com"}))
	tun.WithListener(listen(t))
	tun.WithListener(listen(t))

	select {
	case <-tun.Done():
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "listener already provided") {
			t.Errorf("Err() = %v, want 'listener already provided'", err)
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
		if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "listener already provided") {
			t.Errorf("Err() = %v, want 'listener already provided'", err)
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

// stubReady makes the readiness consensus probe fire immediately so these tests
// exercise the readiness plumbing (channel close, URL unblock) deterministically
// without live DNS — the real probe is covered by the live e2e suite.
func stubReady(t *testing.T) {
	t.Helper()
	t.Cleanup(v1alpha1.SetAuthoritativeProbe(func(context.Context, *slog.Logger, string, string) (resolver.Records, bool) {
		return resolver.Records{A: []netip.Addr{netip.MustParseAddr("104.16.230.132")}}, true
	}))
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

// TestWithContextURLReturnsNilOnContextCancel pins that the caller's context
// caps URL's wait without killing the tunnel: a canceled context yields nil
// from URL, but the tunnel stays alive (Err stays nil). The .invalid hostname
// never resolves, so TunnelReady never fires — only the canceled context can
// unblock URL, making the nil deterministic.
func TestWithContextURLReturnsNilOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller gives up immediately; the tunnel is still coming up

	tun := v1alpha1.New(newFakeEngine(&cloudflare.Spec{Hostname: "never.resolves.invalid"})).
		WithContext(ctx)
	conn := tun.WithListener(listen(t))

	if u := conn.URL(); u != nil {
		t.Errorf("URL() = %v with a canceled context, want nil", u)
	}
	if err := tun.Err(); err != nil {
		t.Errorf("Err() = %v, want nil — the caller's context must not cancel the tunnel", err)
	}
}

func TestForeignBackendCancels(t *testing.T) {
	tun := v1alpha1.New[*cloudflare.Spec](foreignBackend{})
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
	tun := v1alpha1.New[*cloudflare.Spec](failingEngine{})

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
	tun := v1alpha1.New[*cloudflare.Spec](failingEngine{})

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
func (e failingEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e failingEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (failingEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
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
