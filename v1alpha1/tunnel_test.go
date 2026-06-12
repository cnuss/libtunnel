package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// fakeEngine satisfies the Engine contract without dialing anything: it
// records the listener it was handed and reports success immediately.
type fakeEngine struct {
	got  chan net.Listener
	spec *v1.CloudflareSpec
}

func newFakeEngine(spec *v1.CloudflareSpec) *fakeEngine {
	return &fakeEngine{got: make(chan net.Listener, 1), spec: spec}
}

func (e *fakeEngine) Name() string                              { return "fake" }
func (e *fakeEngine) Provider() v1.Provider[*v1.CloudflareSpec] { return v1alpha1.Static(e.spec) }
func (e *fakeEngine) CACerts() []*x509.Certificate              { return []*x509.Certificate{} }
func (e *fakeEngine) WithListener(t *v1alpha1.TunnelImpl[*v1.CloudflareSpec], l net.Listener) error {
	e.got <- l
	return nil
}

// foreignBackend implements v1.Backend but not Engine.
type foreignBackend struct{}

func (foreignBackend) Name() string { return "foreign" }
func (foreignBackend) Provider() v1.Provider[*v1.CloudflareSpec] {
	return v1alpha1.Static(&v1.CloudflareSpec{})
}

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
	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}))
	conn := tun.WithListener(l)

	addr := l.Addr().(*net.TCPAddr)
	if got := conn.LocalPort(); got != addr.Port {
		t.Errorf("LocalPort() = %d, want %d (the listener's port)", got, addr.Port)
	}
	if got := conn.LocalIP(); !got.Equal(addr.IP) {
		t.Errorf("LocalIP() = %v, want %v (the listener's IP)", got, addr.IP)
	}
	wantHost := net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
	if got := conn.LocalURL(); got.Host != wantHost || got.Scheme != "http" {
		t.Errorf("LocalURL() = %v, want http://%s/ (plain listener => http)", got, wantHost)
	}
	if got := conn.Listener(); got != l {
		t.Errorf("Listener() = %v, want the provided listener", got)
	}
}

func TestLocalGettersBlockUntilListener(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{}))

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

	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{}))
	conn := tun.WithListener(l)

	ip := conn.LocalIP()
	if ip == nil {
		t.Skip("no outbound route available")
	}
	if ip.IsUnspecified() {
		t.Errorf("LocalIP() = %v; want a concrete IP for an unspecified bind", ip)
	}
}

func TestSpecGettersDeriveFromProvider(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}))

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

func TestEngineReceivesListener(t *testing.T) {
	engine := newFakeEngine(&v1.CloudflareSpec{})
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

// TestTunnelReadyAfterEngineConnects uses a hostname that genuinely resolves
// (Cloudflare's own) so the public-resolver readiness poller succeeds — the
// fake engine supplies the connection half. Needs outbound DNS.
func TestTunnelReadyAfterEngineConnects(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{Hostname: "one.one.one.one"}))

	conn := tun.WithListener(listen(t))

	select {
	case <-conn.TunnelReady():
	case <-time.After(15 * time.Second):
		t.Fatal("TunnelReady never closed after the engine connected")
	}
}

// TestHostnameReadyBailsWhenNeverResolving feeds a hostname that cannot
// exist (.invalid is reserved): the poller must walk its whole resolver
// fleet and then cancel the tunnel with a descriptive cause rather than wait
// forever. Needs outbound DNS; takes ~10s (one attempt per fleet member).
func TestHostnameReadyBailsWhenNeverResolving(t *testing.T) {
	tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{Hostname: "never.invalid"}))
	tun.HostnameReady()

	select {
	case <-tun.Context().Done():
		cause := context.Cause(tun.Context())
		if cause == nil || !strings.Contains(cause.Error(), "did not resolve on any of") {
			t.Errorf("cancel cause = %v, want fleet-exhausted message", cause)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("tunnel was not canceled after the resolver fleet was exhausted")
	}
}

func TestForeignBackendCancels(t *testing.T) {
	tun := v1alpha1.New[*v1.CloudflareSpec](foreignBackend{})
	tun.WithListener(listen(t))

	select {
	case <-tun.Context().Done():
		if cause := context.Cause(tun.Context()); cause == nil {
			t.Error("context canceled without a cause")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreign backend did not cancel the tunnel")
	}
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
		tun := v1alpha1.New(newFakeEngine(&v1.CloudflareSpec{Hostname: hostname}))
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
