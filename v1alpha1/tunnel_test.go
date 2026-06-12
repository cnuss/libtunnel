package v1alpha1

import (
	"context"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
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
func (e *fakeEngine) Provider() v1.Provider[*v1.CloudflareSpec] { return Static(e.spec) }
func (e *fakeEngine) CACerts() []*x509.Certificate              { return []*x509.Certificate{} }
func (e *fakeEngine) WithListener(t *TunnelImpl[*v1.CloudflareSpec], l net.Listener) error {
	e.got <- l
	return nil
}

// foreignBackend implements v1.Backend but not Engine.
type foreignBackend struct{}

func (foreignBackend) Name() string                              { return "foreign" }
func (foreignBackend) Provider() v1.Provider[*v1.CloudflareSpec] { return Static(&v1.CloudflareSpec{}) }

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
	tun := New[*v1.CloudflareSpec](newFakeEngine(&v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}))
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
	tun := New[*v1.CloudflareSpec](newFakeEngine(&v1.CloudflareSpec{}))

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

	tun := New[*v1.CloudflareSpec](newFakeEngine(&v1.CloudflareSpec{}))
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
	tun := New[*v1.CloudflareSpec](newFakeEngine(&v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}))

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
	New[*v1.CloudflareSpec](engine).WithListener(l)

	select {
	case got := <-engine.got:
		if got != l {
			t.Errorf("engine received listener %v, want %v", got, l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never received the listener")
	}
}

func TestTunnelReadyAfterEngineConnects(t *testing.T) {
	tun := New[*v1.CloudflareSpec](newFakeEngine(&v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}))
	// Pre-resolve hostname readiness so the test doesn't poll real DNS for a
	// fabricated hostname.
	tun.hostnameReadyOnce.Do(func() { close(tun.hostnameReady) })

	conn := tun.WithListener(listen(t))

	select {
	case <-conn.TunnelReady():
	case <-time.After(5 * time.Second):
		t.Fatal("TunnelReady never closed after the engine connected")
	}
}

func TestForeignBackendCancels(t *testing.T) {
	tun := New[*v1.CloudflareSpec](foreignBackend{})
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
// arbitrary hostnames: the first label plus the remainder reassemble the
// input, and the port is 443 unless the hostname encodes a valid one.
func FuzzHostnameParsing(f *testing.F) {
	f.Add("demo.trycloudflare.com")
	f.Add("localhost")
	f.Add("example.com:8443")
	f.Add("")

	f.Fuzz(func(t *testing.T, hostname string) {
		host, domain, port := hostOf(hostname), domainOf(hostname), portOf(hostname)

		if strings.Contains(hostname, ".") {
			if host+"."+domain != hostname {
				t.Errorf("hostOf/domainOf lost data: host=%q domain=%q from %q", host, domain, hostname)
			}
		} else if host != hostname {
			t.Errorf("hostOf(%q) = %q; want the input when it has no dot", hostname, host)
		}
		if port < 1 || port > 65535 {
			t.Errorf("portOf(%q) = %d, out of range", hostname, port)
		}
	})
}

func TestHostnameReadyBailsWhenFleetExhausted(t *testing.T) {
	saved := publicResolvers
	publicResolvers = []string{"127.0.0.1:1", "127.0.0.1:1"} // nothing listens here
	t.Cleanup(func() { publicResolvers = saved })

	tun := New(newFakeEngine(&v1.CloudflareSpec{Hostname: "never.trycloudflare.com"}))
	tun.HostnameReady()

	select {
	case <-tun.Context().Done():
		cause := context.Cause(tun.Context())
		if cause == nil || !strings.Contains(cause.Error(), "did not resolve on any of") {
			t.Errorf("cancel cause = %v, want fleet-exhausted message", cause)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("tunnel was not canceled after the resolver fleet was exhausted")
	}
}
