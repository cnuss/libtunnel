package probe

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// connectProxy is a proxy that speaks CONNECT and nothing else, which is what
// the code under test assumes and what a corporate proxy actually is. It
// records what it was asked to reach so a test can tell a connection that went
// through it from one that went around it.
type connectProxy struct {
	addr string

	// status replaces the 200 when set, for a proxy that refuses.
	status int
	// preamble is written right after the 200: a proxy that says something
	// before the tunnel opens, whose bytes the caller's TLS would never see.
	preamble string

	mu       sync.Mutex
	targets  []string
	authFor  []string
	listener net.Listener
}

func (c *connectProxy) start(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c.listener, c.addr = listener, listener.Addr().String()
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
}

func (c *connectProxy) serve(conn net.Conn) {
	defer conn.Close()

	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	c.mu.Lock()
	c.targets = append(c.targets, request.Host)
	c.authFor = append(c.authFor, request.Header.Get("Proxy-Authorization"))
	c.mu.Unlock()

	if request.Method != http.MethodConnect {
		fmt.Fprint(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	if c.status != 0 {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", c.status, http.StatusText(c.status))
		return
	}

	remote, err := net.Dial("tcp", request.Host)
	if err != nil {
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()

	// One write, so the preamble lands in the same segment as the response.
	// What is being tested is bytes already buffered when the response is
	// parsed; two writes make that a race with the network, which is how
	// this first passed locally and failed on CI.
	fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n"+c.preamble)
	go func() { _, _ = io.Copy(remote, conn) }()
	_, _ = io.Copy(conn, remote)
}

func (c *connectProxy) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.targets...)
}

// echoServer answers whatever is sent to it, so a test can prove bytes really
// crossed rather than that a connection merely opened.
func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// TestProxyForReadsTheEnvironment pins which variable is consulted and that
// NO_PROXY still wins: the target is modelled as https, so HTTPS_PROXY is the
// one that answers for it, and a caller who excluded the relay gets no proxy.
func TestProxyForReadsTheEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		https   string
		plain   string
		exclude string
		want    string
	}{
		{"nothing set", "", "", "", ""},
		{"https proxy answers", "http://proxy.invalid:8080", "", "", "proxy.invalid:8080"},
		{"http proxy does not", "", "http://proxy.invalid:8080", "", ""},
		{"excluded target", "http://proxy.invalid:8080", "", relayHost, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HTTPS_PROXY", tc.https)
			t.Setenv("HTTP_PROXY", tc.plain)
			t.Setenv("NO_PROXY", tc.exclude)

			proxy := proxyFor(fmt.Sprintf("%s:%d", relayHost, relayPort))
			got := ""
			if proxy != nil {
				got = proxy.Host
			}
			if got != tc.want {
				t.Errorf("proxyFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDialViaProxyCarriesBytes pins the point of the whole mechanism: what
// comes back is a socket to the target, not to the proxy, and nothing in
// between has read it — which is what leaves TLS to terminate at the far end.
func TestDialViaProxyCarriesBytes(t *testing.T) {
	target := echoServer(t)
	proxy := &connectProxy{}
	proxy.start(t)

	conn, err := dialViaProxy(context.Background(), &url.URL{Scheme: "http", Host: proxy.addr}, target)
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("read %q, want %q", buf, "ping")
	}
	if asked := proxy.asked(); len(asked) != 1 || asked[0] != target {
		t.Errorf("proxy asked for %v, want one CONNECT to %s", asked, target)
	}
}

// TestDialViaProxyReportsARefusal pins that a proxy saying no is an error and
// not a half-open socket: 7844 is what such a proxy usually refuses, and the
// caller has another route to try.
func TestDialViaProxyReportsARefusal(t *testing.T) {
	proxy := &connectProxy{status: http.StatusForbidden}
	proxy.start(t)

	conn, err := dialViaProxy(context.Background(), &url.URL{Scheme: "http", Host: proxy.addr}, "edge.invalid:7844")
	if err == nil {
		conn.Close()
		t.Fatal("dialViaProxy accepted a refusal")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not say what the proxy answered", err)
	}
}

// TestDialViaProxyRejectsEarlyBytes pins the buffered-data check. Anything the
// proxy sends between the 200 and the handshake sits in a reader this function
// drops, so the TLS that follows would never see it — better no connection
// than one silently missing its first bytes.
func TestDialViaProxyRejectsEarlyBytes(t *testing.T) {
	target := echoServer(t)
	proxy := &connectProxy{preamble: "surprise"}
	proxy.start(t)

	conn, err := dialViaProxy(context.Background(), &url.URL{Scheme: "http", Host: proxy.addr}, target)
	if err == nil {
		conn.Close()
		t.Fatal("dialViaProxy accepted a connection with bytes already buffered")
	}
	if !strings.Contains(err.Error(), "before the tunnel") {
		t.Errorf("error %q does not name the early bytes", err)
	}
}

// TestDialViaProxySendsCredentials pins that a proxy URL carrying a login is
// used: an authenticated proxy is the common corporate case, and without the
// header it answers 407 and the route looks blocked.
func TestDialViaProxySendsCredentials(t *testing.T) {
	target := echoServer(t)
	proxy := &connectProxy{}
	proxy.start(t)

	conn, err := dialViaProxy(context.Background(),
		&url.URL{Scheme: "http", Host: proxy.addr, User: url.UserPassword("ann", "hunter2")}, target)
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()

	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ann:hunter2"))
	if len(proxy.authFor) != 1 || proxy.authFor[0] != want {
		t.Errorf("proxy saw authorization %v, want %q", proxy.authFor, want)
	}
}

// TestForwardThroughProxyCarriesBytes pins the seam the supervisor uses: it
// dials a loopback address knowing nothing of proxies, and what it says
// arrives at the far end anyway.
func TestForwardThroughProxyCarriesBytes(t *testing.T) {
	target := echoServer(t)
	proxy := &connectProxy{}
	proxy.start(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	local, err := New().forwardThroughProxy(ctx, &url.URL{Scheme: "http", Host: proxy.addr}, target)
	if err != nil {
		t.Fatalf("forwardThroughProxy: %v", err)
	}

	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatalf("dial the forwarder: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Errorf("read %q, want %q", buf, "pong")
	}
	if asked := proxy.asked(); len(asked) != 1 || asked[0] != target {
		t.Errorf("proxy asked for %v, want one CONNECT to %s", asked, target)
	}
}

// TestForwardThroughProxyEndsWithTheContext pins that the listener does not
// outlive the tunnel it was opened for: a loopback port left accepting after
// the tunnel is gone is a hole nothing closes.
func TestForwardThroughProxyEndsWithTheContext(t *testing.T) {
	proxy := &connectProxy{}
	proxy.start(t)

	ctx, cancel := context.WithCancel(context.Background())
	local, err := New().forwardThroughProxy(ctx, &url.URL{Scheme: "http", Host: proxy.addr}, "unused.invalid:443")
	if err != nil {
		t.Fatalf("forwardThroughProxy: %v", err)
	}
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", local)
		if err != nil {
			return
		}
		conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("%s still accepts connections after the context ended", local)
}
