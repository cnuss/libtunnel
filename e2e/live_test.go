package e2e_test

// Live scenario tests: real quick tunnels against the Cloudflare edge, gated
// behind LIBTUNNEL_E2E_LIVE=1. These are deliberately complicated — origin
// restarts, process kills, concurrent tunnels — and not meant for human
// consumption; the examples stay simple.
//
// The quick-tunnel API and edge provisioning are burst-sensitive, so the
// tests are stingy with mints: TestLiveTunnel runs every single-tunnel
// scenario as subtests of ONE shared tunnel, and only scenarios that
// inherently need their own tunnel lifecycle (TLS origin, resurrection,
// two tunnels) mint separately — paced by gateLive.

import (
	"bufio"
	cryptotls "crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/cnuss/libtunnel"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// TestLiveTunnel mints one tunnel and runs every scenario that doesn't need
// its own tunnel lifecycle against it, in order: round trip, parallel
// requests, a websocket upgrade, and finally an origin bounce (which tears
// the origin down, so it goes last). The listener is TLS (self-signed), so
// the whole test also covers the https-ingress path — the plain-HTTP path
// rides with the examples and the other live tests.
func TestLiveTunnel(t *testing.T) {
	gateLive(t)

	// Reuse the preflight mint: hand its spec to this tunnel through the
	// environment (the Cloudflare chain adopts TUNNEL_SPEC before minting).
	if preflightSpec != nil {
		if entry, err := v1alpha1.SpecEnviron("cloudflare", preflightSpec); err == nil {
			t.Setenv(v1alpha1.SpecEnv, strings.TrimPrefix(entry, v1alpha1.SpecEnv+"="))
		}
	}

	tlsConfig := selfSignedTLS(t)
	l, err := cryptotls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello through the tunnel")
	})
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		if websocket.Message.Receive(ws, &msg) == nil {
			websocket.Message.Send(ws, "echo: "+msg)
		}
	}))
	srv := &http.Server{Handler: mux}

	conn := libtunnel.New(libtunnel.Cloudflare().WithTLS(true)).WithListener(l)
	// Serve the original listener: the bounce below restarts the origin and
	// the tunnel must persist. (Serving conn.Listener() would tie the tunnel
	// to the server's lifetime — that teardown is exercised at the end.)
	go srv.Serve(l)
	// Free the hostname when done — TestLiveResurrection reuses this spec.
	defer conn.Listener().Close()

	// LocalURL is the local bind address — always http, regardless of the
	// origin's TLS (declared on the backend via WithTLS). The public URL below
	// carries the real scheme.
	if got := conn.LocalURL().Scheme; got != "http" {
		t.Errorf("LocalURL scheme = %q, want http (local bind address)", got)
	}

	waitReady(t, conn, 30*time.Second)
	url := conn.URL().String()

	t.Run("RoundTrip", func(t *testing.T) {
		eventuallyBody(t, url, "hello through the tunnel", 30*time.Second)
	})

	// The HA connection must multiplex parallel requests with every body
	// intact.
	t.Run("ConcurrentRequests", func(t *testing.T) {
		const parallel = 8
		var wg sync.WaitGroup
		errs := make(chan error, parallel)
		for i := range parallel {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				body, code, err := getBody(url)
				if err != nil || code != http.StatusOK || body != "hello through the tunnel" {
					errs <- fmt.Errorf("request %d: body=%q code=%d err=%v", i, body, code, err)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	// Streaming protocols must survive the edge.
	t.Run("WebSocket", func(t *testing.T) {
		ws, err := websocket.Dial("wss://"+conn.Hostname()+"/ws", "", url)
		if err != nil {
			t.Fatalf("websocket dial: %v", err)
		}
		defer ws.Close()

		if err := websocket.Message.Send(ws, "ping through the tunnel"); err != nil {
			t.Fatal(err)
		}
		var reply string
		if err := websocket.Message.Receive(ws, &reply); err != nil {
			t.Fatal(err)
		}
		if want := "echo: ping through the tunnel"; reply != want {
			t.Errorf("reply = %q, want %q", reply, want)
		}
	})

	// Kill the origin and bring it back on the same port: the edge must
	// surface failure while it's down (not the stale body), and traffic must
	// recover through the same tunnel once it returns. Server first — Close
	// tears down kept-alive connections the edge's origin pool would
	// otherwise keep using.
	t.Run("OriginBounce", func(t *testing.T) {
		srv.Close()
		l.Close()

		sawFailure := false
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
			body, code, err := getBody(url)
			if err != nil || code >= http.StatusInternalServerError {
				t.Logf("origin down: code=%d err=%v body=%q", code, err, body)
				sawFailure = true
				break
			}
			time.Sleep(time.Second)
		}
		if !sawFailure {
			t.Error("edge kept serving after the origin died")
		}

		l2, err := cryptotls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			t.Fatalf("rebind %s: %v", addr, err)
		}
		defer l2.Close()
		serveBody(l2, "after the bounce")

		eventuallyBody(t, url, "after the bounce", 30*time.Second)
	})
}

// TestLiveResurrection is the strongest form of the handoff promise: the
// parent mints a spec once; a child connects and serves; the child is
// killed; a second child reuses the same spec and the same hostname serves
// again. Needs its own spec lifecycle.
func TestLiveResurrection(t *testing.T) {
	if role() == "live-serve-child" {
		liveServeChild()
		return
	}
	gateLive(t)

	// Mint a fresh spec: resurrection is about a hostname surviving killed
	// connectors. (Reusing TestLiveTunnel's deliberately closed hostname
	// proved flaky — after a graceful unregister the edge can serve a sticky
	// "530 origin unregistered" long after a new connector registers.)
	// Minting exports the spec into this process's environment, so the
	// spawned children inherit the tunnel identity with no plumbing.
	hostname := libtunnel.New(libtunnel.Cloudflare()).Hostname()
	if hostname == "" {
		t.Fatal("failed to mint a spec")
	}
	t.Logf("minted: %s", hostname)
	url := "https://" + hostname + "/"

	spawn := func(body string) (kill func()) {
		t.Helper()
		cmd := reexec("TestLiveResurrection", roleEnv+"=live-serve-child", "LIBTUNNEL_E2E_BODY="+body)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("child[%s]: %s", body, line)
			if strings.HasPrefix(line, readyPrefix) {
				return func() { cmd.Process.Kill(); cmd.Wait() }
			}
		}
		cmd.Wait()
		t.Fatalf("child[%s] exited before the tunnel became ready", body)
		return nil
	}

	kill1 := spawn("generation one")
	eventuallyBody(t, url, "generation one", 30*time.Second)
	kill1()

	kill2 := spawn("generation two")
	defer kill2()
	eventuallyBody(t, url, "generation two", 45*time.Second)
}

// liveServeChild adopts TUNNEL_SPEC, serves LIBTUNNEL_E2E_BODY, reports
// readiness, and blocks until killed.
func liveServeChild() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		os.Exit(3)
	}
	conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
	serveBody(conn.Listener(), os.Getenv("LIBTUNNEL_E2E_BODY"))
	select {
	case <-conn.TunnelReady():
	case <-conn.Done():
		fmt.Printf("tunnel failed: %v\n", conn.Err())
		os.Exit(3)
	case <-time.After(30 * time.Second):
		fmt.Println("tunnel never became ready")
		os.Exit(3)
	}
	fmt.Printf("%s%s\n", readyPrefix, conn.URL())
	select {} // serve until the parent kills us
}

// TestLiveTwoTunnels runs two tunnels in one process concurrently — the only
// place collisions in cloudflared's global state (the prometheus registerer
// swap, etc.) could surface. The second tunnel binds an unspecified address,
// covering the LocalIP outbound-route fallback in the same mints.
func TestLiveTwoTunnels(t *testing.T) {
	gateLive(t)

	cases := []struct {
		bind string
		body string
	}{
		{"127.0.0.1:0", "tunnel alpha"},
		{":0", "tunnel beta"},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(cases))
	for _, tc := range cases {
		wg.Add(1)
		go func(bind, body string) {
			defer wg.Done()
			l, err := net.Listen("tcp", bind)
			if err != nil {
				errs <- err
				return
			}
			defer l.Close()
			conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
			serveBody(conn.Listener(), body)

			if ip := conn.LocalIP(); ip == nil || ip.IsUnspecified() {
				errs <- fmt.Errorf("%s: LocalIP() = %v, want a concrete IP", body, ip)
				return
			}

			// 60s, not the usual 30s: with the self-export guard both tunnels
			// always mint for real, and two simultaneous mints can draw a
			// rate-limit backoff before the connect + DNS wait even starts.
			if err := readyErr(conn, 60*time.Second); err != nil {
				errs <- fmt.Errorf("%s: %w", body, err)
				return
			}
			// Retry briefly: TunnelReady proves a public resolver sees the
			// hostname, but this host's own resolver can lag a few seconds.
			if err := eventuallyBodyErr(conn.URL().String(), body, 30*time.Second); err != nil {
				errs <- fmt.Errorf("%s: %w", body, err)
				return
			}
		}(tc.bind, tc.body)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
