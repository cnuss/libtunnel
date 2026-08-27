package e2e_test

// Live scenario tests: real quick tunnels against the Cloudflare edge, run by
// `make e2e` (skipped under -short; on CI only the linux/amd64 cell runs
// them — see the tier-selection block in util_test.go). These are
// deliberately complicated — origin restarts, process kills, concurrent
// tunnels — and not meant for human consumption; the examples stay simple.
//
// The quick-tunnel API and edge provisioning are burst-sensitive, so the tests
// are stingy with mints: preflight mints ONE spec and every SHARE test adopts it
// (gateLive), reconnecting a fresh connector to that one hostname in sequence.
// Only scenarios that own a hostname's whole lifecycle mint their own
// (gateLiveOwnSpec): TestLiveHandoff (parent mints, children are killed and
// resurrected) and TestLiveTwoTunnels (two distinct hostnames). The SHARE
// tests run first and contiguous so the preflight spec stays continuously
// connected (well inside its ~5min idle TTL); the OWN tests run last, where
// preflight GC is moot. This all REQUIRES serial execution (no t.Parallel):
// one connector at a time on the shared hostname. Sticky-route release
// between sequential SHARE connectors is paced by gateLive and ridden out by
// the retrying body/warmup polls.

import (
	"bufio"
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TestLiveTunnel mints one tunnel and runs every scenario that doesn't need
// its own tunnel lifecycle against it, in order: round trip, parallel
// requests, a websocket upgrade, and finally an origin bounce (which tears
// the origin down, so it goes last). The listener is TLS (self-signed), so
// the whole test also covers the https-ingress path — the plain-HTTP path
// rides with the examples and the other live tests.
func TestLiveTunnel(t *testing.T) {
	gateLive(t) // adopts the shared preflight spec

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

	tun := libtunnel.New(libtunnel.Cloudflare().WithTLS(true))
	conn := tun.WithListener(l)
	// Serve the original listener: the bounce below restarts the origin and
	// the tunnel must persist. (Serving conn.Listener() would tie the tunnel
	// to the server's lifetime — that teardown is exercised at the end.)
	go srv.Serve(l)
	// Tear the connector down when done: closing the tunnel-owned listener view
	// cancels the tunnel, so this connector releases the shared preflight
	// hostname before the next SHARE test (paced by gateLive) reconnects to it.
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
		ws, err := websocket.Dial("wss://"+tun.Hostname()+"/ws", "", url)
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

// TestLiveMintedListener pins the scenario from #82: no WithListener, no
// net.Listen of the caller's own — serve straight on tun.Listener() (which
// mints the loopback listener and starts the tunnel) and read the public URL.
// The reported failure mode was blocking forever with no output; WithContext
// bounds every wait, so a regression fails the test instead of hanging it.
// (URL-before-listener start ordering is pinned by the unit tests.)
func TestLiveMintedListener(t *testing.T) {
	gateLive(t) // adopts the shared preflight spec

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	// The exact construction from the report: context and logger threaded,
	// no listener of the caller's own.
	tun := libtunnel.New(libtunnel.Cloudflare()).
		WithContext(ctx).
		WithLogger(slog.Default())
	// Cancel and wait for teardown so the connector releases the shared hostname
	// before the next SHARE test reconnects to it.
	defer drain(t, tun, cancel)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello via minted listener")
	})
	go http.Serve(tun.Listener(), mux)

	// WithContext is set, so URL waits for end-to-end readiness and returns
	// nil if ctx expires first — bounded either way.
	url := tun.URL()
	if url == nil {
		t.Fatalf("tunnel never became ready: tunnel err=%v, ctx err=%v", tun.Err(), ctx.Err())
	}
	// 60s: a fresh connector on the just-released shared hostname can see a
	// transient 5xx while the edge re-resolves the sticky route; the poll retries
	// through it.
	eventuallyBody(t, url.String(), "hello via minted listener", 60*time.Second)
}

// TestLiveBinary pins cmd/libtunnel (#90): the env-only launcher. A local
// server is the origin (LIBTUNNEL_LOCAL_URL), Cloudflare is activated by the
// switch (LIBTUNNEL__CLOUDFLARE=1), and the built binary prints the public URL
// to stdout and serves the origin through the edge. No flags, no listener
// plumbing — the whole configuration is environment. gateLive adopts the shared
// preflight spec into this process's environment, and the child binary inherits
// it (LIBTUNNEL_SPEC) through os.Environ() and adopts it too — so this exercises
// the launcher without minting.
func TestLiveBinary(t *testing.T) {
	gateLive(t) // adopts the shared preflight spec

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serveBody(l, "hello via the binary")

	bin := filepath.Join(t.TempDir(), "libtunnel")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/libtunnel").CombinedOutput(); err != nil {
		t.Fatalf("build cmd/libtunnel: %v\n%s", err, out)
	}

	cmd := exec.Command(bin)
	// gateLive exported the shared preflight spec into this process's
	// environment; os.Environ() carries LIBTUNNEL_SPEC to the child, which adopts
	// it instead of minting. The switch is set too, so the activation path is
	// covered even when a spec is present.
	cmd.Env = append(os.Environ(),
		v1.CloudflareEnv+"=1",
		v1.LocalURLEnv+"=http://"+l.Addr().String(),
	)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	// The binary prints the public URL as its first (and only) stdout line.
	var pub string
	scanner := bufio.NewScanner(stdout)
	if scanner.Scan() {
		pub = strings.TrimSpace(scanner.Text())
	}
	if pub == "" {
		t.Fatalf("binary printed no URL before exiting (scan err: %v)", scanner.Err())
	}
	t.Logf("binary URL: %s", pub)

	// 60s: the child adopts the shared hostname, so its first request can hit a
	// transient 5xx while the edge re-resolves the sticky route to the child's
	// connector.
	eventuallyBody(t, pub, "hello via the binary", 60*time.Second)
}

// TestLiveLocalURL pins the attach shape (#86) — the origin is an
// already-running local HTTP server the tunnel does not own, provided as a
// URL (the `cloudflared tunnel --url` equivalent; no listener crosses the
// tunnel API) — and runs every scenario that shape carries on ONE tunnel: a
// plain round trip, then the LIVE proof that the reverse proxy fronting the
// origin relays a real streaming (kubernetes-watch-shaped) chunked HTTP 200
// faithfully — every event, in order — through the live cloudflared + edge
// path. The stream case does NOT assert defeat of any edge buffering (the
// proxy doesn't, and shouldn't be expected to); edge buffering may bunch
// arrival, but every event still lands exactly once and in order. The client
// re-issues the IDENTICAL request as needed (the kubectl re-watch shape) to
// collect the whole stream.
func TestLiveLocalURL(t *testing.T) {
	gateLive(t) // adopts the shared preflight spec

	srv, originHits := startWatchOrigin(t)
	origin, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

	conn := libtunnel.New(cloudflare.New()).
		WithLogger(slog.Default()).
		WithContext(ctx).
		WithLocalURL(origin)
	// Cancel and wait for teardown so the connector releases the shared hostname
	// before the next SHARE test reconnects to it.
	defer drain(t, conn, cancel)

	pub := conn.URL()
	if pub == nil {
		t.Fatalf("tunnel never became ready: tunnel err=%v, ctx err=%v", conn.Err(), ctx.Err())
	}
	base := strings.TrimRight(pub.String(), "/")
	t.Logf("tunnel up via reverse proxy: %s", base)
	// 60s: this fresh connector adopts the shared hostname, so warmup may ride
	// out a transient 5xx while the edge re-resolves the sticky route.
	warmup(t, ctx, base+"/watch?n=1&ms=1", 60*time.Second)

	t.Run("RoundTrip", func(t *testing.T) {
		eventuallyBody(t, base+"/body", "hello via local URL", 30*time.Second)
	})

	t.Run("WatchStream", func(t *testing.T) {
		// One kube watch: 20 events, 500ms apart (~10s of stream). The proxy must
		// relay every event, in order, exactly once (edge buffering may bunch their
		// arrival — that is the edge's doing, not a relay fault).
		const total = 20
		watchURL := base + "/watch?probe=watch&n=20&ms=500"

		seen := map[int]bool{}
		var ordered []int
		deadline := time.Now().Add(45 * time.Second)
		for len(seen) < total && time.Now().Before(deadline) {
			for _, ev := range chopStream(t, ctx, watchURL) {
				if !seen[ev.seq] {
					seen[ev.seq] = true
					ordered = append(ordered, ev.seq)
				}
			}
		}

		t.Logf("collected %d/%d events; origin requests=%d", len(seen), total, originHits.Load())
		if len(seen) != total {
			t.Fatalf("collected %d events, want %d (the proxy must relay the whole stream)", len(seen), total)
		}
		for i, seq := range ordered {
			if seq != i {
				t.Fatalf("event %d arrived as seq %d — out of order", i, seq)
			}
		}
	})
}

// spawnServeChild re-execs anchorTest with the live-serve-child role serving
// body, waits for the child's ready line, and returns the URL that line
// carried plus a kill func. The child inherits this process's environment,
// LIBTUNNEL_SPEC included — that inheritance is the spec handoff under test.
func spawnServeChild(t *testing.T, anchorTest, body string) (ready string, kill func()) {
	t.Helper()
	cmd := reexec(anchorTest, roleEnv+"=live-serve-child", "LIBTUNNEL_E2E_BODY="+body)
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
		if u, ok := strings.CutPrefix(line, readyPrefix); ok {
			return u, func() { cmd.Process.Kill(); cmd.Wait() }
		}
	}
	cmd.Wait()
	t.Fatalf("child[%s] exited before the tunnel became ready (scan err: %v)", body, scanner.Err())
	return "", nil
}

// TestLiveHandoff is the canonical parent→child spec handoff (promoted from
// the old examples/subprocess) and its strongest form — resurrection — on ONE
// mint. The parent mints a spec and never connects: minting exports
// LIBTUNNEL_SPEC into this process's environment, so spawned children inherit
// the tunnel identity with no plumbing at all. Generation one provides the
// listener, connects, and serves — the parent reaches it through the very
// hostname it minted. It is then killed, and generation two reuses the same
// spec: the same hostname serves again after its connector died ungracefully.
// Needs its own spec lifecycle: reusing the shared preflight hostname risks a
// sticky "530 origin unregistered" long after a new connector registers.
func TestLiveHandoff(t *testing.T) {
	if role() == "live-serve-child" {
		liveServeChild()
		return
	}
	gateLiveOwnSpec(t) // owns its hostname's lifecycle; mints its own spec

	hostname := libtunnel.New(libtunnel.Cloudflare()).Hostname()
	if hostname == "" {
		t.Fatal("failed to mint a spec")
	}
	t.Logf("minted: %s", hostname)
	pub := "https://" + hostname + "/"

	ready, kill1 := spawnServeChild(t, "TestLiveHandoff", "generation one")
	childURL, err := url.Parse(ready)
	if err != nil {
		t.Fatalf("child ready line %q is not a URL: %v", ready, err)
	}
	if childURL.Hostname() != hostname {
		t.Errorf("child connected under %q, want the parent's minted hostname %q",
			childURL.Hostname(), hostname)
	}
	eventuallyBody(t, pub, "generation one", 90*time.Second)
	kill1()

	_, kill2 := spawnServeChild(t, "TestLiveHandoff", "generation two")
	defer kill2()
	eventuallyBody(t, pub, "generation two", 90*time.Second)
}

// liveServeChild adopts LIBTUNNEL_SPEC, serves LIBTUNNEL_E2E_BODY, reports
// readiness, and blocks until killed.
func liveServeChild() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		os.Exit(3)
	}
	// Logged: this child is spawned by TestLiveHandoff, whose only view of
	// a readiness failure is whatever the child wrote before exiting.
	conn := libtunnel.New(libtunnel.Cloudflare()).
		WithLogger(slog.Default()).
		WithListener(l)
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
	gateLiveOwnSpec(t) // needs two distinct hostnames; mints its own
	// Two concurrent mints must not share reclaim hints: one scoped cache dir
	// would hand both mints the same reclaimable hostname (crosstalk), so this
	// scenario alone keeps a throwaway dir and pays two fresh mints per run.
	t.Setenv(v1.CacheDirEnv, t.TempDir())

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
			// Logged, and tagged: two tunnels resolve concurrently here, so an
			// untagged line cannot be attributed to either.
			tun := libtunnel.New(libtunnel.Cloudflare()).
				WithLogger(slog.Default().With("tunnel", body))
			conn := tun.WithListener(l)
			serveBody(conn.Listener(), body)

			if ip := tun.LocalIP(); ip == nil || ip.IsUnspecified() {
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
			if err := eventuallyBodyErr(conn.URL().String(), body, 90*time.Second); err != nil {
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
