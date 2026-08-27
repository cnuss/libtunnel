package e2e_test

// Shared plumbing for the scenario tests: re-exec roles, live gating, retry
// helpers, and a self-signed TLS config. Scenario tests re-exec this test
// binary with -test.run anchored to themselves and a role variable set; the
// role branch at the top of each test turns the process into the child.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TestMain raises the default logger to debug before any test runs. The live
// tests hand slog.Default() to their tunnels, and the interesting detail of a
// failing run shows up only at that level. It reaches the re-exec'd children
// too, since they run this same binary and their stderr is the parent's only
// view of them.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	os.Exit(m.Run())
}

// roleEnv selects a child role inside a re-exec'd test binary.
const roleEnv = "LIBTUNNEL_E2E_ROLE"

func role() string { return os.Getenv(roleEnv) }

// reexec builds a command that re-runs this test binary anchored to a single
// test, with extra environment entries appended to the current environment.
func reexec(test string, extraEnv ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd
}

// gateLive gates a live scenario and, by default, hands it the ONE shared
// preflight mint: it skips unless the live tier is enabled, fails fast when the
// preflight comms check failed, paces the suite, then adopts the preflight spec
// so the tunnel reuses that hostname instead of minting its own. Quick-tunnel
// minting is rate-limited and the live tier runs three OS cells in parallel, so
// a per-test mint bursts the limiter; sharing the preflight spec keeps the
// whole live tier to a handful of mints.
//
// Adopt-by-default REQUIRES serial execution — one connector at a time on the
// shared hostname — so no live test may call t.Parallel(). Scenarios that own a
// hostname's whole lifecycle (a distinct hostname, or a connector they kill and
// resurrect) use gateLiveOwnSpec to mint their own instead.
func gateLive(t *testing.T) {
	t.Helper()
	gateLiveBare(t)
	adoptPreflightSpec(t)
}

// gateLiveOwnSpec is gateLive for the few scenarios that must mint their own
// identity: it scrubs any inherited LIBTUNNEL_SPEC so the tunnel mints a fresh
// hostname rather than adopting the shared preflight spec. Used by
// TestLiveHandoff (kills and resurrects connectors on its own hostname —
// reusing the shared one risks a sticky 530 after unregister, and the
// parent-side mint is half its scenario) and TestLiveTwoTunnels (needs two
// distinct hostnames).
func gateLiveOwnSpec(t *testing.T) {
	t.Helper()
	gateLiveBare(t)
	t.Setenv(v1.SpecEnv, "")
	// Own-spec means own cache too: the shared cache dir's latest.spec.json
	// (the preflight's tunnel, or the previous run's via the CI cache) would
	// otherwise seed this mint's reclaim hints and hand back the very tunnel
	// these scenarios must not share. (In-process the library already skips
	// self-cached specs; this also isolates from the restored cross-run one.)
	// The dir is scoped to the test, not throwaway: a fresh hostname per run
	// is how the live tier blew through mint limits (#147).
	t.Setenv(v1.CacheDirEnv, scopedCacheDir(t, "own-"+t.Name()))
}

// scopedCacheDir is a persistent spec-cache dir scoped to name under the
// suite's cache base: isolated from the shared latest.spec.json (so its user
// never adopts the preflight tunnel) but stable across runs — via the CI
// spec cache — so its own previous mint seeds reclaim hints and the hostname
// is reused instead of leaked. Falls back to a throwaway dir when no cache
// base is configured or the subdir can't be made.
func scopedCacheDir(t *testing.T, name string) string {
	base := os.Getenv(v1.CacheDirEnv)
	if base == "" {
		return t.TempDir()
	}
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Logf("scoped cache dir %s: %v (using a throwaway)", dir, err)
		return t.TempDir()
	}
	return dir
}

// Tier selection (#147): no env opt-in — the -short flag draws the line. The
// unit lane (`make test`, and CI's race lane) passes -short and stays
// offline; `make e2e` runs without it and goes live. On CI (the standard
// CI=true env) the tests below narrow further by platform, keeping every
// scrap of tier logic out of the workflow: the full scenario tier runs on
// one cell — linux/amd64 — and the examples tier on one variant of each OS
// family, so every family still mints a real tunnel without every cell
// running the whole suite; the other cells skip all live work. Off CI
// nothing is narrowed, so a developer's `make e2e` runs everything.

func onCI() bool { return os.Getenv("CI") == "true" }

// scenarioCell reports whether this platform runs the live scenario tier.
func scenarioCell() bool {
	return !onCI() || (runtime.GOOS == "linux" && runtime.GOARCH == "amd64")
}

// exampleCell reports whether this platform runs the live examples tier —
// one variant per OS family (the CI spec-cache step keys off the same
// three cells).
func exampleCell() bool {
	if !onCI() {
		return true
	}
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64", "windows/amd64", "darwin/arm64":
		return true
	}
	return false
}

// skipUnlessLive holds the gates every live case shares: -short (the unit
// lane must stay offline) and Dependabot PRs (dependency bumps can't change
// tunnel behavior, and their mints burn the provider's concurrency budget —
// and flake on its incidents — for nothing).
func skipUnlessLive(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("live case (mints a real quick tunnel); run without -short (make e2e)")
	}
	if dependabotRun() {
		t.Skip("Dependabot PR: dependency bumps can't change tunnel behavior; skipping live mints")
	}
}

// dependabotRun reports whether this CI run belongs to a Dependabot PR. The
// event payload is the only place the PR author lives — GITHUB_ACTOR reports
// whoever clicked rerun, so gating on it would let a human rerun go live —
// and on push events the payload has no pull_request, so pushes always run
// live.
func dependabotRun() bool {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var ev struct {
		PullRequest struct {
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return false
	}
	return ev.PullRequest.User.Login == "dependabot[bot]"
}

// gateLiveBare is the shared gate — live check, tier check, preflight, pace —
// behind both gateLive (adopt the shared spec) and gateLiveOwnSpec (mint your
// own).
func gateLiveBare(t *testing.T) {
	t.Helper()
	skipUnlessLive(t)
	if !scenarioCell() {
		t.Skip("live scenario tier runs on one CI cell (linux/amd64); this cell runs at most the examples tier (#147)")
	}
	if err := preflight(); err != nil {
		t.Fatalf("live preflight failed (skipping the expensive part): %v", err)
	}
	paceLive()
}

// preflight is the basic-comms check the whole live tier hangs off: one
// quick-tunnel mint with a short budget. If it fails (rate limit, no
// network), every live test fails fast instead of each burning its own
// timeout. The minted spec is not wasted — TestLiveTunnel adopts it through
// the environment instead of minting again.
var (
	preflightOnce sync.Once
	preflightErr  error
	preflightSpec *cloudflare.Spec
)

func preflight() error {
	preflightOnce.Do(func() {
		// 30s: a mint attempt is bounded at 15s (the endpoint holds the
		// request while it waits out DNS propagation), so this budget fits a
		// retry against a briefly saturated mint endpoint instead of dying on
		// the first hang.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Hand the provider the suite's debug logger, or a throttled
		// preflight fails with nothing but a deadline in the CI log. Not
		// ephemeral (and not since #142): reclaimability is the point — the
		// provider reads latest.spec.json for reclaim hints, so a CI-cache
		// restore turns this mint into a reclaim of the previous run's
		// tunnel.
		qt := cloudflare.QuickTunnel()
		qt.Log = slog.Default()
		preflightSpec, preflightErr = qt.Spec(ctx)
		if preflightErr == nil {
			// The direct provider bypasses the chain's cache write; record
			// the mint so the next run (via the Actions cache) reclaims it.
			_ = v1alpha1.CacheSpec(preflightSpec)
		}
		lastLiveStart = time.Now() // the mint counts toward pacing
	})
	return preflightErr
}

// lastLiveStart paces back-to-back live tests. The quick-tunnel API and edge
// provisioning are burst-sensitive: minting a dozen tunnels in a few minutes
// drew 429s and route-propagation failures live, while the same tests pass
// individually. The gap does double duty now that SHARE tests reconnect a fresh
// connector to the ONE preflight hostname in sequence: after a connector's
// context is canceled the edge can briefly serve its stale route, so the pace
// also gives the edge time to release the sticky route before the next
// connector registers. Tests run sequentially (no t.Parallel), so a plain
// variable suffices.
var lastLiveStart time.Time

func paceLive() {
	// 30s, up from 20s: the extra headroom covers sticky-route release on the
	// shared hostname between sequential SHARE connectors, not just mint spacing.
	const gap = 30 * time.Second
	if since := time.Since(lastLiveStart); since < gap {
		time.Sleep(gap - since)
	}
	lastLiveStart = time.Now()
}

// readyPrefix matches the "ready: <url>" line liveServeChild prints. The
// example children print the same line, but keep their own literal — examples
// are intentionally self-contained — so a change to either side must be
// mirrored: a drifted prefix is a silent scanner hang, not an error.
const readyPrefix = "ready: "

// readyErr waits for TunnelReady with a deadline, returning an error when the
// tunnel dies first (Done) or never readies within d. waitReady is the
// t.Fatal form; scenarios that wait inside worker goroutines (where t.Fatal
// is illegal) use this directly.
func readyErr(conn v1.Tunnel, d time.Duration) error {
	select {
	case <-conn.TunnelReady():
		return nil
	case <-conn.Done():
		return fmt.Errorf("tunnel failed: %w", conn.Err())
	case <-time.After(d):
		return fmt.Errorf("tunnel not ready after %v (rate-limited mint or dead connection?)", d)
	}
}

// waitReady waits for TunnelReady with a deadline, failing fast when the
// tunnel dies first (Done) or never readies within d.
func waitReady(t *testing.T, conn v1.Tunnel, d time.Duration) {
	t.Helper()
	if err := readyErr(conn, d); err != nil {
		t.Fatal(err)
	}
}

// edgeAddrs are tunneled.pizza's anycast edge addresses. The harness dials
// them directly instead of resolving the tunnel hostname: the edge routes by
// TLS SNI, which the transport still sets from the URL's hostname, so DNS is
// out of the request path entirely. That is deliberate — these scenarios are
// about spec handoff and connector lifecycle, not DNS propagation (the serve
// examples cover that), and a lookup racing a fresh tunnel's propagation
// window gets an NXDOMAIN the OS caches for the zone's SOA (1800s), turning
// every later retry into a no-op. Measured as the dominant live-tier flake:
// whichever test drew the fastest mint lost its whole retry window to one
// early lookup.
var edgeAddrs = []string{"104.16.230.132:443", "104.16.231.132:443"}

// dialEdge dials one of edgeAddrs for any :443 destination, falling back to a
// normal resolve-and-dial (covering both a non-edge URL and the day the
// anycast addresses move).
func dialEdge(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	var edgeErr error
	if _, port, err := net.SplitHostPort(addr); err == nil && port == "443" {
		for _, edge := range edgeAddrs {
			conn, err := d.DialContext(ctx, network, edge)
			if err == nil {
				return conn, nil
			}
			edgeErr = err
		}
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil && edgeErr != nil {
		err = fmt.Errorf("%w (edge dial also failed: %v)", err, edgeErr)
	}
	return conn, err
}

// edgeTransport carries dialEdge for every harness request to the public URL.
var edgeTransport = &http.Transport{DialContext: dialEdge}

// httpClient fetches the public URL, through edgeTransport.
var httpClient = &http.Client{Timeout: 15 * time.Second, Transport: edgeTransport}

// getBody requests url once and returns the body.
func getBody(url string) (string, int, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// eventuallyBodyErr polls url until the body equals want or the deadline
// expires. Fresh tunnels and just-restarted origins can lag a few seconds
// behind the edge. eventuallyBody is the t.Fatal form; worker goroutines use
// this directly.
func eventuallyBodyErr(url, want string, deadline time.Duration) error {
	var last string
	var lastErr error
	for end := time.Now().Add(deadline); time.Now().Before(end); {
		body, code, err := getBody(url)
		last, lastErr = body, err
		if err == nil && code == http.StatusOK && body == want {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("never saw body %q from %s (last body %q, last err %v)", want, url, last, lastErr)
}

// eventuallyBody polls url until the body equals want or the deadline
// expires.
func eventuallyBody(t *testing.T, url, want string, deadline time.Duration) {
	t.Helper()
	if err := eventuallyBodyErr(url, want, deadline); err != nil {
		t.Fatal(err)
	}
}

// selfSignedTLS returns a TLS config with a fresh self-signed certificate for
// 127.0.0.1.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "libtunnel e2e"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// serveBody serves a fixed body on l in the background. The returned server
// handle matters when a scenario needs the origin actually dead: Close tears
// down established (kept-alive) connections too, which closing the bare
// listener does not — pooled origin connections would keep serving.
func serveBody(l net.Listener, body string) *http.Server {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	})}
	go srv.Serve(l)
	return srv
}

// adoptPreflightSpec hands the shared preflight mint to a tunnel through the
// environment, so a live test reuses that spec instead of minting its own (the
// Cloudflare chain adopts LIBTUNNEL_SPEC before minting). Same move
// TestLiveTunnel makes — it keeps the live tier's mint count down.
func adoptPreflightSpec(t *testing.T) {
	t.Helper()
	if preflightSpec == nil {
		return
	}
	if entry, err := v1alpha1.SpecEnviron("cloudflare", preflightSpec); err == nil {
		t.Setenv(v1.SpecEnv, strings.TrimPrefix(entry, v1.SpecEnv+"="))
	}
}

// drain cancels a SHARE test's tunnel and blocks until its context reports Done,
// so the connector on the shared preflight hostname is torn down deterministically
// before the test returns (and before the next SHARE test's paceLive begins its
// sticky-route release window). Done fires on cancel propagation, not on the
// edge's own route release — that release is what paceLive's gap covers — so the
// wait is short and bounded.
func drain(t *testing.T, conn v1.Tunnel, cancel context.CancelFunc) {
	t.Helper()
	cancel()
	select {
	case <-conn.Done():
	case <-time.After(5 * time.Second):
		t.Log("connector did not report Done within 5s of cancel")
	}
}

// startWatchOrigin starts a kube-apiserver `?watch=true` lookalike: GET /watch
// returns a chunked application/json NDJSON stream that emits one
// `{"type":"ADDED","object":{"seq":N,"ts":"<RFC3339Nano>","pad":"..."}}` event
// per interval and flushes each — the exact shape a plain tunneled.pizza edge
// buffers. Query params tune the stream: n (event count), ms (interval), pad
// (filler bytes per event), since (first seq, so a reconnect resumes). GET
// /body answers a fixed string, so the one tunnel TestLiveLocalURL puts in
// front of this origin covers the plain round trip too. The returned counter
// tracks requests carrying probe=watch, so a test can assert the session shim
// shielded the origin to exactly one request across reconnects.
func startWatchOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			fmt.Fprint(w, "hello via local URL")
			return
		}
		if r.URL.Path != "/watch" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("probe") == "watch" {
			hits.Add(1)
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-cache, private")
		// No Content-Length: chunked transfer, like the apiserver watch.
		w.WriteHeader(http.StatusOK)
		fl.Flush() // send the response head immediately

		n := intQuery(r, "n", 10)
		interval := time.Duration(intQuery(r, "ms", 500)) * time.Millisecond
		pad := intQuery(r, "pad", 0)
		since := intQuery(r, "since", 0)

		enc := json.NewEncoder(w) // Encode appends '\n' -> NDJSON, like watch
		for i := range n {
			ev := map[string]any{
				"type": "ADDED",
				"object": map[string]any{
					"seq": since + i,
					"ts":  time.Now().UTC().Format(time.RFC3339Nano),
					"pad": strings.Repeat("x", pad),
				},
			}
			if err := enc.Encode(ev); err != nil {
				return // client hung up
			}
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(interval):
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

// intQuery resolves an integer query param, falling back to def.
func intQuery(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// chopEvent is one delivered watch event: its sequence number and the
// end-to-end delivery latency (arrival − embedded origin ts). Origin and client
// share the host clock; only the tunnel is remote.
type chopEvent struct {
	seq     int
	latency time.Duration
}

// chopStream reads one (possibly short) response from url and returns the events
// it carried. It reads line-by-line with a 1 MB buffer, skips blank/unparsable
// lines (partial frames at a boundary), and json-parses each NDJSON object.
// Short responses and connection closes are the expected steady state under
// chop, so an errored request is not fatal.
func chopStream(t *testing.T, ctx context.Context, url string) []chopEvent {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		t.Logf("chopStream: build request: %v", err)
		return nil
	}
	// Not httpClient: a long-lived response would trip its client-level
	// timeout, so reqCtx bounds the read instead. Same edge transport, though
	// — this fetch must not depend on DNS either.
	resp, err := (&http.Client{Transport: edgeTransport}).Do(req)
	if err != nil {
		t.Logf("chopStream: request ended: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var events []chopEvent
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Object struct {
				Seq int    `json:"seq"`
				Ts  string `json:"ts"`
			} `json:"object"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // partial or non-JSON line at a boundary; drop it
		}
		ts, err := time.Parse(time.RFC3339Nano, ev.Object.Ts)
		if err != nil {
			continue
		}
		events = append(events, chopEvent{seq: ev.Object.Seq, latency: time.Since(ts)})
	}
	if err := sc.Err(); err != nil {
		t.Logf("chopStream: body read ended with %v (after %d events)", err, len(events))
	}
	return events
}

// warmup blocks until url returns at least one event or timeout elapses — a
// fresh connector's route can take a few seconds to propagate to the edge, and
// the watch measurements below assume it is already live.
func warmup(t *testing.T, ctx context.Context, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(chopStream(t, ctx, url)) > 0 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("warmup never got a response from %s within %v", url, timeout)
}
