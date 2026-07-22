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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

// gateLive skips the test unless the live tier is enabled, fails fast when
// the preflight comms check failed, scrubs any inherited LIBTUNNEL_SPEC so live
// scenarios always mint their own, and paces the suite.
func gateLive(t *testing.T) {
	t.Helper()
	if os.Getenv("LIBTUNNEL_E2E_LIVE") != "1" {
		t.Skip("live scenario (mints a real quick tunnel); set LIBTUNNEL_E2E_LIVE=1 to run")
	}
	if err := preflight(); err != nil {
		t.Fatalf("live preflight failed (skipping the expensive part): %v", err)
	}
	t.Setenv(v1.SpecEnv, "")
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
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		preflightSpec, preflightErr = cloudflare.QuickTunnel().Spec(ctx)
		lastLiveStart = time.Now() // the mint counts toward pacing
	})
	return preflightErr
}

// lastLiveStart paces back-to-back live tests. The quick-tunnel API and edge
// provisioning are burst-sensitive: minting a dozen tunnels in a few minutes
// drew 429s and route-propagation failures live, while the same tests pass
// individually. Tests run sequentially (no t.Parallel), so a plain variable
// suffices.
var lastLiveStart time.Time

func paceLive() {
	const gap = 20 * time.Second
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

// httpClient fetches the public URL. Readiness already guarantees the hostname
// resolves on every authoritative nameserver before a tunnel reports ready, so
// the stdlib client suffices — no DoH/dualstack workaround is needed here.
var httpClient = &http.Client{Timeout: 15 * time.Second}

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

// startWatchOrigin starts a kube-apiserver `?watch=true` lookalike: GET /watch
// returns a chunked application/json NDJSON stream that emits one
// `{"type":"ADDED","object":{"seq":N,"ts":"<RFC3339Nano>","pad":"..."}}` event
// per interval and flushes each — the exact shape a plain trycloudflare edge
// buffers. Query params tune the stream: n (event count), ms (interval), pad
// (filler bytes per event), since (first seq, so a reconnect resumes). The
// returned counter tracks requests carrying probe=watch, so a test can assert
// the session shim shielded the origin to exactly one request across reconnects.
func startWatchOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	// DefaultClient, not httpClient: a long-lived response would trip a
	// client-level timeout, so reqCtx bounds the read instead.
	resp, err := http.DefaultClient.Do(req)
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
