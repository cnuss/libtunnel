package cloudflare

// Offline tests for the origin reverse proxy (newOriginProxy) below build
// the proxy directly and speak plain HTTP to its listener address — no
// cloudflared, no tunnel mint, no real edge. There is no edge offline, so they
// cannot assert edge-flush timing; they assert the proxy relays the origin's
// response faithfully: right status, right framing, byte-identical body, and —
// for a streaming origin — every event delivered in order.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// TestWithListenerRejectsMalformedSpecID pins the fail-fast contract: a spec
// whose ID is not a UUID (e.g. a corrupted LIBTUNNEL_SPEC handoff) must cancel
// the tunnel with a descriptive cause instead of registering the zero UUID
// with the edge. Runs offline — the ID check fires before any network use.
func TestWithListenerRejectsMalformedSpecID(t *testing.T) {
	t.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"id":"not-a-uuid","hostname":"x.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn := v1alpha1.New(New()).WithListener(l)
	select {
	case <-conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not fail on a malformed spec id")
	}
	if err := conn.Err(); err == nil || !strings.Contains(err.Error(), "invalid tunnel id") {
		t.Errorf("Err() = %v, want an invalid tunnel id cause", err)
	}
}

// TestEnvFixesOriginSchemeKnobs pins the env-beats-code rule for the backend
// bools: LIBTUNNEL_TLS / LIBTUNNEL_HTTP2 fix the knobs at construction and
// the With* mutators become no-ops.
func TestEnvFixesOriginSchemeKnobs(t *testing.T) {
	t.Setenv(v1.TLSEnv, "true")
	t.Setenv(v1.HTTP2Env, "false")

	b := New()
	b.WithTLS(false).WithHTTP2(true) // both lose: env fixed the knobs

	if !b.tls {
		t.Error("TLS = false; want the LIBTUNNEL_TLS=true value to stick over WithTLS(false)")
	}
	if b.http2 {
		t.Error("HTTP2 = true; want the LIBTUNNEL_HTTP2=false value to stick over WithHTTP2(true)")
	}
	if err := b.envErr; err != nil {
		t.Errorf("EnvErr = %v, want nil", err)
	}
}

// TestEnvKnobsUnsetLeaveCodeInCharge pins the fallthrough: without the env
// vars the mutators work exactly as before.
func TestEnvKnobsUnsetLeaveCodeInCharge(t *testing.T) {
	t.Setenv(v1.TLSEnv, "")
	t.Setenv(v1.HTTP2Env, "")

	b := New()
	b.WithTLS(true).WithHTTP2(true)

	if !b.tls || !b.http2 {
		t.Errorf("TLS/HTTP2 = %v/%v after WithTLS(true).WithHTTP2(true) with no env, want true/true", b.tls, b.http2)
	}
}

// TestEnvFixesStreamingLevers pins env-beats-code for the Cloudflare streaming
// lever: LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL fixes the knob at construction and
// WithFlushInterval becomes a no-op.
func TestEnvFixesStreamingLevers(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "500ms")

	b := New()
	b.WithFlushInterval(5 * time.Second) // loses: env fixed 500ms

	if got := b.flushInterval; got == nil || *got != 500*time.Millisecond {
		t.Errorf("FlushInterval = %v, want the LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL=500ms value to stick over WithFlushInterval(5s)", got)
	}
	if err := b.envErr; err != nil {
		t.Errorf("EnvErr = %v, want nil", err)
	}
}

// TestStreamingLeversUnsetLeaveCodeInCharge pins the fallthrough: without the
// env var the mutator works exactly as written.
func TestStreamingLeversUnsetLeaveCodeInCharge(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "")

	b := New().WithFlushInterval(2 * time.Second)

	if got := b.flushInterval; got == nil || *got != 2*time.Second {
		t.Errorf("FlushInterval = %v, want 2s from code", got)
	}
}

// TestFlushIntervalEnvUnparsableSetsEnvErr pins loud failure for a bad duration
// override: New records the parse error, which connect later surfaces (as
// TestEnvKnobUnparsableFailsConnect proves for the bool knobs).
func TestFlushIntervalEnvUnparsableSetsEnvErr(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "banana")

	if err := New().envErr; err == nil || !strings.Contains(err.Error(), v1.CloudflareFlushIntervalEnv) {
		t.Errorf("EnvErr = %v, want a %s parse cause", err, v1.CloudflareFlushIntervalEnv)
	}
}

// clearSpecEnv scrubs the credential-chain env vars so a test resolves
// exactly the channel it stages.
func clearSpecEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{v1.SpecEnv, v1.FromEnv, v1.CloudflareIDEnv, v1.CloudflareNameEnv,
		v1.CloudflareHostnameEnv, v1.CloudflareAccountTagEnv, v1.CloudflareSecretEnv, v1.CloudflareAPIURLEnv} {
		t.Setenv(v, "")
	}
}

// TestSpecFieldSettersPatchResolvedSpec pins the overlay: WithName patches
// the field onto the spec the chain resolves (here a code-pinned one).
func TestSpecFieldSettersPatchResolvedSpec(t *testing.T) {
	clearSpecEnv(t)

	b := From(&Spec{ID: "id", Hostname: "pinned.trycloudflare.com"}).WithName("patched")
	spec, err := b.Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "patched" || spec.Hostname != "pinned.trycloudflare.com" {
		t.Errorf("spec = %+v, want Name patched onto the pinned spec", spec)
	}
}

// TestSpecFieldEnvBeatsCode pins per-field precedence: the
// LIBTUNNEL__CLOUDFLARE_* variable wins over the WithX setter.
func TestSpecFieldEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareNameEnv, "from-env")

	b := From(&Spec{Hostname: "pinned.trycloudflare.com"}).WithName("from-code")
	spec, err := b.Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "from-env" {
		t.Errorf("Name = %q, want the env override", spec.Name)
	}
}

// TestCompleteFieldSetShortCircuitsMint pins the short-circuit: a complete
// credential set from the field env vars is the spec — no mint, no network
// (an attempted mint would fail offline against the bogus API URL).
func TestCompleteFieldSetShortCircuitsMint(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareIDEnv, "3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6")
	t.Setenv(v1.CloudflareHostnameEnv, "fields.trycloudflare.com")
	t.Setenv(v1.CloudflareAccountTagEnv, "tag")
	t.Setenv(v1.CloudflareSecretEnv, "c2VjcmV0")
	t.Setenv(v1.CloudflareAPIURLEnv, "http://127.0.0.1:1/nope")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := New().Provider().Spec(ctx)
	if err != nil {
		t.Fatalf("Spec() = %v; a complete field set must not mint", err)
	}
	if spec.Hostname != "fields.trycloudflare.com" || spec.AccountTag != "tag" || string(spec.Secret) != "secret" {
		t.Errorf("spec = %+v, want the env field set verbatim", spec)
	}
}

// TestSecretEnvUndecodableErrors pins loud failure for a bad secret override.
func TestSecretEnvUndecodableErrors(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareSecretEnv, "%%%not-base64%%%")

	_, err := From(&Spec{Hostname: "pinned.trycloudflare.com"}).Provider().Spec(context.Background())
	if err == nil || !strings.Contains(err.Error(), v1.CloudflareSecretEnv) {
		t.Errorf("Spec err = %v, want a %s decode failure", err, v1.CloudflareSecretEnv)
	}
}

// TestApiURLEnvBeatsCode pins WithApiURL and its env mirror: the mint hits
// the env endpoint, not the code one (which would hang the test in retries).
func TestApiURLEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"minted.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()
	t.Setenv(v1.CloudflareAPIURLEnv, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := New().WithApiURL("http://127.0.0.1:1/nope").Provider().Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "minted.trycloudflare.com" {
		t.Errorf("Hostname = %q, want the spec minted from the env endpoint", spec.Hostname)
	}
}

// TestEnvKnobUnparsableFailsConnect pins loud failure: an operator override
// that can't be honored must fail the tunnel at connect, not be ignored.
func TestEnvKnobUnparsableFailsConnect(t *testing.T) {
	t.Setenv(v1.TLSEnv, "banana")
	t.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"x.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn := v1alpha1.New(New()).WithListener(l)
	select {
	case <-conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not fail on an unparsable LIBTUNNEL_TLS")
	}
	if err := conn.Err(); err == nil || !strings.Contains(err.Error(), v1.TLSEnv) {
		t.Errorf("Err() = %v, want a %s parse cause", err, v1.TLSEnv)
	}
}

// mustProxy interposes the reverse-proxy shim in front of srv and returns the
// http:// base URL a client dials.
func mustProxy(t *testing.T, ctx context.Context, srv *httptest.Server, flushInterval time.Duration) string {
	t.Helper()
	origin, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ps := &http.Server{Handler: newOriginProxy(origin, flushInterval, logger)}
	context.AfterFunc(ctx, func() { ps.Close() })
	go ps.Serve(l)
	return "http://" + l.Addr().String()
}

func qint(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// TestPassthroughContentLength proves a FIXED (Content-Length) origin response
// is relayed VERBATIM through the shim: a normal, complete response — right
// status and a byte-identical body — not a mangled one.
func TestPassthroughContentLength(t *testing.T) { runPassthrough(t, false) }

// TestPassthroughContentLength_TLS is the regression for #106: an apiserver
// /healthz-shaped response (TLS origin, fixed Content-Length body "ok"). The
// shim must dial the origin over TLS (InsecureSkipVerify) and relay verbatim.
func TestPassthroughContentLength_TLS(t *testing.T) { runPassthrough(t, true) }

func runPassthrough(t *testing.T, useTLS bool) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A small, single write with no Flush lets net/http set a fixed
		// Content-Length (the non-chunked, /healthz shape).
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok")
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A non-zero flush interval must NOT affect a fixed response — it is one-shot.
	base := mustProxy(t, ctx, srv, 200*time.Millisecond)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through shim failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (verbatim relay of the fixed origin response)", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body %q, want %q (relay must be byte-identical)", body, "ok")
	}
	if resp.ContentLength != 2 {
		t.Errorf("Content-Length %d, want 2 (fixed framing preserved verbatim)", resp.ContentLength)
	}
	if te := resp.TransferEncoding; len(te) != 0 {
		t.Errorf("Transfer-Encoding %v, want none (fixed response must not be re-chunked)", te)
	}
}

// streamEvent is one NDJSON event the streaming origin emits.
type streamEvent struct {
	Seq int    `json:"seq"`
	Ts  string `json:"ts"`
}

// TestStreamingPassthrough proves a chunked, unbuffered streaming origin
// response (the kube-watch shape) is proxied straight through with FlushInterval
// set: every event arrives, in order. There is no reconnect/session model
// anymore — this is a single straight stream through the reverse proxy.
func TestStreamingPassthrough(t *testing.T) {
	const total = 12
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		n := qint(r, "n", total)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		enc := json.NewEncoder(w) // appends '\n' -> NDJSON, like a watch stream
		for i := 0; i < n; i++ {
			if err := enc.Encode(streamEvent{Seq: i, Ts: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
				return
			}
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := mustProxy(t, ctx, srv, 100*time.Millisecond)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/watch?n="+strconv.Itoa(total), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through shim failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	var ordered []int
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev streamEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("non-JSON line through the proxy (framing corrupted): %q", line)
		}
		ordered = append(ordered, ev.Seq)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("body read ended with %v (after %d events)", err, len(ordered))
	}

	if len(ordered) != total {
		t.Fatalf("collected %d events, want %d (a straight proxied stream must deliver all)", len(ordered), total)
	}
	for i, seq := range ordered {
		if seq != i {
			t.Fatalf("event %d arrived as seq %d — out of order", i, seq)
		}
	}
}

const specJSON = `{"success":true,"result":{
	"id":"00000000-0000-0000-0000-000000000000",
	"name":"test",
	"hostname":"test.trycloudflare.com",
	"account_tag":"tag",
	"secret":"c2VjcmV0"}}`

func TestQuickTunnelSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	spec, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "test.trycloudflare.com" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
	if string(spec.Secret) != "secret" {
		t.Errorf("Secret = %q, want base64-decoded %q", spec.Secret, "secret")
	}
}

func TestQuickTunnelRetriesAfter429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	spec, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (one 429, one success)", got)
	}
	if spec.Hostname != "test.trycloudflare.com" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
}

func TestQuickTunnelRetriesAfterMalformedBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Write([]byte("<html>not json</html>"))
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (one malformed, one success)", got)
	}
}

func TestQuickTunnelRejectionIsPermanent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"success":false,"errors":[{"code":1003,"message":"quick tunnels disabled"}]}`))
	}))
	defer srv.Close()

	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, ErrMintRejected) {
		t.Errorf("err = %v, want errors.Is(_, ErrMintRejected)", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1 (definitive rejection must not retry)", got)
	}
}

func TestQuickTunnelHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success":false,"errors":[{"code":1,"message":"boom"}]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(ctx); err == nil {
		t.Fatal("Spec returned nil error although the API never succeeds and ctx expired")
	}
}

func TestQuickTunnelSurfacesRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	_, err := (&QuickTunnelProvider{URL: srv.URL, Log: log}).Spec(ctx)
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(_, ErrRateLimited)", err)
	}
	if !strings.Contains(buf.String(), "quick tunnel rate limited") {
		t.Errorf("no rate-limit warning logged; log output:\n%s", buf.String())
	}
}
