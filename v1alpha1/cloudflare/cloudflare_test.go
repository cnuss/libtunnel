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

	"github.com/cloudflare/cloudflared/supervisor"

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

// clearSpecEnv scrubs the credential-chain env vars so a test resolves
// exactly the channel it stages.
func clearSpecEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{v1.SpecEnv, v1.FromEnv, v1.CloudflareIDEnv, v1.CloudflareNameEnv,
		v1.CloudflareHostnameEnv, v1.CloudflareAccountTagEnv, v1.CloudflareSecretEnv,
		v1.CloudflareProviderEnv, v1.CloudflareHeadersEnv} {
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
	t.Setenv(v1.CloudflareProviderEnv, "http://127.0.0.1:1/nope")

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

// TestProviderEnvBeatsCode pins WithProvider and its env mirror: the mint hits
// the env endpoint, not the code one (which would hang the test in retries). A
// full URL (with scheme) is honored verbatim — the escape hatch that lets the
// mint point at this mock server.
func TestProviderEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"minted.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()
	t.Setenv(v1.CloudflareProviderEnv, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := New().WithProvider("http://127.0.0.1:1/nope").Provider().Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "minted.trycloudflare.com" {
		t.Errorf("Hostname = %q, want the spec minted from the env endpoint", spec.Hostname)
	}
}

// mintServer returns a mock quick-tunnel endpoint that records the request
// headers it saw and mints a canned spec.
func mintServer(t *testing.T, seen *http.Header) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		fmt.Fprint(w, `{"success":true,"result":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"minted.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWithHeaderSentToMint pins WithHeader: the added header reaches the mint
// request, and the deliberate defaults (Content-Type, User-Agent) still stand.
func TestWithHeaderSentToMint(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithProvider(srv.URL).WithHeader("X-Opaque", "true").Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Opaque"); got != "true" {
		t.Errorf("X-Opaque = %q, want %q", got, "true")
	}
	if seen.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want the default to stand", seen.Get("Content-Type"))
	}
	if !strings.HasPrefix(seen.Get("User-Agent"), "cloudflared/") {
		t.Errorf("User-Agent = %q, want the cloudflared default", seen.Get("User-Agent"))
	}
}

// TestWithHeaderOverridesDefault pins that a caller header replaces the default
// for its key (User-Agent here), rather than adding a second value.
func TestWithHeaderOverridesDefault(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithProvider(srv.URL).WithHeader("User-Agent", "tush/1").Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Values("User-Agent"); len(got) != 1 || got[0] != "tush/1" {
		t.Errorf("User-Agent = %v, want exactly [tush/1] (caller replaces the default)", got)
	}
}

// TestHeadersEnvBeatsCode pins the env mirror: LIBTUNNEL__CLOUDFLARE_HEADERS
// entries replace the code value per key and add new ones.
func TestHeadersEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)
	t.Setenv(v1.CloudflareHeadersEnv, "X-Opaque=false, X-Extra=1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithProvider(srv.URL).WithHeader("X-Opaque", "true").Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Opaque"); got != "false" {
		t.Errorf("X-Opaque = %q, want the env value to beat code", got)
	}
	if got := seen.Get("X-Extra"); got != "1" {
		t.Errorf("X-Extra = %q, want the env-only header added", got)
	}
}

// TestWithEdgePinsAddresses pins WithEdge: the addresses are carried through to
// the supervisor's static-edge list, which bypasses SRV discovery (and with it
// Cloudflare's port 7844) so a relay on an allowed port can be dialed instead.
func TestWithEdgePinsAddresses(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeEnv, "")

	b := New().WithEdge("relay.example:443", "relay2.example:443")
	got := edgeAddresses(b.edgeAddrs)
	if len(got) != 2 || got[0] != "relay.example:443" || got[1] != "relay2.example:443" {
		t.Errorf("edge addrs = %v, want both pinned addresses", got)
	}
	if edgeAddresses(nil) != nil {
		t.Error("unset must stay empty so the edge is discovered by SRV")
	}
}

// TestEdgeEnvBeatsCode pins the env mirror: LIBTUNNEL__CLOUDFLARE_EDGE replaces
// the code value wholesale (it is one list, not a per-entry merge) and tolerates
// whitespace around the commas.
func TestEdgeEnvBeatsCode(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeEnv, " env1.example:443 , env2.example:443 ")

	got := edgeAddresses([]string{"code.example:443"})
	if len(got) != 2 || got[0] != "env1.example:443" || got[1] != "env2.example:443" {
		t.Errorf("edge addrs = %v, want the env list to replace the code value", got)
	}
}

// TestProviderHostSynthesizesEndpoint pins the bare-host → https://host/tunnel
// synthesis and the verbatim passthrough for a scheme-carrying value.
func TestProviderHostSynthesizesEndpoint(t *testing.T) {
	if got := providerEndpoint("api.trycloudflare.com"); got != "https://api.trycloudflare.com/tunnel" {
		t.Errorf("providerEndpoint(host) = %q, want the synthesized https/…/tunnel URL", got)
	}
	if got := providerEndpoint("http://127.0.0.1:8080/tunnel"); got != "http://127.0.0.1:8080/tunnel" {
		t.Errorf("providerEndpoint(url) = %q, want it verbatim", got)
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
func mustProxy(t *testing.T, ctx context.Context, srv *httptest.Server) string {
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
	ps := &http.Server{Handler: newOriginProxy(origin, logger, originTransport(origin))}
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

	base := mustProxy(t, ctx, srv)

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
// response (the kube-watch shape) is proxied straight through: every event
// arrives, in order. This is a single straight stream through the reverse proxy.
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

	base := mustProxy(t, ctx, srv)

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

// --- reconnect lever ---

func TestEdgeUpWatcher(t *testing.T) {
	w := newEdgeUpWatcher()

	gen, ch := w.generation()
	if gen != 0 {
		t.Fatalf("initial generation = %d, want 0", gen)
	}
	select {
	case <-ch:
		t.Fatal("generation channel closed before any up()")
	default:
	}

	w.up()
	select {
	case <-ch:
	default:
		t.Fatal("generation channel not closed after up()")
	}

	gen2, ch2 := w.generation()
	if gen2 != 1 {
		t.Fatalf("generation after up() = %d, want 1", gen2)
	}
	if ch2 == ch {
		t.Fatal("generation channel not swapped after up()")
	}
}

func TestReconnectBeforeConnect(t *testing.T) {
	if err := New().Reconnect(context.Background()); err == nil {
		t.Fatal("Reconnect before connect: want error, got nil")
	}
}

// wireReconnect gives a Backend the runtime state connect() would set, without
// a real supervisor.
func wireReconnect(tunnelCtx context.Context) *Backend {
	b := New()
	b.reconnected = make(chan supervisor.ReconnectSignal)
	b.edgeUp = newEdgeUpWatcher()
	b.reconnectCtx = tunnelCtx
	return b
}

func TestReconnectCyclesAndWaits(t *testing.T) {
	b := wireReconnect(context.Background())

	// Stand in for the supervisor: receive each ReconnectSignal, then report a
	// Connected — exactly what one cycled edge conn does.
	served := make(chan struct{})
	go func() {
		for range haConnections {
			<-b.reconnected
			b.edgeUp.up()
		}
		close(served)
	}()

	if err := b.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("fake supervisor did not receive haConnections signals")
	}
}

func TestReconnectContextCanceled(t *testing.T) {
	b := wireReconnect(context.Background()) // no receiver on b.reconnected

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Reconnect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconnect with canceled ctx: err = %v, want context.Canceled", err)
	}
}

func TestReconnectTunnelShutdown(t *testing.T) {
	tctx, tcancel := context.WithCancel(context.Background())
	b := wireReconnect(tctx) // no receiver on b.reconnected
	tcancel()                // tunnel torn down while a caller waits

	// Caller passes a live ctx; the tunnel-context guard must still unblock.
	if err := b.Reconnect(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconnect after tunnel shutdown: err = %v, want context.Canceled", err)
	}
}
