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
	"os"
	"path/filepath"
	"slices"
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
	t.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"id":"not-a-uuid","hostname":"x.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)

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

// TestMain redirects the spec cache to a throwaway: chain mints cache their
// specs there, and QuickTunnelProvider reads its latest.spec.json for reclaim
// hints — neither may touch (or see) a real user cache.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "libtunnel-cache")
	if err != nil {
		panic(err)
	}
	os.Setenv(v1.CacheDirEnv, dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// clearSpecEnv scrubs the credential-chain env vars so a test resolves
// exactly the channel it stages, and points the spec cache at a per-test
// directory so one test's latest.spec.json never seeds another's mint.
func clearSpecEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{v1.SpecEnv, v1.FromEnv, v1.CloudflareIDEnv, v1.CloudflareNameEnv,
		v1.CloudflareHostnameEnv, v1.CloudflareAccountTagEnv, v1.CloudflareSecretEnv,
		v1.CloudflareProviderEnv, v1.CloudflareHeadersEnv} {
		t.Setenv(v, "")
	}
	t.Setenv(v1.CacheDirEnv, t.TempDir())
}

// writeLatestSpec seeds the test-scoped cache dir with a latest.spec.json,
// as a previous run's mint would have.
func writeLatestSpec(t *testing.T, spec *Spec) {
	t.Helper()
	path := filepath.Join(os.Getenv(v1.CacheDirEnv), "latest.spec.json")
	if err := os.WriteFile(path, []byte(spec.Serialize()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSpecFieldSettersPatchResolvedSpec pins the overlay: WithName patches
// the field onto the spec the chain resolves (here a code-pinned one).
func TestSpecFieldSettersPatchResolvedSpec(t *testing.T) {
	clearSpecEnv(t)

	b := From(&Spec{ID: "id", Hostname: "pinned.tunneled.pizza"}).WithName("patched")
	spec, err := b.Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "patched" || spec.Hostname != "pinned.tunneled.pizza" {
		t.Errorf("spec = %+v, want Name patched onto the pinned spec", spec)
	}
}

// TestSpecFieldEnvBeatsCode pins per-field precedence: the
// LIBTUNNEL__CLOUDFLARE_* variable wins over the WithX setter.
func TestSpecFieldEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareNameEnv, "from-env")

	b := From(&Spec{Hostname: "pinned.tunneled.pizza"}).WithName("from-code")
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
	t.Setenv(v1.CloudflareHostnameEnv, "fields.tunneled.pizza")
	t.Setenv(v1.CloudflareAccountTagEnv, "tag")
	t.Setenv(v1.CloudflareSecretEnv, "c2VjcmV0")
	t.Setenv(v1.CloudflareProviderEnv, "http://127.0.0.1:1/nope")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := New().Provider().Spec(ctx)
	if err != nil {
		t.Fatalf("Spec() = %v; a complete field set must not mint", err)
	}
	if spec.Hostname != "fields.tunneled.pizza" || spec.AccountTag != "tag" || string(spec.Secret) != "secret" {
		t.Errorf("spec = %+v, want the env field set verbatim", spec)
	}
}

// TestSecretEnvUndecodableErrors pins loud failure for a bad secret override.
func TestSecretEnvUndecodableErrors(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareSecretEnv, "%%%not-base64%%%")

	_, err := From(&Spec{Hostname: "pinned.tunneled.pizza"}).Provider().Spec(context.Background())
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
		fmt.Fprint(w, `{"success":true,"result":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"minted.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()
	t.Setenv(v1.CloudflareProviderEnv, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := New().WithProvider("http://127.0.0.1:1/nope").Provider().Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "minted.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the spec minted from the env endpoint", spec.Hostname)
	}
}

// mintServer returns a mock quick-tunnel endpoint that records the request
// headers it saw and mints a canned spec.
func mintServer(t *testing.T, seen *http.Header) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		fmt.Fprint(w, `{"success":true,"result":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"minted.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
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

// TestReclaimHintsSentToMint pins the reclaim hints: spec fields known before
// minting ride the request as X-Id / X-Name / X-Secret (base64), so a
// provider that reaps idle tunnels can hand the matching tunnel back.
func TestReclaimHintsSentToMint(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := New().WithID("id-1").WithName("pizza-1").WithSecret([]byte("secret")).WithProvider(srv.URL)
	if _, err := b.Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Id"); got != "id-1" {
		t.Errorf("X-Id = %q, want %q", got, "id-1")
	}
	if got := seen.Get("X-Name"); got != "pizza-1" {
		t.Errorf("X-Name = %q, want %q", got, "pizza-1")
	}
	if got := seen.Get("X-Secret"); got != "c2VjcmV0" {
		t.Errorf("X-Secret = %q, want %q (base64)", got, "c2VjcmV0")
	}
}

// TestReclaimHintsAbsentByDefault pins the quiet default: a mint with no spec
// fields set carries no reclaim hints.
func TestReclaimHintsAbsentByDefault(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithProvider(srv.URL).Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"X-Id", "X-Name", "X-Secret"} {
		if _, ok := seen[k]; ok {
			t.Errorf("%s = %q, want absent", k, seen.Get(k))
		}
	}
}

// TestReclaimHintEnvBeatsCode pins the mirror precedence inside the hints:
// LIBTUNNEL__CLOUDFLARE_NAME beats WithName in the X-Name hint, matching the
// field overlay's precedence.
func TestReclaimHintEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)
	t.Setenv(v1.CloudflareNameEnv, "env-name")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithName("code-name").WithProvider(srv.URL).Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Name"); got != "env-name" {
		t.Errorf("X-Name = %q, want the env value to beat code", got)
	}
}

// TestWithHeaderBeatsReclaimHint pins the layer order: an explicit WithHeader
// for a hint key replaces the hint.
func TestWithHeaderBeatsReclaimHint(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := New().WithID("id-1").WithProvider(srv.URL).WithHeader("X-Id", "explicit")
	if _, err := b.Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Values("X-Id"); len(got) != 1 || got[0] != "explicit" {
		t.Errorf("X-Id = %v, want exactly [explicit] (WithHeader beats the hint)", got)
	}
}

// TestCachedSpecSeedsReclaimHints pins the latest.spec.json seed (#142): a
// bare provider's mint carries the cached spec's fields as X-Id / X-Name /
// X-Secret — hints for backend-driven reclamation, never credentials.
func TestCachedSpecSeedsReclaimHints(t *testing.T) {
	clearSpecEnv(t)
	writeLatestSpec(t, &Spec{ID: "cached-id", Name: "cached-name", Hostname: "cached.tunneled.pizza", Secret: []byte("secret")})
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Id"); got != "cached-id" {
		t.Errorf("X-Id = %q, want the cached spec's id", got)
	}
	if got := seen.Get("X-Name"); got != "cached-name" {
		t.Errorf("X-Name = %q, want the cached spec's name", got)
	}
	if got := seen.Get("X-Secret"); got != "c2VjcmV0" {
		t.Errorf("X-Secret = %q, want the cached spec's secret (base64)", got)
	}
}

// TestExplicitHintBeatsCachedSpec pins the layering: an explicit spec-field
// setter owns its hint key, and the cache fills only the keys left unset.
func TestExplicitHintBeatsCachedSpec(t *testing.T) {
	clearSpecEnv(t)
	writeLatestSpec(t, &Spec{ID: "cached-id", Name: "cached-name", Hostname: "cached.tunneled.pizza"})
	var seen http.Header
	srv := mintServer(t, &seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New().WithID("explicit").WithProvider(srv.URL).Provider().Spec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Id"); got != "explicit" {
		t.Errorf("X-Id = %q, want the explicit WithID value over the cache", got)
	}
	if got := seen.Get("X-Name"); got != "cached-name" {
		t.Errorf("X-Name = %q, want the cache to fill the key WithID left unset", got)
	}
}

// TestCachedHintRejectionMintsFresh pins the fall-through (#142): a mint
// rejected while carrying cache-derived hints retries once, immediately,
// without them — the backend judged the reclaim, not a fresh mint.
func TestCachedHintRejectionMintsFresh(t *testing.T) {
	clearSpecEnv(t)
	writeLatestSpec(t, &Spec{ID: "cached-id", Hostname: "cached.tunneled.pizza"})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Id") != "" {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1,"message":"tunnel not reclaimable"}]}`)
			return
		}
		fmt.Fprint(w, specJSON)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (reclaim refused, one hint-less retry)", got)
	}
	if spec.Hostname != "test.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the fresh mint's", spec.Hostname)
	}
}

// TestExplicitHintRejectionStaysTerminal pins that only cache-derived hints
// soften a rejection: with the hints coming from an explicit setter, a
// refusal is the API's definitive no, exactly as before #142.
func TestExplicitHintRejectionStaysTerminal(t *testing.T) {
	clearSpecEnv(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := New().WithID("explicit").WithProvider(srv.URL).Provider().Spec(ctx)
	if !errors.Is(err, ErrMintRejected) {
		t.Errorf("err = %v, want errors.Is(_, ErrMintRejected)", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1 (explicit-hint rejection must not retry)", got)
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
}

// TestEdgeDefaultsToTheRegions pins that the edge is never discovered by SRV:
// unset falls back to the regions that lookup would have returned, so starting a
// tunnel does not depend on an SRV query succeeding on the machine's resolver.
func TestEdgeDefaultsToTheRegions(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeEnv, "")

	got := edgeAddresses(nil)
	if !slices.Equal(got, defaultEdgeAddrs) {
		t.Errorf("edge addrs = %v, want the defaults %v", got, defaultEdgeAddrs)
	}
	for _, addr := range got {
		if _, port, err := net.SplitHostPort(addr); err != nil || port != "7844" {
			t.Errorf("default edge addr %q: want host:7844", addr)
		}
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
	if got := providerEndpoint("tunnel.pizza"); got != "https://tunnel.pizza/tunnel" {
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
	t.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"id":"3f1f9a3e-2f2a-4d59-a711-e57e2fc1c3a6","hostname":"x.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)

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

// mustProxy interposes the reverse-proxy shim in front of the origin servers
// (multiple origins get the ?n routing behavior) and returns the http:// base
// URL a client dials.
func mustProxy(t *testing.T, ctx context.Context, srvs ...*httptest.Server) string {
	t.Helper()
	origins := make([]*url.URL, len(srvs))
	for i, srv := range srvs {
		origin, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatalf("parse origin url: %v", err)
		}
		origins[i] = origin
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := originRedirect(len(origins), newOriginProxy(origins, logger, originTransport(origins)))
	ps := &http.Server{Handler: handler}
	context.AfterFunc(ctx, func() { ps.Close() })
	go ps.Serve(l)
	return "http://" + l.Addr().String()
}

// TestMultiOriginRouting pins the multi-URL routing contract on the reverse
// proxy: a bare numeric query param (?n, empty value) routes the request to
// origins[n] and sets the sticky cookie; the sticky cookie routes param-less
// requests; the routing param never reaches the origin; anything out of
// range, non-numeric, or carrying a value falls through to origins[0].
func TestMultiOriginRouting(t *testing.T) {
	newEcho := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s|%s", name, r.URL.RawQuery)
		}))
	}
	a, b := newEcho("A"), newEcho("B")
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := mustProxy(t, ctx, a, b)

	for name, tc := range map[string]struct {
		path     string
		cookie   string // inbound sticky cookie value; "" = none
		referer  string // Referer header; a bare path is prefixed with base
		dest     string // Sec-Fetch-Dest header; "" = not sent
		upgrade  bool   // send a WebSocket handshake's Upgrade/Connection pair
		wantBody string // "<origin name>|<forwarded raw query>"
		wantSet  string // expected Set-Cookie value; "" = no Set-Cookie
	}{
		"naked":                  {path: "/", wantBody: "A|"},
		"explicitSecond":         {path: "/?1", wantBody: "B|", wantSet: "1"},
		"explicitKeepsOthers":    {path: "/?1&x=y", wantBody: "B|x=y", wantSet: "1"},
		"valuedParamNotRouting":  {path: "/?1=foo", wantBody: "A|1=foo"},
		"nonNumericNotRouting":   {path: "/?abc", wantBody: "A|abc"},
		"stickyCookie":           {path: "/", cookie: "1", wantBody: "B|"},
		"explicitBeatsCookie":    {path: "/?0", cookie: "1", wantBody: "A|", wantSet: "0"},
		"outOfRangeFallsBack":    {path: "/?9", wantBody: "A|", wantSet: "0"},
		"garbageCookieFallsBack": {path: "/", cookie: "x", wantBody: "A|"},

		// Referer routing: a same-host referer whose query carries the bare
		// parameter routes the request — an iframe's (or page's) subresources
		// follow their document URL without touching the shared cookie.
		"refererRoutesSubresource": {path: "/asset.js", referer: "/?1", wantBody: "B|"},
		"refererBeatsCookie":       {path: "/", cookie: "0", referer: "/?1", wantBody: "B|"},
		"paramBeatsReferer":        {path: "/?0", referer: "/?1", wantBody: "A|", wantSet: "0"},
		"crossHostRefererIgnored":  {path: "/", referer: "https://evil.example/?1", wantBody: "A|"},
		"valuedRefererNotRouting":  {path: "/", referer: "/?1=foo", wantBody: "A|"},

		// The sticky cookie is a top-level concern: an explicit pick inside an
		// iframe must not churn the tab-wide jar (two side-by-side iframes
		// would fight over it).
		"iframeExplicitNoSticky":   {path: "/?1", dest: "iframe", wantBody: "B|"},
		"documentExplicitStickies": {path: "/?1", dest: "document", wantBody: "B|", wantSet: "1"},

		// A WebSocket handshake carries no Sec-Fetch-Dest at all, which the
		// sticky-cookie branch used to read as "a top-level navigation" (the
		// empty case is there for curl and pre-2020 browsers). A socket is
		// not a navigation: it must route on its own ?n but leave the
		// tab-wide cookie alone, or the last socket to connect re-pins every
		// later parameter-less request (#159).
		"websocketExplicitNoSticky": {path: "/sock?1", upgrade: true, wantBody: "B|"},
		"websocketFollowsCookie":    {path: "/sock", cookie: "1", upgrade: true, wantBody: "B|"},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest("GET", base+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: originCookie, Value: tc.cookie})
			}
			if tc.referer != "" {
				ref := tc.referer
				if !strings.HasPrefix(ref, "http") {
					ref = base + ref
				}
				req.Header.Set("Referer", ref)
			}
			if tc.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", tc.dest)
			}
			if tc.upgrade {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
			gotSet := ""
			for _, c := range resp.Cookies() {
				if c.Name == originCookie {
					gotSet = c.Value
				}
			}
			if gotSet != tc.wantSet {
				t.Errorf("Set-Cookie %s = %q, want %q", originCookie, gotSet, tc.wantSet)
			}
		})
	}
}

// TestMultiOriginRedirect pins the canonicalizing redirect that defends
// referer routing against decay: a GET document/iframe navigation with no
// routing parameter of its own but a same-host referer that carries one is
// answered 307 to the same URL plus that parameter — the new document's URL
// re-pins the origin, so its own subresources keep routing. Everything else
// passes through to the proxy.
func TestMultiOriginRedirect(t *testing.T) {
	newEcho := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s|%s", name, r.URL.RawQuery)
		}))
	}
	a, b := newEcho("A"), newEcho("B")
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := mustProxy(t, ctx, a, b)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	for name, tc := range map[string]struct {
		method       string
		path         string
		referer      string // bare path, prefixed with base
		dest         string
		wantStatus   int
		wantLocation string // when redirected
		wantBody     string // when proxied
	}{
		"iframeNavRedirects":   {method: "GET", path: "/page2?x=y", referer: "/?1", dest: "iframe", wantStatus: 307, wantLocation: "/page2?x=y&1"},
		"documentNavRedirects": {method: "GET", path: "/page2", referer: "/?1", dest: "document", wantStatus: 307, wantLocation: "/page2?1"},
		"zeroIndexRedirects":   {method: "GET", path: "/page2", referer: "/?0", dest: "iframe", wantStatus: 307, wantLocation: "/page2?0"},
		"explicitNoRedirect":   {method: "GET", path: "/page2?x=y&1", referer: "/?0", dest: "document", wantStatus: 200, wantBody: "B|x=y"},
		"noDestNoRedirect":     {method: "GET", path: "/page2?x=y", referer: "/?1", dest: "", wantStatus: 200, wantBody: "B|x=y"},
		"postNoRedirect":       {method: "POST", path: "/submit", referer: "/?1", dest: "document", wantStatus: 200, wantBody: "B|"},
		"noRefererNoRedirect":  {method: "GET", path: "/page2", referer: "", dest: "document", wantStatus: 200, wantBody: "A|"},

		// A path opening "//" (or the backslash variant browsers normalize to
		// it) would echo into Location as a scheme-relative absolute URL — an
		// open redirect. Those navigations proxy un-canonicalized instead.
		"schemeRelativeNoRedirect": {method: "GET", path: "//evil.example/x", referer: "/?1", dest: "document", wantStatus: 200, wantBody: "B|"},
		"backslashNoRedirect":      {method: "GET", path: "/\\evil.example/x", referer: "/?1", dest: "document", wantStatus: 200, wantBody: "B|"},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, base+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", base+tc.referer)
			}
			if tc.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", tc.dest)
			}
			resp, err := noFollow.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantLocation != "" {
				if got := resp.Header.Get("Location"); got != tc.wantLocation {
					t.Errorf("Location = %q, want %q", got, tc.wantLocation)
				}
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}

// TestSingleOriginIgnoresRoutingParams pins the single-URL fast path: no
// query inspection, no cookie — a bare numeric param is application data and
// forwards verbatim, exactly the pre-multi-URL behavior.
func TestSingleOriginIgnoresRoutingParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "solo|%s", r.URL.RawQuery)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := mustProxy(t, ctx, srv)

	// A navigation-shaped request (referer + Sec-Fetch-Dest) must not trigger
	// the canonicalizing redirect either — single origin has no routing at all.
	req, err := http.NewRequest("GET", base+"/?1&x=y", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Referer", base+"/?1")
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "solo|1&x=y" {
		t.Errorf("body = %q, want %q (query forwarded verbatim)", body, "solo|1&x=y")
	}
	for _, c := range resp.Cookies() {
		if c.Name == originCookie {
			t.Errorf("unexpected Set-Cookie %s=%s on a single-origin proxy", c.Name, c.Value)
		}
	}
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
	"hostname":"test.tunneled.pizza",
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
	if spec.Hostname != "test.tunneled.pizza" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
	if string(spec.Secret) != "secret" {
		t.Errorf("Secret = %q, want base64-decoded %q", spec.Secret, "secret")
	}
}

// TestQuickTunnelHonorsProviderEnv pins the env mirror on the direct provider
// path: v1.CloudflareProviderEnv names the mint host for a QuickTunnelProvider
// constructed on its own, exactly as it does for one the Backend builds — the
// endpoint is synthesized from the host, and a value carrying a scheme is used
// verbatim. An explicitly set URL is the test seam and still wins.
func TestQuickTunnelHonorsProviderEnv(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/tunnel" {
			t.Errorf("path = %q, want /tunnel (synthesized from the host)", r.URL.Path)
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	// The env value carries a scheme, so it is used verbatim — minus the
	// path, which the provider appends.
	t.Setenv(v1.CloudflareProviderEnv, srv.URL+"/tunnel")
	if _, err := QuickTunnel().Spec(context.Background()); err != nil {
		t.Fatalf("Spec with %s set: %v", v1.CloudflareProviderEnv, err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("env endpoint called %d times, want 1", got)
	}

	// An explicit URL is the seam callers and tests set directly; it wins
	// over the environment.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(specJSON))
	}))
	defer other.Close()
	if _, err := (&QuickTunnelProvider{URL: other.URL}).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("env endpoint called %d times after an explicit URL, want 1", got)
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
	if spec.Hostname != "test.tunneled.pizza" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
}

// TestQuickTunnelHonorsRetryAfterSeconds pins that a 429's Retry-After wins
// over the linear ramp: with Retry-After: 2, the retry waits ~2s where the
// ramp alone would have retried after 1s.
func TestQuickTunnelHonorsRetryAfterSeconds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	start := time.Now()
	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond {
		t.Errorf("retried after %s, want ~2s (Retry-After honored over the 1s ramp)", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2", got)
	}
}

// TestQuickTunnelHonorsRetryAfterDate pins the RFC 7231 HTTP-date form of
// Retry-After: a date ~3s out delays the retry past the 1s ramp.
func TestQuickTunnelHonorsRetryAfterDate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", time.Now().Add(3*time.Second).UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	start := time.Now()
	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The date form truncates to whole seconds, so ~3s out is at least ~2s.
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Errorf("retried after %s, want the HTTP-date wait honored over the 1s ramp", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2", got)
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

// TestEdgeUpWatcherCountsAttempts pins the count edgeTimeout reports: every
// Reconnecting the supervisor sends before the edge is up is one failed attempt
// to reach it, and Connected events are not attempts.
func TestEdgeUpWatcherCountsAttempts(t *testing.T) {
	w := newEdgeUpWatcher()

	if got := w.attemptCount(); got != 0 {
		t.Fatalf("initial attemptCount() = %d, want 0", got)
	}

	w.attempt()
	w.attempt()
	w.up()

	if got := w.attemptCount(); got != 2 {
		t.Errorf("attemptCount() = %d, want 2", got)
	}
}

// TestEdgeUnreachableWrapsSentinel pins the error a caller matches on: the
// timeout reports v1.ErrEdgeUnreachable, and carries cloudflared's own
// diagnosis of a blocked egress port — which cloudflared logs at a level the
// tunnel's default logger discards.
func TestEdgeUnreachableWrapsSentinel(t *testing.T) {
	err := fmt.Errorf("%w: no connection after %d attempts in %s: %s",
		v1.ErrEdgeUnreachable, 3, edgeTimeout, edgeBlockedHint)

	if !errors.Is(err, v1.ErrEdgeUnreachable) {
		t.Errorf("errors.Is(err, ErrEdgeUnreachable) = false, want true")
	}
	if !strings.Contains(err.Error(), "7844") {
		t.Errorf("Err() = %q, want the blocked port named", err)
	}
	if !strings.Contains(err.Error(), "WithEdge") {
		t.Errorf("Err() = %q, want the WithEdge way around it", err)
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
