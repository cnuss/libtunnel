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
	"crypto/x509"
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

	"github.com/cloudflare/cloudflared/connection"
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

// TestSpecFieldSettersPatchResolvedSpec pins the overlay: WithName patches the
// field onto the spec the chain resolves.
func TestSpecFieldSettersPatchResolvedSpec(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	b := New().WithProvider(srv.URL).WithName("patched")
	spec, err := b.Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "patched" || spec.Hostname != "minted.tunneled.pizza" {
		t.Errorf("spec = %+v, want Name patched onto the resolved spec", spec)
	}
}

// TestReplayedSpecIsNotOverlaid pins the half that a replay depends on: the
// hints From sends ride the request but are never stamped back onto the
// answer, so a spec the provider substitutes arrives as the provider wrote it.
// Overlaying would hand the caller a stale id on a fresh tunnel.
func TestReplayedSpecIsNotOverlaid(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	// The hostname matches what the stub answers, so this exercises the
	// overlay rather than the substitution check.
	replayed := &Spec{ID: "stale-id", Name: "mine", Hostname: "minted.tunneled.pizza", Secret: []byte("s")}
	spec, err := From(replayed).WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID == replayed.ID {
		t.Errorf("ID = %q, want the provider's own — a replayed id must not be overlaid", spec.ID)
	}
	if spec.Hostname != "minted.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the provider's own", spec.Hostname)
	}
	_ = seen
}

// TestSpecFieldEnvBeatsCode pins per-field precedence: the
// LIBTUNNEL__CLOUDFLARE_* variable wins over the WithX setter.
func TestSpecFieldEnvBeatsCode(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareNameEnv, "from-env")

	var seen http.Header
	srv := mintServer(t, &seen)
	b := New().WithProvider(srv.URL).WithName("from-code")
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
	if !errors.Is(err, v1.ErrRejected) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRejected)", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1 (explicit-hint rejection must not retry)", got)
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
	handler := originRedirect(len(origins), newOriginProxy(origins, -1, logger, originTransport(origins)))
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
	if !errors.Is(err, v1.ErrRejected) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRejected)", err)
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

	_, err := (&QuickTunnelProvider{URL: srv.URL, Log: log}).Spec(context.Background())
	if !errors.Is(err, v1.ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRateLimited)", err)
	}
	if !strings.Contains(buf.String(), "quick tunnel rate limited") {
		t.Errorf("no rate-limit warning logged; log output:\n%s", buf.String())
	}
}

// --- reconnect lever ---

func TestEdgeWatcher(t *testing.T) {
	w := newEdgeWatcher()

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

// TestEdgeWatcherCountsAttempts pins the count the ErrEdgeUnreachable
// bound reports: every
// Reconnecting the supervisor sends before the edge is up is one failed attempt
// to reach it, and Connected events are not attempts.
func TestEdgeWatcherCountsAttempts(t *testing.T) {
	w := newEdgeWatcher()

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
		v1.ErrEdgeUnreachable, 3, v1.Budget(v1.ErrEdgeUnreachable), edgeBlockedHint)

	if !errors.Is(err, v1.ErrEdgeUnreachable) {
		t.Errorf("errors.Is(err, ErrEdgeUnreachable) = false, want true")
	}
	if !strings.Contains(err.Error(), "egress") {
		t.Errorf("Err() = %q, want the hint carried", err)
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
	b.edge = newEdgeWatcher()
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
			b.edge.up()
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

// TestWebSocketOriginRouting pins the +ws designation in the proxy (#159): a
// handshake carries no Referer and no per-tab signal of any kind, so without a
// declaration it can only be guessed at. With one, an operator-stated fact
// beats the per-browser cookie guess — but never an explicit ?n, so a page
// that carries its own index (and every iframe in a multiview panel) is
// unaffected. Non-upgrade traffic ignores the designation entirely.
func TestWebSocketOriginRouting(t *testing.T) {
	newEcho := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s|%s", name, r.URL.RawQuery)
		}))
	}
	a, b := newEcho("A"), newEcho("B")
	defer a.Close()
	defer b.Close()

	origins := []*url.URL{mustURL(t, a.URL), mustURL(t, b.URL)}
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// origins[1] owns WebSockets.
	ps := &http.Server{Handler: originRedirect(len(origins), newOriginProxy(origins, 1, logger, originTransport(origins)))}
	context.AfterFunc(ctx, func() { ps.Close() })
	go ps.Serve(l)
	base := "http://" + l.Addr().String()

	for name, tc := range map[string]struct {
		path     string
		cookie   string
		upgrade  bool
		wantBody string
	}{
		"unroutableSocketGoesToDeclaredOrigin": {path: "/hmr", upgrade: true, wantBody: "B|"},
		"declarationBeatsCookie":               {path: "/hmr", cookie: "0", upgrade: true, wantBody: "B|"},
		"explicitIndexBeatsDeclaration":        {path: "/sock?0", upgrade: true, wantBody: "A|"},
		"plainRequestIgnoresDeclaration":       {path: "/page", wantBody: "A|"},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest("GET", base+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: originCookie, Value: tc.cookie})
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
		})
	}
}

// TestUnroutableWebSocketWarns pins the diagnosis (#159): with no declaration
// and nothing to route on, the handshake still falls back to origin 0 — a
// client explicit enough to be broken by a refusal is working by luck today —
// but it says so, naming the socket and the fallback. Silence is the worst
// available failure here: the page loads, the socket connects, the app
// half-works, and the tunnel is the last thing anybody suspects.
func TestUnroutableWebSocketWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer srv.Close()
	origins := []*url.URL{mustURL(t, srv.URL), mustURL(t, srv.URL)}

	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ps := &http.Server{Handler: originRedirect(len(origins), newOriginProxy(origins, -1, logger, originTransport(origins)))}
	context.AfterFunc(ctx, func() { ps.Close() })
	go ps.Serve(l)

	req, err := http.NewRequest("GET", "http://"+l.Addr().String()+"/hmr", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := logs.String()
	if !strings.Contains(got, "/hmr") {
		t.Errorf("warning does not name the socket: %q", got)
	}
	if !strings.Contains(got, "+ws") {
		t.Errorf("warning does not name its own fix (+ws): %q", got)
	}
}

// mustURL parses a test origin URL.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// shortBudgets swaps the retry budgets for millisecond ones so a test can
// drive a loop to expiry without sleeping through the real 45 seconds. The
// seam is the package var, following the URL seam these tests already use.
func shortBudgets(t *testing.T, d time.Duration) {
	t.Helper()
	prev := budget
	budget = func(err error) time.Duration {
		if prev(err) == 0 {
			return 0
		}
		return d
	}
	t.Cleanup(func() { budget = prev })
}

// TestQuickTunnelUnreachableExpiresBudget pins the fix for #162 on the
// retryable side: a provider that never recovers stops looking like a slow
// one, and says so through a class with the cause still in the chain.
func TestQuickTunnelUnreachableExpiresBudget(t *testing.T) {
	shortBudgets(t, 100*time.Millisecond)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1,"message":"boom"}]}`)
	}))
	defer srv.Close()

	// context.Background(): the budget is the only way out, which is the
	// case the issue reported as unfixable from outside the library.
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrProviderUnreachable) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrProviderUnreachable)", err)
	}
	if !errors.Is(err, v1.ErrFailed) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrFailed)", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want the last cause still in the message", err)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("API called %d times, want at least 2 (the budget must allow a retry)", got)
	}
}

// TestQuickTunnelCertificateFailsImmediately pins the non-retryable side: the
// x509 failure from the issue report returns on the first attempt rather than
// burning a budget on a condition no retry can change.
func TestQuickTunnelCertificateFailsImmediately(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, specJSON)
	}))
	defer srv.Close()

	// The provider builds its own client, which has no reason to trust
	// httptest's throwaway CA — exactly a container with no CA bundle.
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrCertificate) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrCertificate)", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("handler reached %d times, want 0 (the handshake must fail first)", got)
	}
}

// TestQuickTunnelLongResetFailsImmediately pins that a throttle outlasting its
// own budget is reported rather than slept on: the caller can act on the reset
// now, where waiting it out would just relocate the hang.
func TestQuickTunnelLongResetFailsImmediately(t *testing.T) {
	shortBudgets(t, 100*time.Millisecond)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrRateLimited) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrRateLimited)", err)
	}
	if !strings.Contains(err.Error(), "resets in") {
		t.Errorf("err = %v, want the advertised reset in the message", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("returned after %s, want immediately (the 120s reset must not be waited out)", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1", got)
	}
}

// TestCACertPoolCarriesEmbeddedRoots pins #164: the pool libtunnel dials with
// contains the roots compiled into the binary, so a host with no
// ca-certificates package can still verify the mint and edge endpoints. Every
// embedded root is self-signed, so verifying one against the pool proves it is
// in there without reaching the network.
func TestCACertPoolCarriesEmbeddedRoots(t *testing.T) {
	pool := caCertPool()
	if pool == nil {
		t.Fatal("caCertPool() = nil")
	}
	embedded := caCerts()
	if len(embedded) == 0 {
		t.Fatal("no embedded roots parsed")
	}
	for _, root := range embedded {
		if _, err := root.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatalf("embedded root %q not in the pool: %v", root.Subject.CommonName, err)
		}
	}
}

// TestEdgeRejectionBeatsTheBudget pins the shape of the failure a caller sees.
// connect's select cannot be driven without a live edge, so this asserts the
// error the refusal branch constructs: the class, the umbrella, the edge's own
// words, and — the point of the fix — no firewall advice.
func TestEdgeRejectionBeatsTheBudget(t *testing.T) {
	b := New()
	b.edgeReject = newEdgeReject()
	b.edgeReject.fire("Unauthorized: Tunnel not found")

	err := b.credentialRejected()

	if !errors.Is(err, v1.ErrCredentialRejected) {
		t.Errorf("err = %v, want errors.Is(_, ErrCredentialRejected)", err)
	}
	if !errors.Is(err, v1.ErrFailed) {
		t.Errorf("err = %v, want errors.Is(_, ErrFailed)", err)
	}
	if errors.Is(err, v1.ErrEdgeUnreachable) {
		t.Error("a refused credential must not read as an unreachable edge")
	}
	if !strings.Contains(err.Error(), "Unauthorized: Tunnel not found") {
		t.Errorf("err = %v, want the edge's own message", err)
	}
	if strings.Contains(err.Error(), "egress") {
		t.Errorf("err = %v, want no firewall advice on a credential failure", err)
	}
	if v1.Budget(err) != 0 {
		t.Errorf("Budget = %s, want 0 (a dead credential is never retried)", v1.Budget(err))
	}
}

// TestReplayFallsBackWhenProviderUnreachable pins the offline path: a complete
// credential set still starts a process that cannot reach the mint, the way it
// did before the reclaim check existed. A dead spec then fails at the edge,
// which is the backstop, rather than failing to start at all.
func TestReplayFallsBackWhenProviderUnreachable(t *testing.T) {
	clearSpecEnv(t)
	shortBudgets(t, 50*time.Millisecond)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening now, so the mint is refused

	replayed := &Spec{ID: "id", Name: "mine", Hostname: "offline.tunneled.pizza", Secret: []byte("s")}
	spec, err := From(replayed).WithProvider("http://" + addr).Provider().Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the replayed spec when the provider cannot be reached", err)
	}
	if spec.Hostname != replayed.Hostname || spec.ID != replayed.ID {
		t.Errorf("spec = %+v, want the replayed one verbatim", spec)
	}
}

// TestReplayAdoptsASubstitutedHostname pins #175: the mint has already run by
// the time the hostname is compared, so a real tunnel exists. Refusing it
// strands that tunnel and forces the caller to mint a second one for the same
// new hostname it was being handed.
func TestReplayAdoptsASubstitutedHostname(t *testing.T) {
	clearSpecEnv(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"success":true,"result":{"id":"fresh","hostname":"substitute.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()

	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	replayed := &Spec{Name: "mine", Hostname: "gone.tunneled.pizza", Secret: []byte("s")}
	b := From(replayed).WithProvider(srv.URL)
	prov := b.Provider()
	if pl, ok := prov.(v1alpha1.LoggerSetter); ok {
		pl.SetLogger(log)
	}
	spec, err := prov.Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the substitute adopted", err)
	}
	if spec.Hostname != "substitute.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the one the provider minted", spec.Hostname)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1 — a second mint is the bug", got)
	}
	if !strings.Contains(buf.String(), "gone.tunneled.pizza") {
		t.Errorf("the hostname change was not reported; log:\n%s", buf.String())
	}
}

// TestReplayAcceptsAReplacedTunnel pins the row that must NOT be an error: the
// provider reclaims by name, so a reaped tunnel comes back as a fresh one
// behind the same hostname. The identity a caller serves on survived, and only
// the id moved.
func TestReplayAcceptsAReplacedTunnel(t *testing.T) {
	clearSpecEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":{"id":"replacement","hostname":"kept.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()

	replayed := &Spec{ID: "reaped", Name: "mine", Hostname: "kept.tunneled.pizza", Secret: []byte("s")}
	spec, err := From(replayed).WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the replacement accepted", err)
	}
	if spec.ID != "replacement" {
		t.Errorf("ID = %q, want the provider's replacement", spec.ID)
	}
	if spec.Hostname != replayed.Hostname {
		t.Errorf("Hostname = %q, want it kept", spec.Hostname)
	}
}

// TestPartialIDDoesNotOverwriteResolvedSpec pins that a resolved spec keeps the
// id whatever resolved it assigned. Overwriting it produces a spec whose id is
// not its tunnel's, which is then what LIBTUNNEL_SPEC exports for a caller to
// store and replay.
func TestPartialIDDoesNotOverwriteResolvedSpec(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := New().WithID("stale").WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID == "stale" {
		t.Errorf("ID = %q, want the id the mint assigned", spec.ID)
	}
}

// TestRecordIDResumesAHostname pins the identity a replay sends. Without it
// the provider mints a fresh record and tunnel, so a retry that drops it costs
// a tunnel per attempt.
func TestRecordIDResumesAHostname(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	replayed := &Spec{RecordID: "rec-1", Hostname: "minted.tunneled.pizza"}
	if _, err := From(replayed).WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Record-Id"); got != "rec-1" {
		t.Errorf("X-Record-Id = %q, want the replayed record", got)
	}
}

// TestFreshMintSendsNoRecord pins the other half: with nothing to resume, the
// request carries no record and the provider mints.
func TestFreshMintSendsNoRecord(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Values("X-Record-Id"); len(got) != 0 {
		t.Errorf("X-Record-Id = %v, want none", got)
	}
}

// TestRecordIDIsStoredOnTheSpec pins that the record round-trips: it comes off
// the response and onto the spec, which is what Serialize and LIBTUNNEL_SPEC
// carry, so the next process can resume with it.
func TestRecordIDIsStoredOnTheSpec(t *testing.T) {
	clearSpecEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Record-Id", "rec-from-server")
		fmt.Fprint(w, `{"success":true,"result":{"id":"t1","hostname":"minted.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.RecordID != "rec-from-server" {
		t.Errorf("RecordID = %q, want the one the provider returned", spec.RecordID)
	}
	if !strings.Contains(spec.Serialize(), "rec-from-server") {
		t.Errorf("Serialize() dropped the record: %s", spec.Serialize())
	}
}

// TestThrottledSpecWaitsForResolution pins the new contract's common case: a
// 429 carrying success:true is a complete spec whose hostname does not resolve
// yet, not a rate limit. Resuming the record is idempotent, so the wait costs
// no extra tunnel — and the retry must carry the record or it would mint one.
func TestThrottledSpecWaitsForResolution(t *testing.T) {
	clearSpecEnv(t)
	var calls atomic.Int32
	var resumed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Header.Get("X-Record-Id") == "rec-1" {
			resumed.Add(1)
		}
		w.Header().Set("X-Record-Id", "rec-1")
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		}
		fmt.Fprint(w, `{"success":true,"result":{"id":"t1","hostname":"settled.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the settled spec", err)
	}
	if spec.Hostname != "settled.tunneled.pizza" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (one unresolved, one settled)", got)
	}
	if got := resumed.Load(); got != 1 {
		t.Errorf("the retry resumed the record %d times, want 1 — without it the provider mints again", got)
	}
}

// TestThrottledFailureIsRetryable pins that a 429 carrying success:false is the
// provider's own failure with the wait it wants, not a refusal: the old
// success:false path made it terminal, which would strand a transient one.
func TestThrottledFailureIsRetryable(t *testing.T) {
	clearSpecEnv(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1002,"message":"tunnel create failed"}]}`)
			return
		}
		fmt.Fprint(w, specJSON)
	}))
	defer srv.Close()

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatalf("Spec() = %v, want the retry to succeed", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2", got)
	}
}

// TestSettleBudgetKeepsTheMintedSpec pins that a hostname which never confirms
// costs latency, not a tunnel. The provider answered with a complete spec on
// every attempt; discarding it at the budget would strand that tunnel and make
// the caller mint a second one for a hostname it already holds.
func TestSettleBudgetKeepsTheMintedSpec(t *testing.T) {
	clearSpecEnv(t)
	// Over the advertised Retry-After, so the budget expiring is what ends the
	// loop rather than the provider asking for longer than it.
	shortBudgets(t, 1500*time.Millisecond)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Record-Id", "rec-slow")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":true,"result":{"id":"t1","hostname":"slow.tunneled.pizza","account_tag":"tag","secret":"c2VjcmV0"}}`)
	}))
	defer srv.Close()

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the minted spec rather than a failure", err)
	}
	if spec.Hostname != "slow.tunneled.pizza" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
	if spec.RecordID != "rec-slow" {
		t.Errorf("RecordID = %q, want it carried so the caller can resume", spec.RecordID)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("API called %d times, want the budget to allow at least one retry", got)
	}
}

// TestNoSpecStillFails pins the other side: a provider that never produced a
// spec has nothing to hand back, so the budget expiring is a real failure.
func TestNoSpecStillFails(t *testing.T) {
	clearSpecEnv(t)
	shortBudgets(t, 100*time.Millisecond)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1001,"message":"record create failed"}]}`)
	}))
	defer srv.Close()

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); !errors.Is(err, v1.ErrRateLimited) {
		t.Fatalf("err = %v, want errors.Is(_, ErrRateLimited)", err)
	}
}

// TestEdgeProtocolDefaultsToAuto pins that libtunnel does not choose the
// transport: cloudflared knows the QUIC-to-http2 fallback and is the thing
// holding the connection when one turns out not to work.
func TestEdgeProtocolDefaultsToAuto(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeProtocolEnv, "")

	got, err := New().resolveEdgeProtocol()
	if err != nil {
		t.Fatal(err)
	}
	if got != EdgeAuto {
		t.Errorf("edge protocol = %q, want %q", got, EdgeAuto)
	}
}

// TestEdgeProtocolEnvBeatsCode pins the mirror, and that a pin survives it.
func TestEdgeProtocolEnvBeatsCode(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeProtocolEnv, "")
	got, err := New().WithEdgeProtocol(EdgeQUIC).resolveEdgeProtocol()
	if err != nil {
		t.Fatal(err)
	}
	if got != EdgeQUIC {
		t.Errorf("edge protocol = %q, want the pinned %q", got, EdgeQUIC)
	}

	t.Setenv(v1.CloudflareEdgeProtocolEnv, " http2 ")
	got, err = New().WithEdgeProtocol(EdgeQUIC).resolveEdgeProtocol()
	if err != nil {
		t.Fatal(err)
	}
	if got != EdgeHTTP2 {
		t.Errorf("edge protocol = %q, want the env value %q", got, EdgeHTTP2)
	}
}

// TestEdgeProtocolRejectsNonsense pins that a transport cloudflared cannot
// dial fails the tunnel rather than falling back quietly to auto.
func TestEdgeProtocolRejectsNonsense(t *testing.T) {
	t.Setenv(v1.CloudflareEdgeProtocolEnv, "")
	if _, err := New().WithEdgeProtocol("h2mux").resolveEdgeProtocol(); err == nil {
		t.Error("h2mux accepted in code, want it rejected")
	}

	t.Setenv(v1.CloudflareEdgeProtocolEnv, "tcp")
	if _, err := New().resolveEdgeProtocol(); err == nil {
		t.Error("tcp accepted from the env, want it rejected")
	}
}

// TestEdgeWatcherCountsDisconnects pins what the count means. The supervisor
// defers Disconnected around each serve attempt, so it fires whether or not
// that attempt connected — the number is serve attempts that ended, not live
// connections lost, which is why it cannot stand in for a refusal.
func TestEdgeWatcherCountsDisconnects(t *testing.T) {
	w := newEdgeWatcher()
	if got := w.disconnectCount(); got != 0 {
		t.Errorf("disconnects = %d, want 0", got)
	}
	w.disconnect()
	w.disconnect()
	if got := w.disconnectCount(); got != 2 {
		t.Errorf("disconnects = %d, want 2", got)
	}
	if got := w.attemptCount(); got != 0 {
		t.Errorf("attempts = %d, want disconnects not to be counted as attempts", got)
	}
}

// TestEdgeEventNames pins the log rendering, including that an event this
// build does not know is reported as itself rather than guessed at.
func TestEdgeEventNames(t *testing.T) {
	for _, tc := range []struct {
		status connection.Status
		want   string
	}{
		{connection.Connected, "connected"},
		{connection.Disconnected, "disconnected"},
		{connection.Reconnecting, "reconnecting"},
		{connection.RegisteringTunnel, "registering"},
		{connection.Unregistering, "unregistering"},
		{connection.SetURL, "set-url"},
		{connection.Status(99), "status(99)"},
	} {
		if got := edgeEventName(tc.status); got != tc.want {
			t.Errorf("edgeEventName(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}
