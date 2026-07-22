package cloudflare_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
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

	conn := v1alpha1.New(cloudflare.New()).WithListener(l)
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

	b := cloudflare.New()
	b.WithTLS(false).WithHTTP2(true) // both lose: env fixed the knobs

	if !b.TLS() {
		t.Error("TLS = false; want the LIBTUNNEL_TLS=true value to stick over WithTLS(false)")
	}
	if b.HTTP2() {
		t.Error("HTTP2 = true; want the LIBTUNNEL_HTTP2=false value to stick over WithHTTP2(true)")
	}
	if err := b.EnvErr(); err != nil {
		t.Errorf("EnvErr = %v, want nil", err)
	}
}

// TestEnvKnobsUnsetLeaveCodeInCharge pins the fallthrough: without the env
// vars the mutators work exactly as before.
func TestEnvKnobsUnsetLeaveCodeInCharge(t *testing.T) {
	t.Setenv(v1.TLSEnv, "")
	t.Setenv(v1.HTTP2Env, "")

	b := cloudflare.New()
	b.WithTLS(true).WithHTTP2(true)

	if !b.TLS() || !b.HTTP2() {
		t.Errorf("TLS/HTTP2 = %v/%v after WithTLS(true).WithHTTP2(true) with no env, want true/true", b.TLS(), b.HTTP2())
	}
}

// TestEnvFixesStreamingLevers pins env-beats-code for the Cloudflare streaming
// levers: LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL / _PADDING fix the knobs at
// construction and WithFlushInterval / WithPadding become no-ops.
func TestEnvFixesStreamingLevers(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "500ms")
	t.Setenv(v1.CloudflarePaddingEnv, "false")

	b := cloudflare.New()
	b.WithFlushInterval(5 * time.Second) // loses: env fixed 500ms
	b.WithPadding()                      // loses: env fixed padding=false

	if got := b.FlushInterval(); got == nil || *got != 500*time.Millisecond {
		t.Errorf("FlushInterval = %v, want the LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL=500ms value to stick over WithFlushInterval(5s)", got)
	}
	if b.Padding() {
		t.Error("Padding = true; want the LIBTUNNEL__CLOUDFLARE_PADDING=false value to stick over WithPadding()")
	}
	if err := b.EnvErr(); err != nil {
		t.Errorf("EnvErr = %v, want nil", err)
	}
}

// TestStreamingLeversUnsetLeaveCodeInCharge pins the fallthrough: without the
// env vars the mutators work exactly as written.
func TestStreamingLeversUnsetLeaveCodeInCharge(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "")
	t.Setenv(v1.CloudflarePaddingEnv, "")

	b := cloudflare.New().WithFlushInterval(2 * time.Second)
	b.WithPadding()

	if got := b.FlushInterval(); got == nil || *got != 2*time.Second {
		t.Errorf("FlushInterval = %v, want 2s from code", got)
	}
	if !b.Padding() {
		t.Error("Padding = false after WithPadding() with no env, want true")
	}
}

// TestFlushIntervalEnvUnparsableSetsEnvErr pins loud failure for a bad duration
// override: New records the parse error, which connect later surfaces (as
// TestEnvKnobUnparsableFailsConnect proves for the bool knobs).
func TestFlushIntervalEnvUnparsableSetsEnvErr(t *testing.T) {
	t.Setenv(v1.CloudflareFlushIntervalEnv, "banana")

	if err := cloudflare.New().EnvErr(); err == nil || !strings.Contains(err.Error(), v1.CloudflareFlushIntervalEnv) {
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

	b := cloudflare.From(&cloudflare.Spec{ID: "id", Hostname: "pinned.trycloudflare.com"}).WithName("patched")
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

	b := cloudflare.From(&cloudflare.Spec{Hostname: "pinned.trycloudflare.com"}).WithName("from-code")
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
	spec, err := cloudflare.New().Provider().Spec(ctx)
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

	_, err := cloudflare.From(&cloudflare.Spec{Hostname: "pinned.trycloudflare.com"}).Provider().Spec(context.Background())
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
	spec, err := cloudflare.New().WithApiURL("http://127.0.0.1:1/nope").Provider().Spec(ctx)
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

	conn := v1alpha1.New(cloudflare.New()).WithListener(l)
	select {
	case <-conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not fail on an unparsable LIBTUNNEL_TLS")
	}
	if err := conn.Err(); err == nil || !strings.Contains(err.Error(), v1.TLSEnv) {
		t.Errorf("Err() = %v, want a %s parse cause", err, v1.TLSEnv)
	}
}
