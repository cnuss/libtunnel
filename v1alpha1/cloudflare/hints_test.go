package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// known is a spec with every field set, so one assertion covers every hint
// header the mint request carries.
var known = &Spec{
	RecordID:   "rec-1",
	ID:         "id-1",
	Name:       "name-1",
	Hostname:   "known.tunneled.pizza",
	AccountTag: "tag-1",
	Secret:     []byte("secret-1"),
}

func envelope(t *testing.T, spec *Spec) string {
	t.Helper()
	out, err := v1alpha1.EncodeSpec("cloudflare", spec)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// echoServer is a stub mint that answers with exactly what it was hinted, the
// way the real provider does while the reservation holds — for tests that
// need a specific spec to come back, corrupt fields included.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Secret"))
		body, _ := json.Marshal(&Spec{
			ID:         r.Header.Get("X-Id"),
			Name:       r.Header.Get("X-Name"),
			Hostname:   r.Header.Get("X-Hostname"),
			AccountTag: r.Header.Get("X-Account-Tag"),
			Secret:     secret,
		})
		fmt.Fprintf(w, `{"success":true,"result":%s}`, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wantHints asserts the mint request carried want, field by field, as the
// hint headers.
func wantHints(t *testing.T, seen http.Header, want *Spec) {
	t.Helper()
	for header, value := range map[string]string{
		"X-Record-Id":   want.RecordID,
		"X-Id":          want.ID,
		"X-Name":        want.Name,
		"X-Hostname":    want.Hostname,
		"X-Account-Tag": want.AccountTag,
		"X-Secret":      base64.StdEncoding.EncodeToString(want.Secret),
	} {
		if got := seen.Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

// wantMinted asserts the resolved spec is the stub provider's answer, not
// the hint handed back.
func wantMinted(t *testing.T, spec *Spec) {
	t.Helper()
	if spec.Hostname != "minted.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the provider's answer", spec.Hostname)
	}
}

// TestAdoptedSpecMintsWithHints pins the handoff: LIBTUNNEL_SPEC is not a
// spec to serve, it is what the process knows about the tunnel, and it rides
// the mint request for the provider to honor or not.
func TestAdoptedSpecMintsWithHints(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.SpecEnv, envelope(t, known))
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("mint never called; an adopted spec must still mint")
	}
	wantHints(t, seen, known)
	wantMinted(t, spec)
}

// TestFromEnvMintsWithHints pins LIBTUNNEL_FROM to the same rule: it is
// From's env mirror, and From mints.
func TestFromEnvMintsWithHints(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.FromEnv, envelope(t, known))
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("mint never called; a LIBTUNNEL_FROM spec must still mint")
	}
	wantHints(t, seen, known)
	wantMinted(t, spec)
}

// TestFromMintsWithHints pins the code replay: every field rides, not just
// the record id.
func TestFromMintsWithHints(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := From(known).WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantHints(t, seen, known)
	wantMinted(t, spec)
}

// TestCompleteFieldSetMintsWithHints pins that a complete credential set is
// a hint like any other: the provider is asked, and its answer is the spec.
func TestCompleteFieldSetMintsWithHints(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.CloudflareIDEnv, known.ID)
	t.Setenv(v1.CloudflareNameEnv, known.Name)
	t.Setenv(v1.CloudflareHostnameEnv, known.Hostname)
	t.Setenv(v1.CloudflareAccountTagEnv, known.AccountTag)
	t.Setenv(v1.CloudflareSecretEnv, base64.StdEncoding.EncodeToString(known.Secret))
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("mint never called; a complete field set must still mint")
	}
	want := *known
	want.RecordID = ""
	wantHints(t, seen, &want)
	wantMinted(t, spec)
}

// TestSpecEnvBeatsFromEnvAsHint pins hint precedence: the handoff wins over
// the replay mirror, env beats code throughout.
func TestSpecEnvBeatsFromEnvAsHint(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.SpecEnv, envelope(t, &Spec{Hostname: "handoff.tunneled.pizza"}))
	t.Setenv(v1.FromEnv, envelope(t, &Spec{Hostname: "replay.tunneled.pizza"}))
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := From(&Spec{Hostname: "code.tunneled.pizza"}).WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Hostname"); got != "handoff.tunneled.pizza" {
		t.Errorf("X-Hostname = %q, want the LIBTUNNEL_SPEC hint", got)
	}
}

// TestFieldSetterOverridesHintSpec pins that a field named outright beats the
// same field on the spec being replayed: the caller means it.
func TestFieldSetterOverridesHintSpec(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := From(known).WithName("mine").WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := *known
	want.Name = "mine"
	wantHints(t, seen, &want)
}

// TestFieldSettersAreNotStampedOntoResult pins that the resolved spec is the
// provider's word: a setter is a hint, and a provider that ignores it has
// spoken.
func TestFieldSettersAreNotStampedOntoResult(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	spec, err := New().WithProvider(srv.URL).WithName("patched").WithHostname("patched.tunneled.pizza").Provider().Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name == "patched" {
		t.Errorf("Name = %q, want the provider's own", spec.Name)
	}
	wantMinted(t, spec)
}

// TestAdoptedSpecUnreachableFallsBack pins the offline path: with nothing
// answering, what the process knows is served as given, so an air-gapped
// handoff still starts.
func TestAdoptedSpecUnreachableFallsBack(t *testing.T) {
	clearSpecEnv(t)
	shortBudgets(t, 50*time.Millisecond)
	t.Setenv(v1.SpecEnv, envelope(t, known))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	spec, err := New().WithProvider("http://" + addr).Provider().Spec(context.Background())
	if err != nil {
		t.Fatalf("Spec() = %v, want the adopted spec when the provider cannot be reached", err)
	}
	if spec.Hostname != known.Hostname || spec.ID != known.ID || spec.RecordID != known.RecordID {
		t.Errorf("spec = %+v, want the adopted one verbatim", spec)
	}
}

// TestResolvedSpecExportedAfterAdopt pins that the handoff carries forward:
// what the provider answered, not what was inherited, is what a grandchild
// gets.
func TestResolvedSpecExportedAfterAdopt(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.SpecEnv, envelope(t, known))
	t.Setenv(v1.HostnameEnv, "")
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(v1.SpecEnv); !strings.Contains(got, "minted.tunneled.pizza") {
		t.Errorf("%s = %q, want the resolved spec exported", v1.SpecEnv, got)
	}
}

// TestSecondTunnelDoesNotHintWithOwnExport pins the in-process isolation
// rule: a second tunnel in the same process mints its own identity, not the
// first tunnel's through the environment it exported to.
func TestSecondTunnelDoesNotHintWithOwnExport(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.HostnameEnv, "")
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(os.Getenv(v1.SpecEnv), "minted.tunneled.pizza") {
		t.Fatalf("%s = %q, want the first mint exported", v1.SpecEnv, os.Getenv(v1.SpecEnv))
	}
	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Hostname"); got != "" {
		t.Errorf("X-Hostname = %q on the second mint, want none: it hinted with the first tunnel's export", got)
	}
}

// TestFromEnvForeignBackendErrors pins loud failure: a LIBTUNNEL_FROM spec
// minted by another backend is an error, not a fallthrough to a fresh mint.
func TestFromEnvForeignBackendErrors(t *testing.T) {
	clearSpecEnv(t)
	t.Setenv(v1.FromEnv, `{"backend":"other","spec":{"hostname":"x.example.com"}}`)
	var seen http.Header
	srv := mintServer(t, &seen)

	_, err := New().WithProvider(srv.URL).Provider().Spec(context.Background())
	if err == nil || !strings.Contains(err.Error(), v1.FromEnv) {
		t.Errorf("Spec err = %v, want a %s backend-tag failure", err, v1.FromEnv)
	}
	if seen != nil {
		t.Error("mint called despite a foreign-backend LIBTUNNEL_FROM")
	}
}

// TestFromEnvReadsSpecFile pins the file form: LIBTUNNEL_FROM names a path,
// and the spec inside is the hint.
func TestFromEnvReadsSpecFile(t *testing.T) {
	clearSpecEnv(t)
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(envelope(t, known)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(v1.FromEnv, path)
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := New().WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantHints(t, seen, known)
}

// TestWithRecordIDRidesAsHint pins the record setter and its env mirror: a
// pinned credential set can name the record it wants back, and env beats
// code.
func TestWithRecordIDRidesAsHint(t *testing.T) {
	clearSpecEnv(t)
	var seen http.Header
	srv := mintServer(t, &seen)

	if _, err := New().WithRecordID("from-code").WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Record-Id"); got != "from-code" {
		t.Errorf("X-Record-Id = %q, want the setter's record", got)
	}

	t.Setenv(v1.CloudflareRecordIDEnv, "from-env")
	if _, err := New().WithRecordID("from-code").WithProvider(srv.URL).Provider().Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("X-Record-Id"); got != "from-env" {
		t.Errorf("X-Record-Id = %q, want the env override", got)
	}
}
