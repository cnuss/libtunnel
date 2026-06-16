package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

func TestSpecEnvironRoundTrip(t *testing.T) {
	spec := &cloudflare.Spec{
		ID:         "id-1",
		Name:       "name-1",
		Hostname:   "demo.trycloudflare.com",
		AccountTag: "tag-1",
		Secret:     []byte("secret"),
	}

	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := v1alpha1.SpecEnv + "="; len(entry) <= len(want) || entry[:len(want)] != want {
		t.Fatalf("SpecEnviron = %q, want a %q entry", entry, want)
	}

	t.Setenv(v1alpha1.SpecEnv, entry[len(v1alpha1.SpecEnv)+1:])

	adopted := &cloudflare.Spec{}
	ok, err := v1alpha1.SpecFromEnv("cloudflare", adopted)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("SpecFromEnv reported absent; want present")
	}
	if adopted.Hostname != spec.Hostname || adopted.AccountTag != spec.AccountTag || string(adopted.Secret) != string(spec.Secret) {
		t.Errorf("round-trip mismatch: got %+v, want %+v", adopted, spec)
	}
}

func TestExportSpecGuardsSelfAdoption(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")     // restore after the test
	t.Setenv(v1alpha1.HostnameEnv, "") // restore after the test
	spec := &cloudflare.Spec{Hostname: "exported.trycloudflare.com"}
	if err := v1alpha1.ExportSpec("cloudflare", spec); err != nil {
		t.Fatal(err)
	}

	// The exported value sits in the environment for children to inherit …
	if env := os.Getenv(v1alpha1.SpecEnv); !strings.Contains(env, "exported.trycloudflare.com") {
		t.Errorf("env %s = %q, want the exported spec", v1alpha1.SpecEnv, env)
	}
	// … alongside the plain-hostname mirror.
	if got := os.Getenv(v1alpha1.HostnameEnv); got != "exported.trycloudflare.com" {
		t.Errorf("env %s = %q, want the plain hostname", v1alpha1.HostnameEnv, got)
	}

	// … but this process never re-adopts its own export: a second in-process
	// tunnel must mint its own identity, not race to inherit this one's.
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); ok || err != nil {
		t.Errorf("SpecFromEnv = (%t, %v) for a self-exported spec; want (false, nil)", ok, err)
	}
}

func TestSpecFromEnvAbsent(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); ok || err != nil {
		t.Errorf("SpecFromEnv = (%t, %v) with no env; want (false, nil)", ok, err)
	}
}

func TestSpecFromEnvMalformed(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "{not json")
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) with malformed env; want an error", ok)
	}
}

func TestSpecFromEnvWrongBackend(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, `{"backend":"other","spec":{"hostname":"x.example.com"}}`)
	ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{})
	if err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) for a foreign backend's spec; want an error", ok)
	}
	if err != nil && !strings.Contains(err.Error(), `"other"`) {
		t.Errorf("err = %v, want it to name the foreign backend", err)
	}
}

func TestSpecFromEnvRejectsUntaggedSpec(t *testing.T) {
	// The pre-envelope wire form: a bare spec with no backend tag.
	t.Setenv(v1alpha1.SpecEnv, `{"hostname":"bare.trycloudflare.com"}`)
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) for an untagged spec; want an error", ok)
	}
}

// trackingProvider records whether it was consulted.
type trackingProvider struct {
	called bool
	spec   *cloudflare.Spec
}

func (p *trackingProvider) Spec(context.Context) (*cloudflare.Spec, error) {
	p.called = true
	return p.spec, nil
}

var (
	_ v1.Provider[*cloudflare.Spec]     = (*trackingProvider)(nil)
	_ v1.Provider[*cloudflare.Spec]     = (*loggingProvider)(nil)
	_ v1alpha1.Engine[*cloudflare.Spec] = loggerEngine{}
)

func TestEnvProviderAdoptsEnvironment(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"fromenv.trycloudflare.com"}}`)

	next := &trackingProvider{}
	spec, err := v1alpha1.Env[cloudflare.Spec]("cloudflare", next).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "fromenv.trycloudflare.com" {
		t.Errorf("Hostname = %q, want the environment's spec", spec.Hostname)
	}
	if next.called {
		t.Error("wrapped provider was consulted although the environment carried a spec")
	}
}

func TestEnvProviderFallsBack(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "minted.trycloudflare.com"}}
	spec, err := v1alpha1.Env[cloudflare.Spec]("cloudflare", next).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("wrapped provider was not consulted although the environment was empty")
	}
	if spec.Hostname != "minted.trycloudflare.com" {
		t.Errorf("Hostname = %q, want the wrapped provider's spec", spec.Hostname)
	}
}

func TestStaticProvider(t *testing.T) {
	want := &cloudflare.Spec{Hostname: "static.trycloudflare.com"}
	got, err := v1alpha1.Static(want).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Static yielded %+v, want the exact spec passed in", got)
	}
}

// loggingProvider records the logger handed down by the tunnel core.
type loggingProvider struct {
	trackingProvider
	log *slog.Logger
}

func (p *loggingProvider) SetLogger(log *slog.Logger) { p.log = log }

func TestTunnelThreadsLoggerIntoProvider(t *testing.T) {
	want := slog.New(slog.DiscardHandler)
	provider := &loggingProvider{trackingProvider: trackingProvider{spec: &cloudflare.Spec{Hostname: "x.y"}}}

	v1alpha1.New(loggerEngine{provider}).WithLogger(want).Hostname() // forces the spec fetch

	if provider.log != want {
		t.Errorf("provider received logger %p, want the tunnel's %p", provider.log, want)
	}
}

func TestEnvProviderForwardsLogger(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")
	want := slog.New(slog.DiscardHandler)
	inner := &loggingProvider{trackingProvider: trackingProvider{spec: &cloudflare.Spec{}}}

	wrapped := v1alpha1.Env[cloudflare.Spec]("cloudflare", inner)
	if pl, ok := wrapped.(interface{ SetLogger(*slog.Logger) }); !ok {
		t.Fatal("Env provider does not forward SetLogger")
	} else {
		pl.SetLogger(want)
	}
	if inner.log != want {
		t.Errorf("wrapped provider received logger %p, want %p", inner.log, want)
	}
}

// loggerEngine is a minimal engine whose provider is injected.
type loggerEngine struct {
	provider v1.Provider[*cloudflare.Spec]
}

func (e loggerEngine) Name() string                                { return "logger-fake" }
func (e loggerEngine) Provider() v1.Provider[*cloudflare.Spec]     { return e.provider }
func (e loggerEngine) CACerts() []*x509.Certificate                { return nil }
func (e loggerEngine) WithTLS(bool) v1.Backend[*cloudflare.Spec]   { return e }
func (e loggerEngine) WithHTTP2(bool) v1.Backend[*cloudflare.Spec] { return e }
func (e loggerEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	return nil
}

func TestEnvProviderExportsMintedSpec(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "minted.trycloudflare.com"}}
	if _, err := v1alpha1.Env[cloudflare.Spec]("cloudflare", next).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The mint lands in the environment for spawned children to inherit.
	if env := os.Getenv(v1alpha1.SpecEnv); !strings.Contains(env, "minted.trycloudflare.com") {
		t.Errorf("env %s = %q, want the minted spec exported", v1alpha1.SpecEnv, env)
	}
}

// TestEnvProviderNeverAdoptsOwnExport pins the in-process isolation rule: a
// second tunnel in the same process must mint its own identity, not inherit
// the first tunnel's export through the environment.
func TestEnvProviderNeverAdoptsOwnExport(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")

	first := &trackingProvider{spec: &cloudflare.Spec{Hostname: "alpha.trycloudflare.com"}}
	if _, err := v1alpha1.Env[cloudflare.Spec]("cloudflare", first).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	second := &trackingProvider{spec: &cloudflare.Spec{Hostname: "beta.trycloudflare.com"}}
	spec, err := v1alpha1.Env[cloudflare.Spec]("cloudflare", second).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.called {
		t.Error("second provider was not consulted: it adopted the first tunnel's export")
	}
	if spec.Hostname != "beta.trycloudflare.com" {
		t.Errorf("second tunnel's Hostname = %q, want its own mint", spec.Hostname)
	}
}
