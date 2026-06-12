package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
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

	entry, err := v1alpha1.SpecEnviron(spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := v1alpha1.SpecEnv + "="; len(entry) <= len(want) || entry[:len(want)] != want {
		t.Fatalf("SpecEnviron = %q, want a %q entry", entry, want)
	}

	t.Setenv(v1alpha1.SpecEnv, entry[len(v1alpha1.SpecEnv)+1:])

	adopted := &cloudflare.Spec{}
	ok, err := v1alpha1.SpecFromEnv(adopted)
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

func TestExportSpec(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "") // restore after the test
	spec := &cloudflare.Spec{Hostname: "exported.trycloudflare.com"}
	if err := v1alpha1.ExportSpec(spec); err != nil {
		t.Fatal(err)
	}

	adopted := &cloudflare.Spec{}
	if ok, err := v1alpha1.SpecFromEnv(adopted); err != nil || !ok {
		t.Fatalf("SpecFromEnv = (%t, %v) after ExportSpec; want (true, nil)", ok, err)
	}
	if adopted.Hostname != spec.Hostname {
		t.Errorf("Hostname = %q, want %q", adopted.Hostname, spec.Hostname)
	}
}

func TestSpecFromEnvAbsent(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")
	if ok, err := v1alpha1.SpecFromEnv(&cloudflare.Spec{}); ok || err != nil {
		t.Errorf("SpecFromEnv = (%t, %v) with no env; want (false, nil)", ok, err)
	}
}

func TestSpecFromEnvMalformed(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "{not json")
	if ok, err := v1alpha1.SpecFromEnv(&cloudflare.Spec{}); err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) with malformed env; want an error", ok)
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
	t.Setenv(v1alpha1.SpecEnv, `{"hostname":"fromenv.trycloudflare.com"}`)

	next := &trackingProvider{}
	spec, err := v1alpha1.Env[cloudflare.Spec](next).Spec(context.Background())
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
	spec, err := v1alpha1.Env[cloudflare.Spec](next).Spec(context.Background())
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

	v1alpha1.New(loggerEngine{provider}).WithLogger(want).Spec()

	if provider.log != want {
		t.Errorf("provider received logger %p, want the tunnel's %p", provider.log, want)
	}
}

func TestEnvProviderForwardsLogger(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")
	want := slog.New(slog.DiscardHandler)
	inner := &loggingProvider{trackingProvider: trackingProvider{spec: &cloudflare.Spec{}}}

	wrapped := v1alpha1.Env[cloudflare.Spec](inner)
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

func (e loggerEngine) Name() string                            { return "logger-fake" }
func (e loggerEngine) Provider() v1.Provider[*cloudflare.Spec] { return e.provider }
func (e loggerEngine) CACerts() []*x509.Certificate            { return nil }
func (e loggerEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	return nil
}

func TestEnvProviderExportsMintedSpec(t *testing.T) {
	t.Setenv(v1alpha1.SpecEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "minted.trycloudflare.com"}}
	if _, err := v1alpha1.Env[cloudflare.Spec](next).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	adopted := &cloudflare.Spec{}
	if ok, err := v1alpha1.SpecFromEnv(adopted); err != nil || !ok {
		t.Fatalf("SpecFromEnv = (%t, %v) after a mint; want the spec exported", ok, err)
	}
	if adopted.Hostname != "minted.trycloudflare.com" {
		t.Errorf("exported Hostname = %q, want the minted spec", adopted.Hostname)
	}
}
