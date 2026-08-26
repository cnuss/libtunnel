package v1alpha1_test

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TestMain redirects the cache dir to a throwaway: minting (even the fake mints
// below) caches the spec there, and the suite must not touch a real cache.
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

func TestSpecEnvironRoundTrip(t *testing.T) {
	spec := &cloudflare.Spec{
		ID:         "id-1",
		Name:       "name-1",
		Hostname:   "demo.tunneled.pizza",
		AccountTag: "tag-1",
		Secret:     []byte("secret"),
	}

	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := v1.SpecEnv + "="; len(entry) <= len(want) || entry[:len(want)] != want {
		t.Fatalf("SpecEnviron = %q, want a %q entry", entry, want)
	}

	t.Setenv(v1.SpecEnv, entry[len(v1.SpecEnv)+1:])

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
	t.Setenv(v1.SpecEnv, "")     // restore after the test
	t.Setenv(v1.HostnameEnv, "") // restore after the test
	spec := &cloudflare.Spec{Hostname: "exported.tunneled.pizza"}
	if err := v1alpha1.ExportSpec("cloudflare", spec); err != nil {
		t.Fatal(err)
	}

	// The exported value sits in the environment for children to inherit …
	if env := os.Getenv(v1.SpecEnv); !strings.Contains(env, "exported.tunneled.pizza") {
		t.Errorf("env %s = %q, want the exported spec", v1.SpecEnv, env)
	}
	// … alongside the plain-hostname mirror.
	if got := os.Getenv(v1.HostnameEnv); got != "exported.tunneled.pizza" {
		t.Errorf("env %s = %q, want the plain hostname", v1.HostnameEnv, got)
	}

	// … but this process never re-adopts its own export: a second in-process
	// tunnel must mint its own identity, not race to inherit this one's.
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); ok || err != nil {
		t.Errorf("SpecFromEnv = (%t, %v) for a self-exported spec; want (false, nil)", ok, err)
	}
}

func TestMintCachesSpec(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(v1.CacheDirEnv, dir)
	t.Setenv(v1.SpecEnv, "") // force the mint path, not adopt

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "cached.tunneled.pizza"}}
	if _, err := v1alpha1.Env("cloudflare", next).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "cached.tunneled.pizza.spec.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mint did not cache the spec at %s: %v", path, err)
	}
	tag, _, err := v1alpha1.DecodeSpec(string(data))
	if err != nil || tag != "cloudflare" {
		t.Errorf("cache content = %q (tag %q, err %v), want a cloudflare envelope", data, tag, err)
	}
}

func TestAdoptedSpecIsNotCached(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(v1.CacheDirEnv, dir)
	t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"adopted.tunneled.pizza"}}`)

	next := &trackingProvider{}
	if _, err := v1alpha1.Env("cloudflare", next).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "adopted.tunneled.pizza.spec.json")
	if _, err := os.Stat(path); err == nil {
		t.Errorf("adopted spec was cached at %s; want mint-only caching", path)
	}
}

func TestCacheDirDefaultUsesPackagePath(t *testing.T) {
	t.Setenv(v1.CacheDirEnv, "") // unset -> default
	dir, err := v1alpha1.CacheDir()
	if err != nil {
		t.Skipf("no user cache dir: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(dir), "github.com/cnuss/libtunnel/v1") {
		t.Errorf("CacheDir() = %q, want it namespaced by the v1 package path", dir)
	}
}

func TestHostsListsCachedSpecs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(v1.CacheDirEnv, dir)

	for _, h := range []string{"bbb.tunneled.pizza", "aaa.tunneled.pizza"} {
		spec := &cloudflare.Spec{Hostname: h}
		if err := os.WriteFile(filepath.Join(dir, h+".spec.json"), []byte(spec.Serialize()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A non-spec file is ignored.
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := v1alpha1.Hosts()
	want := []string{
		"https://aaa.tunneled.pizza:443/",
		"https://bbb.tunneled.pizza:443/",
	}
	if len(got) != len(want) {
		t.Fatalf("Hosts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Hosts()[%d] = %q, want %q (sorted, 443 backfilled)", i, got[i], want[i])
		}
	}
}

func TestSpecFromEnvAbsent(t *testing.T) {
	t.Setenv(v1.SpecEnv, "")
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); ok || err != nil {
		t.Errorf("SpecFromEnv = (%t, %v) with no env; want (false, nil)", ok, err)
	}
}

func TestSpecFromEnvMalformed(t *testing.T) {
	t.Setenv(v1.SpecEnv, "{not json")
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) with malformed env; want an error", ok)
	}
}

func TestSpecFromEnvWrongBackend(t *testing.T) {
	t.Setenv(v1.SpecEnv, `{"backend":"other","spec":{"hostname":"x.example.com"}}`)
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
	t.Setenv(v1.SpecEnv, `{"hostname":"bare.tunneled.pizza"}`)
	if ok, err := v1alpha1.SpecFromEnv("cloudflare", &cloudflare.Spec{}); err == nil {
		t.Errorf("SpecFromEnv = (%t, nil) for an untagged spec; want an error", ok)
	}
}

// trackingProvider records whether it was consulted.
// TestReplayEnvReplaysCachedSpec pins LIBTUNNEL_FROM: a bare hostname
// resolves through the cache (like libtunnel.From) and supersedes the wrapped
// provider — even a code-pinned spec.
func TestReplayEnvReplaysCachedSpec(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(v1.CacheDirEnv, dir)
	envelope, err := v1alpha1.EncodeSpec("cloudflare", &cloudflare.Spec{Hostname: "replayed.tunneled.pizza"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replayed.tunneled.pizza.spec.json"), []byte(envelope), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(v1.FromEnv, "replayed.tunneled.pizza")

	pinned := &trackingProvider{spec: &cloudflare.Spec{Hostname: "pinned.tunneled.pizza"}}
	spec, err := v1alpha1.Replay("cloudflare", v1.Provider[*cloudflare.Spec](pinned)).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "replayed.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the replayed spec", spec.Hostname)
	}
	if pinned.called {
		t.Error("wrapped provider resolved despite LIBTUNNEL_FROM (env must beat code)")
	}
}

// TestReplayEnvForeignBackendErrors pins loud failure: a LIBTUNNEL_FROM spec
// minted by another backend is an error, not a fallthrough.
func TestReplayEnvForeignBackendErrors(t *testing.T) {
	t.Setenv(v1.FromEnv, `{"backend":"other","spec":{"hostname":"x.example.com"}}`)

	_, err := v1alpha1.Replay("cloudflare", v1.Provider[*cloudflare.Spec](&trackingProvider{})).Spec(context.Background())
	if err == nil || !strings.Contains(err.Error(), v1.FromEnv) {
		t.Errorf("Spec err = %v, want a %s backend-tag failure", err, v1.FromEnv)
	}
}

// TestReplayEnvUnsetFallsThrough pins the default: no LIBTUNNEL_FROM, the
// wrapped provider resolves as usual.
func TestReplayEnvUnsetFallsThrough(t *testing.T) {
	t.Setenv(v1.FromEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "next.tunneled.pizza"}}
	spec, err := v1alpha1.Replay("cloudflare", v1.Provider[*cloudflare.Spec](next)).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !next.called || spec.Hostname != "next.tunneled.pizza" {
		t.Errorf("called=%v hostname=%q, want the wrapped provider's spec", next.called, spec.Hostname)
	}
}

// TestSpecEnvBeatsFromEnv pins the chain order: with both set, the
// LIBTUNNEL_SPEC handoff wins over the LIBTUNNEL_FROM replay.
func TestSpecEnvBeatsFromEnv(t *testing.T) {
	t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"handoff.tunneled.pizza"}}`)
	t.Setenv(v1.FromEnv, `{"backend":"cloudflare","spec":{"hostname":"replayed.tunneled.pizza"}}`)

	chain := v1alpha1.Env("cloudflare", v1alpha1.Replay("cloudflare", v1.Provider[*cloudflare.Spec](&trackingProvider{})))
	spec, err := chain.Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "handoff.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the LIBTUNNEL_SPEC handoff to win", spec.Hostname)
	}
}

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
	t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"fromenv.tunneled.pizza"}}`)

	next := &trackingProvider{}
	spec, err := v1alpha1.Env("cloudflare", next).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "fromenv.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the environment's spec", spec.Hostname)
	}
	if next.called {
		t.Error("wrapped provider was consulted although the environment carried a spec")
	}
}

func TestEnvProviderFallsBack(t *testing.T) {
	t.Setenv(v1.SpecEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "minted.tunneled.pizza"}}
	spec, err := v1alpha1.Env("cloudflare", next).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("wrapped provider was not consulted although the environment was empty")
	}
	if spec.Hostname != "minted.tunneled.pizza" {
		t.Errorf("Hostname = %q, want the wrapped provider's spec", spec.Hostname)
	}
}

func TestStaticProvider(t *testing.T) {
	want := &cloudflare.Spec{Hostname: "static.tunneled.pizza"}
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
	t.Setenv(v1.SpecEnv, "")
	want := slog.New(slog.DiscardHandler)
	inner := &loggingProvider{trackingProvider: trackingProvider{spec: &cloudflare.Spec{}}}

	wrapped := v1alpha1.Env("cloudflare", inner)
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
func (loggerEngine) Reconnect(context.Context) error               { return nil }
func (loggerEngine) Proxy() *httputil.ReverseProxy                 { return nil }
func (loggerEngine) Listener() net.Listener                        { return nil }
func (e loggerEngine) WithListener(t *v1alpha1.TunnelImpl[*cloudflare.Spec], l net.Listener) error {
	return nil
}
func (e loggerEngine) WithLocalURL(t *v1alpha1.TunnelImpl[*cloudflare.Spec], u *url.URL) error {
	return nil
}

func TestEnvProviderExportsMintedSpec(t *testing.T) {
	t.Setenv(v1.SpecEnv, "")

	next := &trackingProvider{spec: &cloudflare.Spec{Hostname: "minted.tunneled.pizza"}}
	if _, err := v1alpha1.Env("cloudflare", next).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The mint lands in the environment for spawned children to inherit.
	if env := os.Getenv(v1.SpecEnv); !strings.Contains(env, "minted.tunneled.pizza") {
		t.Errorf("env %s = %q, want the minted spec exported", v1.SpecEnv, env)
	}
}

// TestEnvProviderNeverAdoptsOwnExport pins the in-process isolation rule: a
// second tunnel in the same process must mint its own identity, not inherit
// the first tunnel's export through the environment.
func TestEnvProviderNeverAdoptsOwnExport(t *testing.T) {
	t.Setenv(v1.SpecEnv, "")

	first := &trackingProvider{spec: &cloudflare.Spec{Hostname: "alpha.tunneled.pizza"}}
	if _, err := v1alpha1.Env("cloudflare", first).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	second := &trackingProvider{spec: &cloudflare.Spec{Hostname: "beta.tunneled.pizza"}}
	spec, err := v1alpha1.Env("cloudflare", second).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.called {
		t.Error("second provider was not consulted: it adopted the first tunnel's export")
	}
	if spec.Hostname != "beta.tunneled.pizza" {
		t.Errorf("second tunnel's Hostname = %q, want its own mint", spec.Hostname)
	}
}

// TestMintCachesLatestSpec pins the latest.spec.json write (#142): a mint
// through the env chain records the spec under the fixed name, and LatestSpec
// loads it back — for the matching backend only.
func TestMintCachesLatestSpec(t *testing.T) {
	t.Setenv(v1.SpecEnv, "")
	t.Setenv(v1.CacheDirEnv, t.TempDir())

	spec := &cloudflare.Spec{ID: "id-latest", Hostname: "cachedmint.tunneled.pizza", AccountTag: "tag", Secret: []byte("s")}
	if _, err := v1alpha1.Env("cloudflare", v1alpha1.Static(spec)).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}

	var got cloudflare.Spec
	if !v1alpha1.LatestSpec("cloudflare", &got) {
		t.Fatal("LatestSpec = false, want the freshly minted spec loaded")
	}
	if got.ID != spec.ID || got.Hostname != spec.Hostname {
		t.Errorf("LatestSpec loaded %+v, want %+v", got, *spec)
	}
	var foreign cloudflare.Spec
	if v1alpha1.LatestSpec("other", &foreign) {
		t.Error("LatestSpec = true for a foreign backend tag, want absent")
	}
}

// TestLatestSpecAbsent pins the quiet default: an empty cache reads as
// absent, never an error — the file is a hint source, not credentials.
func TestLatestSpecAbsent(t *testing.T) {
	t.Setenv(v1.CacheDirEnv, t.TempDir())

	var got cloudflare.Spec
	if v1alpha1.LatestSpec("cloudflare", &got) {
		t.Error("LatestSpec = true with an empty cache, want false")
	}
}
