package main

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
)

// TestDispatchVersion pins the `version` argument: it prints the banner to
// the writer and signals exit with no error.
func TestDispatchVersion(t *testing.T) {
	var out strings.Builder
	done, err := dispatch([]string{"version"}, &out)
	if !done || err != nil {
		t.Fatalf("dispatch(version) = (%v, %v), want (true, nil)", done, err)
	}
	if got := strings.TrimSpace(out.String()); !strings.HasPrefix(got, "libtunnel ") {
		t.Errorf("version banner = %q, want it to start with %q", got, "libtunnel ")
	}
}

// TestDispatchNoArgs pins the normal path: no arguments proceeds to the run.
func TestDispatchNoArgs(t *testing.T) {
	var out strings.Builder
	done, err := dispatch(nil, &out)
	if done || err != nil {
		t.Fatalf("dispatch(nil) = (%v, %v), want (false, nil)", done, err)
	}
	if out.Len() != 0 {
		t.Errorf("dispatch(nil) wrote %q, want nothing", out.String())
	}
}

// TestDispatchUnexpectedArg pins rejection: any argument other than `version`
// exits with an error rather than silently ignoring it.
func TestDispatchUnexpectedArg(t *testing.T) {
	var out strings.Builder
	done, err := dispatch([]string{"--serve"}, &out)
	if !done || err == nil {
		t.Fatalf("dispatch(--serve) = (%v, %v), want (true, non-nil)", done, err)
	}
	if !strings.Contains(err.Error(), "environment") {
		t.Errorf("error %q does not point the operator at env configuration", err)
	}
}

// TestVersionLineNonEmpty pins that the banner carries a version: it delegates
// to libtunnel.Version(), which always resolves a non-empty identifier.
func TestVersionLineNonEmpty(t *testing.T) {
	if got := versionLine(); !strings.HasPrefix(got, "libtunnel ") || strings.HasSuffix(got, "libtunnel ") {
		t.Errorf("versionLine() = %q, want a non-empty libtunnel banner", got)
	}
}

// clearEnv scrubs every variable build() consults so each case starts from a
// known-empty environment regardless of the host's.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{v1.SpecEnv, v1.CloudflareEnv, v1.LocalURLEnv} {
		t.Setenv(v, "")
	}
}

// TestBuildNoBackendActivated pins the first guard: with neither the spec
// handoff nor the switch, build fails before any network use, naming both
// activation paths.
func TestBuildNoBackendActivated(t *testing.T) {
	clearEnv(t)
	t.Setenv(v1.LocalURLEnv, "http://127.0.0.1:8080") // origin present, backend not

	_, err := build(context.Background())
	if err == nil {
		t.Fatal("build succeeded with no backend activated, want an error")
	}
	if !strings.Contains(err.Error(), v1.SpecEnv) || !strings.Contains(err.Error(), v1.CloudflareEnv) {
		t.Errorf("error %q does not name both activation variables %s / %s", err, v1.SpecEnv, v1.CloudflareEnv)
	}
}

// TestBuildNoOrigin pins the second guard: a backend activated but no
// LIBTUNNEL_LOCAL_URL fails clean rather than minting a dead loopback.
func TestBuildNoOrigin(t *testing.T) {
	clearEnv(t)
	t.Setenv(v1.CloudflareEnv, "1")

	_, err := build(context.Background())
	if err == nil {
		t.Fatal("build succeeded with no origin, want an error")
	}
	if !strings.Contains(err.Error(), v1.LocalURLEnv) {
		t.Errorf("error %q does not name %s", err, v1.LocalURLEnv)
	}
}

// TestBuildActivatedBySpec pins that the spec handoff alone activates the
// backend: with an origin set too, build returns a tunnel and no error. The
// spec is fabricated and never connected (build returns the unstarted tunnel).
func TestBuildActivatedBySpec(t *testing.T) {
	clearEnv(t)
	t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"handoff.tunneled.pizza"}}`)
	t.Setenv(v1.LocalURLEnv, "http://127.0.0.1:8080")

	tun, err := build(context.Background())
	if err != nil {
		t.Fatalf("build failed with a spec handoff and origin: %v", err)
	}
	if tun == nil {
		t.Fatal("build returned a nil tunnel")
	}
}

// TestCloudflareActivated pins the activation predicate directly across the
// three env shapes.
func TestCloudflareActivated(t *testing.T) {
	t.Run("switch", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(v1.CloudflareEnv, "1")
		if !cloudflareActivated() {
			t.Error("cloudflareActivated() = false with the switch set")
		}
	})
	t.Run("spec", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{}}`)
		if !cloudflareActivated() {
			t.Error("cloudflareActivated() = false with a spec handoff")
		}
	})
	t.Run("neither", func(t *testing.T) {
		clearEnv(t)
		if cloudflareActivated() {
			t.Error("cloudflareActivated() = true with nothing set")
		}
	})
	t.Run("switch not one", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(v1.CloudflareEnv, "true") // only "1" activates
		if cloudflareActivated() {
			t.Error("cloudflareActivated() = true for LIBTUNNEL__CLOUDFLARE=true, want only \"1\"")
		}
	})
}
