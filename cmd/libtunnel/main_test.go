package main

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
)

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
	t.Setenv(v1.SpecEnv, `{"backend":"cloudflare","spec":{"hostname":"handoff.trycloudflare.com"}}`)
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
