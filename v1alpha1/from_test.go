package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TestFromEmptyIsNoSpec pins that an empty spec — the literal empty string,
// or a path to an empty file — is no spec: build is called with an empty
// backend tag and nil raw, and decides what that means.
func TestFromEmptyIsNoSpec(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"", empty} {
		var gotBackend string
		var gotRaw json.RawMessage
		called := false
		tun := v1alpha1.From(spec, func(backend string, raw json.RawMessage, _ v1.SpecMetadata) (v1.Tunnel, error) {
			called, gotBackend, gotRaw = true, backend, raw
			return v1alpha1.Failed(nil), nil
		})
		if !called {
			t.Errorf("From(%q): build not called; want it asked for the no-spec tunnel", spec)
			continue
		}
		if gotBackend != "" || gotRaw != nil {
			t.Errorf("From(%q): build(%q, %q), want (\"\", nil)", spec, gotBackend, gotRaw)
		}
		_ = tun
	}
}

// TestReplayFromEnvEmptyFileIsUnset pins the env mirror to the same rule:
// LIBTUNNEL_FROM naming an empty file is no spec, not a parse failure.
func TestReplayFromEnvEmptyFileIsUnset(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(v1.FromEnv, empty)

	ok, err := v1alpha1.ReplayFromEnv("cloudflare", &cloudflare.Spec{})
	if ok || err != nil {
		t.Errorf("ReplayFromEnv = (%t, %v) for an empty file; want (false, nil)", ok, err)
	}
}
