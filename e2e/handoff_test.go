package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
)

// childEnv flags a re-exec of this test binary into the child role of the
// offline handoff scenario.
const childEnv = "LIBTUNNEL_E2E_HANDOFF_CHILD"

// TestSpecHandoffAcrossProcesses is the offline parent→child handoff
// scenario: the parent (this test) mints a spec and passes it to a child (a
// re-exec of this test binary) through the environment; the child adopts it
// via the Env provider and reports what its tunnel resolves to. No network is
// involved — the spec is fabricated and no listener is ever provided, so the
// child's getters resolve purely from the handed-off spec. The live
// counterpart (real edge connection, shared traffic) is
// TestHandoffSharedHostname.
func TestSpecHandoffAcrossProcesses(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		handoffChild()
		return
	}

	spec := &v1.CloudflareSpec{
		ID:         "00000000-0000-0000-0000-000000000000",
		Name:       "e2e-scenario",
		Hostname:   "scenario.trycloudflare.com",
		AccountTag: "tag",
		Secret:     []byte("secret"),
	}
	entry, err := libtunnel.SpecEnviron(spec)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSpecHandoffAcrossProcesses$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", entry)
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}

	// The child's tunnel must resolve to the exact identity the parent
	// minted, plus the spec-independent trust roots.
	for _, want := range []string{
		"child hostname: scenario.trycloudflare.com",
		"child host=scenario domain=trycloudflare.com port=443",
		"child cacerts: true",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("child output does not contain %q", want)
		}
	}
}

// handoffChild is the child role: build a tunnel whose Env provider adopts
// TUNNEL_SPEC, then report the identity it resolved. The QuickTunnel fallback
// is never consulted, so nothing dials out.
func handoffChild() {
	tun := libtunnel.New(libtunnel.Cloudflare(), libtunnel.Env(libtunnel.QuickTunnel()))

	fmt.Printf("child hostname: %s\n", tun.Hostname())
	fmt.Printf("child host=%s domain=%s port=%d\n", tun.Host(), tun.Domain(), tun.Port())
	fmt.Printf("child cacerts: %t\n", len(tun.CACerts()) > 0)
}
