package e2e

// Offline scenario tests: subprocess flows that exercise the spec handoff
// machinery without any network access. Every spec here is fabricated, no
// listener is ever provided, and the Cloudflare credential chain always finds
// TUNNEL_SPEC before it would mint anything.

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
)

// reportSpec is the shared child role body: build a tunnel, adopt whatever
// the environment carries, and report the resolved identity.
func reportSpec() {
	tun := libtunnel.New(libtunnel.Cloudflare())
	fmt.Printf("%s hostname: %s\n", role(), tun.Hostname())
	fmt.Printf("%s host=%s domain=%s port=%d\n", role(), tun.Host(), tun.Domain(), tun.Port())
}

// TestExportSpecReExec covers the re-exec (daemonize) handoff path: the
// parent publishes the spec into its own environment with ExportSpec — no
// explicit exec.Cmd.Env entry — and a re-exec'd child inherits and adopts it.
func TestExportSpecReExec(t *testing.T) {
	if role() == "reexec-child" {
		reportSpec()
		return
	}

	t.Setenv(libtunnel.SpecEnv, "") // register restore before mutating the env
	spec := &v1.CloudflareSpec{Hostname: "reexec.trycloudflare.com"}
	if err := libtunnel.ExportSpec(spec); err != nil {
		t.Fatal(err)
	}

	cmd := reexec("TestExportSpecReExec", roleEnv+"=reexec-child")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
	if want := "reexec-child hostname: reexec.trycloudflare.com"; !strings.Contains(string(out), want) {
		t.Errorf("child output does not contain %q", want)
	}
}

// TestHandoffChain proves the handoff composes: parent → child → grandchild,
// each hop inheriting TUNNEL_SPEC through the environment, all three
// resolving the same hostname.
func TestHandoffChain(t *testing.T) {
	switch role() {
	case "chain-child":
		reportSpec()
		// Spawn the grandchild with a plainly inherited environment — no
		// explicit entry; TUNNEL_SPEC rides along.
		out, err := reexec("TestHandoffChain", roleEnv+"=chain-grandchild").CombinedOutput()
		if err != nil {
			fmt.Printf("grandchild failed: %v\n%s", err, out)
			os.Exit(3)
		}
		fmt.Print(string(out))
		return
	case "chain-grandchild":
		reportSpec()
		return
	}

	spec := &v1.CloudflareSpec{Hostname: "chain.trycloudflare.com"}
	entry, err := libtunnel.SpecEnviron(spec)
	if err != nil {
		t.Fatal(err)
	}

	out, err := reexec("TestHandoffChain", roleEnv+"=chain-child", entry).CombinedOutput()
	t.Logf("chain output:\n%s", out)
	if err != nil {
		t.Fatalf("chain failed: %v", err)
	}
	for _, want := range []string{
		"chain-child hostname: chain.trycloudflare.com",
		"chain-grandchild hostname: chain.trycloudflare.com",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("chain output does not contain %q", want)
		}
	}
}

// TestMalformedSpecEnv pins the failure path: a child handed a corrupt
// TUNNEL_SPEC must fail loudly — SpecFromEnv errors, and the tunnel built on
// the same environment resolves to nothing.
func TestMalformedSpecEnv(t *testing.T) {
	if role() == "malformed-child" {
		spec := &v1.CloudflareSpec{}
		ok, err := libtunnel.SpecFromEnv(spec)
		fmt.Printf("specfromenv ok=%t err=%v\n", ok, err)

		tun := libtunnel.New(libtunnel.Cloudflare())
		fmt.Printf("hostname=%q\n", tun.Hostname())

		if err == nil {
			os.Exit(0) // unexpected: parent will flag the zero exit
		}
		os.Exit(3)
	}

	cmd := reexec("TestMalformedSpecEnv", roleEnv+"=malformed-child", libtunnel.SpecEnv+"={this is not json")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err == nil {
		t.Fatal("child exited 0 with a corrupt TUNNEL_SPEC; want a loud failure")
	}
	if want := "unable to parse TUNNEL_SPEC"; !strings.Contains(string(out), want) {
		t.Errorf("child output does not contain %q", want)
	}
	if want := `hostname=""`; !strings.Contains(string(out), want) {
		t.Errorf("child output does not contain %q — a corrupt spec must not resolve a hostname", want)
	}
}

// TestSpecHostnameWithPort runs a hostname that encodes a port through the
// full subprocess flow: the child's Port() must pick it up (and Host stays
// the first label).
func TestSpecHostnameWithPort(t *testing.T) {
	if role() == "port-child" {
		reportSpec()
		return
	}

	spec := &v1.CloudflareSpec{Hostname: "scenario.trycloudflare.com:8443"}
	entry, err := libtunnel.SpecEnviron(spec)
	if err != nil {
		t.Fatal(err)
	}

	out, err := reexec("TestSpecHostnameWithPort", roleEnv+"=port-child", entry).CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
	if want := "port-child host=scenario domain=trycloudflare.com:8443 port=8443"; !strings.Contains(string(out), want) {
		t.Errorf("child output does not contain %q", want)
	}
}
