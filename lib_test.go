package libtunnel_test

// Subprocess handoff tests for the façade: fabricated specs, no network, no
// real tunnels (those live in e2e). Each test re-execs this test binary with
// -test.run anchored to itself and a role variable set; the role branch at
// the top turns the process into the child.

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cnuss/libtunnel"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// roleEnv selects a child role inside a re-exec'd test binary.
const roleEnv = "LIBTUNNEL_TEST_ROLE"

func role() string { return os.Getenv(roleEnv) }

// reexec builds a command that re-runs this test binary anchored to a single
// test, with extra environment entries appended to the current environment.
func reexec(test string, extraEnv ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd
}

// reportSpec is the shared child role body: build a tunnel, adopt whatever
// the environment carries, and report the resolved identity.
func reportSpec() {
	tun := libtunnel.New(libtunnel.Cloudflare())
	fmt.Printf("%s hostname: %s\n", role(), tun.Hostname())
	fmt.Printf("%s host=%s domain=%s port=%d\n", role(), tun.Host(), tun.Domain(), tun.Port())
}

// TestSpecHandoffAcrossProcesses is the basic parent→child handoff: the
// parent (this test) mints a spec and passes it to a child (a re-exec of
// this test binary) through an explicit exec.Cmd.Env entry; the child adopts
// it via the Cloudflare credential chain and reports what its tunnel
// resolves to. The quick-tunnel fallback is never consulted, so nothing
// dials out.
func TestSpecHandoffAcrossProcesses(t *testing.T) {
	if role() == "handoff-child" {
		reportSpec()
		fmt.Printf("%s cacerts: %t\n", role(), len(libtunnel.New(libtunnel.Cloudflare()).CACerts()) > 0)
		return
	}

	spec := &cloudflare.Spec{
		ID:         "00000000-0000-0000-0000-000000000000",
		Name:       "lib-scenario",
		Hostname:   "scenario.trycloudflare.com",
		AccountTag: "tag",
		Secret:     []byte("secret"),
	}
	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
	if err != nil {
		t.Fatal(err)
	}

	out, err := reexec("TestSpecHandoffAcrossProcesses", roleEnv+"=handoff-child", entry).CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
	for _, want := range []string{
		"handoff-child hostname: scenario.trycloudflare.com",
		"handoff-child host=scenario domain=trycloudflare.com port=443",
		"handoff-child cacerts: true",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("child output does not contain %q", want)
		}
	}
}

// TestReExecInheritsSpec covers the re-exec (daemonize) handoff path: the
// spec sits in this process's own environment — no explicit exec.Cmd.Env
// entry — and a re-exec'd child inherits and adopts it. (In a live parent
// the Cloudflare chain puts it there automatically on mint.)
func TestReExecInheritsSpec(t *testing.T) {
	if role() == "reexec-child" {
		reportSpec()
		return
	}

	spec := &cloudflare.Spec{Hostname: "reexec.trycloudflare.com"}
	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(v1alpha1.SpecEnv, strings.TrimPrefix(entry, v1alpha1.SpecEnv+"="))

	out, err := reexec("TestReExecInheritsSpec", roleEnv+"=reexec-child").CombinedOutput()
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

	spec := &cloudflare.Spec{Hostname: "chain.trycloudflare.com"}
	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
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
// TUNNEL_SPEC must fail loudly — the tunnel resolves to nothing and the
// cancellation cause names the parse failure on the child's logger.
func TestMalformedSpecEnv(t *testing.T) {
	if role() == "malformed-child" {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		tun := libtunnel.New(libtunnel.Cloudflare()).WithLogger(logger)
		fmt.Printf("hostname=%q\n", tun.Hostname())
		if tun.Hostname() == "" {
			os.Exit(3)
		}
		os.Exit(0) // unexpected: parent will flag the zero exit
	}

	cmd := reexec("TestMalformedSpecEnv", roleEnv+"=malformed-child", v1alpha1.SpecEnv+"={this is not json")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err == nil {
		t.Fatal("child exited 0 with a corrupt TUNNEL_SPEC; want a loud failure")
	}
	if want := "unable to parse TUNNEL_SPEC"; !strings.Contains(string(out), want) {
		t.Errorf("child output does not contain %q (the cancellation cause)", want)
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

	spec := &cloudflare.Spec{Hostname: "scenario.trycloudflare.com:8443"}
	entry, err := v1alpha1.SpecEnviron("cloudflare", spec)
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
