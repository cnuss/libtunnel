package e2e

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runner builds one example binary, then runs it. The harness builds at test
// time (not via `go build ./...`) so example source changes are always picked
// up — that's why `make e2e` passes -count=1 to defeat the test cache.
type runner struct {
	name string
	bin  string
}

func newRunner(t *testing.T, name string) *runner {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../examples/"+name).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	return &runner{name: name, bin: bin}
}

// run executes the built example with args and returns (output, exitCode).
// exitCode is -1 if the process could not be started.
func (r *runner) run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	out, err := exec.Command(r.bin, args...).CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	t.Logf("$ %s %s (exit %d)\n%s", r.name, strings.Join(args, " "), code, out)
	return string(out), code
}

// assertExample builds an example, runs it, and checks the exit code is 0 and
// stdout contains want. Each example added under examples/ should get a row in
// the table below.
func assertExample(t *testing.T, name, want string) {
	t.Helper()
	r := newRunner(t, name)
	out, code := r.run(t)
	if code != 0 {
		t.Errorf("%s exited %d, want 0", name, code)
	}
	if !strings.Contains(out, want) {
		t.Errorf("%s output %q does not contain %q", name, out, want)
	}
}

func TestExamples(t *testing.T) {
	cases := []struct {
		name string
		want string
		live bool // mints a real tunnel; gated behind LIBTUNNEL_E2E_LIVE=1
	}{
		{"serve", "served: hello from libtunnel", true},
		{"handoff", "handoff: hello from the child", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.live && os.Getenv("LIBTUNNEL_E2E_LIVE") != "1" {
				t.Skip("live example (mints a real quick tunnel); set LIBTUNNEL_E2E_LIVE=1 to run")
			}
			t.Parallel()
			assertExample(t, tc.name, tc.want)
		})
	}
}

// capture returns the remainder of the first output line starting with
// prefix, and whether one was found.
func capture(out, prefix string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
			return rest, true
		}
	}
	return "", false
}

// TestHandoffSharedHostname runs the handoff example and asserts the
// parent→child spec handoff end to end: the parent mints a hostname, the
// child (a subprocess) provides the listener and connects, and both interact
// with the tunnel under the exact same hostname.
func TestHandoffSharedHostname(t *testing.T) {
	if os.Getenv("LIBTUNNEL_E2E_LIVE") != "1" {
		t.Skip("live example (mints a real quick tunnel); set LIBTUNNEL_E2E_LIVE=1 to run")
	}

	r := newRunner(t, "handoff")
	out, code := r.run(t)
	if code != 0 {
		t.Fatalf("handoff exited %d, want 0", code)
	}

	minted, ok := capture(out, "minted: ")
	if !ok {
		t.Fatalf("parent never printed the minted hostname:\n%s", out)
	}

	ready, ok := capture(out, "child: ready: ")
	if !ok {
		t.Fatalf("child never reported the tunnel ready:\n%s", out)
	}
	childURL, err := url.Parse(ready)
	if err != nil {
		t.Fatalf("child ready line %q is not a URL: %v", ready, err)
	}
	if childURL.Hostname() != minted {
		t.Errorf("child connected under %q, want the parent's minted hostname %q", childURL.Hostname(), minted)
	}

	// The parent fetched through its own handle on the minted hostname; the
	// served body proves the same tunnel carried both processes' traffic.
	if want := "handoff: hello from the child"; !strings.Contains(out, want) {
		t.Errorf("output does not contain %q — the parent's request through the shared hostname failed", want)
	}
}
