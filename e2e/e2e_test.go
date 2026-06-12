package e2e

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// runTimeout bounds a single example run. A wedged example (e.g. a
// rate-limited mint retrying forever) must fail its own test, not time the
// whole suite out.
const runTimeout = 120 * time.Second

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
// exitCode is -1 if the process could not be started or was killed by the
// run timeout.
func (r *runner) run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.bin, args...).CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if ctx.Err() != nil {
		t.Errorf("%s did not finish within %v", r.name, runTimeout)
	}
	t.Logf("$ %s %s (exit %d)\n%s", r.name, strings.Join(args, " "), code, out)
	return string(out), code
}

// assertExample builds an example, runs it, and checks the exit code is 0 and
// stdout contains want. Each example added under examples/ should get a row in
// the table below.
func assertExample(t *testing.T, name, want string) string {
	t.Helper()
	r := newRunner(t, name)
	out, code := r.run(t)
	if code != 0 {
		t.Errorf("%s exited %d, want 0", name, code)
	}
	if !strings.Contains(out, want) {
		t.Errorf("%s output %q does not contain %q", name, out, want)
	}
	return out
}

func TestExamples(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		live   bool                           // mints a real tunnel; gated behind LIBTUNNEL_E2E_LIVE=1
		verify func(t *testing.T, out string) // optional deeper assertions on the same run
	}{
		{"serve", "served: hello from libtunnel", true, nil},
		{"handoff", "handoff: hello from the child", true, verifySharedHostname},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.live {
				if os.Getenv("LIBTUNNEL_E2E_LIVE") != "1" {
					t.Skip("live example (mints a real quick tunnel); set LIBTUNNEL_E2E_LIVE=1 to run")
				}
				// No t.Parallel, and paced: live cases mint real tunnels,
				// and burst minting invites 429s and edge-propagation races.
				paceLive()
			}
			out := assertExample(t, tc.name, tc.want)
			if tc.verify != nil {
				tc.verify(t, out)
			}
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

// verifySharedHostname asserts the parent→child spec handoff on the handoff
// example's output: the parent mints a hostname, the child (a subprocess)
// provides the listener and connects, and both interact with the tunnel
// under the exact same hostname.
func verifySharedHostname(t *testing.T, out string) {
	t.Helper()

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
}
