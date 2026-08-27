package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
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
	cmd := exec.CommandContext(ctx, r.bin, args...)
	// CombinedOutput reads until every writer closes the pipe. If an example
	// wedges and is killed on ctx while anything it spawned still holds the
	// pipe, the read — and the whole suite — blocks past runTimeout with
	// nothing to show for it. WaitDelay closes the pipe regardless, turning a
	// wedged example back into a test failure carrying whatever output it did
	// produce.
	cmd.WaitDelay = 5 * time.Second
	// Run examples at Debug so a CI failure (e.g. a DNS-readiness stall) carries
	// the per-rung probe detail; the examples default to Info for humans.
	// Both names: v1.LogEnv is what the library reads, LIBTUNNEL_LOG_LEVEL what
	// serve-tls checks to build its own logger.
	//
	// Each example gets its own spec cache: a child is a fresh process, so an
	// inherited cache dir would let its mint read the suite's (or another
	// example's) latest.spec.json and reclaim that tunnel — putting this
	// example on a hostname whose dead connectors still hold sticky edge
	// routes. Scoped, not throwaway (#147): the example's own previous mint
	// persists via the CI spec cache, so the next run reclaims the same
	// hostname instead of leaking a fresh one.
	cmd.Env = append(os.Environ(), v1.LogEnv+"=debug", "LIBTUNNEL_LOG_LEVEL=debug",
		v1.CacheDirEnv+"="+scopedCacheDir(t, "example-"+r.name))
	out, err := cmd.CombinedOutput()
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
		live   bool                           // mints a real tunnel; skipped under -short (see skipUnlessLive)
		verify func(t *testing.T, out string) // optional deeper assertions on the same run
	}{
		{"serve", "served: hello from libtunnel", true, nil},
		{"serve-tls", "served: hello from libtunnel (tls)", true, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.live {
				skipUnlessLive(t)
				if !exampleCell() {
					t.Skip("live examples tier runs on one CI cell per OS family (#147)")
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
