package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestProbeRejectsAMalformedIDWithoutAsking pins that a tunnel id that cannot
// be a tunnel is answered here rather than at the edge: the id is parsed
// before anything is dialed, so a caller that fat-fingers one gets the answer
// without a round trip — and gets it as ErrGone, which is what ends a tunnel.
func TestProbeRejectsAMalformedIDWithoutAsking(t *testing.T) {
	start := time.Now()
	err := New().WithID("not-a-uuid").Probe(context.WithCancel(context.Background()))
	if !errors.Is(err, ErrGone) {
		t.Errorf("probe answered %v, want ErrGone", err)
	}
	// A dial would not fit in this; discovery alone takes longer.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("probe took %s, want the id rejected before the edge is asked", elapsed)
	}
}

// TestProbeStopsWithTheContextRatherThanGuessing pins the distinction the
// tunnel's life hangs on: an ask that never reached the edge is reported as
// one, not as a verdict. Only ErrGone ends a tunnel, so a probe that cannot
// ask — no network, a deadline, a cancelled caller — must not return it,
// however many attempts it burns.
func TestProbeStopsWithTheContextRatherThanGuessing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := New().
		WithID("cc90e77f-5ce4-4782-b5df-70c0bca10807").
		WithHostname("libtunnel-probe-test.invalid").
		Probe(ctx, cancel)
	if errors.Is(err, ErrGone) {
		t.Errorf("probe reported the tunnel gone without an answer: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("probe answered %v, want the cancellation as the cause", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("probe returned after %s, want it to stop with the context", elapsed)
	}
}

// TestProbeWithoutAHostnameAnswersOnce pins what a prober built without a
// hostname does: a refusal cannot be weighed without one, so there is no
// verdict to be had — and since asking again cannot conjure a hostname, the
// answer is neither ErrRetry nor ErrGone, and it comes back before any dial.
func TestProbeWithoutAHostnameAnswersOnce(t *testing.T) {
	start := time.Now()
	err := New().
		WithID("cc90e77f-5ce4-4782-b5df-70c0bca10807").
		Probe(context.WithTimeout(context.Background(), 10*time.Second))

	if err == nil {
		t.Fatal("probe answered nil without a hostname")
	}
	if errors.Is(err, ErrRetry) {
		t.Error("probe asked to be retried for something retrying cannot fix")
	}
	if errors.Is(err, ErrGone) {
		t.Error("probe reported the tunnel gone without asking the edge")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("probe took %s, want the answer before any dial", elapsed)
	}
}
