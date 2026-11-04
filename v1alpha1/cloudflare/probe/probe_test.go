package probe

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// TestProbeRejectsAMalformedIDWithoutAsking pins that a tunnel id that cannot
// be a tunnel is answered here rather than at the edge: the id is parsed
// before anything is dialed, so a caller that fat-fingers one gets the answer
// without a round trip — and gets it as ErrGone, which is what ends a tunnel.
func TestProbeRejectsAMalformedIDWithoutAsking(t *testing.T) {
	start := time.Now()
	err := New().WithID("not-a-uuid").Probe(context.WithCancelCause(context.Background()))
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
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(nil)

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

// TestIPv4First pins the order a DoH answer is handed on in: IPv4 before
// IPv6, each family as it came. A machine with no working IPv6 route can drop
// packets to an IPv6 address rather than refuse them, and the edge is reached
// over IPv4 only.
func TestIPv4First(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"2606:4700:a0::1", "104.21.33.129", "2606:4700:a0::2", "172.67.145.48"},
			[]string{"104.21.33.129", "172.67.145.48", "2606:4700:a0::1", "2606:4700:a0::2"}},
		{[]string{"198.41.192.7", "198.41.192.67"}, []string{"198.41.192.7", "198.41.192.67"}},
		{[]string{"2606:4700:a0::1"}, []string{"2606:4700:a0::1"}},
		{nil, nil},
	} {
		if got := ipv4First(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("ipv4First(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
