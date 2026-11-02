package edgesock

import (
	"testing"
	"time"
)

// TestStall pins what counts as a stall: bytes waiting to go with nothing new
// acknowledged for the whole of After. An empty buffer is never one, however
// long it stays empty, and any acknowledgement ends one.
func TestStall(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	queued := func(q, progress uint64) Stats { return Stats{Queued: q, Progress: progress} }

	for _, tc := range []struct {
		name  string
		reads []Stats
		want  []Change
	}{
		{
			name:  "idle with an empty buffer",
			reads: []Stats{queued(0, 10), queued(0, 10), queued(0, 10), queued(0, 10), queued(0, 10), queued(0, 10), queued(0, 10)},
			want:  []Change{None, None, None, None, None, None, None},
		},
		{
			name:  "queued but acknowledged every second",
			reads: []Stats{queued(500, 10), queued(500, 20), queued(500, 30), queued(500, 40), queued(500, 50), queued(500, 60), queued(500, 70)},
			want:  []Change{None, None, None, None, None, None, None},
		},
		{
			name:  "queued with no progress for five seconds",
			reads: []Stats{queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10)},
			want:  []Change{None, None, None, None, None, Stalled, None},
		},
		{
			name:  "a stall ends on the next acknowledgement",
			reads: []Stats{queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 11)},
			want:  []Change{None, None, None, None, None, Stalled, Recovered},
		},
		{
			name:  "a stall ends when the buffer drains",
			reads: []Stats{queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(0, 10)},
			want:  []Change{None, None, None, None, None, Stalled, Recovered},
		},
		{
			name:  "progress restarts the clock",
			reads: []Stats{queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 10), queued(500, 11), queued(500, 11), queued(500, 11)},
			want:  []Change{None, None, None, None, None, None, None},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Stall{After: 5 * time.Second}
			for i, r := range tc.reads {
				if got := s.Observe(at(i), r); got != tc.want[i] {
					t.Fatalf("read %d (%+v) = %v, want %v", i, r, got, tc.want[i])
				}
			}
		})
	}
}

// TestStallFor pins how long a stall has lasted: zero when there is none, and
// measured from the last read that saw progress.
func TestStallFor(t *testing.T) {
	t0 := time.Unix(1000, 0)
	s := Stall{After: 2 * time.Second}
	s.Observe(t0, Stats{Queued: 1, Progress: 1})
	if got := s.For(t0.Add(time.Second)); got != 0 {
		t.Errorf("For before a stall = %v, want 0", got)
	}
	s.Observe(t0.Add(3*time.Second), Stats{Queued: 1, Progress: 1})
	if got := s.For(t0.Add(4 * time.Second)); got != 4*time.Second {
		t.Errorf("For during a stall = %v, want 4s", got)
	}
}
