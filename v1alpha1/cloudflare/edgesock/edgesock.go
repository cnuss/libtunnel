// Package edgesock reads the TCP state of the sockets cloudflared holds to the
// tunnel edge. cloudflared dials them itself and hands nothing back, so they
// are found among this process's own descriptors by their peer address, and
// only ever inspected: never read from, written to, or closed.
//
// One HTTP/2 connection carries every request on it, so a socket that stops
// draining stalls them all. Its readings tell the two kinds of stall apart:
// retransmissions climbing is loss on the way, a peer window of zero is the
// edge not taking what was sent.
package edgesock

import (
	"errors"
	"time"
)

// errGone is what a Socket answers once its descriptor is no longer the
// socket it was found as: closed, or reused for something else.
var errGone = errors.New("edge socket closed")

// Stats is one reading of a socket's TCP state.
type Stats struct {
	// Queued is the bytes in the send buffer: written and not yet
	// acknowledged, sent or not.
	Queued uint64
	// Progress counts new data sent on acknowledgements, and only grows.
	Progress uint64
	// Retransmitted counts bytes sent again, and only grows.
	Retransmitted uint64
	// PeerWindow is the receive window the peer last advertised, in bytes.
	PeerWindow uint64
}

// Change is what a reading changed about a socket's stall.
type Change int

const (
	None Change = iota
	Stalled
	Recovered
)

func (c Change) String() string {
	switch c {
	case Stalled:
		return "stalled"
	case Recovered:
		return "recovered"
	default:
		return "none"
	}
}

// Stall tells from a socket's readings when it stops making progress: bytes
// queued and no progress for the whole of After. An empty buffer is never a
// stall, however long it stays empty.
type Stall struct {
	After time.Duration

	last    Stats
	since   time.Time // the last reading with progress or an empty buffer
	stalled bool
}

// Observe takes a reading made at now and reports what it changed.
func (s *Stall) Observe(now time.Time, r Stats) Change {
	moving := r.Queued == 0 || s.since.IsZero() || r.Progress != s.last.Progress
	s.last = r
	if moving {
		s.since = now
		if s.stalled {
			s.stalled = false
			return Recovered
		}
		return None
	}
	if !s.stalled && now.Sub(s.since) >= s.After {
		s.stalled = true
		return Stalled
	}
	return None
}

// For is how long the current stall has lasted at now, or zero when there is
// none.
func (s *Stall) For(now time.Time) time.Duration {
	if !s.stalled {
		return 0
	}
	return now.Sub(s.since)
}
