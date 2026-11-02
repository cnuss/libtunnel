//go:build darwin || linux

package edgesock

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// records is a slog handler that hands every record's message and attributes
// to a channel, for a test to wait on from another goroutine.
type records chan slog.Record

func (r records) Enabled(context.Context, slog.Level) bool { return true }
func (r records) Handle(_ context.Context, rec slog.Record) error {
	r <- rec.Clone()
	return nil
}
func (r records) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r records) WithGroup(string) slog.Handler      { return r }

// next is the next record whose message is msg, failing the test after a
// deadline; records with other messages are passed over.
func (r records) next(t *testing.T, msg string) slog.Record {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case rec := <-r:
			if rec.Message == msg {
				return rec
			}
		case <-deadline:
			t.Fatalf("no %q logged", msg)
		}
	}
}

func attr(rec slog.Record, key string) slog.Value {
	var v slog.Value
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v = a.Value
			return false
		}
		return true
	})
	return v
}

// TestSocketWatchLogsAStall pins the watcher end to end on a real socket: the
// socket found is named; a peer that stops reading is logged as a stall on
// that connection index, with the
// bytes left queued; reading again is logged as recovered; and the socket
// closing ends the watch with its final figures.
func TestSocketWatchLogsAStall(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	edge := netip.MustParseAddrPort(l.Addr().String())
	client, err := net.Dial("tcp", edge.String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()

	got := make(records, 64)
	w := NewWatch()
	w.port, w.interval, w.after = edge.Port(), 50*time.Millisecond, 300*time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.Connected(ctx, 1, net.IP(edge.Addr().AsSlice()), slog.New(got))

	found := got.next(t, "watching edge connection socket")
	if l := attr(found, "local").String(); l != client.LocalAddr().String() {
		t.Errorf("watching local = %q, want the client's %q", l, client.LocalAddr())
	}

	// Far more than the two ends' buffers hold, so the writer blocks and bytes
	// stay queued while the peer reads nothing.
	go func() { _, _ = client.Write(make([]byte, 64<<20)) }()

	stalled := got.next(t, "edge connection stalled")
	if i := attr(stalled, "connIndex").Uint64(); i != 1 {
		t.Errorf("stalled connIndex = %d, want 1", i)
	}
	if q := attr(stalled, "queued_bytes").Uint64(); q == 0 {
		t.Error("stalled queued_bytes = 0, want what the peer left unread")
	}

	go func() { _, _ = io.Copy(io.Discard, server) }()
	got.next(t, "edge connection recovered")

	client.Close()
	got.next(t, "edge connection ended")
}

// TestSocketWatchFindsNothingQuietly pins that a connection whose socket cannot
// be found, such as one carried through the bridge's loopback forwarder, is
// logged once and left alone.
func TestSocketWatchFindsNothingQuietly(t *testing.T) {
	got := make(records, 8)
	w := NewWatch()
	w.port, w.findFor = 1, 200*time.Millisecond
	w.Connected(t.Context(), 0, net.IPv4(127, 0, 0, 1), slog.New(got))
	got.next(t, "edge connection socket not found")
}
