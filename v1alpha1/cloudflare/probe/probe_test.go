package probe

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/rs/zerolog"
)

// counting is a logger that counts lines carrying msg, so a test can watch
// Run ask without reaching the edge: over a protocol with no registration
// path every probe ends before dialing, and Run logs it.
type counting struct {
	mu   sync.Mutex
	msg  string
	seen int
}

func (c *counting) Write(b []byte) (int, error) {
	if strings.Contains(string(b), c.msg) {
		c.mu.Lock()
		c.seen++
		c.mu.Unlock()
	}
	return len(b), nil
}

func (c *counting) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen
}

// unsupported is a protocol Probe has no registration path for, so a probe
// over it ends without reaching the edge.
const unsupported = connection.Protocol(99)

func watched(t *testing.T, interval time.Duration) (*Prober, *counting) {
	t.Helper()
	c := &counting{msg: "probe got no answer"}
	log := zerolog.New(c)
	return New().WithInterval(interval).WithProtocol(unsupported).WithLogger(&log), c
}

// TestRunKeepsAsking pins that the prober keeps asking. A tunnel reaped while
// its connections still look fine produces no edge event, so waiting for one
// is waiting forever.
func TestRunKeepsAsking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, probes := watched(t, 50*time.Millisecond)

	go p.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for probes.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := probes.count(); got < 3 {
		t.Errorf("probed %d times, want the loop to keep going", got)
	}
}

// TestRunStopsWithTheContext pins that nothing outlives the tunnel: a probe
// firing after close would dial the edge on behalf of something already gone.
func TestRunStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, probes := watched(t, 50*time.Millisecond)

	go p.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for probes.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	settled := probes.count()
	time.Sleep(300 * time.Millisecond)
	if got := probes.count(); got > settled+1 {
		t.Errorf("probed %d times after the context ended, want the loop stopped", got-settled)
	}
}

// TestProbeOnlyAcceptsNXDOMAIN pins the narrow reading of the DNS check. A
// provider that reaps a tunnel deletes its record, so a name that positively
// does not exist answers the question — but a resolver that is merely
// unhappy does not, and treating the two alike would report a healthy
// tunnel gone every time the machine's DNS wobbled. Over a protocol with no
// registration path, a probe that gets past the DNS check ends there without
// dialing, which is how a not-gone verdict shows here.
func TestProbeOnlyAcceptsNXDOMAIN(t *testing.T) {
	ctx := context.Background()

	// RFC 2606 reserves .invalid, so no resolver will ever answer for it.
	err := New().WithHostname("libtunnel-reaped.invalid").WithProtocol(unsupported).Probe(context.WithCancel(ctx))
	if !errors.Is(err, ErrGone) {
		t.Skipf("resolver does not return NXDOMAIN here (captive portal or wildcard DNS): %v", err)
	}
	if err := New().WithHostname("one.one.one.one").WithProtocol(unsupported).Probe(context.WithCancel(ctx)); errors.Is(err, ErrGone) {
		t.Error("a resolving hostname reported gone")
	}
	if err := New().WithProtocol(unsupported).Probe(context.WithCancel(ctx)); errors.Is(err, ErrGone) {
		t.Error("an empty hostname reported gone")
	}
	// A cancelled lookup is the resolver being unavailable, not an answer.
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if err := New().WithHostname("libtunnel-reaped.invalid").WithProtocol(unsupported).Probe(dead, cancel); errors.Is(err, ErrGone) {
		t.Error("a cancelled lookup reported gone; only NXDOMAIN is an answer")
	}
}

// TestProbeStripsAPort pins that a hostname carrying :port still resolves —
// a spec's hostname may include one and the resolver will not take it.
func TestProbeStripsAPort(t *testing.T) {
	if err := New().WithHostname("one.one.one.one:443").WithProtocol(unsupported).Probe(context.WithCancel(context.Background())); errors.Is(err, ErrGone) {
		t.Error("a resolving host:port reported gone; the port was not stripped")
	}
}
