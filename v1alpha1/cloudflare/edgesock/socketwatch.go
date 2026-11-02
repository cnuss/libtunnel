package edgesock

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// edgePort is the port cloudflared reaches the edge on.
const edgePort = 7844

// Watch reads each edge connection's socket once a second, so a connection
// that stops draining is logged with the figures that say why, at debug level.
// It only reads: the socket is cloudflared's.
type Watch struct {
	port     uint16
	interval time.Duration // between readings
	after    time.Duration // without progress before a stall is logged
	findFor  time.Duration // to find a connection's socket once it is up

	mu       sync.Mutex
	watching map[uint8]watched
}

type watched struct {
	cancel context.CancelFunc
	local  netip.AddrPort // zero until the socket is found
}

// NewWatch is a Watch with its defaults: a reading a second, and a stall
// logged after five seconds without progress.
func NewWatch() *Watch {
	return &Watch{
		port:     edgePort,
		interval: time.Second,
		after:    5 * time.Second,
		findFor:  2 * time.Second,
		watching: map[uint8]watched{},
	}
}

// Connected watches connection index, now up to the edge at ip, until Ended
// is called for it or ctx ends. The socket is looked for by its peer, passing
// over any another index already holds.
func (w *Watch) Connected(ctx context.Context, index uint8, ip net.IP, log *slog.Logger) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	peer := netip.AddrPortFrom(addr.Unmap(), w.port)
	w.Ended(index)
	ctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.watching[index] = watched{cancel: cancel}
	w.mu.Unlock()
	go func() {
		defer cancel()
		sock, ok := w.find(ctx, index, peer)
		if !ok {
			if ctx.Err() == nil {
				log.Debug("edge connection socket not found", "connIndex", index, "edgeAddress", peer.String())
			}
			return
		}
		log.Debug("watching edge connection socket", "connIndex", index,
			"local", sock.Local().String(), "edgeAddress", sock.Peer().String())
		w.watch(ctx, index, sock, log)
	}()
}

// Ended stops watching connection index.
func (w *Watch) Ended(index uint8) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.watching[index]; ok {
		c.cancel()
		delete(w.watching, index)
	}
}

// find looks for index's socket for up to findFor: Connected fires once the
// connection has registered, so it is there, but the descriptor scan can race
// a reconnect. A socket found is claimed for index under the lock.
func (w *Watch) find(ctx context.Context, index uint8, peer netip.AddrPort) (Socket, bool) {
	deadline := time.Now().Add(w.findFor)
	for {
		w.mu.Lock()
		taken := map[netip.AddrPort]bool{}
		for i, c := range w.watching {
			if i != index && c.local.IsValid() {
				taken[c.local] = true
			}
		}
		sock, err := Find(peer, func(local netip.AddrPort) bool { return taken[local] })
		if err == nil {
			if c, ok := w.watching[index]; ok {
				c.local = sock.Local()
				w.watching[index] = c
			}
		}
		w.mu.Unlock()
		if err == nil {
			return sock, true
		}
		if time.Now().After(deadline) {
			return sock, false
		}
		select {
		case <-ctx.Done():
			return sock, false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// watch reads sock until it closes or ctx ends, logging each stall and its
// end, and the connection's figures once the socket is gone.
func (w *Watch) watch(ctx context.Context, index uint8, sock Socket, log *slog.Logger) {
	start := time.Now()
	stall := Stall{After: w.after}
	var first, last, atStall Stats
	read := false
	defer func() {
		log.Debug("edge connection ended", "connIndex", index,
			"age", time.Since(start).Round(time.Second),
			"progress_bytes", last.Progress-first.Progress,
			"retransmitted_bytes", last.Retransmitted-first.Retransmitted,
			"queued_bytes", last.Queued)
	}()
	tick := time.NewTicker(w.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			r, err := sock.Stats()
			if err != nil {
				return
			}
			if !read {
				first, read = r, true
			}
			last = r
			lasted := stall.For(now)
			switch stall.Observe(now, r) {
			case Stalled:
				atStall = r
				log.Debug("edge connection stalled", "connIndex", index,
					"queued_bytes", r.Queued,
					"no_progress", stall.For(now).Round(time.Second),
					"peer_window_bytes", r.PeerWindow,
					"retransmitted_bytes", r.Retransmitted-first.Retransmitted)
			case Recovered:
				log.Debug("edge connection recovered", "connIndex", index,
					"after", lasted.Round(time.Second),
					"retransmitted_bytes", r.Retransmitted-atStall.Retransmitted)
			}
		}
	}
}
