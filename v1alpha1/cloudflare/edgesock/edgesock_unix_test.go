//go:build darwin || linux

package edgesock

import (
	"io"
	"net"
	"net/netip"
	"testing"
)

// pair is a connected TCP pair on loopback, closed with the test.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func addrPort(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// TestFind pins that a socket is found by its peer, that skip passes over one
// by its local address, and that a peer nothing is connected to finds nothing.
func TestFind(t *testing.T) {
	client, _ := pair(t)
	peer, local := addrPort(t, client.RemoteAddr()), addrPort(t, client.LocalAddr())

	s, err := Find(peer, nil)
	if err != nil {
		t.Fatalf("Find(%v) = %v", peer, err)
	}
	if s.Local() != local || s.Peer() != peer {
		t.Errorf("Find(%v) = %v -> %v, want %v -> %v", peer, s.Local(), s.Peer(), local, peer)
	}
	if !s.Same() {
		t.Error("Same() = false for a socket still open")
	}

	if _, err := Find(peer, func(l netip.AddrPort) bool { return l == local }); err == nil {
		t.Error("Find with that socket skipped found it anyway")
	}
	if _, err := Find(netip.MustParseAddrPort("127.0.0.1:1"), nil); err == nil {
		t.Error("Find for a peer nothing is connected to found something")
	}
}

// TestSameAfterClose pins that a closed socket is no longer the same one, so
// a descriptor the system has since reused is never read as it.
func TestSameAfterClose(t *testing.T) {
	client, _ := pair(t)
	s, err := Find(addrPort(t, client.RemoteAddr()), nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if s.Same() {
		t.Error("Same() = true after the socket was closed")
	}
	if _, err := s.Stats(); err == nil {
		t.Error("Stats() on a closed socket = nil error")
	}
}

// TestStats pins that a socket's reading moves as data is sent and taken: the
// acknowledged count grows, and nothing is left queued once the peer has read
// everything.
func TestStats(t *testing.T) {
	client, server := pair(t)
	s, err := Find(addrPort(t, client.RemoteAddr()), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats() = %v", err)
	}
	const n = 256 << 10
	go func() { _, _ = client.Write(make([]byte, n)) }()
	if _, err := io.ReadFull(server, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	var after Stats
	for range 100 {
		if after, err = s.Stats(); err != nil {
			t.Fatal(err)
		}
		if after.Queued == 0 {
			break
		}
	}
	if after.Progress < before.Progress+n {
		t.Errorf("Progress %d -> %d after %d bytes taken, want it to grow by at least that", before.Progress, after.Progress, n)
	}
	if after.Queued != 0 {
		t.Errorf("Queued = %d after the peer read everything, want 0", after.Queued)
	}
	if after.PeerWindow == 0 {
		t.Error("PeerWindow = 0 on a peer that is reading")
	}
}
