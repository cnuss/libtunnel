//go:build darwin || linux

package edgesock

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Socket is a TCP socket of this process's, known by its descriptor and the
// address pair it had when found.
type Socket struct {
	fd          int
	local, peer netip.AddrPort
}

func (s Socket) Local() netip.AddrPort { return s.local }
func (s Socket) Peer() netip.AddrPort  { return s.peer }

// Find is this process's TCP socket connected to peer, among those whose local
// address skip, when given, does not pass over.
func Find(peer netip.AddrPort, skip func(local netip.AddrPort) bool) (Socket, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return Socket{}, err
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		local, p, ok := addrs(fd)
		if !ok || p != peer || (skip != nil && skip(local)) {
			continue
		}
		return Socket{fd: fd, local: local, peer: p}, nil
	}
	return Socket{}, fmt.Errorf("no socket connected to %v", peer)
}

// Same reports whether the descriptor is still the socket it was found as. A
// descriptor is reused as soon as it is closed, so this is asked before every
// reading.
func (s Socket) Same() bool {
	local, peer, ok := addrs(s.fd)
	return ok && local == s.local && peer == s.peer
}

// Stats is a reading of the socket's TCP state.
func (s Socket) Stats() (Stats, error) {
	if !s.Same() {
		return Stats{}, errGone
	}
	return stats(s.fd)
}

// addrs is fd's local and peer address when it is a connected TCP socket.
func addrs(fd int) (local, peer netip.AddrPort, ok bool) {
	if t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != unix.SOCK_STREAM {
		return local, peer, false
	}
	p, err := unix.Getpeername(fd)
	if err != nil {
		return local, peer, false
	}
	l, err := unix.Getsockname(fd)
	if err != nil {
		return local, peer, false
	}
	local, lok := fromSockaddr(l)
	peer, pok := fromSockaddr(p)
	return local, peer, lok && pok
}

func fromSockaddr(sa unix.Sockaddr) (netip.AddrPort, bool) {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(a.Addr).Unmap(), uint16(a.Port)), true
	}
	return netip.AddrPort{}, false
}
