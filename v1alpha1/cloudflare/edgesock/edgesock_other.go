//go:build !darwin && !linux

package edgesock

import (
	"errors"
	"net/netip"
)

// Socket finds nothing here: there is no way yet to read another socket's TCP
// state on this platform.
type Socket struct{}

func (Socket) Local() netip.AddrPort { return netip.AddrPort{} }
func (Socket) Peer() netip.AddrPort  { return netip.AddrPort{} }
func (Socket) Same() bool            { return false }
func (Socket) Stats() (Stats, error) { return Stats{}, errors.ErrUnsupported }

func Find(netip.AddrPort, func(netip.AddrPort) bool) (Socket, error) {
	return Socket{}, errors.ErrUnsupported
}
