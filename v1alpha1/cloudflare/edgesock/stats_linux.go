package edgesock

import "golang.org/x/sys/unix"

// stats reads TCP_INFO, and the send queue's size from TIOCOUTQ, which on a
// socket is every byte not yet acknowledged, sent or not.
func stats(fd int) (Stats, error) {
	i, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return Stats{}, err
	}
	queued, err := unix.IoctlGetInt(fd, unix.TIOCOUTQ)
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		Queued:        uint64(queued),
		Progress:      i.Bytes_acked,
		Retransmitted: i.Bytes_retrans,
		PeerWindow:    uint64(i.Snd_wnd),
	}, nil
}
