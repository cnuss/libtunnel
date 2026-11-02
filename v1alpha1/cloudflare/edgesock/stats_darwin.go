package edgesock

import "golang.org/x/sys/unix"

// stats reads TCP_CONNECTION_INFO. darwin counts no acknowledged bytes, so
// Progress is new data sent: past the first window, more goes out only as
// acknowledgements open room for it.
func stats(fd int) (Stats, error) {
	i, err := unix.GetsockoptTCPConnectionInfo(fd, unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		Queued:        uint64(i.Snd_sbbytes),
		Progress:      i.Txbytes - i.Txretransmitbytes,
		Retransmitted: i.Txretransmitbytes,
		PeerWindow:    uint64(i.Snd_wnd),
	}, nil
}
