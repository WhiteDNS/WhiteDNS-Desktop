// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// reuseport_unix.go — SO_REUSEPORT UDP listeners.
//
// One socket read by N goroutines serialises on a single kernel receive queue,
// which is the throughput ceiling for a high-packet-rate DNS tunnel long before
// CPU saturates. SO_REUSEPORT lets several sockets bind the same address, and
// the kernel hashes each datagram to one of them, so every reader gets its own
// queue and the contention disappears.
//
// All the sockets share one local address, so a reply written on any of them
// leaves with the same source ip:port. Replying on the socket the request
// arrived on is therefore an affinity choice that also spreads transmit load,
// not a correctness requirement.
// ==============================================================================

//go:build linux || android || darwin || freebsd || netbsd || openbsd || dragonfly

package udpserver

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortSupported reports whether this build can open SO_REUSEPORT sockets.
const reusePortSupported = true

// reusePortControl sets the socket options that let several sockets share one
// address. SO_REUSEPORT is the load-balancing one; SO_REUSEADDR is set
// alongside it because a listener may otherwise be refused while a previous
// socket for the address lingers in TIME_WAIT.
func reusePortControl(_, _ string, c syscall.RawConn) error {
	var ctrlErr error
	if err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			ctrlErr = err
			return
		}
		ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return ctrlErr
}

// listenTCPReusePort opens one of several TCP listeners sharing an address. The
// kernel gives each its own accept queue and assigns an incoming connection to
// one of them at SYN time, so N accept loops no longer contend for a single
// queue.
//
// Caveat worth knowing: if one of these listeners is closed while its siblings
// stay open, connections already sitting in that listener's accept queue are
// reset rather than redistributed. That is acceptable here because the whole
// set is only ever closed together, at shutdown.
func listenTCPReusePort(address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	return lc.Listen(context.Background(), "tcp", address)
}

func listenUDPReusePort(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: reusePortControl}

	pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}

	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errReusePortUnsupported
	}
	return conn, nil
}
