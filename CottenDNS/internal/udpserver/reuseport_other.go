// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// reuseport_other.go — fallback for platforms without SO_REUSEPORT (Windows,
// and anything else not covered by reuseport_unix.go). Windows has
// SO_REUSEADDR, but its semantics for UDP are hijacking rather than
// load-balancing, so it is deliberately not used here: the caller falls back to
// a single shared socket, which is exactly the behaviour that shipped before.
// ==============================================================================

//go:build !(linux || android || darwin || freebsd || netbsd || openbsd || dragonfly)

package udpserver

import "net"

const reusePortSupported = false

func listenUDPReusePort(_ *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errReusePortUnsupported
}

func listenTCPReusePort(_ string) (net.Listener, error) {
	return nil, errReusePortUnsupported
}
