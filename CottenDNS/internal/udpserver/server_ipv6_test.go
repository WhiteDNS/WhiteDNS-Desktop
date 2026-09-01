package udpserver

import (
	"net"
	"testing"

	"cottendns-go/internal/config"
)

func TestServerListenUDPIPv6(t *testing.T) {
	s := &Server{cfg: config.ServerConfig{UDPReaders: 1}}
	conns, err := s.listenUDP(&net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	if len(conns) != 1 {
		t.Fatalf("IPv6 listeners = %d, want 1", len(conns))
	}
	addr := conns[0].LocalAddr().(*net.UDPAddr)
	if addr.IP.To4() != nil {
		t.Fatalf("server listener is not IPv6: %v", addr)
	}
}

// TestServerListenUDPForcesIPv4Family guards the dual-stack fix: a wildcard-ish
// IPv4 bind must yield an IPv4 socket (network udp4), so the separate IPv6
// listener the server opens alongside it is not shadowed by an accidental
// dual-stack socket.
func TestServerListenUDPForcesIPv4Family(t *testing.T) {
	s := &Server{cfg: config.ServerConfig{UDPReaders: 1}}
	conns, err := s.listenUDP(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listenUDP v4: %v", err)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	if addr := conns[0].LocalAddr().(*net.UDPAddr); addr.IP.To4() == nil {
		t.Fatalf("expected IPv4 listener, got %v", addr)
	}
}
