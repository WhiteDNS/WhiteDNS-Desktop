// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net"
	"runtime"
	"testing"

	"cottendns-go/internal/config"
)

// Sockets must never outnumber readers, or a socket would sit unread. They must
// also stay at or below the CPU count: extra queues past the cores that drain
// them buy nothing and multiply SO_RCVBUF memory. Crucially, when readers
// exceed the cap the surplus readers double up on shared sockets, so a single
// heavy flow is never pinned to one reader's worth of decrypt.
func TestUDPSocketCountNeverStarvesOrOversubscribes(t *testing.T) {
	cpus := runtime.NumCPU()
	for _, readers := range []int{0, 1, 2, 3, 7, 16, 64, 512} {
		got := udpSocketCount(readers)

		if got < 1 {
			t.Fatalf("readers=%d: socket count %d, must be at least 1", readers, got)
		}
		if readers >= 1 && got > readers {
			t.Fatalf("readers=%d: %d sockets would leave sockets unread", readers, got)
		}
		if got > cpus {
			t.Fatalf("readers=%d: %d sockets exceeds %d CPUs", readers, got, cpus)
		}
	}

	if udpSocketCount(1) != 1 {
		t.Fatal("a single reader must use exactly one socket")
	}
	if got := udpSocketCount(7); got != min(3, cpus) {
		t.Fatalf("seven readers: socket count %d, want %d so readers share queues", got, min(3, cpus))
	}
	// Far more readers than cores must collapse onto the CPU cap, leaving
	// multiple readers per socket rather than one flow per reader.
	if got := udpSocketCount(cpus * 8); got != cpus {
		t.Fatalf("readers=%d: socket count %d, want the CPU cap %d", cpus*8, got, cpus)
	}
}

// freeUDPPort reserves an ephemeral port and releases it, so the reuse-port
// sockets under test can all bind one concrete port. Port 0 cannot be used
// here: each SO_REUSEPORT socket would be assigned its own ephemeral port
// instead of sharing one, which is not how the server binds in production.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("reserve ephemeral port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// listenUDP must hand back the calculated socket count where SO_REUSEPORT
// exists and exactly one shared socket where it does not. The calculated count
// deliberately keeps multiple readers on each socket and caps queues at the
// available CPU count.
func TestListenUDPSocketCountMatchesPlatform(t *testing.T) {
	const readers = 4
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)}

	s := &Server{cfg: config.ServerConfig{UDPReaders: readers}}
	conns, err := s.listenUDP(addr)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	want := 1
	if reusePortSupported {
		want = udpSocketCount(readers)
	}
	if len(conns) != want {
		t.Fatalf("socket count = %d, want %d (reusePortSupported=%v)", len(conns), want, reusePortSupported)
	}

	// Whichever path was taken, every socket must answer on the one address
	// clients were told to reach, or replies would leave from the wrong port.
	for i, conn := range conns {
		got := conn.LocalAddr().(*net.UDPAddr)
		if got.Port != addr.Port {
			t.Fatalf("socket %d bound port %d, want %d", i, got.Port, addr.Port)
		}
	}
}

// A single reader must not take the reuse-port path at all: opening one socket
// with SO_REUSEPORT buys nothing and would differ from the long-standing
// single-socket behaviour for no reason.
func TestListenUDPSingleReaderUsesOneSocket(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)}

	s := &Server{cfg: config.ServerConfig{UDPReaders: 1}}
	conns, err := s.listenUDP(addr)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	if len(conns) != 1 {
		t.Fatalf("socket count = %d, want 1", len(conns))
	}
}

// The datagram must come back from the address the client sent to, whichever
// socket the kernel handed it to. This is the property that makes replying on
// the arrival socket safe.
func TestReusePortSocketsShareReplyAddress(t *testing.T) {
	const readers = 3
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)}

	s := &Server{cfg: config.ServerConfig{UDPReaders: readers}}
	conns, err := s.listenUDP(addr)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer client.Close()

	// Reply from the last socket regardless of which one would have received
	// the request: they share a local address, so the client cannot tell.
	if _, err := conns[len(conns)-1].WriteToUDP([]byte("pong"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	buf := make([]byte, 16)
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("payload = %q, want %q", buf[:n], "pong")
	}
	if from.Port != addr.Port {
		t.Fatalf("reply came from port %d, want %d", from.Port, addr.Port)
	}
}
