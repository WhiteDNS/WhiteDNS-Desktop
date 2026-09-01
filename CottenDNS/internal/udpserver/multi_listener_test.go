// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// Every connection accepted on any underlying listener must surface through the
// single Accept(), because the connection accounting upstream (TCPMaxConns and
// the per-IP cap) is keyed to one logical listener. A connection that bypassed
// it would be a connection that escaped those limits.
func TestMultiListenerSurfacesConnectionsFromEveryListener(t *testing.T) {
	const count = 3

	listeners := make([]net.Listener, 0, count)
	for range count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
	}

	multi := newMultiListener(listeners)
	defer multi.Close()

	accepted := make(chan net.Addr, count)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range count {
			conn, err := multi.Accept()
			if err != nil {
				return
			}
			accepted <- conn.LocalAddr()
			_ = conn.Close()
		}
	}()

	// Dial each underlying listener; all three must come out of the one Accept.
	for i, ln := range listeners {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial listener %d: %v", i, err)
		}
		_ = conn.Close()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("only %d of %d connections surfaced through Accept", len(accepted), count)
	}

	if len(accepted) != count {
		t.Fatalf("accepted %d connections, want %d", len(accepted), count)
	}
}

// Close must shut every underlying listener, not just the first, or a socket
// would keep accepting after shutdown.
func TestMultiListenerCloseClosesAllListeners(t *testing.T) {
	const count = 3

	listeners := make([]net.Listener, 0, count)
	addrs := make([]string, 0, count)
	for range count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		addrs = append(addrs, ln.Addr().String())
	}

	multi := newMultiListener(listeners)
	if err := multi.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Close must be idempotent: the server closes on ctx cancel and again via defer.
	if err := multi.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	for i, ln := range listeners {
		if _, err := ln.Accept(); err == nil {
			t.Fatalf("listener %d (%s) still accepting after Close", i, addrs[i])
		}
	}
}

// The TCP path must keep working where SO_REUSEPORT does not exist, and must
// bind the address it was asked for either way.
func TestListenTCPSharedFallsBackCleanly(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	address := probe.Addr().String()
	_ = probe.Close()

	s := &Server{cfg: config.ServerConfig{UDPReaders: 4}}
	ln, err := s.listenTCPShared(address, 4)
	if err != nil {
		t.Fatalf("listenTCPShared: %v", err)
	}
	defer ln.Close()

	if got := ln.Addr().String(); got != address {
		t.Fatalf("bound %s, want %s", got, address)
	}

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = accepted.Close()
}

func TestListenTCP53AcceptsIPv4AndIPv6(t *testing.T) {
	v6Probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = v6Probe.Close()
	v4Probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := v4Probe.Addr().(*net.TCPAddr).Port
	_ = v4Probe.Close()

	s := &Server{cfg: config.ServerConfig{
		UDPReaders:     1,
		TCPIPv6Enabled: true,
		TCPIPv6Host:    "::1",
	}}
	ln, err := s.listenTCP53("127.0.0.1", port)
	if err != nil {
		t.Fatalf("listenTCP53: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 2)
	go func() {
		for range 2 {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	for _, address := range []string{
		net.JoinHostPort("127.0.0.1", itoaPort(port)),
		net.JoinHostPort("::1", itoaPort(port)),
	} {
		conn, dialErr := net.DialTimeout("tcp", address, 5*time.Second)
		if dialErr != nil {
			t.Fatalf("dial %s: %v", address, dialErr)
		}
		_ = conn.Close()
	}
	for range 2 {
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("dual-stack TCP listener did not accept both families")
		}
	}
}
