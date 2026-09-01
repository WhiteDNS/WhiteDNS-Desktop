package client

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIPv6TunnelSocketCarriesDNSDatagram(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()

	conns, err := openTunnelSocketFamily("udp6", 1)
	if err != nil {
		t.Fatalf("open IPv6 tunnel socket: %v", err)
	}
	defer conns[0].Close()

	want := []byte{0x12, 0x34, 0x01, 0x00}
	if _, err := conns[0].WriteToUDP(want, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write IPv6 datagram: %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, peer, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read IPv6 datagram: %v", err)
	}
	if peer.IP.To4() != nil || !peer.IP.IsLoopback() {
		t.Fatalf("unexpected IPv6 peer: %v", peer)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("payload = %x, want %x", buf[:n], want)
	}
}

func TestTunnelSocketPairSelectsMatchingFamily(t *testing.T) {
	v4 := &net.UDPConn{}
	v6 := &net.UDPConn{}
	pair := tunnelSocketPair{v4: v4, v6: v6}
	if got := pair.forAddr(&net.UDPAddr{IP: net.ParseIP("1.1.1.1")}); got != v4 {
		t.Fatal("IPv4 destination did not select IPv4 socket")
	}
	if got := pair.forAddr(&net.UDPAddr{IP: net.ParseIP("2606:4700:4700::1111")}); got != v6 {
		t.Fatal("IPv6 destination did not select IPv6 socket")
	}
}

func TestAsyncWriterUsesIPv6Socket(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	conns, err := openTunnelSocketFamily("udp6", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conns[0].Close()

	c := createTestClient(t)
	c.encodedTXChannel = make(chan encodedOutboundTask, 1)
	ctx, cancel := context.WithCancel(context.Background())
	c.asyncWG.Add(1)
	go c.asyncWriterWorker(ctx, 0, tunnelSocketPair{v6: conns[0]})
	want := []byte{0x12, 0x34, 0x01, 0x00}
	c.encodedTXChannel <- encodedOutboundTask{frames: []encodedOutboundDatagram{{
		addr: server.LocalAddr().(*net.UDPAddr), packet: want, serverKey: "v6",
	}}}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, _, err := server.ReadFromUDP(buf)
	cancel()
	c.asyncWG.Wait()
	if err != nil {
		t.Fatalf("read async IPv6 datagram: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("payload = %x, want %x", buf[:n], want)
	}
}
