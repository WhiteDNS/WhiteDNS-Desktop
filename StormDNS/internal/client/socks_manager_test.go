package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"stormdns-go/internal/config"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestSupportsSOCKS4Policy(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ClientConfig
		want bool
	}{
		{
			name: "auth disabled supports socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: false},
			want: true,
		},
		{
			name: "auth enabled with username and password disables socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: true, SOCKS5User: "user", SOCKS5Pass: "pass"},
			want: false,
		},
		{
			name: "auth enabled with username only supports socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: true, SOCKS5User: "user"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{cfg: tt.cfg}
			if got := c.supportsSOCKS4(); got != tt.want {
				t.Fatalf("supportsSOCKS4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSendSocks4ReplyFormatsResponse(t *testing.T) {
	c := &Client{}
	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- c.sendSocks4Reply(server, true)
	}()

	reply := make([]byte, 8)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("failed to read SOCKS4 reply: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendSocks4Reply returned error: %v", err)
	}

	want := []byte{0x00, SOCKS4_REPLY_GRANTED, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := range want {
		if reply[i] != want[i] {
			t.Fatalf("reply[%d] = 0x%02x, want 0x%02x", i, reply[i], want[i])
		}
	}
}

func TestLateSocksResultDoesNotReactivateCancelledStream(t *testing.T) {
	c := &Client{
		active_streams: make(map[uint16]*Stream_client),
	}

	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	s := &Stream_client{
		client:            c,
		StreamID:          7,
		LocalSocksVersion: SOCKS5_VERSION,
		NetConn:           server,
		Status:            streamStatusSocksConnecting,
		CreateTime:        time.Now(),
		LastActivityTime:  time.Now(),
	}
	c.active_streams[s.StreamID] = s

	c.handlePendingSOCKSLocalClose(s.StreamID, "test cancel")
	if got := s.StatusValue(); got != streamStatusCancelled {
		t.Fatalf("expected stream status %q after local close, got %q", streamStatusCancelled, got)
	}

	if err := c.HandleSocksConnected(VpnProto.Packet{StreamID: s.StreamID}); err != nil {
		t.Fatalf("HandleSocksConnected returned error: %v", err)
	}

	if got := s.StatusValue(); got != streamStatusCancelled {
		t.Fatalf("expected cancelled stream not to reactivate, got %q", got)
	}
	if s.TerminalSince().IsZero() {
		t.Fatal("expected cancelled stream to remain terminal after late SOCKS result")
	}
}

func TestSocksConnectRejectedWhenTunnelAdmissionClosed(t *testing.T) {
	now := time.Unix(100, 0)
	c := newAdmissionTestClient(now)
	c.active_streams = make(map[uint16]*Stream_client)
	c.recordTunnelResponse(now)
	c.recordTunnelSend(now.Add(time.Second))
	c.nowFn = func() time.Time {
		return now.Add(10 * time.Second)
	}

	server, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{}, 1)
	go func() {
		c.handleSOCKSConnect(context.Background(), server, "example.com", 443, SOCKS5_ATYP_DOMAIN, SOCKS5_VERSION)
		done <- struct{}{}
	}()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("failed to read SOCKS rejection: %v", err)
	}
	if reply[0] != SOCKS5_VERSION || reply[1] != SOCKS5_REPLY_NETWORK_UNREACHABLE {
		t.Fatalf("unexpected SOCKS rejection reply: %#v", reply)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected rejected SOCKS connect to return")
	}
	if len(c.active_streams) != 0 {
		t.Fatalf("expected no stream to be created, got %d", len(c.active_streams))
	}
}

func TestSocksUDPAssociateUnsupportedTargetClosesAssociation(t *testing.T) {
	c := &Client{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for SOCKS control connection: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{}, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			done <- struct{}{}
			return
		}
		defer server.Close()
		c.handleSocksUDPAssociate(context.Background(), server, "127.0.0.1", 0, SOCKS5_ATYP_IPV4)
		done <- struct{}{}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial SOCKS control connection: %v", err)
	}
	defer clientConn.Close()

	reply := make([]byte, 10)
	n, err := io.ReadFull(clientConn, reply)
	if err != nil {
		t.Fatalf("failed to read UDP associate reply after %d byte(s) %#v: %v", n, reply[:n], err)
	}
	if reply[0] != SOCKS5_VERSION || reply[1] != SOCKS5_REPLY_SUCCESS || reply[3] != SOCKS5_ATYP_IPV4 {
		t.Fatalf("unexpected UDP associate reply: %#v", reply)
	}
	udpPort := binary.BigEndian.Uint16(reply[8:10])
	if udpPort == 0 {
		t.Fatal("expected UDP associate reply to include a bound port")
	}

	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(udpPort)})
	if err != nil {
		t.Fatalf("failed to dial UDP associate socket: %v", err)
	}
	defer udpConn.Close()

	packet := []byte{
		0x00, 0x00, 0x00, SOCKS5_ATYP_IPV4,
		1, 1, 1, 1,
		0x01, 0xbb, // UDP/443, commonly QUIC/HTTP3.
		0xde, 0xad,
	}
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatalf("failed to send unsupported UDP packet: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected unsupported UDP target to close the association")
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected SOCKS control connection to be closed")
	}
}
