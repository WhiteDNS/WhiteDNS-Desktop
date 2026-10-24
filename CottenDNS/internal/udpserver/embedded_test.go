package udpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/arq"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestEmbeddedIsolationPolicyAndShutdown(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	key := "embedded-account-key-material-000001"
	var tcpCalls, udpCalls, dnsCalls atomic.Int32
	policyErr := errors.New("account quota denied")
	e, err := NewEmbedded(context.Background(), EmbeddedConfig{Domain: "v.example.com", Key: key, Allowed: allowed.Load,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network == "tcp" {
				tcpCalls.Add(1)
			} else {
				udpCalls.Add(1)
			}
			return nil, policyErr
		},
		ExchangeDNS: func(context.Context, []byte) ([]byte, error) { dnsCalls.Add(1); return nil, policyErr },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	codec, _ := security.NewCodec(5, key)
	query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{security.DownstreamEncryptedFlag, 1, 2, 3, 4}})
	response := e.HandleDNS(query)
	if _, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, codec); err != nil {
		t.Fatal("native encrypted probe failed", err)
	}
	other, _ := security.NewCodec(5, key+"other")
	if _, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, other); err == nil {
		t.Fatal("another account decrypted reply")
	}
	if _, err := e.s.dialTCPTargetContext(context.Background(), "8.8.8.8:443"); !errors.Is(err, policyErr) {
		t.Fatal("TCP bypassed policy", err)
	}
	u := newUDPAssociationConn(e.s)
	if _, err := u.endpointFor("8.8.8.8", 443); !errors.Is(err, policyErr) {
		t.Fatal("UDP bypassed policy", err)
	}
	u.Close()
	dnsQuery := embeddedTestDNSQuery(t, "example.com", 1)
	dnsResponse := e.s.buildDNSQueryResponsePayload(dnsQuery, 1, 1)
	parsedDNS, parseErr := DnsParser.ParsePacketLite(dnsResponse)
	if parseErr != nil || parsedDNS.Header.RCode != 2 {
		t.Fatal("DNS bypassed policy", parseErr)
	}
	if tcpCalls.Load() != 1 || udpCalls.Load() != 1 || dnsCalls.Load() != 1 {
		t.Fatal("missing egress hooks")
	}
	allowed.Store(false)
	if len(e.HandleDNS(query)) != 0 {
		t.Fatal("disabled account still answered")
	}
	allowed.Store(true)
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("embedded server did not stop")
	}
	if len(e.HandleDNS(query)) != 0 {
		t.Fatal("closed account answered")
	}
}

func TestEmbeddedRequiresPolicyHooks(t *testing.T) {
	if _, err := NewEmbedded(context.Background(), EmbeddedConfig{Domain: "v.example.com", Key: "embedded-account-key-material-000001"}); err == nil {
		t.Fatal("embedding without account policy was accepted")
	}
}

func embeddedSessionLimitConfig(limit int) EmbeddedConfig {
	return EmbeddedConfig{
		Domain: "v.example.com", Key: "embedded-account-key-material-000001", MaxActiveSessions: limit,
		Allowed:     func() bool { return true },
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
		ExchangeDNS: func(context.Context, []byte) ([]byte, error) { return nil, net.ErrClosed },
	}
}

func TestEmbeddedSessionLimit(t *testing.T) {
	for _, tt := range []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", want: 64},
		{name: "minimum", limit: 1, want: 1},
		{name: "above_previous_limit", limit: 9, want: 9},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := embeddedSessionLimitConfig(tt.limit)
			e, err := NewEmbedded(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { e.Close() })
			codec, err := security.NewCodec(5, in.Key)
			if err != nil {
				t.Fatal(err)
			}
			initSession := func(n int) VpnProto.Packet {
				t.Helper()
				payload := []byte{security.DownstreamEncryptedFlag, 0, 0, 100, 2, 0, 1, 2, 3, byte(n)}
				query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{
					PacketType: Enums.PACKET_SESSION_INIT, Payload: payload,
				})
				packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(e.HandleDNS(query), false, []string{in.Domain}, codec)
				if err != nil {
					t.Fatal(err)
				}
				return packet
			}
			for n := 0; n < tt.want; n++ {
				if packet := initSession(n); packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
					t.Fatalf("session %d: packet type = %d, want SESSION_ACCEPT", n+1, packet.PacketType)
				}
			}
			if packet := initSession(tt.want); packet.PacketType != Enums.PACKET_SESSION_BUSY {
				t.Fatalf("session above cap: packet type = %d, want SESSION_BUSY", packet.PacketType)
			}
			if packet := initSession(0); packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
				t.Fatalf("existing session at cap: packet type = %d, want SESSION_ACCEPT", packet.PacketType)
			}
		})
	}
}

func TestEmbeddedSessionLimitBounds(t *testing.T) {
	for _, limit := range []int{-1, 65536} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			e, err := NewEmbedded(context.Background(), embeddedSessionLimitConfig(limit))
			if e != nil {
				e.Close()
			}
			if err == nil {
				t.Fatal("invalid session limit accepted")
			}
		})
	}
	e, err := NewEmbedded(context.Background(), embeddedSessionLimitConfig(65535))
	if err != nil {
		t.Fatalf("maximum session limit rejected: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	if got := e.s.sessions.maxActiveSessions; got != 65535 {
		t.Fatalf("maximum session limit = %d, want 65535", got)
	}
}

func TestEmbeddedStreamLimit(t *testing.T) {
	for _, tt := range []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", want: 128},
		{name: "minimum", limit: 1, want: 1},
		{name: "above_previous_limit", limit: 129, want: 129},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := embeddedSessionLimitConfig(0)
			in.MaxStreamsPerSession = tt.limit
			e, err := NewEmbedded(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { e.Close() })
			record, _, err := e.s.sessions.findOrCreate(legacyInitPayload(1), 0, 0, 8, false)
			if err != nil || record == nil {
				t.Fatal("session creation failed", err)
			}
			cfg := arq.Config{IsVirtual: true}
			for n := 1; n <= tt.want; n++ {
				if stream := record.getOrCreateStream(uint16(n), cfg, nil, nil); stream == nil {
					t.Fatalf("stream %d rejected within cap %d", n, tt.want)
				}
			}
			if stream := record.getOrCreateStream(uint16(tt.want+1), cfg, nil, nil); stream != nil {
				t.Fatal("stream above configured cap accepted")
			}
			for _, id := range []uint16{0, 1} {
				if stream := record.getOrCreateStream(id, cfg, nil, nil); stream == nil {
					t.Fatalf("existing stream %d blocked at cap", id)
				}
			}
		})
	}
}

func TestEmbeddedStreamLimitBounds(t *testing.T) {
	for _, limit := range []int{-1, 65536} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			in := embeddedSessionLimitConfig(0)
			in.MaxStreamsPerSession = limit
			e, err := NewEmbedded(context.Background(), in)
			if e != nil {
				e.Close()
			}
			if err == nil {
				t.Fatal("invalid stream limit accepted")
			}
		})
	}
	in := embeddedSessionLimitConfig(0)
	in.MaxStreamsPerSession = 65535
	e, err := NewEmbedded(context.Background(), in)
	if err != nil {
		t.Fatalf("maximum stream limit rejected: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	if got := e.s.sessions.maxStreamsPerSession; got != 65535 {
		t.Fatalf("maximum stream limit = %d, want 65535", got)
	}
}
