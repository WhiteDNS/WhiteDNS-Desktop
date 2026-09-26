package client

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestEncryptedSessionHandshakeAfterReset(t *testing.T) {
	for _, base64 := range []bool{false, true} {
		t.Run(fmt.Sprint(base64), func(t *testing.T) {
			c := createTestClient(t)
			c.cfg.BaseEncodeData = base64
			c.cfg.ResolverTransport = "udp"
			c.codec, _ = security.NewCodec(5, "testkey")
			c.syncedUploadMTU, c.syncedDownloadMTU = 128, 512
			defer c.closeResolverConnPools()
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 2; i++ {
					buf := make([]byte, 4096)
					n, addr, e := listener.ReadFromUDP(buf)
					if e != nil {
						done <- e
						return
					}
					query := buf[:n]
					parsed, e := DnsParser.ParsePacket(query)
					if e != nil {
						done <- e
						return
					}
					name := parsed.Questions[0].Name
					labels := strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(name, "."), ".example.com"), ".", "")
					request, e := VpnProto.ParseFromLabels(labels, c.codec)
					if e != nil {
						done <- e
						return
					}
					if request.PacketType != Enums.PACKET_SESSION_INIT || request.Payload[0]&security.DownstreamEncryptedFlag == 0 {
						done <- fmt.Errorf("missing encryption negotiation")
						return
					}
					var verify [4]byte
					copy(verify[:], request.Payload[6:10])
					payload := VpnProto.EncodeSessionAccept(300, 77, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
					response, e := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(query, name, "example.com", VpnProto.Packet{PacketType: Enums.PACKET_SESSION_ACCEPT, Payload: payload}, base64, true, true, c.codec)
					if e != nil {
						done <- e
						return
					}
					if _, e = listener.WriteToUDP(response, addr); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			for i := 0; i < 2; i++ {
				if i > 0 {
					c.resetSessionState(true)
				}
				payload, _, verify, e := c.buildSessionInitPayload()
				if e != nil {
					t.Fatal(e)
				}
				conn := Connection{Domain: "example.com", ResolverLabel: listener.LocalAddr().String()}
				if e = c.exchangeSessionInit(conn, payload, verify, time.Second); e != nil {
					t.Fatalf("handshake %d: %v", i, e)
				}
				if !c.sessionReady || c.sessionID != 300 || c.sessionCookie != 77 {
					t.Fatal("session not committed")
				}
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSecureClientRejectsPlaintextAndStaleSession(t *testing.T) {
	c := createTestClient(t)
	c.codec, _ = security.NewCodec(5, "testkey")
	c.sessionReady = true
	c.sessionID = 300
	c.sessionCookie = 77
	q, err := DnsParser.BuildTXTQuestionPacket("query.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	packet := VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_PONG}
	plain, err := DnsParser.BuildVPNResponsePacket(q, "query.example.com", packet, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.extractVPNResponse(plain, false); err == nil {
		t.Fatal("accepted plaintext downgrade")
	}
	if !c.acceptsSessionResponse(packet) {
		t.Fatal("valid session rejected")
	}
	packet.SessionCookie++
	if c.acceptsSessionResponse(packet) {
		t.Fatal("accepted wrong cookie")
	}
	packet.SessionCookie = 77
	packet.SessionID++
	if c.acceptsSessionResponse(packet) {
		t.Fatal("accepted old session")
	}
	packet.SessionID = 300
	packet.LegacySessionID = true
	if c.acceptsSessionResponse(packet) {
		t.Fatal("accepted wrong wire format")
	}
	legacy := &Client{cfg: config.ClientConfig{LegacySessionID: true}, codec: c.codec}
	if legacy.encryptedDownstream() {
		t.Fatal("legacy compatibility unexpectedly changed")
	}
}

func TestLargeEncryptedBase64ResponseFitsReadBuffer(t *testing.T) {
	codec, _ := security.NewCodec(5, "buffer test key")
	for _, mtu := range []int{4000, 8192, 20000} {
		q, err := DnsParser.BuildTXTQuestionPacket("query.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
		if err != nil {
			t.Fatal(err)
		}
		response, err := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(q, "query.example.com", "example.com", VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_STREAM_DATA, Payload: bytes.Repeat([]byte{0xab}, mtu)}, true, true, true, codec)
		if err != nil {
			t.Fatal(err)
		}
		if len(response) > runtimeDNSReadBufferSize(mtu) {
			t.Fatalf("MTU %d: %d-byte response exceeds %d-byte buffer", mtu, len(response), runtimeDNSReadBufferSize(mtu))
		}
	}
}
