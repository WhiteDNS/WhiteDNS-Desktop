package dnsparser

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestResponseFrameCapacityWireBudgets(t *testing.T) {
	codec, err := security.NewCodec(5, "response-budget-test-key-material-000001")
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + "." + strings.Repeat("z", 63) + ".v.example.com"
	for _, edns := range []uint16{0, 512, 1232, 4096} {
		for _, typ := range []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_SVCB} {
			for _, encrypted := range []bool{false, true} {
				for _, base64 := range []bool{false, true} {
					t.Run(fmt.Sprintf("edns%d/type%d/encrypted%v/base64%v", edns, typ, encrypted, base64), func(t *testing.T) {
						query, err := BuildTXTQuestionPacket(name, typ, edns)
						if err != nil {
							t.Fatal(err)
						}
						capacity := ResponseFrameCapacity(query, "v.example.com", false, false, base64, encrypted, false) - 12
						if encrypted {
							capacity -= codec.CiphertextOverhead()
						}
						if capacity <= 0 {
							t.Fatal("nonpositive capacity", capacity)
						}
						payload := make([]byte, capacity)
						for i := range payload {
							payload[i] = byte(i*73 + i/251)
						}
						packet := VpnProto.Packet{SessionID: 300, StreamID: 1, SequenceNum: 7, PacketType: Enums.PACKET_STREAM_DATA, Payload: payload}
						var response []byte
						if encrypted {
							response, err = BuildEncryptedVPNResponsePacketMatchingQuery(query, name, "v.example.com", packet, base64, false, false, codec)
						} else {
							response, err = BuildVPNResponsePacketMatchingQuery(query, name, "v.example.com", packet, base64, false)
						}
						if err != nil {
							t.Fatal(err)
						}
						if len(response) > UDPResponseLimit(query) {
							t.Fatalf("response=%d budget=%d payload=%d", len(response), UDPResponseLimit(query), capacity)
						}
						var decoded VpnProto.Packet
						if encrypted {
							decoded, err = ExtractEncryptedVPNResponseMatching(response, base64, []string{"v.example.com"}, codec)
						} else {
							decoded, err = ExtractVPNResponseMatching(response, base64, []string{"v.example.com"})
						}
						if err != nil || !bytes.Equal(decoded.Payload, payload) {
							t.Fatal("bounded frame did not round trip", err)
						}
					})
				}
			}
		}
	}
}

func TestBoundUDPResponseNeverReturnsPartialCiphertext(t *testing.T) {
	query, err := BuildTXTQuestionPacket("v.example.com", Enums.DNS_RECORD_TYPE_TXT, 512)
	if err != nil {
		t.Fatal(err)
	}
	response := BoundUDPResponse(query, make([]byte, 1500))
	parsed, err := ParsePacket(response)
	if err != nil || parsed.Header.TC != 1 || len(parsed.Answers) != 0 || len(response) > 512 {
		t.Fatalf("invalid truncated response: %+v %v", parsed.Header, err)
	}
}
