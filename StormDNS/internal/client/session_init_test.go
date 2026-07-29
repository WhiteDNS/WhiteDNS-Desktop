package client

import (
	"bytes"
	"encoding/binary"
	"testing"

	"stormdns-go/internal/compression"
	"stormdns-go/internal/config"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestNextSessionInitAttemptUsesBalancerSnapshotConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")

	originalDomain := c.connections[0].Domain
	c.connections[0].Domain = "mutated.example.com"

	conn, _, _, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}

	if conn.Domain != originalDomain {
		t.Fatalf("expected session init to use balancer snapshot domain %q, got %q", originalDomain, conn.Domain)
	}
}

func TestNextSessionInitAttemptsFansOutAcrossSnapshotConnections(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		UploadSetupPacketDuplicationCount:   4,
		DownloadSetupPacketDuplicationCount: 4,
	}, "a", "b", "c", "d")

	attempts, err := c.nextSessionInitAttempts(c.sessionInitFanoutCount())
	if err != nil {
		t.Fatalf("nextSessionInitAttempts returned error: %v", err)
	}
	if len(attempts) != 4 {
		t.Fatalf("unexpected fanout count: got=%d want=4", len(attempts))
	}

	seen := map[string]bool{}
	for _, attempt := range attempts {
		seen[attempt.conn.Key] = true
	}
	for _, key := range []string{"a", "b", "c", "d"} {
		if !seen[key] {
			t.Fatalf("expected fanout to include resolver %q; got=%v", key, seen)
		}
	}
}

func TestBuildSessionInitPayloadForMTUUsesProvidedValues(t *testing.T) {
	c := &Client{
		cfg:                 config.ClientConfig{BaseEncodeData: true},
		uploadCompression:   compression.TypeZLIB,
		downloadCompression: compression.TypeOff,
	}

	payload, responseBase64, verifyCode, err := c.buildSessionInitPayloadForMTU(123, 456)
	if err != nil {
		t.Fatalf("buildSessionInitPayloadForMTU returned error: %v", err)
	}
	if len(payload) != sessionInitPayloadSize {
		t.Fatalf("unexpected payload size: got=%d want=%d", len(payload), sessionInitPayloadSize)
	}
	if !responseBase64 {
		t.Fatal("expected base64 response mode to be enabled")
	}
	if payload[0] != mtuProbeBase64Reply {
		t.Fatalf("unexpected response mode byte: got=%d want=%d", payload[0], mtuProbeBase64Reply)
	}
	if payload[1] != compression.PackPair(c.uploadCompression, c.downloadCompression) {
		t.Fatalf("unexpected compression pair: got=%d want=%d", payload[1], compression.PackPair(c.uploadCompression, c.downloadCompression))
	}
	if got := int(binary.BigEndian.Uint16(payload[2:4])); got != 123 {
		t.Fatalf("unexpected upload mtu in payload: got=%d want=%d", got, 123)
	}
	if got := int(binary.BigEndian.Uint16(payload[4:6])); got != 456 {
		t.Fatalf("unexpected download mtu in payload: got=%d want=%d", got, 456)
	}
	if !bytes.Equal(payload[6:10], verifyCode[:]) {
		t.Fatal("expected verify code to be copied into payload")
	}
}

func TestVerifySessionAcceptPacketRequiresMatchingVerifyCode(t *testing.T) {
	verifyCode := [4]byte{1, 2, 3, 4}
	packet := VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    []byte{7, 9, compression.PackPair(compression.TypeOff, compression.TypeZLIB), 1, 2, 3, 4},
	}

	sessionID, sessionCookie, compressionPair, ok := verifySessionAcceptPacket(packet, verifyCode)
	if !ok {
		t.Fatal("expected accept packet verification to succeed")
	}
	if sessionID != 7 || sessionCookie != 9 {
		t.Fatalf("unexpected session identifiers: id=%d cookie=%d", sessionID, sessionCookie)
	}
	if compressionPair != compression.PackPair(compression.TypeOff, compression.TypeZLIB) {
		t.Fatalf("unexpected compression pair: got=%d", compressionPair)
	}

	packet.Payload[6] ^= 0xFF
	if _, _, _, ok := verifySessionAcceptPacket(packet, verifyCode); ok {
		t.Fatal("expected accept packet verification to fail after verify code mismatch")
	}
}

func TestVerifySessionBusyPacketRequiresMatchingVerifyCode(t *testing.T) {
	verifyCode := [4]byte{5, 6, 7, 8}
	packet := VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_BUSY,
		Payload:    []byte{5, 6, 7, 8},
	}
	if !verifySessionBusyPacket(packet, verifyCode) {
		t.Fatal("expected busy packet verification to succeed")
	}

	packet.Payload[3] ^= 0xFF
	if verifySessionBusyPacket(packet, verifyCode) {
		t.Fatal("expected busy packet verification to fail after verify code mismatch")
	}
}
