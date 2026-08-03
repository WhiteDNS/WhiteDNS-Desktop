// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"testing"

	Enums "cottendns-go/internal/enums"
)

// A legacy frame must survive BuildRaw -> Parse with its one-byte session-ID
// layout intact, and must come back flagged as legacy so the server replies in
// the same format.
func TestLegacySessionIDRoundTrips(t *testing.T) {
	for _, id := range []uint16{0, 1, 200, maxLegacySessionID} {
		raw, err := BuildRaw(BuildOptions{
			SessionID:       id,
			PacketType:      Enums.PACKET_PING,
			SessionCookie:   0x5A,
			LegacySessionID: true,
		})
		if err != nil {
			t.Fatalf("BuildRaw(legacy, id=%d): %v", id, err)
		}
		if got := raw[0]; got != byte(id) {
			t.Fatalf("legacy id=%d: header byte 0 = %d, want %d", id, got, byte(id))
		}
		if got := raw[1]; got != Enums.PACKET_PING {
			t.Fatalf("legacy id=%d: packet type must sit at byte 1, got %d", id, got)
		}

		parsed, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(legacy, id=%d): %v", id, err)
		}
		if !parsed.LegacySessionID {
			t.Fatalf("legacy id=%d: parsed as native", id)
		}
		if parsed.SessionID != id {
			t.Fatalf("legacy id=%d: SessionID round-trip got %d", id, parsed.SessionID)
		}
		if parsed.SessionCookie != 0x5A || parsed.PacketType != Enums.PACKET_PING {
			t.Fatalf("legacy id=%d: header corrupted: cookie=%d type=%d",
				id, parsed.SessionCookie, parsed.PacketType)
		}
	}
}

func TestNativeMTUProbeSentinelRemainsNative(t *testing.T) {
	for _, packetType := range []uint8{
		Enums.PACKET_MTU_UP_REQ,
		Enums.PACKET_MTU_UP_RES,
		Enums.PACKET_MTU_DOWN_REQ,
		Enums.PACKET_MTU_DOWN_RES,
	} {
		raw, err := BuildRaw(BuildOptions{
			SessionID:      255,
			PacketType:     packetType,
			StreamID:       1,
			SequenceNum:    1,
			TotalFragments: 1,
			Payload:        []byte{0, 1, 2, 3, 4, 0, 30},
		})
		if err != nil {
			t.Fatalf("packet type %d BuildRaw: %v", packetType, err)
		}
		packet, err := Parse(raw)
		if err != nil {
			t.Fatalf("packet type %d Parse: %v", packetType, err)
		}
		if packet.LegacySessionID || packet.SessionID != 255 || packet.PacketType != packetType {
			t.Fatalf("packet type %d parsed incorrectly: %+v", packetType, packet)
		}
	}
}

// Native frames must not regress into the legacy layout now that parsing tries
// both. Native session IDs live above the legacy range by allocator contract.
func TestNativeSessionIDStillPreferred(t *testing.T) {
	for _, id := range []uint16{0, 256, 1000, 65535} {
		raw, err := BuildRaw(BuildOptions{
			SessionID:     id,
			PacketType:    Enums.PACKET_PING,
			SessionCookie: 0x5A,
		})
		if err != nil {
			t.Fatalf("BuildRaw(native, id=%d): %v", id, err)
		}

		parsed, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(native, id=%d): %v", id, err)
		}
		if parsed.LegacySessionID {
			t.Fatalf("native id=%d: parsed as legacy", id)
		}
		if parsed.SessionID != id {
			t.Fatalf("native id=%d: SessionID round-trip got %d", id, parsed.SessionID)
		}
	}
}

// SESSION_INIT is the packet that decides which format a session speaks for the
// rest of its life, and it carries session ID 0 in both formats. The native
// layout puts a zero in byte 1 where the legacy layout puts the packet type, so
// the two are always distinguishable here — no session record exists yet to
// disambiguate them.
func TestSessionInitDistinguishesWireFormat(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		raw, err := BuildRaw(BuildOptions{
			SessionID:       0,
			PacketType:      Enums.PACKET_SESSION_INIT,
			SessionCookie:   0,
			Payload:         make([]byte, 10),
			LegacySessionID: legacy,
		})
		if err != nil {
			t.Fatalf("BuildRaw(SESSION_INIT, legacy=%v): %v", legacy, err)
		}

		parsed, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(SESSION_INIT, legacy=%v): %v", legacy, err)
		}
		if parsed.LegacySessionID != legacy {
			t.Fatalf("SESSION_INIT legacy=%v detected as legacy=%v", legacy, parsed.LegacySessionID)
		}
		if parsed.SessionID != 0 {
			t.Fatalf("SESSION_INIT legacy=%v: SessionID = %d, want 0", legacy, parsed.SessionID)
		}
		if len(parsed.Payload) != 10 {
			t.Fatalf("SESSION_INIT legacy=%v: payload len = %d, want 10", legacy, len(parsed.Payload))
		}
	}
}
