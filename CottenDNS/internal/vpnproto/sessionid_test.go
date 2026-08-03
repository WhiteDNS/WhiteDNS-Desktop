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

// SessionID is a 16-bit field on the wire: ids above 255 must round-trip through
// BuildRaw -> Parse unchanged (this is the point of widening from uint8).
func TestSessionIDWiderThanByteRoundTrips(t *testing.T) {
	for _, id := range []uint16{0, 1, 255, 256, 300, 1000, 65535} {
		raw, err := BuildRaw(BuildOptions{
			SessionID:     id,
			PacketType:    Enums.PACKET_PING,
			SessionCookie: 0x5A,
		})
		if err != nil {
			t.Fatalf("BuildRaw(SessionID=%d): %v", id, err)
		}

		parsed, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(SessionID=%d): %v", id, err)
		}
		if parsed.SessionID != id {
			t.Fatalf("SessionID round-trip: got %d want %d", parsed.SessionID, id)
		}
		if parsed.SessionCookie != 0x5A {
			t.Fatalf("SessionCookie corrupted for SessionID=%d: got %d", id, parsed.SessionCookie)
		}
		if parsed.PacketType != Enums.PACKET_PING {
			t.Fatalf("PacketType corrupted for SessionID=%d: got %d", id, parsed.PacketType)
		}
	}
}
