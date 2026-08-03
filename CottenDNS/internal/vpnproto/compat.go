// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// compat.go — wire compatibility with the MasterDNS/StormDNS lineage.
//
// CottenDns widened the on-wire session ID from one byte to two so a server
// could hold 65535 sessions instead of 255. That shifted every header field
// after byte 0, which is why an unmodified MasterDNS/StormDNS/WhiteDNS client
// cannot talk to a CottenDns server: its frames fail the header check and the
// server answers NODATA.
//
// The width is carried per packet (Packet.LegacySessionID on ingress,
// BuildOptions.LegacySessionID on egress) rather than as a process-wide mode,
// so a single server instance serves both client generations at once. The
// server keeps the width on the session record and replies in whichever format
// the client opened the session with.
// ==============================================================================
package vpnproto

// maxLegacySessionID is the largest session ID expressible in a one-byte
// header field. The server allocator reserves 1..255 for legacy sessions and
// hands native sessions IDs above it, which is what lets the parser tell the
// two layouts apart (see parseFrom).
const maxLegacySessionID = 255

// sessionIDWidth returns the on-wire width, in bytes, of the session-ID field.
func sessionIDWidth(legacy bool) int {
	if legacy {
		return 1
	}
	return 2
}

func readSessionID(data []byte, sessionIDLen int) uint16 {
	if sessionIDLen == 1 {
		return uint16(data[0])
	}
	return (uint16(data[0]) << 8) | uint16(data[1])
}

func writeSessionID(raw []byte, id uint16, sessionIDLen int) {
	if sessionIDLen == 1 {
		raw[0] = byte(id)
		return
	}
	raw[0] = byte(id >> 8)
	raw[1] = byte(id)
}
