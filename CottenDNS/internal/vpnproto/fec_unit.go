// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// fec_unit.go — serialization of a single STREAM_DATA element carried inside a
// FEC block. Each block element is one data packet's (seq, fragID, payload);
// the FEC layer treats the serialized unit as an opaque byte slice. On recovery
// the client unpacks the unit and replays it into the stream's ARQ as if the
// STREAM_DATA packet had arrived normally.
// ==============================================================================

package vpnproto

import "encoding/binary"

// FECUnitHeaderSize is the fixed per-unit overhead: seq(2) + fragID(1).
const FECUnitHeaderSize = 3

// PackFECDataUnit serializes a data packet element for inclusion in a FEC block.
func PackFECDataUnit(seq uint16, fragID uint8, payload []byte) []byte {
	out := make([]byte, FECUnitHeaderSize+len(payload))
	binary.BigEndian.PutUint16(out[0:2], seq)
	out[2] = fragID
	copy(out[FECUnitHeaderSize:], payload)
	return out
}

// UnpackFECDataUnit reverses PackFECDataUnit. ok is false for an undersized unit.
func UnpackFECDataUnit(unit []byte) (seq uint16, fragID uint8, payload []byte, ok bool) {
	if len(unit) < FECUnitHeaderSize {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(unit[0:2]), unit[2], unit[FECUnitHeaderSize:], true
}
