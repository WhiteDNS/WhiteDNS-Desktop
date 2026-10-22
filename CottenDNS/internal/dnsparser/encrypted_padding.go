package dnsparser

import (
	"encoding/binary"
	"fmt"
)

// PadEncryptedDNSQuery applies RFC 7830 padding to a self-contained DNS query.
// Call only on an encrypted resolver transport. Zero retains exact wire bytes.
// Existing padding is retained, and input slices are never modified.
func PadEncryptedDNSQuery(packet []byte, blockSize int) ([]byte, error) {
	if blockSize == 0 {
		return packet, nil
	}
	if blockSize < 16 || blockSize > 4096 {
		return nil, fmt.Errorf("DNS padding block must be 16..4096")
	}
	if len(packet) < 12 || len(packet) > 65535 || packet[2]&0xf8 != 0 || binary.BigEndian.Uint16(packet[4:6]) != 1 || binary.BigEndian.Uint16(packet[6:8]) != 0 || binary.BigEndian.Uint16(packet[8:10]) != 0 {
		return nil, fmt.Errorf("DNS padding requires a standard single-question query")
	}
	_, offset, err := parseName(packet, 12)
	if err != nil || offset+4 > len(packet) {
		return nil, fmt.Errorf("invalid DNS padding question")
	}
	offset += 4
	ar := int(binary.BigEndian.Uint16(packet[10:12]))
	optData, optEnd, optLengthOffset := -1, -1, -1
	for i := 0; i < ar; i++ {
		start := offset
		_, end, e := parseName(packet, offset)
		if e != nil || end+10 > len(packet) {
			return nil, fmt.Errorf("invalid DNS padding additional record")
		}
		size := int(binary.BigEndian.Uint16(packet[end+8 : end+10]))
		offset = end + 10 + size
		if offset > len(packet) {
			return nil, fmt.Errorf("truncated DNS padding additional record")
		}
		if binary.BigEndian.Uint16(packet[end:end+2]) == 41 {
			if optData >= 0 || packet[start] != 0 {
				return nil, fmt.Errorf("invalid DNS padding OPT")
			}
			optData, optEnd, optLengthOffset = end+10, offset, end+8
		}
	}
	if offset != len(packet) {
		return nil, fmt.Errorf("trailing DNS query data")
	}
	if optData >= 0 {
		if optEnd != len(packet) {
			return nil, fmt.Errorf("DNS padding requires the OPT record last")
		}
		for i := optData; i < optEnd; {
			if i+4 > optEnd {
				return nil, fmt.Errorf("truncated EDNS option")
			}
			code, n := binary.BigEndian.Uint16(packet[i:i+2]), int(binary.BigEndian.Uint16(packet[i+2:i+4]))
			if i+4+n > optEnd {
				return nil, fmt.Errorf("truncated EDNS option value")
			}
			if code == 12 {
				return packet, nil
			}
			i += 4 + n
		}
	}
	base := len(packet) + 4
	if optData < 0 {
		base += 11
	}
	padding := (blockSize - base%blockSize) % blockSize
	if base+padding > 65535 {
		return nil, fmt.Errorf("padded DNS query exceeds 65535 bytes")
	}
	out := append([]byte(nil), packet...)
	if optData < 0 {
		if ar == 65535 {
			return nil, fmt.Errorf("too many EDNS records")
		}
		binary.BigEndian.PutUint16(out[10:12], uint16(ar+1))
		out = append(out, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0) // OPT; 1232-byte advertised answer cap.
		optLengthOffset = len(out) - 2
	}
	old := int(binary.BigEndian.Uint16(out[optLengthOffset : optLengthOffset+2]))
	binary.BigEndian.PutUint16(out[optLengthOffset:optLengthOffset+2], uint16(old+4+padding))
	out = binary.BigEndian.AppendUint16(out, 12)
	out = binary.BigEndian.AppendUint16(out, uint16(padding))
	return append(out, make([]byte, padding)...), nil
}
