// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import "cottendns-go/internal/security"

type BuildOptions struct {
	SessionID       uint16
	PacketType      uint8
	SessionCookie   uint8
	StreamID        uint16
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte

	// LegacySessionID emits the one-byte session-ID header of the
	// MasterDNS/StormDNS lineage instead of CottenDns's two-byte field. The
	// server copies it from the request packet so replies match the format the
	// client speaks; native clients leave it false.
	LegacySessionID bool
}

func BuildRaw(opts BuildOptions) ([]byte, error) {
	flags := packetFlags[opts.PacketType]
	if flags&packetFlagValid == 0 {
		return nil, ErrInvalidPacketType
	}

	sessionIDLen := sessionIDWidth(opts.LegacySessionID)
	headerLen := sessionIDLen + 1 + integrityLength // SessionID(1|2) + PacketType + SessionCookie + Integrity
	if flags&packetFlagStream != 0 {
		headerLen += 2
	}
	if flags&packetFlagSequence != 0 {
		headerLen += 2
	}
	if flags&packetFlagFragment != 0 {
		headerLen += 2
	}
	if flags&packetFlagCompression != 0 {
		headerLen++
	}

	raw := make([]byte, headerLen+len(opts.Payload))
	writeSessionID(raw, opts.SessionID, sessionIDLen)
	raw[sessionIDLen] = opts.PacketType
	offset := sessionIDLen + 1

	if flags&packetFlagStream != 0 {
		raw[offset] = byte(opts.StreamID >> 8)
		raw[offset+1] = byte(opts.StreamID)
		offset += 2
	}
	if flags&packetFlagSequence != 0 {
		raw[offset] = byte(opts.SequenceNum >> 8)
		raw[offset+1] = byte(opts.SequenceNum)
		offset += 2
	}
	if flags&packetFlagFragment != 0 {
		raw[offset] = opts.FragmentID
		raw[offset+1] = opts.TotalFragments
		offset += 2
	}
	if flags&packetFlagCompression != 0 {
		raw[offset] = opts.CompressionType
		offset++
	}

	raw[offset] = opts.SessionCookie
	offset++
	raw[offset] = computeHeaderCheckByte(raw[:offset])
	offset++
	copy(raw[offset:], opts.Payload)
	return raw, nil
}

func BuildEncoded(opts BuildOptions, codec *security.Codec) (string, error) {
	raw, err := BuildRaw(opts)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncode(raw)
}

func HeaderRawSize(packetType uint8) int {
	flags := packetFlags[packetType]
	if flags&packetFlagValid == 0 {
		return 0
	}

	size := 3 + integrityLength
	if flags&packetFlagStream != 0 {
		size += 2
	}
	if flags&packetFlagSequence != 0 {
		size += 2
	}
	if flags&packetFlagFragment != 0 {
		size += 2
	}
	if flags&packetFlagCompression != 0 {
		size++
	}
	return size
}

func MaxHeaderRawSize() int {
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
		}
	}
	return maxSize
}

func MaxHeaderPacketType() uint8 {
	var bestType uint8
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
			bestType = uint8(packetType)
		}
	}
	return bestType
}
