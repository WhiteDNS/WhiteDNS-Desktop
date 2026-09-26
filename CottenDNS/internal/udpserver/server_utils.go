// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/binary"
	"fmt"

	"cottendns-go/internal/compression"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
)

func (s *Server) debugLoggingEnabled() bool {
	return s != nil && s.log != nil && s.log.Enabled(logger.LevelDebug)
}

func summarizeQName(name string) string {
	if len(name) <= 96 {
		return name
	}
	return fmt.Sprintf("%s...%s", name[:48], name[len(name)-24:])
}

func buildNoDataResponse(packet []byte) []byte {
	response, err := DnsParser.BuildNoDataResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildNoDataResponseLogged(packet []byte, reason string) []byte {
	return buildNoDataResponse(packet)
}

func (s *Server) buildNoDataResponseLiteLogged(packet []byte, parsed DnsParser.LitePacket, reason string) []byte {
	return s.zoneNoDataResponse(packet, parsed, s.domainMatcher.Match(parsed).BaseDomain)
}

// zoneNoDataResponse answers as the zone's authoritative server when the query
// is inside one of our zones, and REFUSED otherwise (we are not a resolver).
func (s *Server) zoneNoDataResponse(packet []byte, parsed DnsParser.LitePacket, zone string) []byte {
	var response []byte
	var err error
	if zone == "" {
		response, err = DnsParser.BuildRefusedResponseFromLite(packet, parsed)
	} else {
		response, err = DnsParser.BuildAuthoritativeNoDataFromLite(packet, parsed, zone)
	}
	if err != nil {
		return nil
	}
	return response
}

// markAuthoritative sets AA and clears RA on a response the server generated.
// The shared dnsparser builders emit resolver-style flags (RA=1, AA=0), which
// BIND rejects as a "lame" answer from a delegated server for every carrier
// except CNAME. REFUSED replies stay non-authoritative.
func markAuthoritative(response []byte) []byte {
	if len(response) >= 4 && response[3]&0x0F != Enums.DNSR_CODE_REFUSED {
		response[2] |= 0x04
		response[3] &^= 0x80
	}
	return response
}

func isClosedStreamAwarePacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_CLOSE_WRITE,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_RST:
		return true
	default:
		return false
	}
}

func sessionResponseModeName(mode uint8) string {
	if mode&^security.DownstreamEncryptedFlag == mtuProbeModeBase64 {
		return "BASE64"
	}
	return "RAW (Bytes)"
}

func buildCompressionMask(values []int) uint8 {
	var mask uint8 = 1 << compression.TypeOff
	for _, value := range values {
		if value < compression.TypeOff || value > compression.TypeZLIB || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		mask |= 1 << uint8(value)
	}
	return mask
}

func parseMTUProbeBaseEncoding(mode uint8) (bool, bool) {
	switch mode &^ security.DownstreamEncryptedFlag {
	case mtuProbeModeRaw:
		return false, true
	case mtuProbeModeBase64:
		return true, true
	default:
		return false, false
	}
}

func buildMTUProbeMetaPayload(probeCode []byte, payloadLen int) [mtuProbeMetaLength]byte {
	var payload [mtuProbeMetaLength]byte
	copy(payload[:mtuProbeCodeLength], probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(payloadLen))
	return payload
}

func fillMTUProbeBytes(dst []byte) {
	if len(dst) == 0 {
		return
	}
	clear(dst)
}
