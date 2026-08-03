// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		response := s.handleTunnelCandidate(packet, parsed, decision)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	// Encryption-method auto-detection: the upstream frame is fully encrypted, so
	// the client's method is discovered by trying each candidate codec. s.codecs
	// is pre-ordered AEAD-first (see SetCodecSet), so iterating from index 0 tries
	// authenticated methods before any unauthenticated one and costs a single
	// attempt for the common single-method deployment.
	startIdx := int(s.preferredCodec.Load())
	vpnPacket, codecIdx, err := VpnProto.ParseInflatedFromLabelsAnyMatching(decision.Labels, s.codecs, startIdx, s.matchesInboundPacketCandidate)
	if err != nil {
		if errors.Is(err, VpnProto.ErrInvalidFragmentInfo) {
			s.fragmentInvalidHeader.Add(1)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}
	if codecIdx != startIdx {
		s.preferredCodec.Store(int32(codecIdx))
	}
	return s.handleDecodedTunnelPacket(packet, parsed, decision, vpnPacket)
}

func (s *Server) handlePreparedIngress(packet []byte, prepared preparedIngress) []byte {
	vpnPacket, err := VpnProto.InflatePayload(prepared.packet)
	if err != nil {
		if errors.Is(err, VpnProto.ErrInvalidFragmentInfo) {
			s.fragmentInvalidHeader.Add(1)
		}
		s.ingressInflateFailures.Add(1)
		return s.buildNoDataResponseLiteLogged(packet, prepared.parsed, "vpn-proto-inflate-failed")
	}
	return s.handleDecodedTunnelPacket(packet, prepared.parsed, prepared.decision, vpnPacket)
}

func (s *Server) handleDecodedTunnelPacket(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}

// matchesInboundPacketCandidate resolves the protocol's format ambiguity using
// state the wire itself does not carry. Established packets must match the ID,
// cookie and format of a live or recently closed session. Pre-session packets
// have ID zero and strict payload shapes, which also distinguishes their native
// and legacy layouts without another round trip or an extra wire byte.
func (s *Server) matchesInboundPacketCandidate(packet VpnProto.Packet) bool {
	if s == nil {
		return false
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_INIT:
		return packet.SessionID == 0 && len(packet.Payload) == sessionInitDataSize
	case Enums.PACKET_MTU_UP_REQ:
		return packet.SessionID == 255 && validMTUUpCandidatePayload(packet.Payload)
	case Enums.PACKET_MTU_DOWN_REQ:
		return packet.SessionID == 255 && validMTUDownCandidatePayload(packet.Payload)
	}

	if packet.SessionID == 0 {
		return false
	}
	lookup, ok := s.sessions.Lookup(packet.SessionID)
	return ok && lookup.Cookie == packet.SessionCookie && lookup.LegacySessionID == packet.LegacySessionID
}

func validMTUUpCandidatePayload(payload []byte) bool {
	if len(payload) < mtuProbeUpMinSize {
		return false
	}
	if _, ok := parseMTUProbeBaseEncoding(payload[0]); !ok {
		return false
	}
	// Native and legacy clients zero-fill the capacity probe after its response
	// mode and four-byte nonce. Checking that padding makes a wrong
	// unauthenticated decoder extraordinarily unlikely to steal a valid probe.
	return allZero(payload[mtuProbeUpMinSize:])
}

func validMTUDownCandidatePayload(payload []byte) bool {
	if len(payload) < mtuProbeDownMinSize || !validMTUUpCandidatePayload(payload[:mtuProbeUpMinSize]) {
		return false
	}
	downloadSize := int(payload[mtuProbeUpMinSize])<<8 | int(payload[mtuProbeUpMinSize+1])
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return false
	}
	return allZero(payload[mtuProbeDownMinSize:])
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
