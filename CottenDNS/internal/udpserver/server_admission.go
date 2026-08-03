package udpserver

import (
	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	VpnProto "cottendns-go/internal/vpnproto"
)

type preparedIngress struct {
	parsed   DnsParser.LitePacket
	decision domainMatcher.Decision
	packet   VpnProto.Packet
}

// ingressQueueCapacity bounds the queue by both request count and worst-case
// backing-buffer bytes. It protects upgraded servers whose preserved config
// still contains the historical 65,535-byte packet size and 16,384-slot queue.
func (s *Server) ingressQueueCapacity() int {
	requestLimit := s.cfg.MaxConcurrentRequests
	if requestLimit < 1 {
		requestLimit = 1
	}
	packetBytes := s.cfg.MaxPacketSize
	if packetBytes < 1 {
		packetBytes = 1
	}
	byteLimit := s.cfg.MaxIngressQueueBytes
	if byteLimit < packetBytes {
		return 1
	}
	byteCapacity := byteLimit / packetBytes
	if byteCapacity < requestLimit {
		return byteCapacity
	}
	return requestLimit
}

// ingressQueueCapacities returns the exact work-conserving control/data split
// used by Run. Keeping this calculation available outside Run lets monitoring
// report configured capacity without retaining queue references or touching
// the data-plane hot path.
func (s *Server) ingressQueueCapacities() (control int, data int) {
	if s == nil {
		return 0, 0
	}
	total := s.ingressQueueCapacity()
	control = total / 8
	if total >= 128 {
		control = max(control, 64)
	}
	if control >= total && total > 1 {
		control = total - 1
	}
	return control, total - control
}

// admitIngressPacket performs only the cheap DNS/domain checks and tunnel frame
// decryption/header validation needed to decide whether a UDP datagram deserves
// scarce queue space. Payload decompression and all session work stay on bounded
// workers. Remembering the successful codec keeps dynamic method detection to
// one trial in steady state without tying admission to a source IP.
func (s *Server) admitIngressPacket(packet []byte) bool {
	_, ok := s.prepareIngressPacket(packet)
	return ok
}

// prepareIngressPacket performs the expensive decode/decrypt and header-width
// resolution once. The bounded worker retains decompression and session work,
// while avoiding a second DNS parse, domain match, codec trial, and decrypt.
func (s *Server) prepareIngressPacket(packet []byte) (preparedIngress, bool) {
	if s == nil || s.domainMatcher == nil || len(s.codecs) == 0 {
		return preparedIngress{}, false
	}
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil || !parsed.HasQuestion {
		return preparedIngress{}, false
	}
	decision := s.domainMatcher.Match(parsed)
	if decision.Action != domainMatcher.ActionProcess {
		return preparedIngress{}, false
	}
	startIdx := int(s.preferredCodec.Load())
	vpnPacket, codecIdx, err := VpnProto.ParseFromLabelsAnyMatching(decision.Labels, s.codecs, startIdx, s.matchesInboundPacketCandidate)
	if err != nil {
		// Preserve the deliberately broad admission behavior for malformed or
		// older pre-session probes. The worker will apply strict semantics, but a
		// frame that the historical parser accepted must remain dynamically
		// answerable rather than being rejected merely by the optimization.
		vpnPacket, codecIdx, err = VpnProto.ParseFromLabelsAny(decision.Labels, s.codecs, startIdx)
	}
	if err == nil && codecIdx != startIdx {
		s.preferredCodec.Store(int32(codecIdx))
	}
	if err != nil {
		return preparedIngress{}, false
	}
	if codecIdx >= 0 && codecIdx < len(s.codecs) && s.codecs[codecIdx] != nil {
		method := s.codecs[codecIdx].Method()
		if method >= 0 && method < len(s.codecAccepted) {
			s.codecAccepted[method].Add(1)
		}
	}
	return preparedIngress{parsed: parsed, decision: decision, packet: vpnPacket}, true
}
