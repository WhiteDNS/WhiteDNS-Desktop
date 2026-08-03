// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"cottendns-go/internal/arq"
	"cottendns-go/internal/compression"
	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

// tunnelBaseDomain returns the configured tunnel domain that is the suffix of
// requestName (longest match wins), or "" if none matches. It is used as the
// CNAME target suffix for A2 response-type matching so the client can strip it
// before decoding. Returning "" makes BuildVPNResponsePacketMatchingQuery fall
// back to the TXT encoding.
func (s *Server) tunnelBaseDomain(requestName string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(requestName), "."))
	if name == "" || s == nil || s.domainMatcher == nil {
		return ""
	}
	best := ""
	for _, d := range s.domainMatcher.Domains() {
		dd := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if dd == "" {
			continue
		}
		if (name == dd || strings.HasSuffix(name, "."+dd)) && len(dd) > len(best) {
			best = dd
		}
	}
	return best
}

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
		}
	}

	if !validation.Known {
		mode := s.nextUnknownInvalidDropMode()
		s.logInvalidSessionDrop("unknown session", vpnPacket.SessionID, vpnPacket.SessionCookie, 0, mode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, mode, vpnPacket.LegacySessionID),
		}
	}

	if validation.Lookup.State == sessionLookupClosed {
		s.logInvalidSessionDrop("recently closed session", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode, vpnPacket.LegacySessionID),
		}
	}

	if !s.invalidCookieTracker.Note(
		vpnPacket.SessionID,
		validation.Lookup,
		validation.Known,
		vpnPacket.SessionCookie,
		now.UnixNano(),
		s.invalidCookieWindowNanos,
		s.invalidCookieThreshold,
	) {
		return postSessionValidation{}
	}

	s.logInvalidSessionDrop("invalid cookie threshold", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)

	return postSessionValidation{
		response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode, vpnPacket.LegacySessionID),
	}
}

func (s *Server) handleSessionCloseNotice(vpnPacket VpnProto.Packet, now time.Time) {
	if s == nil || vpnPacket.SessionID == 0 {
		return
	}

	lookup, known := s.sessions.Lookup(vpnPacket.SessionID)
	if !known || lookup.State != sessionLookupActive || lookup.Cookie != vpnPacket.SessionCookie {
		return
	}

	record, ok := s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention())
	if !ok {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID, record)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) logInvalidSessionDrop(reason string, sessionID uint16, receivedCookie uint8, expectedCookie uint8, responseMode uint8) {
	if !s.debugLoggingEnabled() {
		return
	}
	now := time.Now()
	logKey, interval := invalidSessionDropLogConfig(reason, sessionID, receivedCookie, expectedCookie, responseMode)
	if !s.invalidSessionDropLog.allow(logKey, now, interval) {
		return
	}
	if expectedCookie == 0 {
		s.log.Debugf(
			"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
			reason,
			sessionID,
			receivedCookie,
			sessionResponseModeName(responseMode),
		)
		return
	}
	s.log.Debugf(
		"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
		reason,
		sessionID,
		expectedCookie,
		receivedCookie,
		sessionResponseModeName(responseMode),
	)
}

func invalidSessionDropLogConfig(reason string, sessionID uint16, receivedCookie uint8, expectedCookie uint8, responseMode uint8) (string, time.Duration) {
	switch reason {
	case "recently closed session":
		return fmt.Sprintf("recently-closed:%d:%d:%d", sessionID, expectedCookie, responseMode), 3 * time.Second
	case "invalid cookie threshold":
		return fmt.Sprintf("invalid-cookie:%d:%d:%d", sessionID, expectedCookie, responseMode), 1500 * time.Millisecond
	case "unknown session":
		return fmt.Sprintf("unknown-session:%d:%d", sessionID, responseMode), 1500 * time.Millisecond
	default:
		return fmt.Sprintf("%s:%d:%d:%d", reason, sessionID, expectedCookie, responseMode), time.Second
	}
}

// legacy selects the reply's wire format. There is no session record to consult
// here (the whole point is that the session is unknown, closed, or failed its
// cookie), so it comes from the format the rejected request itself arrived in.
func (s *Server) buildInvalidSessionErrorResponse(questionPacket []byte, requestName string, sessionID uint16, responseMode uint8, legacy bool) []byte {
	payload := s.nextInvalidDropPayload()
	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, requestName, s.tunnelBaseDomain(requestName), VpnProto.Packet{
		SessionID:       sessionID,
		PacketType:      Enums.PACKET_ERROR_DROP,
		Payload:         payload[:],
		LegacySessionID: legacy,
	}, responseMode == mtuProbeModeBase64, s.cfg.ARecordDataDelivery)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionBusyResponse(questionPacket []byte, requestName string, responseMode uint8, verifyCode []byte, legacy bool) []byte {
	if len(verifyCode) < mtuProbeCodeLength {
		return nil
	}
	var payload [mtuProbeCodeLength]byte
	copy(payload[:], verifyCode[:mtuProbeCodeLength])
	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, requestName, s.tunnelBaseDomain(requestName), VpnProto.Packet{
		SessionID:       0,
		PacketType:      Enums.PACKET_SESSION_BUSY,
		Payload:         payload[:],
		LegacySessionID: legacy,
	}, responseMode == mtuProbeModeBase64, s.cfg.ARecordDataDelivery)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionVPNResponse(questionPacket []byte, requestName string, record *sessionRuntimeView, packet VpnProto.Packet) []byte {
	if record == nil {
		return nil
	}
	packet.SessionID = record.ID
	packet.SessionCookie = record.Cookie
	// Single chokepoint for session-scoped replies: whatever built the packet
	// upstream (pong, queued data, ack, packed control blocks), it goes back in
	// the wire format this session was opened with.
	packet.LegacySessionID = record.LegacySessionID
	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, requestName, s.tunnelBaseDomain(requestName), packet, record.ResponseBase64, s.cfg.ARecordDataDelivery)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) queueSessionPacket(sessionID uint16, packet VpnProto.Packet) bool {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return false
	}

	if packet.StreamID == 0 {
		record.ensureStream0(s.log)
		stream, exists := record.getStream(0)
		if !exists || stream == nil {
			return false
		}

		return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
	}

	stream, exists := record.getStream(packet.StreamID)
	if !exists || stream == nil {
		return false
	}

	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
}

func (s *Server) streamARQConfig(compressionType uint8) arq.Config {
	return arq.Config{
		WindowSize:                  s.cfg.ARQWindowSize,
		RTO:                         s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                      s.cfg.ARQMaxRTOSeconds,
		EnableControlReliability:    true,
		ControlRTO:                  s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:               s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:           s.cfg.ARQMaxControlRetries,
		InactivityTimeout:           s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:               s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:              s.cfg.ARQMaxDataRetries,
		DataNackMaxGap:              s.cfg.ARQDataNackMaxGap,
		DataNackInitialDelaySeconds: s.cfg.ARQDataNackInitialDelaySeconds,
		DataNackRepeatSeconds:       s.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:            s.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:        s.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:      s.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:             compressionType,
	}
}

// maybeEnableStreamFEC configures download-direction FEC for a freshly created
// data stream. FEC_DOWNLOAD_ENABLED forces it always-on at the fixed parity;
// otherwise FEC_AUTO_ENABLED arms loss-triggered FEC that turns on only when the
// stream's measured loss crosses the threshold. It is idempotent, so it is safe
// to call at every data-stream entry point.
func (s *Server) maybeEnableStreamFEC(stream *Stream_server) {
	if stream == nil {
		return
	}
	if s.cfg.FECDownloadEnabled {
		stream.EnableFEC(s.cfg.FECBlockSize, s.cfg.FECParity)
		return
	}
	if s.cfg.FECAutoEnabled {
		stream.ConfigureAutoFEC(s.cfg.FECBlockSize, s.cfg.FECParity, s.cfg.FECAutoMaxParity, s.cfg.FECAutoLossThreshold)
		stream.ConfigureSuperFEC(s.cfg.FECSuperEnabled, s.cfg.FECSuperLossFloor, s.cfg.FECSuperLossCeil, s.cfg.FECSuperMaxParity)
	}
}

func (s *Server) queueMainSessionPacket(sessionID uint16, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint16, record *sessionRecord) {
	if s == nil || sessionID == 0 {
		return
	}
	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	if record != nil {
		record.closeAllStreams("session closed cleanup")
	}
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupDeferredSessionState(sessionID uint16) {
	if s == nil || sessionID == 0 {
		return
	}
	if s.deferredDNSSession != nil {
		s.deferredDNSSession.RemoveSession(sessionID)
	}
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.RemoveSession(sessionID)
	}
	s.removeDNSQueryFragmentsForSession(sessionID)
}

func (s *Server) cleanupIdleDeferredSession(sessionID uint16, lastActivityNano int64, now time.Time) {
	if s == nil || sessionID == 0 {
		return
	}

	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupStreamArtifacts(sessionID uint16, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) finalizeStreamArtifacts(sessionID uint16, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.finalizeDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}

	sessionID := record.ID

	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		return s.buildSessionVPNResponse(questionPacket, requestName, record, *pkt)
	}

	payload := s.nextPongPayload()
	return s.buildSessionVPNResponse(questionPacket, requestName, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint16, now time.Time) (*VpnProto.Packet, bool) {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return nil, false
	}

	record.mu.Lock()
	if pkt, ok := s.dequeueDuplicatedPackedControlBlock(record); ok {
		record.mu.Unlock()
		return pkt, true
	}
	rrStreamID := record.RRStreamID
	record.mu.Unlock()

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0
	totalCandidates := len(readyIDs)

	if hasOrphan {
		totalCandidates++
	}

	if totalCandidates == 0 {
		return nil, false
	}

	startIdx := 0
	candidateAt := func(idx int) (int32, *Stream_server) {
		if hasOrphan {
			if idx == 0 {
				return -1, nil
			}
			idx--
		}
		if idx < 0 || idx >= len(readyIDs) {
			return 0, nil
		}
		return readyIDs[idx], readyStreams[idx]
	}

	for i := 0; i < totalCandidates; i++ {
		id, _ := candidateAt(i)
		if id >= rrStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < totalCandidates; i++ {
		idx := (startIdx + i) % totalCandidates
		id, stream := candidateAt(idx)

		var item *serverStreamTXPacket
		var ok bool
		var selectedStreamID uint16

		if id == -1 {
			p, _, popOk := record.OrphanQueue.Pop(func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if popOk {
				item = &serverStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        p.Payload,
				}
				selectedStreamID = p.StreamID
				ok = true
			}
		} else {
			fecActive := stream != nil && stream.FECEnabled()
			if stream == nil || stream.TXQueue == nil ||
				(stream.FastTXQueueSize() == 0 && !(fecActive && stream.HasBufferedFECWork())) {
				continue
			}
			if stream.ARQ != nil && stream.ARQ.IsClosed() {
				stream.ClearTXQueue()
				record.deactivateStream(uint16(id))
				continue
			}
			if fecActive {
				var popped *serverStreamTXPacket
				popped, ok = s.fecDequeueFromStream(stream, id)
				if ok {
					item = popped
					selectedStreamID = uint16(id)
				} else {
					continue
				}
			} else {
				var popped *serverStreamTXPacket
				popped, _, ok = stream.PopNextTXPacket()
				if ok {
					stream.NoteTXPacketDequeued(popped)
					if (popped.PacketType == Enums.PACKET_STREAM_DATA || popped.PacketType == Enums.PACKET_STREAM_RESEND) &&
						stream.ARQ != nil && !stream.ARQ.HasPendingSequence(popped.SequenceNum) {
						putTXPacketToPool(popped)
						continue
					}
					item = popped
					selectedStreamID = uint16(id)
				}
			}
		}

		if ok && item != nil {
			record.mu.Lock()
			record.RRStreamID = id + 1
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				pkt := s.packControlBlocks(record, item, id, selectedStreamID)
				s.cachePackedControlBlockDuplicate(record, pkt)
				record.mu.Unlock()
				return pkt, true
			}
			record.mu.Unlock()
			pkt := vpnPacketFromTX(item, selectedStreamID)
			if id != -1 {
				putTXPacketToPool(item)
			}
			return &pkt, true
		}
	}

	return nil, false
}

func cloneVPNPacket(packet *VpnProto.Packet) *VpnProto.Packet {
	if packet == nil {
		return nil
	}
	cloned := *packet
	if len(packet.Payload) > 0 {
		cloned.Payload = append([]byte(nil), packet.Payload...)
	}
	return &cloned
}

func (s *Server) dequeueDuplicatedPackedControlBlock(record *sessionRecord) (*VpnProto.Packet, bool) {
	if s == nil || record == nil || record.LastPackedControlBlock == nil || record.LastPackedControlBlockRemaining <= 0 {
		return nil, false
	}
	packet := cloneVPNPacket(record.LastPackedControlBlock)
	record.LastPackedControlBlockRemaining--
	if record.LastPackedControlBlockRemaining <= 0 {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
	}
	return packet, packet != nil
}

func (s *Server) cachePackedControlBlockDuplicate(record *sessionRecord, packet *VpnProto.Packet) {
	if s == nil || record == nil {
		return
	}
	duplication := s.cfg.PacketBlockControlDuplication
	if duplication <= 1 || packet == nil || packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
		return
	}
	record.LastPackedControlBlock = cloneVPNPacket(packet)
	record.LastPackedControlBlockRemaining = duplication - 1
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialID int32, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, first.FragmentID, first.TotalFragments)
	blocks := 1

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0

	processID := func(id int32, stream *Stream_server) bool {
		if blocks >= limit {
			return true
		}

		if id == -1 {
			for blocks < limit {
				if record.OrphanQueue == nil || record.OrphanQueue.FastSize() == 0 {
					return false
				}
				popped, ok := record.OrphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					return false
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
			return false
		}

		if stream == nil || stream.TXQueue == nil {
			return false
		}

		for blocks < limit {
			if stream.FastTXQueueSize() == 0 {
				return false
			}
			popped, ok := stream.PopAnyTXPacket(2, func(p *serverStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			})
			if !ok {
				return false
			}
			stream.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			putTXPacketToPool(popped)
		}
		return false
	}

	var initialStream *Stream_server
	var initialIndex int = -1
	if initialID != -1 {
		for i, id := range readyIDs {
			if id == initialID {
				initialIndex = i
				initialStream = readyStreams[i]
				break
			}
		}
	}
	if processID(initialID, initialStream) {
		goto buildResult
	}

	if hasOrphan && initialID != -1 {
		if processID(-1, nil) {
			goto buildResult
		}
	}

	if initialIndex >= 0 {
		for i := initialIndex + 1; i < len(readyIDs); i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
		for i := 0; i < initialIndex; i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
	} else {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

	if initialID == -1 && hasOrphan {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

buildResult:
	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)

		if initialID != -1 {
			putTXPacketToPool(first)
		}
		return &pkt
	}

	if initialID != -1 {
		putTXPacketToPool(first)
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

// fecDequeueFromStream services one poll for a FEC-enabled stream. It returns
// the next PACKET_FEC_SHARD to send (or a non-data control packet, which is
// never FEC-encoded), or (nil,false) when nothing is ready this poll. Data
// packets popped from the TXQueue are marked dispatched on the ARQ (preserving
// its retransmit backstop), folded into the encoder, and replaced on the wire
// by shard frames. The trailing partial block is flushed once the TXQueue
// drains so a paused stream's tail is not stuck below a block boundary.
func (s *Server) fecDequeueFromStream(stream *Stream_server, id int32) (*serverStreamTXPacket, bool) {
	if frame, ok := stream.popFECShard(); ok {
		return s.fecShardTXPacket(frame), true
	}

	for {
		popped, _, ok := stream.PopNextTXPacket()
		if !ok {
			break
		}
		stream.NoteTXPacketDequeued(popped)

		if popped.PacketType == Enums.PACKET_STREAM_DATA || popped.PacketType == Enums.PACKET_STREAM_RESEND {
			if stream.ARQ != nil && !stream.ARQ.HasPendingSequence(popped.SequenceNum) {
				putTXPacketToPool(popped)
				continue
			}
			if !stream.feedFECData(popped.SequenceNum, popped.FragmentID, popped.Payload) {
				// Auto-FEC may have disengaged after the caller observed it active.
				// Send this already-popped packet raw instead of dropping it until
				// the ARQ retransmission timer fires.
				return popped, true
			}
			putTXPacketToPool(popped)
			if frame, ok := stream.popFECShard(); ok {
				return s.fecShardTXPacket(frame), true
			}
			continue
		}

		// Control packets (SYN/ACK/CLOSE/RST/...) are reliability-critical and
		// must not be hidden behind FEC; send them directly, unchanged.
		return popped, true
	}

	stream.flushFEC()
	if frame, ok := stream.popFECShard(); ok {
		return s.fecShardTXPacket(frame), true
	}
	return nil, false
}

func (s *Server) fecShardTXPacket(frame []byte) *serverStreamTXPacket {
	pkt := getTXPacketFromPool()
	pkt.PacketType = Enums.PACKET_FEC_SHARD
	pkt.SequenceNum = 0
	pkt.FragmentID = 0
	pkt.TotalFragments = 0
	pkt.CompressionType = compression.TypeOff
	pkt.Payload = frame
	pkt.CreatedAt = time.Now()
	pkt.TTL = 0
	return pkt
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         p.PacketType,
		StreamID:           streamID,
		SequenceNum:        p.SequenceNum,
		FragmentID:         p.FragmentID,
		TotalFragments:     p.TotalFragments,
		CompressionType:    p.CompressionType,
		HasCompressionType: p.CompressionType != compression.TypeOff,
		Payload:            p.Payload,
		HasSequenceNum:     p.SequenceNum != 0,
		HasFragmentInfo:    p.FragmentID != 0 || p.TotalFragments != 0,
		HasStreamID:        true,
	}
}

func (s *Server) nextPongPayload() [7]byte {
	var payload [7]byte
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:], nonce)
	return payload
}

func (s *Server) nextInvalidDropPayload() [8]byte {
	var payload [8]byte
	payload[0] = 'I'
	payload[1] = 'N'
	payload[2] = 'V'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:7], nonce)
	payload[7] = byte(nonce)
	return payload
}

func (s *Server) nextUnknownInvalidDropMode() uint8 {
	if s == nil {
		return mtuProbeModeRaw
	}

	if s.invalidDropMode.Add(1)&1 == 0 {
		return mtuProbeModeRaw
	}

	return mtuProbeModeBase64
}

func deferredSessionLaneForPacket(packet VpnProto.Packet) deferredSessionLane {
	return deferredSessionLane{
		sessionID: packet.SessionID,
		streamID:  packet.StreamID,
	}
}

func isDeferredPostSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func(context.Context)) bool {
	if s == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	var processor *deferredSessionProcessor
	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		processor = s.deferredDNSSession
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		processor = s.deferredConnectSession
	default:
		return false
	}
	if processor == nil {
		return false
	}
	return processor.Enqueue(deferredSessionLaneForPacket(packet), run)
}

func isPreSessionRequestType(packetType uint8) bool {
	return preSessionPacketTypes[packetType]
}

func buildPreSessionPacketTypes() [256]bool {
	var values [256]bool
	values[Enums.PACKET_SESSION_INIT] = true
	values[Enums.PACKET_MTU_UP_REQ] = true
	values[Enums.PACKET_MTU_DOWN_REQ] = true
	return values
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if vpnPacket.SessionID != 0 || len(vpnPacket.Payload) != sessionInitDataSize {
		return nil
	}

	requestedUpload, requestedDownload := compression.SplitPair(vpnPacket.Payload[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, reused, err := s.sessions.findOrCreate(
		vpnPacket.Payload,
		resolvedUpload,
		resolvedDownload,
		s.cfg.MaxPacketsPerBatch,
		vpnPacket.LegacySessionID,
	)
	if err != nil {
		if err == ErrSessionTableFull {
			s.sessionBusyResponses.Add(1)
			if s.log != nil {
				s.log.Errorf(
					"\U0001F6AB <red>Session Table Full Request: <cyan>SESSION_INIT</cyan>, Domain: <cyan>%s</cyan></red>",
					decision.RequestName,
				)
			}
			return s.buildSessionBusyResponse(questionPacket, decision.RequestName, vpnPacket.Payload[0], vpnPacket.Payload[6:10], vpnPacket.LegacySessionID)
		}
		return nil
	}
	if record == nil {
		return nil
	}
	record.streamCleanup = s.cleanupStreamArtifacts

	if !reused && s.log != nil {
		s.log.Infof(
			"\U0001F9DD <green>Session Created, ID: <cyan>%d</cyan>, Mode: <cyan>%s</cyan>, Upload Compression: <cyan>%s</cyan>, Download Compression: <cyan>%s</cyan>, Client Upload MTU: <cyan>%d</cyan>, Client Download MTU: <cyan>%d</cyan>, Max Packed Blocks: <cyan>%d</cyan></green>",
			record.ID,
			sessionResponseModeName(record.ResponseMode),
			compression.TypeName(record.UploadCompression),
			compression.TypeName(record.DownloadCompression),
			record.UploadMTU,
			record.DownloadMTU,
			record.MaxPackedBlocks,
		)
	}

	// The accept payload carries the assigned session ID at the same width as
	// the header, so the whole layout shifts down a byte for legacy clients:
	// [sid(1|2)] [cookie] [compression] [verifyCode(4)] [policy(13, optional)].
	// The policy block is appended only when the operator configured ceilings;
	// otherwise this is byte-for-byte the payload that shipped before.
	responsePayload := VpnProto.EncodeSessionAccept(
		record.ID,
		record.Cookie,
		compression.PackPair(record.UploadCompression, record.DownloadCompression),
		record.VerifyCode,
		s.clientPolicy,
		record.LegacySessionID,
	)

	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, decision.RequestName, decision.BaseDomain, VpnProto.Packet{
		SessionID:       0,
		PacketType:      Enums.PACKET_SESSION_ACCEPT,
		Payload:         responsePayload,
		LegacySessionID: record.LegacySessionID,
	}, record.ResponseMode == mtuProbeModeBase64, s.cfg.ARecordDataDelivery)
	if err != nil {
		return nil
	}

	return response
}

func resolveCompressionType(requested uint8, allowedMask uint8) uint8 {
	if requested <= compression.TypeZLIB && allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeUpMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}

	responsePayload := buildMTUProbeMetaPayload(vpnPacket.Payload[1:mtuProbeUpMinSize], len(vpnPacket.Payload))
	// Match the response RR type to the probe query type (A2). The up-probe
	// response is small, so it encodes cleanly as CNAME when the query was
	// non-TXT, and its size does not affect upload-MTU measurement.
	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, decision.RequestName, decision.BaseDomain, VpnProto.Packet{
		SessionID:       vpnPacket.SessionID,
		PacketType:      Enums.PACKET_MTU_UP_RES,
		Payload:         responsePayload[:],
		LegacySessionID: vpnPacket.LegacySessionID,
	}, baseEncode, s.cfg.ARecordDataDelivery)

	if err != nil {
		return nil
	}

	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeDownMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return nil
	}

	payloadBuffer := s.mtuProbePayloadPool.Get().([]byte)
	defer s.mtuProbePayloadPool.Put(payloadBuffer)
	payload := payloadBuffer[:downloadSize]
	copy(payload[:mtuProbeCodeLength], vpnPacket.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		fillMTUProbeBytes(payload[mtuProbeMetaLength:])
	}

	// Match the response RR type to the probe query type (A2). Large download
	// probe sizes exceed a single CNAME and auto-fall-back to TXT inside the
	// builder, so the download-capacity ceiling is still measured on the TXT
	// channel that bulk data actually uses; smaller sizes match the query type.
	response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(questionPacket, decision.RequestName, decision.BaseDomain, VpnProto.Packet{
		SessionID:       vpnPacket.SessionID,
		PacketType:      Enums.PACKET_MTU_DOWN_RES,
		StreamID:        vpnPacket.StreamID,
		SequenceNum:     vpnPacket.SequenceNum,
		FragmentID:      vpnPacket.FragmentID,
		TotalFragments:  vpnPacket.TotalFragments,
		Payload:         payload,
		LegacySessionID: vpnPacket.LegacySessionID,
	}, baseEncode, s.cfg.ARecordDataDelivery)
	if err != nil {
		return nil
	}

	return response
}
