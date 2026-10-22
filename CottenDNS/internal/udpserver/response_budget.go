package udpserver

import (
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	"cottendns-go/internal/security"
)

const udpBudgetStallTimeout = 30 * time.Second

func isTCPResponse(tcp []bool) bool { return len(tcp) > 0 && tcp[0] }

func (s *Server) responsePayloadCapacity(question []byte, domain string, mode uint8, codec *security.Codec, tcp bool, reserveQuestionHeadroom ...bool) int {
	baseEncoded, valid := parseMTUProbeBaseEncoding(mode)
	if !valid {
		return 0
	}
	encrypted := mode&security.DownstreamEncryptedFlag != 0
	capacity := DnsParser.ResponseFrameCapacity(question, domain, s.cfg.ARecordDataDelivery, s.cfg.AAAARecordDataDelivery, baseEncoded, encrypted, tcp, reserveQuestionHeadroom...)
	capacity -= maxVPNFrameHeaderLen
	if encrypted {
		if codec == nil {
			return 0
		}
		capacity -= codec.CiphertextOverhead()
	}
	return max(0, capacity)
}

func (s *Server) noteBudgetBlocked(sessionID uint16, capacity int, now time.Time) {
	if record, ok := s.sessions.Get(sessionID); ok {
		record.mu.Lock()
		if record.udpBudgetBlockedSince.IsZero() {
			record.udpBudgetBlockedSince = now
			record.udpBudgetBlockedCapacity = capacity
		}
		record.mu.Unlock()
	}
}

func (s *Server) noteBudgetDelivered(sessionID uint16, size int) {
	if record, ok := s.sessions.Get(sessionID); ok {
		record.mu.Lock()
		if size > record.udpBudgetBlockedCapacity {
			record.udpBudgetBlockedSince = time.Time{}
		}
		record.mu.Unlock()
	}
}

// A temporary small carrier retains queued frames for a later larger UDP/TCP
// poll. If all usable paths shrink, old ARQ sequences cannot be split without
// changing their meaning to existing clients. Bound that stall with the existing
// ERROR_DROP recovery signal, then release the old session. The next UDP init
// negotiates a download MTU that fits its current wire budget.
func (s *Server) resetBudgetStalledSession(question []byte, name string, view *sessionRuntimeView, capacity int, now time.Time, tcp bool) bool {
	record, ok := s.sessions.Get(view.ID)
	if !ok {
		return false
	}
	record.mu.Lock()
	if tcp || capacity >= record.DownloadMTUBytes {
		record.udpBudgetBlockedSince = time.Time{}
		record.mu.Unlock()
		return false
	}
	since := record.udpBudgetBlockedSince
	record.mu.Unlock()
	if since.IsZero() || now.Sub(since) < udpBudgetStallTimeout {
		return false
	}
	// Inspect without removing packets. This slow path runs only after a
	// prolonged stall, so ACKs that already removed the blocked sequence cannot
	// cause an unnecessary reset of an otherwise healthy session.
	_, streams := record.activeStreamSnapshot()
	blocked := false
	for _, stream := range streams {
		stream.PopAnyTXPacket(5, func(packet *serverStreamTXPacket) bool {
			blocked = blocked || len(packet.Payload) > capacity
			return false
		})
		if blocked {
			break
		}
	}
	if !blocked {
		record.mu.Lock()
		record.udpBudgetBlockedSince = time.Time{}
		record.mu.Unlock()
		return false
	}
	if closed, ok := s.sessions.Close(view.ID, now, s.cfg.ClosedSessionRetention()); ok {
		s.cleanupClosedSession(view.ID, closed)
	}
	return true
}
