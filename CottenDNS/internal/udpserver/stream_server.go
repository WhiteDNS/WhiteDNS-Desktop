// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/arq"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/fec"
	"cottendns-go/internal/mlq"
	VpnProto "cottendns-go/internal/vpnproto"
)

// Stream_server encapsulates an ARQ instance and its transmit queue for a single stream.
type Stream_server struct {
	mu        sync.RWMutex
	txQueueMu sync.Mutex
	txClosed  bool
	cleanupMu sync.Once
	rxQueueMu sync.Mutex

	ID        uint16
	SessionID uint16
	ARQ       *arq.ARQ
	TXQueue   *mlq.MultiLevelQueue[*serverStreamTXPacket]

	Status       string
	CreatedAt    time.Time
	LastActivity time.Time
	CloseTime    time.Time

	UpstreamConn io.ReadWriteCloser
	TargetHost   string
	TargetPort   uint16
	Connected    bool
	onClosed     func(uint16, time.Time, string)
	log          arq.Logger

	// Forward error correction (download direction, opt-in). When fecEnc is
	// non-nil, STREAM_DATA/RESEND popped for this stream are diverted into the
	// encoder at dequeue time and emitted as PACKET_FEC_SHARD frames instead of
	// raw data packets; fecShardQueue holds frames waiting for a poll to carry
	// them. ARQ above is unchanged: it still tracks, dedups and retransmits the
	// underlying data packets, providing the backstop when a block is lost
	// beyond recovery. All FEC state is guarded by fecMu.
	fecMu         sync.Mutex
	fecEnc        *fec.Encoder
	fecShardQueue [][]byte
	// fecActive gates whether *new* download data is actually diverted through
	// the encoder. The encoder object is kept alive once created so its block
	// numbering stays monotonic across a disengage/re-engage cycle (a reset
	// blockID could collide with a still-tracked block on the client decoder);
	// while fecActive is false the stream sends raw packets at zero FEC overhead.
	// fecLowWindows counts consecutive sub-threshold loss windows for the
	// disengage hysteresis. Both are guarded by fecMu.
	fecActive     bool
	fecLowWindows int

	// Loss-triggered FEC (tier-2 auto activation). When fecAuto is set, the
	// stream measures its own download loss from the retransmit rate over a
	// sliding window and turns FEC on (and scales parity) once loss crosses
	// fecAutoThreshold. It engages on loss and, once the link stays clean for
	// fecDisengageWindows windows, fully disengages back to raw packets so a
	// long-lived stream that saw one loss spike does not pay parity overhead for
	// the rest of its life. Auto params are guarded by fecMu; window counters are
	// atomic.
	fecAuto           atomic.Bool
	fecAutoBlock      int
	fecAutoBaseParity int
	fecAutoMaxParity  int
	fecAutoThreshold  float64
	// Super-FEC: a last-ditch, loss-aware high-parity band for extreme loss. When
	// enabled and measured loss enters [fecSuperLossFloor, fecSuperLossCeil], parity
	// is scaled continuously to the *measured* loss (via fec.ParityForLoss), lifted
	// above the normal auto ceiling up to fecSuperMaxParity — so 76% loss gets less
	// protection than 84% instead of a flat slam. Above fecSuperLossCeil the link is
	// treated as hopeless: the server stops escalating and relaxes to the base rate
	// so it does not burn CPU/bandwidth encoding giant Reed-Solomon blocks for
	// traffic that will not arrive anyway (the block is dropped from FEC and left to
	// ARQ). fecSuperMaxParity == 0 means the Reed-Solomon hard limit for the block.
	fecSuperEnabled    bool
	fecSuperLossFloor  float64
	fecSuperLossCeil   float64
	fecSuperMaxParity  int
	fecWindowData      atomic.Uint64
	fecWindowResends   atomic.Uint64
	fecWindowAdjusting atomic.Bool
}

const fecAutoWindow = 64

// fecDisengageWindows is how many consecutive sub-threshold loss windows an
// active stream must see before it tears FEC back down to raw packets. The delay
// is hysteresis: it stops FEC flapping on/off when loss hovers at the threshold,
// while still returning a recovered link to zero FEC overhead.
const fecDisengageWindows = 3

func NewStreamServer(streamID uint16, sessionID uint16, arqConfig arq.Config, localConn io.ReadWriteCloser, mtu int, queueInitialCapacity int, logger arq.Logger) *Stream_server {
	if queueInitialCapacity < 1 {
		queueInitialCapacity = 32
	}
	s := &Stream_server{
		ID:           streamID,
		SessionID:    sessionID,
		TXQueue:      mlq.New[*serverStreamTXPacket](queueInitialCapacity),
		Status:       "PENDING",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		log:          logger,
	}

	if s.log == nil {
		s.log = &arq.DummyLogger{}
	}

	s.ARQ = arq.NewARQ(streamID, sessionID, s, localConn, mtu, s.log, arqConfig)
	s.ARQ.Start()

	return s
}

func (s *Stream_server) enqueueInboundData(packetType uint8, sequenceNum uint16, fragmentID uint8, payload []byte) bool {
	if s == nil || s.ARQ == nil {
		return false
	}

	return s.ARQ.ReceiveData(sequenceNum, payload)
}

// PushTXPacket implements arq.PacketEnqueuer.
// It adds a packet to the stream's multi-level queue.
func (s *Stream_server) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()

	s.recordFECSample(packetType)

	priority = Enums.NormalizePacketPriority(packetType, priority)

	dataKey := Enums.PacketIdentityKey(s.ID, Enums.PACKET_STREAM_DATA, sequenceNum, fragmentID)
	resendKey := Enums.PacketIdentityKey(s.ID, Enums.PACKET_STREAM_RESEND, sequenceNum, fragmentID)
	key := Enums.PacketIdentityKey(s.ID, packetType, sequenceNum, fragmentID)

	pkt := getTXPacketFromPool()
	pkt.PacketType = packetType
	pkt.SequenceNum = sequenceNum
	pkt.FragmentID = fragmentID
	pkt.TotalFragments = totalFragments
	pkt.CompressionType = compressionType
	pkt.Payload = payload
	pkt.CreatedAt = time.Now()
	pkt.TTL = ttl

	s.txQueueMu.Lock()
	if s.txClosed {
		s.txQueueMu.Unlock()
		putTXPacketToPool(pkt)
		return false
	}

	switch packetType {
	case Enums.PACKET_STREAM_DATA:
		if _, exists := s.TXQueue.Get(dataKey); exists {
			s.txQueueMu.Unlock()
			putTXPacketToPool(pkt)
			return false
		}

		if _, exists := s.TXQueue.Get(resendKey); exists {
			s.txQueueMu.Unlock()
			putTXPacketToPool(pkt)
			return false
		}
	case Enums.PACKET_STREAM_RESEND:
		if _, exists := s.TXQueue.Get(resendKey); exists {
			s.txQueueMu.Unlock()
			putTXPacketToPool(pkt)
			return false
		}
	}

	ok := s.TXQueue.Push(priority, key, pkt)
	if !ok {
		s.txQueueMu.Unlock()
		putTXPacketToPool(pkt)
		return false
	}

	if packetType == Enums.PACKET_STREAM_RESEND {
		if stale, removed := s.TXQueue.RemoveByKey(dataKey, func(p *serverStreamTXPacket) uint64 {
			return Enums.PacketIdentityKey(s.ID, p.PacketType, p.SequenceNum, p.FragmentID)
		}); removed {
			putTXPacketToPool(stale)
		}
	}

	s.txQueueMu.Unlock()

	// Notify session that this stream is active (handled by the caller or session management)
	return true
}

func (s *Stream_server) NoteTXPacketDequeued(packet *serverStreamTXPacket) {
	if s == nil || packet == nil || s.ARQ == nil {
		return
	}

	s.ARQ.NoteTXPacketDequeued(packet.PacketType, packet.SequenceNum, packet.FragmentID)
}

func (s *Stream_server) RemoveQueuedData(sequenceNum uint16) bool {
	if s == nil || s.TXQueue == nil {
		return false
	}

	s.txQueueMu.Lock()
	removedAny := false
	for _, packetType := range []uint8{Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND} {
		key := Enums.PacketIdentityKey(s.ID, packetType, sequenceNum, 0)
		pkt, ok := s.TXQueue.RemoveByKey(key, func(p *serverStreamTXPacket) uint64 {
			return Enums.PacketIdentityKey(s.ID, p.PacketType, p.SequenceNum, p.FragmentID)
		})
		if ok {
			putTXPacketToPool(pkt)
			removedAny = true
		}
	}

	s.txQueueMu.Unlock()

	return removedAny
}

func (s *Stream_server) RemoveQueuedDataNack(sequenceNum uint16) bool {
	if s == nil || s.TXQueue == nil {
		return false
	}

	s.txQueueMu.Lock()
	key := Enums.PacketIdentityKey(s.ID, Enums.PACKET_STREAM_DATA_NACK, sequenceNum, 0)
	pkt, ok := s.TXQueue.RemoveByKey(key, func(p *serverStreamTXPacket) uint64 {
		return Enums.PacketIdentityKey(s.ID, p.PacketType, p.SequenceNum, p.FragmentID)
	})

	if !ok {
		s.txQueueMu.Unlock()
		return false
	}

	putTXPacketToPool(pkt)
	s.txQueueMu.Unlock()
	return true
}

func (s *Stream_server) ClearTXQueue() {
	s.clearTXQueue(false)
}

// closeTXQueue atomically prevents every future producer from enqueueing and
// releases packets already queued. Holding the same lock as PushTXPacket closes
// the teardown race where an ARQ goroutine could enqueue a terminal packet just
// after cleanup had cleared the queue.
func (s *Stream_server) closeTXQueue() {
	s.clearTXQueue(true)
}

func (s *Stream_server) clearTXQueue(closeQueue bool) {
	if s == nil || s.TXQueue == nil {
		return
	}

	s.txQueueMu.Lock()
	if closeQueue {
		s.txClosed = true
	}
	s.TXQueue.Clear(func(pkt *serverStreamTXPacket) {
		putTXPacketToPool(pkt)
	})
	s.txQueueMu.Unlock()
}

func (s *Stream_server) FastTXQueueSize() int {
	if s == nil || s.TXQueue == nil {
		return 0
	}

	return s.TXQueue.FastSize()
}

func (s *Stream_server) PopNextTXPacket() (*serverStreamTXPacket, int, bool) {
	if s == nil || s.TXQueue == nil {
		return nil, 0, false
	}

	s.txQueueMu.Lock()
	packet, priority, ok := s.TXQueue.Pop(func(p *serverStreamTXPacket) uint64 {
		return Enums.PacketIdentityKey(s.ID, p.PacketType, p.SequenceNum, p.FragmentID)
	})
	s.txQueueMu.Unlock()

	return packet, priority, ok
}

func (s *Stream_server) PopAnyTXPacket(maxPriority int, predicate func(*serverStreamTXPacket) bool) (*serverStreamTXPacket, bool) {
	if s == nil || s.TXQueue == nil {
		return nil, false
	}

	s.txQueueMu.Lock()
	packet, ok := s.TXQueue.PopAnyIf(maxPriority, predicate, func(p *serverStreamTXPacket) uint64 {
		return Enums.PacketIdentityKey(s.ID, p.PacketType, p.SequenceNum, p.FragmentID)
	})
	s.txQueueMu.Unlock()

	return packet, ok
}

func (s *Stream_server) Abort(reason string) {
	s.CloseStream(true, 0, reason)
}

func (s *Stream_server) attachUpstreamConn(conn io.ReadWriteCloser, host string, port uint16, status string) bool {
	if s == nil || conn == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Status == "CLOSED" || !s.CloseTime.IsZero() {
		return false
	}
	if s.ARQ != nil && s.ARQ.IsClosed() {
		return false
	}
	if s.UpstreamConn != nil || s.Connected {
		return false
	}

	s.UpstreamConn = conn
	s.TargetHost = host
	s.TargetPort = port
	s.Connected = true
	if status != "" {
		s.Status = status
	}
	s.LastActivity = time.Now()
	// worker is already started in NewStreamServer
	return true
}

func (s *Stream_server) cleanupResources() {
	var upstream io.ReadWriteCloser

	s.mu.Lock()
	s.Status = "CLOSED"
	s.CloseTime = time.Now()
	s.Connected = false
	upstream = s.UpstreamConn
	s.UpstreamConn = nil
	s.mu.Unlock()

	if upstream != nil {
		_ = upstream.Close()
	}
	s.closeTXQueue()
}

func (s *Stream_server) finalizeAfterARQClose(reason string) {
	if s == nil {
		return
	}

	s.cleanupMu.Do(func() {
		now := time.Now()
		s.cleanupResources()
		if s.onClosed != nil {
			s.onClosed(s.ID, now, reason)
		}
	})
}

func (s *Stream_server) OnARQClosed(reason string) {
	s.finalizeAfterARQClose(reason)
}

func (s *Stream_server) closeUpstreamOnly(status string) {
	if s == nil {
		return
	}

	var upstream io.ReadWriteCloser

	s.mu.Lock()
	if status != "" {
		s.Status = status
	} else if s.Status != "CLOSED" {
		s.Status = "CLOSING"
	}
	s.CloseTime = time.Now()
	s.Connected = false
	upstream = s.UpstreamConn
	s.UpstreamConn = nil
	s.mu.Unlock()

	if upstream != nil {
		_ = upstream.Close()
	}
}

func (s *Stream_server) CloseStream(force bool, ttl time.Duration, reason string) {
	if s == nil {
		return
	}

	if s.ARQ != nil {
		if force {
			s.closeUpstreamOnly("CLOSED")
			s.ARQ.Close(reason, arq.CloseOptions{
				SendRST: true,
				TTL:     ttl,
			})
			return
		}

		s.ARQ.Close(reason, arq.CloseOptions{
			SendCloseRead: true,
			AfterDrain:    true,
			TTL:           ttl,
		})
		return
	}

	s.finalizeAfterARQClose(reason)
}

// EnableFEC turns on download-direction forward error correction for this
// stream. It is idempotent: a second call (e.g. from another data-stream entry
// point) is a no-op so a stream's FEC block numbering is never reset mid-flight.
func (s *Stream_server) EnableFEC(blockSize, parity int) {
	if s == nil {
		return
	}
	s.fecMu.Lock()
	if s.fecEnc == nil {
		s.fecEnc = fec.NewEncoder(blockSize, parity)
	}
	// Explicit FEC is always active. Auto-FEC uses the same gate but may later
	// disengage it after sustained clean windows.
	s.fecActive = true
	s.fecMu.Unlock()
}

// ConfigureAutoFEC arms loss-triggered FEC for this stream. FEC stays off (zero
// overhead) until the measured download loss crosses threshold, at which point
// it turns on with parity scaled to the loss, clamped to [baseParity, maxParity].
func (s *Stream_server) ConfigureAutoFEC(blockSize, baseParity, maxParity int, threshold float64) {
	if s == nil {
		return
	}
	s.fecMu.Lock()
	s.fecAutoBlock = blockSize
	s.fecAutoBaseParity = baseParity
	s.fecAutoMaxParity = maxParity
	s.fecAutoThreshold = threshold
	s.fecMu.Unlock()
	s.fecAuto.Store(true)
}

// ConfigureSuperFEC arms the Super-FEC escalation band on top of auto-FEC. Only
// takes effect when auto-FEC is also configured. floor/ceil are loss fractions
// (0..1); the band is clamped to a sane order (floor <= ceil). maxParity caps the
// per-block parity in the band (0 = the Reed-Solomon hard limit for the block).
func (s *Stream_server) ConfigureSuperFEC(enabled bool, lossFloor, lossCeil float64, maxParity int) {
	if s == nil {
		return
	}
	if lossFloor < 0 {
		lossFloor = 0
	}
	if lossCeil > 1 {
		lossCeil = 1
	}
	if lossCeil < lossFloor {
		lossCeil = lossFloor
	}
	if maxParity < 0 {
		maxParity = 0
	}
	s.fecMu.Lock()
	s.fecSuperEnabled = enabled
	s.fecSuperLossFloor = lossFloor
	s.fecSuperLossCeil = lossCeil
	s.fecSuperMaxParity = maxParity
	s.fecMu.Unlock()
}

// recordFECSample tallies a download data send (STREAM_DATA) or a retransmit
// (STREAM_RESEND) into the current loss window. When the window fills it
// re-evaluates whether to enable/scale auto FEC. Cheap no-op when auto is off.
func (s *Stream_server) recordFECSample(packetType uint8) {
	if s == nil || !s.fecAuto.Load() {
		return
	}
	switch packetType {
	case Enums.PACKET_STREAM_DATA:
		if s.fecWindowData.Add(1) >= fecAutoWindow {
			s.runPendingAutoFECAdjustments()
		}
	case Enums.PACKET_STREAM_RESEND:
		s.fecWindowResends.Add(1)
	}
}

// runPendingAutoFECAdjustments guarantees only one goroutine closes a loss
// window at a time. Data and retransmit producers can enqueue concurrently; a
// simple threshold check would otherwise let multiple callers swap tiny
// follow-up windows and incorrectly count them as clean hysteresis windows.
func (s *Stream_server) runPendingAutoFECAdjustments() {
	if !s.fecWindowAdjusting.CompareAndSwap(false, true) {
		return
	}
	defer s.fecWindowAdjusting.Store(false)
	for {
		s.maybeAdjustAutoFEC()
		s.fecWindowAdjusting.Store(false)
		if s.fecWindowData.Load() < fecAutoWindow ||
			!s.fecWindowAdjusting.CompareAndSwap(false, true) {
			return
		}
	}
}

// maybeAdjustAutoFEC computes the loss over the just-closed window and, if it is
// at or above the threshold, turns FEC on (or raises parity) scaled to the loss.
// Once the link stays below the threshold for fecDisengageWindows windows it
// fully disengages FEC back to raw packets (zero overhead), keeping the encoder
// object so block numbering stays monotonic for the client if FEC re-engages.
func (s *Stream_server) maybeAdjustAutoFEC() {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()

	data := s.fecWindowData.Swap(0)
	resends := s.fecWindowResends.Swap(0)
	if data == 0 {
		return
	}
	loss := float64(resends) / float64(data+resends)

	if loss < s.fecAutoThreshold {
		if !s.fecActive {
			return // already at zero overhead — nothing to relax or tear down
		}
		s.fecLowWindows++
		if s.fecLowWindows < fecDisengageWindows {
			// Not yet confident the link recovered: relax parity toward the base
			// but keep FEC engaged so a quick relapse stays protected.
			if s.fecEnc != nil {
				s.fecEnc.SetParity(s.fecAutoBaseParity)
			}
			return
		}
		// Sustained clean windows: tear FEC all the way down to raw packets. The
		// encoder is kept (block numbering stays monotonic); its buffered tail and
		// any queued shards are dropped here and recovered by the ARQ retransmit
		// backstop, which still holds those sequences un-acked and resends them raw.
		s.fecActive = false
		s.fecLowWindows = 0
		if s.fecEnc != nil {
			_, _ = s.fecEnc.Flush()
		}
		s.fecShardQueue = nil
		if s.log != nil {
			s.log.Debugf("Stream %d: auto-FEC disengaged after %d clean windows (loss=%.0f%%) — back to raw packets", s.ID, fecDisengageWindows, loss*100)
		}
		return
	}

	// Super-FEC banding. When enabled and loss is extreme, decide between a
	// last-ditch maximum-parity rebuild attempt (inside the band) and giving up on
	// FEC protection entirely (above the ceiling) so the server does not spend CPU
	// encoding hopeless blocks.
	if s.fecSuperEnabled {
		if loss > s.fecSuperLossCeil {
			// Beyond the ceiling the link is effectively dead: stop escalating and
			// relax to the base rate. The unrecoverable block is left to ARQ rather
			// than protected with a giant Reed-Solomon encode that would only strain
			// the server. This is the "drop instead of rebuild" behavior.
			s.fecLowWindows = 0
			if s.fecActive && s.fecEnc != nil {
				s.fecEnc.SetParity(s.fecAutoBaseParity)
				if s.log != nil {
					s.log.Debugf("Stream %d: Super-FEC disengaged (loss=%.0f%% > %.0f%% ceiling) — dropping FEC protection to spare server", s.ID, loss*100, s.fecSuperLossCeil*100)
				}
			}
			return
		}
		if loss >= s.fecSuperLossFloor {
			// Inside the Super-FEC band: scale parity to the *measured* loss so the
			// code rate tracks how bad the link actually is, lifted above the normal
			// auto ceiling up to the super cap (0 = Reed-Solomon hard limit). This is
			// loss-aware, not a flat slam: 76% loss buys less parity than 84%.
			// At extreme loss, sizing parity only to the expected survivor count
			// makes reconstruction a coin flip. Super-FEC targets 90% random-loss
			// block recovery (subject to the configured/hard parity cap).
			parity := fec.ParityForLossTarget(s.fecAutoBlock, loss, 0.90)
			superCap := s.fecSuperMaxParity
			hardMax := fec.MaxParity(s.fecAutoBlock)
			if superCap <= 0 || superCap > hardMax {
				superCap = hardMax
			}
			if parity > superCap {
				parity = superCap
			}
			if parity < s.fecAutoBaseParity {
				parity = s.fecAutoBaseParity
			}
			wasActive := s.fecActive
			s.engageAutoFECLocked(parity)
			if s.log != nil && !wasActive {
				s.log.Debugf("Stream %d: Super-FEC engaged (loss=%.0f%%, parity=%d, cap=%d)", s.ID, loss*100, parity, superCap)
			}
			return
		}
	}

	parity := fec.ParityForLoss(s.fecAutoBlock, loss)
	if parity < s.fecAutoBaseParity {
		parity = s.fecAutoBaseParity
	}
	if s.fecAutoMaxParity > 0 && parity > s.fecAutoMaxParity {
		parity = s.fecAutoMaxParity
	}
	wasActive := s.fecActive
	s.engageAutoFECLocked(parity)
	if s.log != nil && !wasActive {
		s.log.Debugf("Stream %d: auto-enabled FEC (loss=%.0f%%, parity=%d)", s.ID, loss*100, parity)
	}
}

// engageAutoFECLocked (re)activates download FEC at the given parity. It creates
// the encoder on first use and otherwise reuses the existing one so block
// numbering stays monotonic across any prior disengage. Resets the clean-window
// counter used for disengage hysteresis. Callers must hold fecMu.
func (s *Stream_server) engageAutoFECLocked(parity int) {
	if s.fecEnc == nil {
		s.fecEnc = fec.NewEncoder(s.fecAutoBlock, parity)
	} else {
		s.fecEnc.SetParity(parity)
	}
	s.fecActive = true
	s.fecLowWindows = 0
}

// FECEnabled reports whether this stream is currently diverting data through FEC.
func (s *Stream_server) FECEnabled() bool {
	if s == nil {
		return false
	}
	s.fecMu.Lock()
	on := s.fecActive
	s.fecMu.Unlock()
	return on
}

// feedFECData packs a data packet into a FEC unit and buffers it into the
// encoder, appending any shard frames produced at a block boundary.
func (s *Stream_server) feedFECData(seq uint16, fragID uint8, payload []byte) bool {
	unit := VpnProto.PackFECDataUnit(seq, fragID, payload)
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if !s.fecActive || s.fecEnc == nil {
		return false
	}
	frames, err := s.fecEnc.AddPacket(unit)
	if err != nil {
		return false
	}
	s.fecShardQueue = append(s.fecShardQueue, frames...)
	return true
}

// flushFEC emits a short trailing block for whatever data units are buffered,
// so a paused stream's tail is not stuck below a block boundary.
func (s *Stream_server) flushFEC() {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if !s.fecActive || s.fecEnc == nil {
		return
	}
	frames, err := s.fecEnc.Flush()
	if err != nil {
		return
	}
	s.fecShardQueue = append(s.fecShardQueue, frames...)
}

// popFECShard returns the next buffered shard frame, or (nil,false) if none.
func (s *Stream_server) popFECShard() ([]byte, bool) {
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if len(s.fecShardQueue) == 0 {
		return nil, false
	}
	frame := s.fecShardQueue[0]
	s.fecShardQueue = s.fecShardQueue[1:]
	if len(s.fecShardQueue) == 0 {
		s.fecShardQueue = nil
	}
	return frame, true
}

// HasBufferedFECWork reports whether this stream still owes FEC output: either
// queued shard frames or data units buffered in the encoder below a block
// boundary. The dequeue loop uses it to keep selecting a FEC stream that has no
// TXQueue entries left but still has a trailing block to flush.
func (s *Stream_server) HasBufferedFECWork() bool {
	if s == nil {
		return false
	}
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if !s.fecActive {
		return false
	}
	if len(s.fecShardQueue) > 0 {
		return true
	}
	return s.fecEnc != nil && s.fecEnc.Buffered() > 0
}
