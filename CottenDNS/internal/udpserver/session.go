// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/arq"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/mlq"
	VpnProto "cottendns-go/internal/vpnproto"
)

var ErrSessionTableFull = errors.New("session table full")

const (
	maxServerSessionID    = 65535
	maxServerSessionSlots = 65535
	// maxLegacySessionID is the largest ID a MasterDNS/StormDNS client can
	// represent in its one-byte session field. The ID space is split at this
	// boundary — legacy sessions below it, native sessions above — so that the
	// parser can tell the two header layouts apart by the ID they decode to
	// (see vpnproto.parseFrom). Native clients lose the first 255 IDs, which is
	// immaterial against a 65535 space.
	maxLegacySessionID  = 255
	sessionInitDataSize = 10
	minSessionMTU       = 10
	maxSessionMTU       = 4096
)

type sessionRecord struct {
	mu sync.RWMutex

	ID uint16
	// LegacySessionID records that this session was opened by a client of the
	// MasterDNS/StormDNS lineage, which spends one header byte on the session
	// ID instead of two. Every reply on this session is built back in that
	// format.
	LegacySessionID                     bool
	Cookie                              uint8
	ResponseMode                        uint8
	UploadCompression                   uint8
	DownloadCompression                 uint8
	UploadMTU                           uint16
	DownloadMTU                         uint16
	DownloadMTUBytes                    int
	VerifyCode                          [4]byte
	Signature                           [sessionInitDataSize]byte
	MaxPackedBlocks                     int
	StreamReadBufferSize                int
	CreatedAt                           time.Time
	ReuseUntil                          time.Time
	reuseUntilUnixNano                  int64
	lastActivityUnixNano                int64
	lastDeferredCleanupActivityUnixNano int64

	// New fields for ARQ refactor
	Streams                         map[uint16]*Stream_server
	ActiveStreams                   []uint16 // Sorted list of active stream IDs for Round-Robin
	activeStreamSetVersion          uint64
	activeStreamSnapshotIDs         []int32
	activeStreamSnapshotStreams     []*Stream_server
	activeStreamSnapshotVersion     uint64
	RRStreamID                      int32  // Last served stream ID for RR
	EnqueueSeq                      uint64 // Global sequence for FIFO inside same priority
	StreamQueueCap                  int
	MaxStreams                      int
	streamCapRejections             *atomic.Uint64
	activeStreamCounter             *atomic.Uint64
	StreamsMu                       sync.RWMutex
	RecentlyClosed                  map[uint16]recentlyClosedStreamRecord
	RecentlyClosedTTL               time.Duration
	RecentlyClosedCap               int
	OrphanQueue                     *mlq.MultiLevelQueue[VpnProto.Packet]
	LastPackedControlBlock          *VpnProto.Packet
	LastPackedControlBlockRemaining int
	closedFlag                      uint32
	streamCleanup                   func(uint16, uint16)
}

type recentlyClosedStreamRecord struct {
	ClosedAt       time.Time
	SuppressOrphan bool
}

// serverStreamTXPacket represents a queued packet pending transmission or retransmission.
type serverStreamTXPacket struct {
	PacketType      uint8
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
	CreatedAt       time.Time
	TTL             time.Duration
}

var txPacketPool = sync.Pool{
	New: func() any {
		return &serverStreamTXPacket{}
	},
}

func getTXPacketFromPool() *serverStreamTXPacket {
	return txPacketPool.Get().(*serverStreamTXPacket)
}

func putTXPacketToPool(p *serverStreamTXPacket) {
	if p == nil {
		return
	}
	p.Payload = nil
	p.TTL = 0
	txPacketPool.Put(p)
}

// getEffectivePriority maps packet types to priorities (0 is highest, 5 is lowest).
func getEffectivePriority(packetType uint8, basePriority int) int {
	return Enums.NormalizePacketPriority(packetType, basePriority)
}

type sessionRuntimeView struct {
	ID                  uint16
	LegacySessionID     bool
	Cookie              uint8
	ResponseMode        uint8
	ResponseBase64      bool
	DownloadCompression uint8
	DownloadMTU         uint16
	DownloadMTUBytes    int
	MaxPackedBlocks     int
}

type closedSessionRecord struct {
	Cookie          uint8
	ResponseMode    uint8
	LegacySessionID bool
	ExpiresAt       time.Time
}

type sessionLookupState uint8

const (
	sessionLookupUnknown sessionLookupState = iota
	sessionLookupActive
	sessionLookupClosed
)

type sessionLookupResult struct {
	Cookie          uint8
	ResponseMode    uint8
	LegacySessionID bool
	State           sessionLookupState
}

type sessionValidationResult struct {
	Lookup sessionLookupResult
	Known  bool
	Valid  bool
	Active *sessionRuntimeView
}

type closedSessionCleanup struct {
	ID     uint16
	record *sessionRecord
}

type idleDeferredCleanup struct {
	ID               uint16
	lastActivityNano int64
}

type sessionStore struct {
	mu                     sync.RWMutex
	legacyNextID           uint16
	nativeNextID           uint16
	activeCount            uint16
	activeNative           uint16
	activeLegacy           uint16
	nextReuseSweepUnixNano int64
	cookieBytes            [32]byte
	cookieIndex            int
	byID                   [maxServerSessionID + 1]*sessionRecord
	// liveByID mirrors active byID entries for the packet hot path. Allocation,
	// cleanup, signature reuse and recently-closed bookkeeping remain under mu;
	// established packet lookup and cookie validation need only an atomic load.
	liveByID [maxServerSessionID + 1]atomic.Pointer[sessionRecord]
	// activeIDs is the set of currently-allocated session IDs. It lets the
	// background sweeps iterate only live sessions instead of scanning the full
	// 65536-slot byID array, which matters now that the session cap is uint16.
	activeIDs            map[uint16]struct{}
	bySig                map[[sessionInitDataSize]byte]uint16
	recentClosed         map[uint16]closedSessionRecord
	orphanQueueCap       int
	streamQueueCap       int
	maxStreamsPerSession int
	// maxActiveSessions caps how many sessions may be live at once. 0 means fall
	// back to the hard slot ceiling (maxServerSessionSlots).
	maxActiveSessions int
	// maxClientUploadMTU/maxClientDownloadMTU are the operator's ceilings on
	// what a client may request in SESSION_INIT. Zero means no ceiling. Set via
	// setClientMTUCeilings rather than the positional options list, which is
	// already long enough that another anonymous int would invite mix-ups.
	maxClientUploadMTU   int
	maxClientDownloadMTU int
	sessionInitTTL       time.Duration
	recentlyClosedTTL    time.Duration
	recentlyClosedCap    int
	// streamCapRejections counts every getOrCreateStream call that was
	// refused because MaxStreams had been reached. The pointer is shared
	// with each sessionRecord so the cap-enforcement path can increment it
	// without holding a back-reference to the store.
	streamCapRejections atomic.Uint64
	activeStreams       atomic.Uint64
}

// streamCapRejectionsCount returns the running count of stream-cap rejections
// observed by getOrCreateStream across all sessions in this store.
func (s *sessionStore) streamCapRejectionsCount() uint64 {
	if s == nil {
		return 0
	}
	return s.streamCapRejections.Load()
}

func newSessionStore(orphanQueueCap int, streamQueueCap int, options ...any) *sessionStore {
	if orphanQueueCap < 1 {
		orphanQueueCap = 8
	}
	if streamQueueCap < 1 {
		streamQueueCap = 32
	}

	sessionInitTTL := 10 * time.Minute
	recentlyClosedTTL := 600 * time.Second
	recentlyClosedCap := 2000
	maxStreamsPerSession := 0
	maxActiveSessions := 0
	if len(options) > 0 {
		if v, ok := options[0].(time.Duration); ok && v > 0 {
			sessionInitTTL = v
		}
	}
	if len(options) > 1 {
		if v, ok := options[1].(time.Duration); ok && v > 0 {
			recentlyClosedTTL = v
		}
	}
	if len(options) > 2 {
		if v, ok := options[2].(int); ok && v > 0 {
			recentlyClosedCap = v
		}
	}
	if len(options) > 3 {
		if v, ok := options[3].(int); ok && v > 0 {
			maxStreamsPerSession = v
		}
	}
	if len(options) > 4 {
		if v, ok := options[4].(int); ok && v > 0 {
			maxActiveSessions = v
		}
	}
	return &sessionStore{
		activeIDs:            make(map[uint16]struct{}, 64),
		bySig:                make(map[[sessionInitDataSize]byte]uint16, 64),
		recentClosed:         make(map[uint16]closedSessionRecord, 32),
		cookieIndex:          32,
		legacyNextID:         1,
		nativeNextID:         maxLegacySessionID + 1,
		orphanQueueCap:       orphanQueueCap,
		streamQueueCap:       streamQueueCap,
		maxStreamsPerSession: maxStreamsPerSession,
		maxActiveSessions:    maxActiveSessions,
		sessionInitTTL:       sessionInitTTL,
		recentlyClosedTTL:    recentlyClosedTTL,
		recentlyClosedCap:    recentlyClosedCap,
	}
}

func (s *sessionStore) findOrCreate(payload []byte, uploadCompressionType uint8, downloadCompressionType uint8, maxPacketsPerBatch int, legacy bool) (*sessionRecord, bool, error) {
	if len(payload) != sessionInitDataSize || !isValidSessionResponseMode(payload[0]) {
		return nil, false, nil
	}

	var signature [sessionInitDataSize]byte
	copy(signature[:], payload[:sessionInitDataSize])

	now := time.Now()
	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireReuseLocked(nowUnixNano)

	if sessionID, ok := s.bySig[signature]; ok {
		if existing := s.byID[sessionID]; existing != nil {
			// The signature is derived from the init payload alone, which is
			// identical in both wire formats, so it can collide across client
			// generations. Reusing a record of the other format would hand the
			// client a session ID it cannot express, so only reuse on a match.
			if nowUnixNano <= existing.reuseUntilUnixNano && existing.LegacySessionID == legacy {
				existing.setLastActivityUnixNano(nowUnixNano)
				return existing, true, nil
			}
		}
		delete(s.bySig, signature)
	}

	slot := s.allocateSlotLocked(legacy)
	if slot < 0 {
		return nil, false, ErrSessionTableFull
	}

	record := &sessionRecord{
		ID:                  uint16(slot),
		LegacySessionID:     legacy,
		ResponseMode:        payload[0],
		CreatedAt:           now,
		ReuseUntil:          now.Add(s.sessionInitTTL),
		Signature:           signature,
		Streams:             make(map[uint16]*Stream_server),
		ActiveStreams:       make([]uint16, 0, 8),
		StreamQueueCap:      s.streamQueueCap,
		MaxStreams:          s.maxStreamsPerSession,
		streamCapRejections: &s.streamCapRejections,
		activeStreamCounter: &s.activeStreams,
		RecentlyClosed:      make(map[uint16]recentlyClosedStreamRecord, 8),
		RecentlyClosedTTL:   s.recentlyClosedTTL,
		RecentlyClosedCap:   s.recentlyClosedCap,
		OrphanQueue:         mlq.New[VpnProto.Packet](s.orphanQueueCap),
	}

	// Initialize virtual Stream 0 for control packets
	record.ensureStream0(nil) // Caller should update logger if needed
	record.reuseUntilUnixNano = record.ReuseUntil.UnixNano()
	record.setLastActivityUnixNano(nowUnixNano)
	record.UploadCompression = uploadCompressionType
	record.DownloadCompression = downloadCompressionType
	record.applyMTUFromSessionInit(
		binary.BigEndian.Uint16(payload[2:4]),
		binary.BigEndian.Uint16(payload[4:6]),
		maxPacketsPerBatch,
		s.maxClientUploadMTU,
		s.maxClientDownloadMTU,
	)
	copy(record.VerifyCode[:], payload[6:10])
	record.Cookie = s.randomCookieLocked()

	s.byID[slot] = record
	s.liveByID[slot].Store(record)
	s.activeIDs[uint16(slot)] = struct{}{}
	s.activeCount++
	if legacy {
		s.activeLegacy++
		s.legacyNextID = nextSessionIDInRange(uint16(slot), 1, maxLegacySessionID)
	} else {
		s.activeNative++
		s.nativeNextID = nextSessionIDInRange(uint16(slot), maxLegacySessionID+1, maxServerSessionID)
	}
	s.bySig[signature] = uint16(slot)
	s.updateNextReuseSweepLocked(record.reuseUntilUnixNano)
	delete(s.recentClosed, uint16(slot))
	return record, false, nil
}

// setClientMTUCeilings bounds what a client may request in SESSION_INIT. Zero
// for either value leaves that dimension uncapped. Call before serving.
func (s *sessionStore) setClientMTUCeilings(maxUploadMTU int, maxDownloadMTU int) {
	if s == nil {
		return
	}
	s.maxClientUploadMTU = maxUploadMTU
	s.maxClientDownloadMTU = maxDownloadMTU
}

func (s *sessionStore) expireReuseLocked(nowUnixNano int64) {
	if len(s.bySig) == 0 {
		s.nextReuseSweepUnixNano = 0
		return
	}
	if s.nextReuseSweepUnixNano != 0 && nowUnixNano < s.nextReuseSweepUnixNano {
		return
	}

	nextReuseSweepUnixNano := int64(0)
	for signature, sessionID := range s.bySig {
		record := s.byID[sessionID]
		if record == nil || nowUnixNano > record.reuseUntilUnixNano {
			delete(s.bySig, signature)
			continue
		}
		if nextReuseSweepUnixNano == 0 || record.reuseUntilUnixNano < nextReuseSweepUnixNano {
			nextReuseSweepUnixNano = record.reuseUntilUnixNano
		}
	}
	s.nextReuseSweepUnixNano = nextReuseSweepUnixNano
}

func (s *sessionStore) Get(sessionID uint16) (*sessionRecord, bool) {
	if s == nil || sessionID == 0 {
		return nil, false
	}
	record := s.liveByID[sessionID].Load()
	if record == nil || record.isClosed() {
		return nil, false
	}
	return record, true
}

func (s *sessionStore) HasActive(sessionID uint16) bool {
	if s == nil || sessionID == 0 {
		return false
	}

	record := s.liveByID[sessionID].Load()
	return record != nil && !record.isClosed()
}

func (s *sessionStore) Lookup(sessionID uint16) (sessionLookupResult, bool) {
	if s == nil || sessionID == 0 {
		return sessionLookupResult{}, false
	}
	if record := s.liveByID[sessionID].Load(); record != nil && !record.isClosed() {
		return sessionLookupResult{
			Cookie:          record.Cookie,
			ResponseMode:    record.ResponseMode,
			LegacySessionID: record.LegacySessionID,
			State:           sessionLookupActive,
		}, true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if record, ok := s.recentClosed[sessionID]; ok {
		return sessionLookupResult{
			Cookie:          record.Cookie,
			ResponseMode:    record.ResponseMode,
			LegacySessionID: record.LegacySessionID,
			State:           sessionLookupClosed,
		}, true
	}

	return sessionLookupResult{}, false
}

func (s *sessionStore) ValidateAndTouch(sessionID uint16, cookie uint8, now time.Time) sessionValidationResult {
	if s == nil || sessionID == 0 {
		return sessionValidationResult{}
	}
	if record := s.liveByID[sessionID].Load(); record != nil && !record.isClosed() {
		result := sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:          record.Cookie,
				ResponseMode:    record.ResponseMode,
				LegacySessionID: record.LegacySessionID,
				State:           sessionLookupActive,
			},
			Known: true,
			Valid: record.Cookie == cookie,
		}
		if result.Valid {
			view := record.runtimeView()
			result.Active = &view
		}
		if result.Valid {
			record.setLastActivity(now)
		}
		return result
	}

	s.mu.RLock()
	if record, ok := s.recentClosed[sessionID]; ok {
		s.mu.RUnlock()
		return sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:          record.Cookie,
				ResponseMode:    record.ResponseMode,
				LegacySessionID: record.LegacySessionID,
				State:           sessionLookupClosed,
			},
			Known: true,
			Valid: false,
		}
	}

	s.mu.RUnlock()
	return sessionValidationResult{}
}

func (s *sessionStore) Close(sessionID uint16, now time.Time, retention time.Duration) (*sessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	record.markClosed()
	s.liveByID[sessionID].Store(nil)

	delete(s.bySig, record.Signature)
	s.byID[sessionID] = nil
	delete(s.activeIDs, sessionID)
	if s.activeCount > 0 {
		s.activeCount--
	}
	s.decrementFormatCountLocked(record)
	if retention > 0 {
		s.recentClosed[sessionID] = closedSessionRecord{
			Cookie:          record.Cookie,
			ResponseMode:    record.ResponseMode,
			LegacySessionID: record.LegacySessionID,
			ExpiresAt:       now.Add(retention),
		}
	} else {
		delete(s.recentClosed, sessionID)
	}
	return record, true
}

func (s *sessionStore) Cleanup(now time.Time, idleTimeout time.Duration, closedRetention time.Duration) []closedSessionCleanup {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUnixNano := now.UnixNano()
	s.expireReuseLocked(nowUnixNano)

	for sessionID, record := range s.recentClosed {
		if !now.Before(record.ExpiresAt) {
			delete(s.recentClosed, sessionID)
		}
	}

	if idleTimeout <= 0 {
		return nil
	}

	expired := make([]closedSessionCleanup, 0, 8)
	idleTimeoutNanos := idleTimeout.Nanoseconds()
	activeSnapshot := make([]uint16, 0, len(s.activeIDs))
	for id := range s.activeIDs {
		activeSnapshot = append(activeSnapshot, id)
	}
	for _, sessionID := range activeSnapshot {
		record := s.byID[sessionID]
		if record == nil {
			continue
		}

		lastActivityUnixNano := record.lastActivity()
		if lastActivityUnixNano != 0 && nowUnixNano-lastActivityUnixNano < idleTimeoutNanos {
			continue
		}

		delete(s.bySig, record.Signature)
		s.byID[sessionID] = nil
		s.liveByID[sessionID].Store(nil)
		delete(s.activeIDs, sessionID)
		if s.activeCount > 0 {
			s.activeCount--
		}
		s.decrementFormatCountLocked(record)
		if closedRetention > 0 {
			s.recentClosed[uint16(sessionID)] = closedSessionRecord{
				Cookie:          record.Cookie,
				ResponseMode:    record.ResponseMode,
				LegacySessionID: record.LegacySessionID,
				ExpiresAt:       now.Add(closedRetention),
			}
		}
		record.markClosed()
		expired = append(expired, closedSessionCleanup{
			ID:     uint16(sessionID),
			record: record,
		})
	}

	return expired
}

// activeRecordsSnapshot returns the live session records, iterating only the
// active-ID set (not the full 65536-slot byID array).
func (s *sessionStore) activeRecordsSnapshot() []*sessionRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	records := make([]*sessionRecord, 0, len(s.activeIDs))
	for id := range s.activeIDs {
		if record := s.byID[id]; record != nil {
			records = append(records, record)
		}
	}
	s.mu.RUnlock()
	return records
}

func (s *sessionStore) operationalCounts() (sessions uint64, native uint64, legacy uint64, streams uint64) {
	if s == nil {
		return 0, 0, 0, 0
	}
	s.mu.RLock()
	sessions = uint64(s.activeCount)
	native = uint64(s.activeNative)
	legacy = uint64(s.activeLegacy)
	s.mu.RUnlock()
	return sessions, native, legacy, s.activeStreams.Load()
}

func (s *sessionStore) decrementFormatCountLocked(record *sessionRecord) {
	if record != nil && record.LegacySessionID {
		if s.activeLegacy > 0 {
			s.activeLegacy--
		}
		return
	}
	if s.activeNative > 0 {
		s.activeNative--
	}
}

func (s *sessionStore) SweepTerminalStreams(now time.Time, retention time.Duration) {
	for _, record := range s.activeRecordsSnapshot() {
		record.cleanupTerminalStreams(now, retention)
	}
}

func (s *sessionStore) SweepRecentlyClosedStreams(now time.Time) {
	for _, record := range s.activeRecordsSnapshot() {
		record.pruneRecentlyClosed(now)
	}
}

// allocateSlotLocked picks a free session ID from the half of the space that
// matches the client's header format: 1..255 for legacy MasterDNS/StormDNS
// clients, which cannot express anything wider, and 256..65535 for native
// clients. Keeping the ranges disjoint is what lets the parser resolve the two
// header layouts, so neither branch may borrow from the other — a legacy client
// gets ErrSessionTableFull once 255 of them are connected even while the native
// range is empty.
func (s *sessionStore) allocateSlotLocked(legacy bool) int {
	cap := s.maxActiveSessions
	if cap <= 0 || cap > maxServerSessionSlots {
		cap = maxServerSessionSlots
	}
	if int(s.activeCount) >= cap {
		return -1
	}

	low, high := maxLegacySessionID+1, maxServerSessionID
	if legacy {
		low, high = 1, maxLegacySessionID
	}

	start := int(s.nativeNextID)
	if legacy {
		start = int(s.legacyNextID)
	}
	if start < low || start > high {
		start = low
	}
	for slot := start; slot <= high; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	for slot := low; slot < start; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	return -1
}

func (s *sessionStore) randomCookieLocked() uint8 {
	if s.cookieIndex >= len(s.cookieBytes) {
		if _, err := rand.Read(s.cookieBytes[:]); err != nil {
			s.cookieIndex = len(s.cookieBytes)
			return 0
		}
		s.cookieIndex = 0
	}
	value := s.cookieBytes[s.cookieIndex]
	s.cookieIndex++
	return value
}

func (s *sessionStore) updateNextReuseSweepLocked(reuseUntilUnixNano int64) {
	if s.nextReuseSweepUnixNano == 0 || reuseUntilUnixNano < s.nextReuseSweepUnixNano {
		s.nextReuseSweepUnixNano = reuseUntilUnixNano
	}
}

func clampMTU(value uint16) uint16 {
	if value < minSessionMTU {
		return minSessionMTU
	}

	if value > maxSessionMTU {
		return maxSessionMTU
	}

	return value
}

// clampMTUCeiling applies an operator-configured ceiling on top of the protocol
// bounds already applied by clampMTU. A ceiling of zero or less means none was
// configured. The result never falls below minSessionMTU: a ceiling set absurdly
// low must not produce a session too small to carry a packet.
func clampMTUCeiling(value uint16, ceiling int) uint16 {
	if ceiling <= 0 || int(value) <= ceiling {
		return value
	}
	if ceiling < minSessionMTU {
		return minSessionMTU
	}
	return uint16(ceiling)
}

func isValidSessionResponseMode(value uint8) bool {
	return value <= mtuProbeModeBase64
}

func (r *sessionRecord) setLastActivity(now time.Time) {
	r.setLastActivityUnixNano(now.UnixNano())
}

func (r *sessionRecord) setLastActivityUnixNano(nowUnixNano int64) {
	atomic.StoreInt64(&r.lastActivityUnixNano, nowUnixNano)
}

func (r *sessionRecord) lastActivity() int64 {
	return atomic.LoadInt64(&r.lastActivityUnixNano)
}

func (s *sessionStore) CollectIdleDeferredSessions(now time.Time, idleTimeout time.Duration) []idleDeferredCleanup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idleTimeout <= 0 {
		return nil
	}

	nowUnixNano := now.UnixNano()
	idleTimeoutNanos := idleTimeout.Nanoseconds()
	idle := make([]idleDeferredCleanup, 0, 4)

	for sessionID := range s.activeIDs {
		record := s.byID[sessionID]
		if record == nil || record.isClosed() {
			continue
		}

		lastActivityUnixNano := record.lastActivity()
		if lastActivityUnixNano == 0 || nowUnixNano-lastActivityUnixNano < idleTimeoutNanos {
			continue
		}
		if record.lastDeferredCleanupActivity() == lastActivityUnixNano {
			continue
		}

		record.markDeferredCleanupActivity(lastActivityUnixNano)
		idle = append(idle, idleDeferredCleanup{
			ID:               uint16(sessionID),
			lastActivityNano: lastActivityUnixNano,
		})
	}

	return idle
}

func (r *sessionRecord) lastDeferredCleanupActivity() int64 {
	return atomic.LoadInt64(&r.lastDeferredCleanupActivityUnixNano)
}

func (r *sessionRecord) markDeferredCleanupActivity(activityUnixNano int64) {
	atomic.StoreInt64(&r.lastDeferredCleanupActivityUnixNano, activityUnixNano)
}

func nextSessionID(current uint16) uint16 {
	if current >= maxServerSessionID {
		return 1
	}
	return current + 1
}

func nextSessionIDInRange(current uint16, low int, high int) uint16 {
	next := int(current) + 1
	if next < low || next > high {
		next = low
	}
	return uint16(next)
}

// applyMTUFromSessionInit sets the session MTUs from what the client asked for
// in SESSION_INIT, bounded by the server's ceilings.
//
// The download ceiling is enforced here rather than merely advertised because
// it directly sizes every response the server builds. Upload MTU is retained
// for accounting while compatible clients apply that ceiling to their query
// construction. A ceiling of zero means the operator set none.
func (r *sessionRecord) applyMTUFromSessionInit(uploadMTU uint16, downloadMTU uint16, maxPacketsPerBatch int, maxUploadMTU int, maxDownloadMTU int) {
	if r == nil {
		return
	}
	r.UploadMTU = clampMTUCeiling(clampMTU(uploadMTU), maxUploadMTU)
	r.DownloadMTU = clampMTUCeiling(clampMTU(downloadMTU), maxDownloadMTU)
	r.DownloadMTUBytes = int(r.DownloadMTU)
	r.MaxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(r.DownloadMTUBytes, 80, maxPacketsPerBatch)
}

func (r *sessionRecord) runtimeView() sessionRuntimeView {
	return sessionRuntimeView{
		ID:                  r.ID,
		LegacySessionID:     r.LegacySessionID,
		Cookie:              r.Cookie,
		ResponseMode:        r.ResponseMode,
		ResponseBase64:      r.ResponseMode == mtuProbeModeBase64,
		DownloadCompression: r.DownloadCompression,
		DownloadMTU:         r.DownloadMTU,
		DownloadMTUBytes:    r.DownloadMTUBytes,
		MaxPackedBlocks:     r.MaxPackedBlocks,
	}
}

func (r *sessionRecord) markClosed() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 1)
}

func (r *sessionRecord) reopen() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 0)
}

func (r *sessionRecord) isClosed() bool {
	if r == nil {
		return true
	}
	return atomic.LoadUint32(&r.closedFlag) != 0
}

// ensureStream0 creates correctly virtual stream 0 if not exist
func (r *sessionRecord) ensureStream0(logger arq.Logger) {
	if r == nil || r.isClosed() {
		return
	}
	r.getOrCreateStream(0, arq.Config{IsVirtual: true}, nil, logger)
}

func (r *sessionRecord) getOrCreateStream(streamID uint16, arqConfig arq.Config, localConn io.ReadWriteCloser, logger arq.Logger) *Stream_server {
	if r == nil || r.isClosed() {
		return nil
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()
	if r.isClosed() {
		return nil
	}

	if s, ok := r.Streams[streamID]; ok {
		return s
	}

	// Enforce per-session stream cap to bound memory under attacker-driven
	// stream creation. Stream 0 is the always-present virtual control stream
	// and is excluded from the cap so signalling can never be denied.
	if streamID != 0 && r.MaxStreams > 0 {
		// len(r.Streams) includes stream 0 when present, so subtract 1 to
		// count only data streams against the cap.
		active := len(r.Streams)
		if _, hasStream0 := r.Streams[0]; hasStream0 {
			active--
		}
		if active >= r.MaxStreams {
			if r.streamCapRejections != nil {
				r.streamCapRejections.Add(1)
			}
			return nil
		}
	}

	delete(r.RecentlyClosed, streamID)

	s := NewStreamServer(streamID, r.ID, arqConfig, localConn, r.DownloadMTUBytes, r.StreamQueueCap, logger)
	s.onClosed = r.onStreamClosed
	r.Streams[streamID] = s
	if streamID != 0 && r.activeStreamCounter != nil {
		r.activeStreamCounter.Add(1)
	}

	// Active streams tracking: keep sorted for Round-Robin predictability
	found := slices.Contains(r.ActiveStreams, streamID)
	if !found {
		// Insert sorted
		insertAt := 0
		for i, id := range r.ActiveStreams {
			if id > streamID {
				insertAt = i
				break
			}
			insertAt = i + 1
		}
		if insertAt == len(r.ActiveStreams) {
			r.ActiveStreams = append(r.ActiveStreams, streamID)
		} else {
			r.ActiveStreams = append(r.ActiveStreams[:insertAt+1], r.ActiveStreams[insertAt:]...)
			r.ActiveStreams[insertAt] = streamID
		}
		r.markActiveStreamsChangedLocked()
	}

	return s
}

func shouldSuppressServerOrphanForCloseReason(reason string) bool {
	return strings.Contains(reason, "close handshake completed") ||
		strings.HasSuffix(reason, "acknowledged")
}

func (r *sessionRecord) onStreamClosed(streamID uint16, now time.Time, reason string) {
	if r == nil || streamID == 0 {
		return
	}
	r.removeStream(streamID, now, shouldSuppressServerOrphanForCloseReason(reason))
	if r.streamCleanup != nil {
		r.streamCleanup(r.ID, streamID)
	}
}

func (r *sessionRecord) getStream(streamID uint16) (*Stream_server, bool) {
	if r == nil || r.isClosed() {
		return nil, false
	}
	r.StreamsMu.RLock()
	s, ok := r.Streams[streamID]
	r.StreamsMu.RUnlock()
	return s, ok
}
func (r *sessionRecord) noteStreamClosed(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	r.pruneRecentlyClosedLocked(now)

	r.RecentlyClosed[streamID] = recentlyClosedStreamRecord{
		ClosedAt:       now,
		SuppressOrphan: suppressOrphan,
	}

	// Cap the map size
	if len(r.RecentlyClosed) > r.closedStreamRecordCap() {
		var oldestID uint16
		var oldestAt time.Time
		first := true
		for id, record := range r.RecentlyClosed {
			if first || record.ClosedAt.Before(oldestAt) {
				oldestID = id
				oldestAt = record.ClosedAt
				first = false
			}
		}
		delete(r.RecentlyClosed, oldestID)
	}
}

func (r *sessionRecord) pruneRecentlyClosed(now time.Time) {
	if r == nil || r.isClosed() {
		return
	}
	r.StreamsMu.Lock()
	r.pruneRecentlyClosedLocked(now)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) pruneRecentlyClosedLocked(now time.Time) {
	if r == nil {
		return
	}
	expiredBefore := now.Add(-r.closedStreamRecordTTL())
	for id, record := range r.RecentlyClosed {
		if record.ClosedAt.Before(expiredBefore) {
			delete(r.RecentlyClosed, id)
		}
	}
}

func (r *sessionRecord) isRecentlyClosed(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL()
}

func (r *sessionRecord) shouldSuppressOrphanForClosedStream(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL() && record.SuppressOrphan
}

func (r *sessionRecord) closedStreamRecordTTL() time.Duration {
	if r == nil || r.RecentlyClosedTTL <= 0 {
		return 600 * time.Second
	}
	return r.RecentlyClosedTTL
}

func (r *sessionRecord) closedStreamRecordCap() int {
	if r == nil || r.RecentlyClosedCap < 1 {
		return 2000
	}
	return r.RecentlyClosedCap
}

func (r *sessionRecord) removeStream(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	_, existed := r.Streams[streamID]
	delete(r.Streams, streamID)
	if existed && r.activeStreamCounter != nil {
		r.activeStreamCounter.Add(^uint64(0))
	}

	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()

	r.noteStreamClosed(streamID, now, suppressOrphan)
}

func (r *sessionRecord) deactivateStream(streamID uint16) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}

	r.StreamsMu.Lock()
	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) removeActiveStreamLocked(streamID uint16) {
	for i, id := range r.ActiveStreams {
		if id == streamID {
			r.ActiveStreams = append(r.ActiveStreams[:i], r.ActiveStreams[i+1:]...)
			r.markActiveStreamsChangedLocked()
			break
		}
	}
}

func (r *sessionRecord) markActiveStreamsChangedLocked() {
	r.activeStreamSetVersion++
}

func (r *sessionRecord) activeStreamSnapshot() ([]int32, []*Stream_server) {
	if r == nil || r.isClosed() {
		return nil, nil
	}

	r.StreamsMu.RLock()
	version := r.activeStreamSetVersion
	if version == r.activeStreamSnapshotVersion {
		ids := r.activeStreamSnapshotIDs
		streams := r.activeStreamSnapshotStreams
		r.StreamsMu.RUnlock()
		return ids, streams
	}
	r.StreamsMu.RUnlock()

	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	if r.activeStreamSetVersion != r.activeStreamSnapshotVersion {
		snapshotIDs := make([]int32, len(r.ActiveStreams))
		snapshotStreams := make([]*Stream_server, len(r.ActiveStreams))
		for i, id := range r.ActiveStreams {
			snapshotIDs[i] = int32(id)
			snapshotStreams[i] = r.Streams[id]
		}
		r.activeStreamSnapshotIDs = snapshotIDs
		r.activeStreamSnapshotStreams = snapshotStreams
		r.activeStreamSnapshotVersion = r.activeStreamSetVersion
	}

	return r.activeStreamSnapshotIDs, r.activeStreamSnapshotStreams
}

func (r *sessionRecord) closeAllStreams(reason string) {
	if r == nil {
		return
	}
	r.markClosed()

	r.StreamsMu.RLock()
	streams := make([]*Stream_server, 0, len(r.Streams))
	for _, stream := range r.Streams {
		if stream != nil {
			streams = append(streams, stream)
		}
	}
	r.StreamsMu.RUnlock()

	for _, stream := range streams {
		if reason != "session closed cleanup" {
			stream.Abort(reason)
		} else if stream.ARQ != nil {
			stream.ARQ.Close(reason, arq.CloseOptions{Force: true})
		}

		stream.finalizeAfterARQClose(reason)
		// ARQ finalization may briefly enqueue its terminal control packet while
		// the close callback is clearing resources. A whole-session teardown has
		// no consumer left for that packet, so make the post-close state
		// deterministic and release it here as well.
		stream.ClearTXQueue()
	}

	r.StreamsMu.Lock()
	dataStreams := 0
	for id := range r.Streams {
		if id != 0 {
			dataStreams++
		}
	}
	clear(r.Streams)
	r.ActiveStreams = r.ActiveStreams[:0]
	r.markActiveStreamsChangedLocked()
	r.StreamsMu.Unlock()
	if dataStreams > 0 && r.activeStreamCounter != nil {
		r.activeStreamCounter.Add(^uint64(dataStreams - 1))
	}

	if r.OrphanQueue != nil {
		r.OrphanQueue.Clear(nil)
	}
}

func (r *sessionRecord) cleanupTerminalStreams(now time.Time, retention time.Duration) {
	if r == nil || r.isClosed() {
		return
	}

	r.StreamsMu.RLock()
	snapshot := make(map[uint16]*Stream_server, len(r.Streams))
	for id, stream := range r.Streams {
		snapshot[id] = stream
	}
	r.StreamsMu.RUnlock()

	var removeIDs []uint16
	for streamID, stream := range snapshot {
		if streamID == 0 || stream == nil || stream.ARQ == nil {
			continue
		}

		state := stream.ARQ.State()
		stream.mu.Lock()
		switch state {
		case arq.StateDraining:
			stream.Status = "DRAINING"
		case arq.StateHalfClosedLocal, arq.StateHalfClosedRemote, arq.StateClosing:
			stream.Status = "CLOSING"
		case arq.StateTimeWait:
			stream.Status = "TIME_WAIT"
		}

		forceClosedExpired := !stream.CloseTime.IsZero() && now.Sub(stream.CloseTime) >= retention
		if stream.ARQ.IsClosed() || forceClosedExpired {
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.Status = "TIME_WAIT"
			if forceClosedExpired || now.Sub(stream.CloseTime) >= retention {
				removeIDs = append(removeIDs, streamID)
			}
		}
		stream.mu.Unlock()
	}

	for _, streamID := range removeIDs {
		if stream, ok := snapshot[streamID]; ok && stream != nil {
			stream.Abort("terminal stream retention cleanup")
			stream.finalizeAfterARQClose("terminal stream retention cleanup")
		}
		r.removeStream(streamID, now, false)
	}
}

func orphanResetKey(packetType uint8, streamID uint16) uint64 {
	return Enums.PacketTypeStreamKey(streamID, packetType)
}

func (r *sessionRecord) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if r == nil || r.isClosed() || r.OrphanQueue == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	key := orphanResetKey(packetType, streamID)
	// Orphans have high priority (0).
	r.OrphanQueue.Push(0, key, packet)
}
