// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"
	"time"

	"cottendns-go/internal/arq"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func newLegacyTestStore() *sessionStore {
	return newSessionStore(8, 32, time.Minute, time.Minute, 100, 100, 0)
}

func legacyInitPayload(n int) []byte {
	p := make([]byte, sessionInitDataSize)
	p[0] = 1 // valid ResponseMode
	p[8] = byte(n >> 8)
	p[9] = byte(n)
	return p
}

func TestLegacyCollisionRejectedByPreSessionSemantics(t *testing.T) {
	// This checksum collision used to make the legacy PING also validate as a
	// native SESSION_ACCEPT for session 4103. SESSION_ACCEPT is pre-session and
	// must carry ID zero, so the impossible native candidate is now discarded
	// before the server needs a session lookup.
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:       16,
		PacketType:      Enums.PACKET_PING,
		SessionCookie:   6,
		Payload:         []byte("PO:test"),
		LegacySessionID: true,
	})
	if err != nil {
		t.Fatalf("BuildRaw: %v", err)
	}
	candidates := VpnProto.ParseCandidates(raw)
	if len(candidates) != 1 || !candidates[0].LegacySessionID {
		t.Fatalf("candidates = %+v, want only the valid legacy frame", candidates)
	}

	store := newLegacyTestStore()
	record := &sessionRecord{ID: 16, Cookie: 6, LegacySessionID: true}
	store.byID[16] = record
	store.liveByID[16].Store(record)
	s := &Server{sessions: store}
	if !s.matchesInboundPacketCandidate(candidates[0]) {
		t.Fatalf("correct legacy candidate did not match: %+v", candidates[0])
	}
}

// The parser tells the two header layouts apart by which half of the ID space a
// session lands in, so the allocator must keep them disjoint: a legacy client
// can never be handed an ID it cannot fit in one byte, and a native client must
// never be handed one that would decode as legacy.
func TestSessionIDSpaceSplitByWireFormat(t *testing.T) {
	store := newLegacyTestStore()

	for i := 0; i < 50; i++ {
		legacy, _, err := store.findOrCreate(legacyInitPayload(i), 0, 0, 8, true)
		if err != nil || legacy == nil {
			t.Fatalf("legacy session %d: err=%v record=%v", i, err, legacy)
		}
		if legacy.ID == 0 || legacy.ID > maxLegacySessionID {
			t.Fatalf("legacy session %d got ID %d, want 1..%d", i, legacy.ID, maxLegacySessionID)
		}
		if !legacy.LegacySessionID {
			t.Fatalf("legacy session %d not flagged legacy", i)
		}

		native, _, err := store.findOrCreate(legacyInitPayload(1000+i), 0, 0, 8, false)
		if err != nil || native == nil {
			t.Fatalf("native session %d: err=%v record=%v", i, err, native)
		}
		if native.ID <= maxLegacySessionID {
			t.Fatalf("native session %d got ID %d, want >%d", i, native.ID, maxLegacySessionID)
		}
		if native.LegacySessionID {
			t.Fatalf("native session %d wrongly flagged legacy", i)
		}
	}
}

func TestSessionFormatCountersAndAllocationCursorsRemainIndependent(t *testing.T) {
	store := newLegacyTestStore()

	native1, _, err := store.findOrCreate(legacyInitPayload(4000), 0, 0, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	legacy1, _, err := store.findOrCreate(legacyInitPayload(4001), 0, 0, 8, true)
	if err != nil {
		t.Fatal(err)
	}
	native2, _, err := store.findOrCreate(legacyInitPayload(4002), 0, 0, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	legacy2, _, err := store.findOrCreate(legacyInitPayload(4003), 0, 0, 8, true)
	if err != nil {
		t.Fatal(err)
	}

	if native2.ID != native1.ID+1 || legacy2.ID != legacy1.ID+1 {
		t.Fatalf("allocation cursors crossed formats: native=%d,%d legacy=%d,%d", native1.ID, native2.ID, legacy1.ID, legacy2.ID)
	}
	if stream := native1.getOrCreateStream(8, arq.Config{}, nil, nil); stream == nil {
		t.Fatal("native stream creation failed")
	}
	sessions, native, legacy, streams := store.operationalCounts()
	if sessions != 4 || native != 2 || legacy != 2 || streams != 1 {
		t.Fatalf("unexpected counts: sessions=%d native=%d legacy=%d streams=%d", sessions, native, legacy, streams)
	}
	closed, ok := store.Close(native1.ID, time.Now(), time.Minute)
	if !ok {
		t.Fatal("native session close failed")
	}
	closed.closeAllStreams("session closed cleanup")
	sessions, native, legacy, streams = store.operationalCounts()
	if sessions != 3 || native != 1 || legacy != 2 || streams != 0 {
		t.Fatalf("unexpected post-close counts: sessions=%d native=%d legacy=%d streams=%d", sessions, native, legacy, streams)
	}
}

// The reuse signature comes from the init payload, which is byte-identical in
// both wire formats. Reuse must not hand a client a session belonging to the
// other format, or it would receive a session ID it cannot express.
func TestSessionReuseDoesNotCrossWireFormats(t *testing.T) {
	store := newLegacyTestStore()

	legacy, _, err := store.findOrCreate(legacyInitPayload(7), 0, 0, 8, true)
	if err != nil || legacy == nil {
		t.Fatalf("legacy create: err=%v record=%v", err, legacy)
	}

	// Same payload, native client: must not reuse the legacy record.
	native, reused, err := store.findOrCreate(legacyInitPayload(7), 0, 0, 8, false)
	if err != nil || native == nil {
		t.Fatalf("native create: err=%v record=%v", err, native)
	}
	if reused {
		t.Fatal("native client reused a legacy session record")
	}
	if native.ID == legacy.ID {
		t.Fatalf("native and legacy sessions share ID %d", native.ID)
	}
	if native.LegacySessionID {
		t.Fatal("native session inherited the legacy wire format")
	}
}

// Legacy capacity is inherently capped at 255 by the one-byte field. Exhausting
// it must be refused cleanly rather than spilling into the native range.
func TestLegacySessionExhaustionDoesNotSpillIntoNativeRange(t *testing.T) {
	store := newLegacyTestStore()

	for i := 0; i < maxLegacySessionID; i++ {
		record, _, err := store.findOrCreate(legacyInitPayload(i), 0, 0, 8, true)
		if err != nil || record == nil {
			t.Fatalf("legacy session %d should fit: err=%v", i, err)
		}
		if record.ID > maxLegacySessionID {
			t.Fatalf("legacy session %d spilled to ID %d", i, record.ID)
		}
	}

	_, _, err := store.findOrCreate(legacyInitPayload(9999), 0, 0, 8, true)
	if err != ErrSessionTableFull {
		t.Fatalf("expected ErrSessionTableFull once legacy range is full, got %v", err)
	}

	// The native range must still be usable while legacy is exhausted.
	native, _, err := store.findOrCreate(legacyInitPayload(20000), 0, 0, 8, false)
	if err != nil || native == nil {
		t.Fatalf("native session should still allocate: err=%v", err)
	}
	if native.ID <= maxLegacySessionID {
		t.Fatalf("native session got legacy-range ID %d", native.ID)
	}
}
