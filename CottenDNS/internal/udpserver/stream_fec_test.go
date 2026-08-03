// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// stream_fec_test.go — locks the live server-side FEC contract: data packets
// fed through Stream_server.feedFECData / flushFEC / popFECShard must be
// recoverable by a fec.Decoder + UnpackFECDataUnit on the client side, even
// when a fraction of the framed shards are dropped in flight. This guards the
// exact framing used by the dequeue path, independently of the codec's own
// tests.
// ==============================================================================

package udpserver

import (
	"fmt"
	"sync"
	"testing"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/fec"
	"cottendns-go/internal/mlq"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestStreamServerAutoFECEnablesOnLoss(t *testing.T) {
	s := &Stream_server{ID: 1}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)
	if s.FECEnabled() {
		t.Fatal("auto FEC should start off")
	}

	// One window: 40 retransmits against 64 originals -> loss ~38% (> 30%).
	for i := 0; i < 40; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_RESEND)
	}
	for i := 0; i < fecAutoWindow; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_DATA)
	}

	if !s.FECEnabled() {
		t.Fatal("auto FEC should turn on once loss crosses the threshold")
	}
}

func TestStreamServerAutoFECStaysOffOnLowLoss(t *testing.T) {
	s := &Stream_server{ID: 2}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)

	// 5 retransmits against 64 originals -> loss ~7% (< 30%).
	for i := 0; i < 5; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_RESEND)
	}
	for i := 0; i < fecAutoWindow; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_DATA)
	}

	if s.FECEnabled() {
		t.Fatal("auto FEC should stay off under low loss")
	}
}

func TestStreamServerAutoFECDisengagesAfterSustainedLowLoss(t *testing.T) {
	s := &Stream_server{ID: 3}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)
	driveLossWindow(s, 0.40)
	if !s.FECEnabled() {
		t.Fatal("auto FEC should engage after a high-loss window")
	}

	// Leave both a partial encoder block and completed shards queued. A clean
	// disengage must discard both; ARQ will retransmit any unacknowledged source
	// sequences as ordinary packets after FEC is inactive.
	s.feedFECData(1, 0, []byte("partial"))
	for seq := uint16(2); seq <= 5; seq++ {
		s.feedFECData(seq, 0, []byte("queued"))
	}

	for window := 1; window < fecDisengageWindows; window++ {
		driveLossWindow(s, 0)
		if !s.FECEnabled() {
			t.Fatalf("auto FEC disengaged before hysteresis completed at window %d", window)
		}
	}
	driveLossWindow(s, 0)
	if s.FECEnabled() {
		t.Fatal("auto FEC should fully disengage after sustained low loss")
	}
	if s.HasBufferedFECWork() {
		t.Fatal("disengaged auto FEC must not retain encoder work")
	}
	if _, ok := s.popFECShard(); ok {
		t.Fatal("disengaged auto FEC must discard queued recovery shards")
	}
}

func TestStreamServerAutoFECReengagesWithoutReplacingEncoder(t *testing.T) {
	s := &Stream_server{ID: 4}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)
	driveLossWindow(s, 0.40)
	encoder := s.fecEnc
	for range fecDisengageWindows {
		driveLossWindow(s, 0)
	}
	if s.FECEnabled() {
		t.Fatal("expected auto FEC to be inactive after clean windows")
	}

	driveLossWindow(s, 0.40)
	if !s.FECEnabled() {
		t.Fatal("auto FEC should re-engage when loss returns")
	}
	if s.fecEnc != encoder {
		t.Fatal("auto FEC must reuse its encoder so block IDs remain monotonic")
	}
}

func TestStreamServerExplicitFECRemainsActive(t *testing.T) {
	s := &Stream_server{ID: 5}
	s.EnableFEC(4, 2)
	if !s.FECEnabled() {
		t.Fatal("explicit FEC must remain active")
	}
	s.feedFECData(1, 0, []byte("payload"))
	if !s.HasBufferedFECWork() {
		t.Fatal("explicit FEC should buffer source data below a block boundary")
	}
}

func TestFECDequeueFallsBackToRawWhenAutoFECDisengages(t *testing.T) {
	stream := &Stream_server{
		ID:      6,
		TXQueue: mlq.New[*serverStreamTXPacket](4),
		fecEnc:  fec.NewEncoder(4, 2),
		// Model the race where the caller observed active=true, but the clean
		// window disengaged FEC before fecDequeueFromStream reached feedFECData.
		fecActive: false,
	}
	payload := []byte("send-me-raw")
	if !stream.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA), Enums.PACKET_STREAM_DATA, 9, 0, 0, 0, 0, payload) {
		t.Fatal("failed to queue source packet")
	}

	packet, ok := (&Server{}).fecDequeueFromStream(stream, int32(stream.ID))
	if !ok || packet == nil {
		t.Fatal("dequeue must return the source packet when FEC no longer accepts it")
	}
	defer putTXPacketToPool(packet)
	if packet.PacketType != Enums.PACKET_STREAM_DATA || packet.SequenceNum != 9 || string(packet.Payload) != string(payload) {
		t.Fatalf("unexpected raw fallback packet: type=%d seq=%d payload=%q", packet.PacketType, packet.SequenceNum, packet.Payload)
	}
}

func TestConcurrentFECWindowCloseCountsOneCleanWindow(t *testing.T) {
	s := &Stream_server{
		ID:        7,
		fecEnc:    fec.NewEncoder(4, 2),
		fecActive: true,
	}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(fecAutoWindow + 1)
	for range fecAutoWindow + 1 {
		go func() {
			defer workers.Done()
			<-start
			s.recordFECSample(Enums.PACKET_STREAM_DATA)
		}()
	}
	close(start)
	workers.Wait()

	s.fecMu.Lock()
	lowWindows := s.fecLowWindows
	active := s.fecActive
	s.fecMu.Unlock()
	if !active || lowWindows != 1 {
		t.Fatalf("concurrent threshold crossing must close exactly one clean window: active=%v lowWindows=%d", active, lowWindows)
	}
}

// driveLossWindow feeds one full FEC sampling window at the requested loss
// fraction so maybeAdjustAutoFEC runs exactly once, then returns the parity the
// encoder settled on (0 when FEC never turned on).
func driveLossWindow(s *Stream_server, lossFrac float64) int {
	resends := int(float64(fecAutoWindow) * lossFrac / (1 - lossFrac))
	for i := 0; i < resends; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_RESEND)
	}
	for i := 0; i < fecAutoWindow; i++ {
		s.recordFECSample(Enums.PACKET_STREAM_DATA)
	}
	s.fecMu.Lock()
	defer s.fecMu.Unlock()
	if s.fecEnc == nil {
		return 0
	}
	return s.fecEnc.Parity()
}

func TestStreamServerSuperFECIsLossAwareInBand(t *testing.T) {
	// Two streams, identical config, driven at different in-band loss. The higher
	// loss must earn strictly more parity — proving the band scales with loss
	// instead of slamming a flat maximum.
	lowLoss := &Stream_server{ID: 20}
	lowLoss.ConfigureAutoFEC(4, 2, 16, 0.3)
	lowLoss.ConfigureSuperFEC(true, 0.75, 0.85, 0)

	highLoss := &Stream_server{ID: 21}
	highLoss.ConfigureAutoFEC(4, 2, 16, 0.3)
	highLoss.ConfigureSuperFEC(true, 0.75, 0.85, 0)

	pLow := driveLossWindow(lowLoss, 0.76)
	pHigh := driveLossWindow(highLoss, 0.84)

	if pLow <= 2 {
		t.Fatalf("in-band low-loss parity should be well above base, got %d", pLow)
	}
	if pHigh <= pLow {
		t.Fatalf("higher in-band loss must earn more parity: low(76%%)=%d high(84%%)=%d", pLow, pHigh)
	}
	// The band must be allowed to exceed the normal auto ceiling (16) under the
	// heavier loss — that lift is the whole point of Super-FEC.
	if pHigh <= 16 {
		t.Fatalf("Super-FEC should lift parity above the auto ceiling (16), got %d", pHigh)
	}
}

func TestStreamServerSuperFECRespectsMaxParityCap(t *testing.T) {
	s := &Stream_server{ID: 22}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)
	// Cap the band at 20 parity.
	s.ConfigureSuperFEC(true, 0.75, 0.85, 20)

	if got := driveLossWindow(s, 0.84); got != 20 {
		t.Fatalf("in-band parity should be clamped to the super cap 20, got %d", got)
	}
}

func TestStreamServerSuperFECDropsAboveCeiling(t *testing.T) {
	s := &Stream_server{ID: 23}
	s.ConfigureAutoFEC(4, 2, 16, 0.3)
	s.ConfigureSuperFEC(true, 0.75, 0.85, 0)

	// First push loss into the band so FEC is on with elevated parity.
	if got := driveLossWindow(s, 0.80); got <= 2 {
		t.Fatalf("expected elevated parity in band, got %d", got)
	}
	// Now exceed the ceiling (~92%): server should stop escalating and relax to the
	// base parity (2) rather than encode a giant block for a hopeless link.
	if got := driveLossWindow(s, 0.92); got != 2 {
		t.Fatalf("above ceiling parity should relax to base 2 (drop), got %d", got)
	}
}

func TestStreamServerSuperFECDisabledUsesScaledParity(t *testing.T) {
	s := &Stream_server{ID: 24}
	s.ConfigureAutoFEC(4, 2, 64, 0.3)
	s.ConfigureSuperFEC(false, 0.75, 0.85, 0)

	// With Super-FEC off, 80% loss uses the normal ParityForLoss scaling, which is
	// well above base but must not be forced to max/dropped.
	got := driveLossWindow(s, 0.80)
	if got < 3 {
		t.Fatalf("expected scaled parity above base with Super-FEC off, got %d", got)
	}
}

func TestStreamServerFECRoundTripWithLoss(t *testing.T) {
	// block=4 data + parity=4 recovery -> any 4 of 8 shards reconstruct a block,
	// i.e. each block survives up to 50% shard loss.
	const (
		blockSize = 4
		parity    = 4
		numUnits  = 10 // intentionally not a multiple of blockSize (tail flush)
		dropEvery = 2  // drop every 2nd shard -> 50% loss
	)

	s := &Stream_server{ID: 7, SessionID: 1}
	s.EnableFEC(blockSize, parity)

	type unit struct {
		seq     uint16
		payload []byte
	}
	want := make([]unit, numUnits)
	for i := range want {
		want[i] = unit{
			seq:     uint16(100 + i),
			payload: []byte(fmt.Sprintf("data-unit-%d-payload", i)),
		}
		s.feedFECData(want[i].seq, 0, want[i].payload)
	}
	// Flush the trailing partial block so the last units are emitted.
	s.flushFEC()

	// Drain every framed shard the stream produced, dropping half of them.
	var delivered [][]byte
	idx := 0
	for {
		frame, ok := s.popFECShard()
		if !ok {
			break
		}
		if idx%dropEvery != 0 {
			delivered = append(delivered, frame)
		}
		idx++
	}
	if idx == 0 {
		t.Fatal("stream produced no FEC shards")
	}

	// Client side: decode surviving shards and replay recovered units.
	dec := fec.NewDecoder()
	got := make(map[uint16][]byte)
	for _, frame := range delivered {
		units, err := dec.AddShard(frame)
		if err != nil {
			t.Fatalf("AddShard: %v", err)
		}
		for _, u := range units {
			seq, _, payload, ok := VpnProto.UnpackFECDataUnit(u)
			if !ok {
				t.Fatalf("UnpackFECDataUnit failed for recovered unit")
			}
			got[seq] = append([]byte(nil), payload...)
		}
	}

	for _, w := range want {
		p, ok := got[w.seq]
		if !ok {
			t.Fatalf("unit seq=%d not recovered after 50%% shard loss", w.seq)
		}
		if string(p) != string(w.payload) {
			t.Fatalf("unit seq=%d payload mismatch: got %q want %q", w.seq, p, w.payload)
		}
	}
}
