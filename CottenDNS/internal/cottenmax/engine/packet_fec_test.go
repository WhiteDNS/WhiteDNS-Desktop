package soar

import (
	"bytes"
	"testing"
	"time"

	"cottendns-go/internal/fec"
)

func drainPacketFEC(t *testing.T, e *packetFECEncoder, budgets []int) []*fecFragment {
	t.Helper()
	var fragments []*fecFragment
	for i := 0; e.pending(); i++ {
		if i > 10000 {
			t.Fatal("parity queue made no progress")
		}
		budget := budgets[i%len(budgets)]
		prefix := []byte{0xa5, 0x5a}
		out, emitted := e.appendParity(append([]byte(nil), prefix...), budget)
		if !bytes.Equal(out[:len(prefix)], prefix) || len(out)-len(prefix) > budget {
			t.Fatalf("parity exceeded budget %d: %x", budget, out)
		}
		if !emitted {
			if !bytes.Equal(out, prefix) {
				t.Fatal("unsent parity changed the output")
			}
			continue
		}
		wire := out[len(prefix):]
		if len(wire) == 0 || wire[0] != frFECParity {
			t.Fatalf("missing parity frame type: %x", wire)
		}
		r := reader{b: wire[1:]}
		fragment, err := readFECFragment(&r)
		if err != nil || len(r.b) != 0 {
			t.Fatalf("parse emitted parity: %v, %d trailing bytes", err, len(r.b))
		}
		fragments = append(fragments, fragment)
	}
	return fragments
}

func TestPacketFECRecoversTwoLossesAfterReorderedParity(t *testing.T) {
	encoder := newPacketFECEncoder(4, 2)
	pns := []uint64{7, 8, 13, 31}
	sources := make([][]byte, len(pns))
	for i, pn := range pns {
		sources[i] = appendStream(nil, 1, uint64(i*150), bytes.Repeat([]byte{byte('a' + i)}, 80+i*17), false, false)
		before := append([]byte(nil), sources[i]...)
		if err := encoder.add(pn, sources[i], false); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sources[i], before) {
			t.Fatal("FEC changed an original stream packet")
		}
	}
	fragments := drainPacketFEC(t, encoder, []int{3, 35, 64, 90, 47})
	if len(fragments) <= 2 {
		t.Fatal("test did not fragment both repair shards")
	}
	decoder := newPacketFECDecoder()
	now := time.Unix(100, 0)
	for i := len(fragments) - 1; i >= 0; i-- {
		recovered, err := decoder.repair(fragments[i], now)
		if err != nil || len(recovered) != 0 {
			t.Fatalf("parity before originals: %v, recovered %d", err, len(recovered))
		}
	}
	if recovered, err := decoder.observe(pns[0], sources[0], now); err != nil || len(recovered) != 0 {
		t.Fatalf("too few surviving sources: %v, recovered %d", err, len(recovered))
	}
	recovered, err := decoder.observe(pns[3], sources[3], now)
	if err != nil || len(recovered) != 2 {
		t.Fatalf("two losses were not repaired: %v, recovered %d", err, len(recovered))
	}
	for i, packet := range recovered {
		if packet.pn != pns[i+1] || !bytes.Equal(packet.frames, sources[i+1]) {
			t.Fatalf("wrong recovered packet %d: PN %d", i, packet.pn)
		}
		if err := parseFrames(packet.frames, func(*frame) error { return nil }); err != nil {
			t.Fatalf("recovery did not preserve stream frames: %v", err)
		}
	}
	// DNS can deliver duplicate answers. Identical chunks and late originals must
	// be harmless and must not redeliver a recovered source to the session.
	for _, fragment := range fragments {
		if again, err := decoder.repair(fragment, now); err != nil || len(again) != 0 {
			t.Fatalf("duplicate parity redelivered a source: %v, %d", err, len(again))
		}
	}
	if again, err := decoder.observe(pns[1], sources[1], now); err != nil || len(again) != 0 {
		t.Fatalf("late original redelivered a source: %v, %d", err, len(again))
	}
}

func TestPacketFECFlushSingleSourceAndOwnsInput(t *testing.T) {
	encoder := newPacketFECEncoder(8, 1)
	source := appendStream(nil, 3, 0, bytes.Repeat([]byte{0xa5}, 120), true, false)
	want := append([]byte(nil), source...)
	if err := encoder.add(1000, source, false); err != nil {
		t.Fatal(err)
	}
	clear(source)
	if encoder.pending() {
		t.Fatal("short tail unexpectedly encoded before flush")
	}
	if err := encoder.add(0, nil, true); err != nil {
		t.Fatal(err)
	}
	decoder := newPacketFECDecoder()
	var recovered []fecRecovered
	for _, fragment := range drainPacketFEC(t, encoder, []int{24, 37, 65}) {
		packets, err := decoder.repair(fragment, time.Unix(100, 0))
		if err != nil {
			t.Fatal(err)
		}
		recovered = append(recovered, packets...)
	}
	if len(recovered) != 1 || recovered[0].pn != 1000 || !bytes.Equal(recovered[0].frames, want) {
		t.Fatal("single-source tail was not recovered from parity alone")
	}
	if len(encoder.group) != 0 || encoder.pending() {
		t.Fatal("flushed encoder retained work")
	}
}

func TestPacketFECMaximumBlockAndSourceSize(t *testing.T) {
	encoder := newPacketFECEncoder(packetFECMaxData, packetFECMaxParity)
	decoder := newPacketFECDecoder()
	now := time.Unix(100, 0)
	want := make(map[uint64][]byte)
	for i := 0; i < packetFECMaxData; i++ {
		pn := uint64(1)<<40 + uint64(i)*71
		frames := appendStream(nil, uint64(i+1), 0, bytes.Repeat([]byte{byte('a' + i)}, 1228), false, false)
		if len(frames) != packetFECMaxSourceSize {
			t.Fatal("test source does not exercise the maximum packet size")
		}
		if err := encoder.add(pn, frames, false); err != nil {
			t.Fatal(err)
		}
		if i < packetFECMaxParity {
			want[pn] = frames
		} else if _, err := decoder.observe(pn, frames, now); err != nil {
			t.Fatal(err)
		}
	}
	fragments := drainPacketFEC(t, encoder, []int{3, 64, 80, 123})
	for i := len(fragments) - 1; i >= 0; i-- {
		recovered, err := decoder.repair(fragments[i], now)
		if err != nil {
			t.Fatal(err)
		}
		for _, packet := range recovered {
			frames, missing := want[packet.pn]
			if !missing || !bytes.Equal(packet.frames, frames) {
				t.Fatalf("unexpected recovered packet %d", packet.pn)
			}
			delete(want, packet.pn)
		}
	}
	if len(want) != 0 {
		t.Fatalf("maximum-sized block left %d packets missing", len(want))
	}
}

func TestPacketFECBoundsAndExpiry(t *testing.T) {
	if validPacketFEC(1, 1) || validPacketFEC(17, 1) || validPacketFEC(2, 0) || validPacketFEC(2, 5) || !validPacketFEC(16, 4) || newPacketFECEncoder(1, 1) != nil {
		t.Fatal("invalid configured FEC limits")
	}
	encoder := newPacketFECEncoder(2, 1)
	for pn := uint64(0); pn < 20; pn++ {
		if err := encoder.add(pn, []byte{frPing}, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(encoder.queue) != packetFECMaxQueued || encoder.queue[0].pns[0] != 12 {
		t.Fatal("parity queue did not evict its oldest blocks")
	}
	for _, block := range encoder.queue {
		block.created = time.Now().Add(-packetFECLifetime)
	}
	if encoder.pending() {
		t.Fatal("expired queued parity survived")
	}
	if err := encoder.add(21, []byte{frPing}, false); err != nil {
		t.Fatal(err)
	}
	encoder.groupCreated = time.Now().Add(-packetFECLifetime)
	if err := encoder.add(0, nil, true); err != nil || encoder.pending() || len(encoder.group) != 0 {
		t.Fatal("expired short tail survived")
	}
	now := time.Unix(100, 0)
	decoder := newPacketFECDecoder()
	for pn := uint64(0); pn < packetFECHistory+10; pn++ {
		if _, err := decoder.observe(pn, []byte{frPing}, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(decoder.sources) != packetFECHistory || len(decoder.order) != packetFECHistory {
		t.Fatal("source history exceeded its bound")
	}
	if _, ok := decoder.sources[0]; ok {
		t.Fatal("oldest source was not evicted")
	}
	for i := 0; i < packetFECMaxBlocks+4; i++ {
		fragment := &fecFragment{pns: []uint64{1000 + uint64(i)*4, 1001 + uint64(i)*4}, parityCount: 1, shardSize: 20, data: []byte{1}}
		if _, err := decoder.repair(fragment, now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if len(decoder.blocks) != packetFECMaxBlocks {
		t.Fatal("repair blocks exceeded their bound")
	}
	if _, ok := decoder.blocks[1000]; ok {
		t.Fatal("oldest repair block was not evicted")
	}
	decoder.expire(now.Add(packetFECLifetime + time.Second))
	if len(decoder.sources) != 0 || len(decoder.order) != 0 || len(decoder.blocks) != 0 {
		t.Fatal("expired FEC state survived")
	}
}

func packetFECWireForTest(values ...uint64) []byte {
	var b []byte
	for _, value := range values {
		b = appendVarint(b, value)
	}
	return b
}

func TestReadFECFragmentRejectsMalformedMetadata(t *testing.T) {
	cases := map[string][]byte{
		"no sources":        packetFECWireForTest(0, 1, 0),
		"too many sources":  packetFECWireForTest(17, 1, 0),
		"no parity":         packetFECWireForTest(2, 0, 0),
		"too much parity":   packetFECWireForTest(2, 5, 0),
		"bad parity index":  packetFECWireForTest(2, 1, 1),
		"duplicate PN":      packetFECWireForTest(2, 1, 0, 7, 0, 3, 0, 1, 0),
		"overflowing PN":    packetFECWireForTest(2, 1, 0, maxVarint, 1, 3, 0, 1, 0),
		"short shard":       packetFECWireForTest(1, 1, 0, 7, 2, 0, 1, 0),
		"large shard":       packetFECWireForTest(1, 1, 0, 7, packetFECMaxShardSize+1, 0, 1, 0),
		"offset after end":  packetFECWireForTest(1, 1, 0, 7, 3, 3, 1, 0),
		"zero length":       packetFECWireForTest(1, 1, 0, 7, 3, 0, 0),
		"length after end":  packetFECWireForTest(1, 1, 0, 7, 3, 2, 2, 0, 0),
		"truncated payload": packetFECWireForTest(1, 1, 0, 7, 3, 0, 2, 0),
		"truncated varint":  {0x40},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readFECFragment(&reader{b: wire}); err == nil {
				t.Fatal("accepted malformed parity metadata")
			}
		})
	}
}

func TestPacketFECRejectsConflictingDuplicatesAndLengths(t *testing.T) {
	now := time.Unix(100, 0)
	decoder := newPacketFECDecoder()
	fragment := &fecFragment{pns: []uint64{7, 8}, parityCount: 1, shardSize: 5, data: []byte{0xa5}}
	if _, err := decoder.repair(fragment, now); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.repair(fragment, now); err != nil || decoder.blocks[7].counts[0] != 1 {
		t.Fatal("identical fragment was not idempotent")
	}
	for name, bad := range map[string]*fecFragment{
		"conflicting chunk": {pns: []uint64{7, 8}, parityCount: 1, shardSize: 5, data: []byte{0x5a}},
		"different PNs":     {pns: []uint64{7, 9}, parityCount: 1, shardSize: 5, data: []byte{0xa5}},
		"different size":    {pns: []uint64{7, 8}, parityCount: 1, shardSize: 6, data: []byte{0xa5}},
		"different parity":  {pns: []uint64{7, 8}, parityCount: 2, shardSize: 5, data: []byte{0xa5}},
		"duplicate PNs":     {pns: []uint64{7, 7}, parityCount: 1, shardSize: 5, data: []byte{0xa5}},
		"overlapping block": {pns: []uint64{6, 7}, parityCount: 1, shardSize: 5, data: []byte{0xa5}},
		"negative offset":   {pns: []uint64{7, 8}, parityCount: 1, shardSize: 5, offset: -1, data: []byte{0xa5}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decoder.repair(bad, now); err == nil {
				t.Fatal("accepted conflicting parity")
			}
		})
	}
	if _, err := decoder.observe(7, []byte{frPing}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.observe(7, []byte{frClose, 0}, now); err == nil {
		t.Fatal("accepted conflicting source duplicate")
	}
	if _, err := decoder.observe(8, bytes.Repeat([]byte{frPing}, 4), now); err == nil {
		t.Fatal("accepted original larger than its declared shard")
	}
	encoder := newPacketFECEncoder(2, 1)
	if err := encoder.add(1, bytes.Repeat([]byte{frPing}, packetFECMaxSourceSize+1), false); err == nil {
		t.Fatal("accepted oversized source")
	}
	if err := encoder.add(1, []byte{frPing}, false); err != nil {
		t.Fatal(err)
	}
	if err := encoder.add(1, []byte{frPing}, false); err == nil {
		t.Fatal("accepted duplicate encoder PN")
	}
	// A reconstructed length prefix must describe a nonempty valid-sized source.
	block, err := fec.EncodePackets([][]byte{nil}, 1)
	if err != nil {
		t.Fatal(err)
	}
	empty := &fecFragment{pns: []uint64{50}, parityCount: 1, shardSize: block.ShardSize, data: block.Shards[1]}
	if _, err := newPacketFECDecoder().repair(empty, now); err == nil {
		t.Fatal("accepted an empty recovered source")
	}
}

func FuzzReadFECFragment(f *testing.F) {
	f.Add(packetFECWireForTest(2, 1, 0, 7, 1, 3, 0, 1, 0))
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, wire []byte) {
		fragment, err := readFECFragment(&reader{b: wire})
		if err == nil && !validFECFragment(fragment) {
			t.Fatal("parser returned invalid FEC metadata")
		}
	})
}
