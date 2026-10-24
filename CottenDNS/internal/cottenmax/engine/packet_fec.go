package soar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"cottendns-go/internal/fec"
)

const (
	frFECConfig = 0x10
	frFECParity = 0x11

	packetFECMaxData       = 16
	packetFECMaxParity     = 4
	packetFECMaxSourceSize = 1232
	packetFECMaxShardSize  = packetFECMaxSourceSize + 2
	packetFECHistory       = 128
	packetFECMaxBlocks     = 16
	packetFECMaxQueued     = 4
	packetFECLifetime      = 8 * time.Second
)

var errPacketFEC = errors.New("cottenmax: malformed FEC repair")

func validPacketFEC(k, p int) bool {
	return k >= 2 && k <= packetFECMaxData && p >= 1 && p <= packetFECMaxParity
}

// fecFragment describes part of one parity shard. Original packets have no FEC
// header: the parity metadata identifies their existing authenticated packet
// numbers instead. pns are strictly increasing; index counts only parity shards.
type fecFragment struct {
	pns         []uint64
	parityCount int
	index       int
	shardSize   int
	offset      int
	data        []byte
}

// readFECFragment consumes the fields following frFECParity. All integers use
// the session's existing varint encoding; subsequent source PNs are positive
// deltas from the preceding PN. Fragment bytes alias the reader's input.
func readFECFragment(r *reader) (*fecFragment, error) {
	n, p, index := r.varint(), r.varint(), r.varint()
	if r.err != nil {
		return nil, r.err
	}
	if n < 1 || n > packetFECMaxData || p < 1 || p > packetFECMaxParity || index >= p {
		return nil, errPacketFEC
	}
	f := &fecFragment{pns: make([]uint64, int(n)), parityCount: int(p), index: int(index)}
	f.pns[0] = r.varint()
	for i := 1; i < len(f.pns); i++ {
		delta := r.varint()
		if r.err != nil {
			return nil, r.err
		}
		if delta == 0 || delta > maxVarint-f.pns[i-1] {
			return nil, errPacketFEC
		}
		f.pns[i] = f.pns[i-1] + delta
	}
	size, offset, length := r.varint(), r.varint(), r.varint()
	if r.err != nil {
		return nil, r.err
	}
	if size < 3 || size > packetFECMaxShardSize || offset >= size || length == 0 || length > size-offset {
		return nil, errPacketFEC
	}
	f.shardSize, f.offset = int(size), int(offset)
	f.data = r.bytes(length)
	if r.err != nil {
		return nil, r.err
	}
	return f, nil
}

type fecSource struct {
	pn     uint64
	frames []byte
}

type fecParityBlock struct {
	pns     []uint64
	shards  [][]byte
	index   int
	offset  int
	created time.Time
}

// packetFECEncoder never delays or changes original packets. Only parity is
// queued, and it is expendable when the resolver cannot carry it fast enough.
// Its caller serializes access together with normal session packet building.
type packetFECEncoder struct {
	k, p         int
	group        []fecSource
	groupCreated time.Time
	queue        []*fecParityBlock
	lastPN       uint64
	havePN       bool
}

func newPacketFECEncoder(k, p int) *packetFECEncoder {
	if !validPacketFEC(k, p) {
		return nil
	}
	return &packetFECEncoder{k: k, p: p}
}

func (e *packetFECEncoder) expire(now time.Time) {
	if len(e.group) > 0 && now.Sub(e.groupCreated) >= packetFECLifetime {
		e.group = nil
	}
	for len(e.queue) > 0 && now.Sub(e.queue[0].created) >= packetFECLifetime {
		e.queue[0] = nil
		e.queue = e.queue[1:]
	}
}

// add records the exact FRAME plaintext, excluding the downstream packet header.
// The caller supplies only original packets, before appending any parity frames.
// A nil frames slice with flush=true flushes a short tail without another source.
func (e *packetFECEncoder) add(pn uint64, frames []byte, flush bool) error {
	if e == nil {
		return errPacketFEC
	}
	now := time.Now()
	e.expire(now)
	if len(frames) > 0 {
		if len(frames) > packetFECMaxSourceSize || pn > maxVarint || (e.havePN && pn <= e.lastPN) {
			return errPacketFEC
		}
		if len(e.group) == 0 {
			e.groupCreated = now
		}
		e.group = append(e.group, fecSource{pn: pn, frames: append([]byte(nil), frames...)})
		e.lastPN, e.havePN = pn, true
	} else if !flush {
		return errPacketFEC
	}
	if len(e.group) == 0 || (len(e.group) < e.k && !flush) {
		return nil
	}
	packets := make([][]byte, len(e.group))
	pns := make([]uint64, len(e.group))
	for i, source := range e.group {
		pns[i], packets[i] = source.pn, source.frames
	}
	block, err := fec.EncodePackets(packets, e.p)
	if err != nil {
		return err
	}
	e.group = nil
	if len(e.queue) == packetFECMaxQueued {
		copy(e.queue, e.queue[1:])
		e.queue[len(e.queue)-1] = nil
		e.queue = e.queue[:len(e.queue)-1]
	}
	e.queue = append(e.queue, &fecParityBlock{pns: pns, shards: block.Shards[block.DataShards:], created: now})
	return nil
}

func (e *packetFECEncoder) pending() bool {
	if e == nil {
		return false
	}
	e.expire(time.Now())
	return len(e.queue) > 0
}

// appendParity appends at most one fragment in at most budget additional bytes.
// An insufficient budget leaves the bounded queue untouched. In particular, it
// never enlarges an original response or assumes the next DNS response's MTU.
func (e *packetFECEncoder) appendParity(dst []byte, budget int) ([]byte, bool) {
	if e == nil || budget <= 0 {
		return dst, false
	}
	e.expire(time.Now())
	if len(e.queue) == 0 {
		return dst, false
	}
	b := e.queue[0]
	shard := b.shards[b.index]
	header := appendVarint([]byte{frFECParity}, uint64(len(b.pns)))
	header = appendVarint(header, uint64(len(b.shards)))
	header = appendVarint(header, uint64(b.index))
	header = appendVarint(header, b.pns[0])
	for i := 1; i < len(b.pns); i++ {
		header = appendVarint(header, b.pns[i]-b.pns[i-1])
	}
	header = appendVarint(header, uint64(len(shard)))
	header = appendVarint(header, uint64(b.offset))
	n := min(len(shard)-b.offset, budget-len(header)-1)
	for n > 0 && len(header)+varintLen(uint64(n))+n > budget {
		n--
	}
	if n <= 0 {
		return dst, false
	}
	dst = append(dst, header...)
	dst = appendVarint(dst, uint64(n))
	dst = append(dst, shard[b.offset:b.offset+n]...)
	b.offset += n
	if b.offset == len(shard) {
		b.index++
		b.offset = 0
		if b.index == len(b.shards) {
			e.queue[0] = nil
			e.queue = e.queue[1:]
		}
	}
	return dst, true
}

type fecRecovered struct {
	pn     uint64
	frames []byte
}

type fecObserved struct {
	frames []byte
	at     time.Time
}

type fecRepairBlock struct {
	pns         []uint64
	parityCount int
	shardSize   int
	shards      [][]byte
	filled      [][]bool
	counts      []int
	created     time.Time
}

type packetFECDecoder struct {
	sources map[uint64]fecObserved
	order   []uint64
	blocks  map[uint64]*fecRepairBlock
}

func newPacketFECDecoder() *packetFECDecoder {
	return &packetFECDecoder{sources: make(map[uint64]fecObserved), blocks: make(map[uint64]*fecRepairBlock)}
}

func (d *packetFECDecoder) expire(now time.Time) {
	kept := d.order[:0]
	for _, pn := range d.order {
		if source, ok := d.sources[pn]; ok && now.Sub(source.at) < packetFECLifetime {
			kept = append(kept, pn)
		} else {
			delete(d.sources, pn)
		}
	}
	d.order = kept
	for id, block := range d.blocks {
		if now.Sub(block.created) >= packetFECLifetime {
			delete(d.blocks, id)
		}
	}
}

func (d *packetFECDecoder) remember(pn uint64, frames []byte, now time.Time) error {
	if previous, ok := d.sources[pn]; ok {
		if !bytes.Equal(previous.frames, frames) {
			return errPacketFEC
		}
		return nil
	}
	if len(d.order) == packetFECHistory {
		delete(d.sources, d.order[0])
		copy(d.order, d.order[1:])
		d.order = d.order[:len(d.order)-1]
	}
	d.sources[pn] = fecObserved{frames: append([]byte(nil), frames...), at: now}
	d.order = append(d.order, pn)
	return nil
}

// observe accepts only authenticated original/recovered FRAME plaintext. It also
// retries repair blocks received before their surviving original packets.
func (d *packetFECDecoder) observe(pn uint64, frames []byte, now time.Time) ([]fecRecovered, error) {
	if d == nil || pn > maxVarint || len(frames) == 0 || len(frames) > packetFECMaxSourceSize {
		return nil, errPacketFEC
	}
	d.expire(now)
	if err := d.remember(pn, frames, now); err != nil {
		return nil, err
	}
	return d.recover(now)
}

func validFECFragment(f *fecFragment) bool {
	if f == nil || len(f.pns) < 1 || len(f.pns) > packetFECMaxData || f.parityCount < 1 || f.parityCount > packetFECMaxParity || f.index < 0 || f.index >= f.parityCount || f.shardSize < 3 || f.shardSize > packetFECMaxShardSize || f.offset < 0 || f.offset >= f.shardSize || len(f.data) == 0 || len(f.data) > f.shardSize-f.offset {
		return false
	}
	for i, pn := range f.pns {
		if pn > maxVarint || (i > 0 && pn <= f.pns[i-1]) {
			return false
		}
	}
	return true
}

func sameFECBlock(b *fecRepairBlock, f *fecFragment) bool {
	if b.parityCount != f.parityCount || b.shardSize != f.shardSize || len(b.pns) != len(f.pns) {
		return false
	}
	for i, pn := range b.pns {
		if pn != f.pns[i] {
			return false
		}
	}
	return true
}

func (d *packetFECDecoder) repair(f *fecFragment, now time.Time) ([]fecRecovered, error) {
	if d == nil || !validFECFragment(f) {
		return nil, errPacketFEC
	}
	d.expire(now)
	id := f.pns[0]
	b := d.blocks[id]
	if b != nil {
		if !sameFECBlock(b, f) {
			return nil, errPacketFEC
		}
	} else {
		// A source belongs to one block. Reject overlapping live block identities
		// rather than allowing conflicting metadata to amplify the repair state.
		for _, existing := range d.blocks {
			for _, pn := range existing.pns {
				for _, candidate := range f.pns {
					if pn == candidate {
						return nil, errPacketFEC
					}
				}
			}
		}
		if len(d.blocks) == packetFECMaxBlocks {
			var oldestID uint64
			var oldest *fecRepairBlock
			for blockID, candidate := range d.blocks {
				if oldest == nil || candidate.created.Before(oldest.created) {
					oldestID, oldest = blockID, candidate
				}
			}
			delete(d.blocks, oldestID)
		}
		b = &fecRepairBlock{pns: append([]uint64(nil), f.pns...), parityCount: f.parityCount, shardSize: f.shardSize, shards: make([][]byte, f.parityCount), filled: make([][]bool, f.parityCount), counts: make([]int, f.parityCount), created: now}
		d.blocks[id] = b
	}
	if b.shards[f.index] == nil {
		b.shards[f.index] = make([]byte, b.shardSize)
		b.filled[f.index] = make([]bool, b.shardSize)
	}
	for i, value := range f.data {
		pos := f.offset + i
		if b.filled[f.index][pos] && b.shards[f.index][pos] != value {
			return nil, errPacketFEC
		}
	}
	for i, value := range f.data {
		pos := f.offset + i
		if !b.filled[f.index][pos] {
			b.shards[f.index][pos] = value
			b.filled[f.index][pos] = true
			b.counts[f.index]++
		}
	}
	return d.recover(now)
}

func (d *packetFECDecoder) recover(now time.Time) ([]fecRecovered, error) {
	var recovered []fecRecovered
	for id, b := range d.blocks {
		k := len(b.pns)
		present, missing := 0, 0
		for _, pn := range b.pns {
			if source, ok := d.sources[pn]; ok {
				if len(source.frames)+2 > b.shardSize {
					delete(d.blocks, id)
					return nil, errPacketFEC
				}
				present++
			} else {
				missing++
			}
		}
		if missing == 0 {
			delete(d.blocks, id)
			continue
		}
		for i := range b.shards {
			if b.counts[i] == b.shardSize {
				present++
			}
		}
		if present < k {
			continue
		}
		block := &fec.Block{DataShards: k, ParityShards: b.parityCount, ShardSize: b.shardSize, Shards: make([][]byte, k+b.parityCount)}
		for i, pn := range b.pns {
			if source, ok := d.sources[pn]; ok {
				shard := make([]byte, b.shardSize)
				binary.BigEndian.PutUint16(shard, uint16(len(source.frames)))
				copy(shard[2:], source.frames)
				block.Shards[i] = shard
			}
		}
		for i, shard := range b.shards {
			if b.counts[i] == b.shardSize {
				// DecodePackets may reconstruct into its input; retain stable shard
				// storage for incomplete blocks and later fragments.
				block.Shards[k+i] = append([]byte(nil), shard...)
			}
		}
		packets, err := fec.DecodePackets(block)
		if err != nil {
			delete(d.blocks, id)
			return nil, err
		}
		for _, frames := range packets {
			if len(frames) == 0 || len(frames) > packetFECMaxSourceSize {
				delete(d.blocks, id)
				return nil, errPacketFEC
			}
		}
		for i, pn := range b.pns {
			if _, ok := d.sources[pn]; !ok {
				if err := d.remember(pn, packets[i], now); err != nil {
					delete(d.blocks, id)
					return nil, err
				}
				recovered = append(recovered, fecRecovered{pn: pn, frames: packets[i]})
			}
		}
		delete(d.blocks, id)
	}
	return recovered, nil
}
