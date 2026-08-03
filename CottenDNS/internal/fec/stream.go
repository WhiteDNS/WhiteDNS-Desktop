// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// stream.go — stateful FEC layer that bridges a stream of data packets and the
// block codec, with on-wire shard framing. The Encoder (sender) batches data
// packets into blocks and emits framed shard packets (N data + K parity); the
// Decoder (receiver) collects shards and emits the recovered data packets once
// a block is decodable. ARQ runs above this layer unchanged: it sees the data
// packets, the FEC layer just hides most of the loss.
//
// Shard packet wire framing (header = 9 bytes, then the shard bytes):
//
//	blockID(4) | shardIndex(1) | dataShards(1) | parityShards(1) | shardSize(2)
// ==============================================================================

package fec

import (
	"encoding/binary"
	"errors"
)

const (
	// ShardHeaderSize is the per-shard framing overhead on the wire.
	ShardHeaderSize  = 9
	maxTrackedBlocks = 64 // decoder LRU bound
)

var (
	ErrShortShardPacket   = errors.New("fec: shard packet shorter than header")
	ErrBadShardFrame      = errors.New("fec: shard frame inconsistent with header")
	ErrShardBlockMismatch = errors.New("fec: shard metadata does not match its block")
)

// FrameShard serializes one block shard into a wire packet.
func FrameShard(blockID uint32, shardIndex, dataShards, parityShards int, shard []byte) []byte {
	out := make([]byte, ShardHeaderSize+len(shard))
	binary.BigEndian.PutUint32(out[0:4], blockID)
	out[4] = byte(shardIndex)
	out[5] = byte(dataShards)
	out[6] = byte(parityShards)
	binary.BigEndian.PutUint16(out[7:9], uint16(len(shard)))
	copy(out[ShardHeaderSize:], shard)
	return out
}

type shardFrame struct {
	blockID      uint32
	shardIndex   int
	dataShards   int
	parityShards int
	shard        []byte
}

func parseShard(packet []byte) (shardFrame, error) {
	if len(packet) < ShardHeaderSize {
		return shardFrame{}, ErrShortShardPacket
	}
	f := shardFrame{
		blockID:      binary.BigEndian.Uint32(packet[0:4]),
		shardIndex:   int(packet[4]),
		dataShards:   int(packet[5]),
		parityShards: int(packet[6]),
	}
	shardSize := int(binary.BigEndian.Uint16(packet[7:9]))
	if f.dataShards < 1 || f.parityShards < 1 ||
		f.dataShards+f.parityShards > maxShards ||
		f.shardIndex >= f.dataShards+f.parityShards ||
		ShardHeaderSize+shardSize != len(packet) {
		return shardFrame{}, ErrBadShardFrame
	}
	f.shard = packet[ShardHeaderSize:]
	return f, nil
}

// Encoder batches data packets into Reed-Solomon blocks and frames their shards
// for transmission. It is single-goroutine; callers serialize access.
type Encoder struct {
	blockID   uint32
	blockSize int
	parity    int
	buf       [][]byte
}

// NewEncoder creates an encoder that forms blocks of blockSize data packets with
// parity recovery shards each. Both are clamped to valid Reed-Solomon ranges.
func NewEncoder(blockSize, parity int) *Encoder {
	if blockSize < 1 {
		blockSize = 1
	}
	if blockSize >= maxShards {
		blockSize = maxShards - 1
	}
	if parity < 1 {
		parity = 1
	}
	if blockSize+parity > maxShards {
		parity = maxShards - blockSize
	}
	return &Encoder{blockSize: blockSize, parity: parity}
}

// Buffered reports how many data packets are held below the current block
// boundary (i.e. would be emitted by a Flush). Zero means nothing is pending.
func (e *Encoder) Buffered() int {
	return len(e.buf)
}

// Parity reports the parity-shard count currently in effect for new blocks.
func (e *Encoder) Parity() int {
	return e.parity
}

// SetParity adjusts the parity-shard count for subsequent blocks (e.g. as the
// measured loss changes). It takes effect at the next block boundary.
func (e *Encoder) SetParity(parity int) {
	if parity < 1 {
		parity = 1
	}
	if e.blockSize+parity > maxShards {
		parity = maxShards - e.blockSize
	}
	e.parity = parity
}

// AddPacket buffers a data packet. When the block fills, it returns the framed
// shard packets for that block (N data + K parity) and starts a new block.
func (e *Encoder) AddPacket(pkt []byte) ([][]byte, error) {
	e.buf = append(e.buf, append([]byte(nil), pkt...))
	if len(e.buf) < e.blockSize {
		return nil, nil
	}
	return e.flushLocked()
}

// Flush emits a (possibly short) block for whatever is currently buffered, or
// nil when empty. Use it to bound latency when the data stream pauses.
func (e *Encoder) Flush() ([][]byte, error) {
	if len(e.buf) == 0 {
		return nil, nil
	}
	return e.flushLocked()
}

func (e *Encoder) flushLocked() ([][]byte, error) {
	parity := e.parity
	if len(e.buf)+parity > maxShards {
		parity = maxShards - len(e.buf)
	}
	block, err := EncodePackets(e.buf, parity)
	if err != nil {
		e.buf = nil
		return nil, err
	}
	frames := make([][]byte, len(block.Shards))
	for i, shard := range block.Shards {
		frames[i] = FrameShard(e.blockID, i, block.DataShards, block.ParityShards, shard)
	}
	e.blockID++
	e.buf = nil
	return frames, nil
}

// Decoder collects framed shards and reconstructs each block's data packets once
// enough shards arrive. It is single-goroutine; callers serialize access.
type Decoder struct {
	blocks map[uint32]*decodeBlock
	order  []uint32 // FIFO for LRU eviction
}

type decodeBlock struct {
	dataShards   int
	parityShards int
	shardSize    int
	shards       [][]byte
	present      int
	done         bool
}

func NewDecoder() *Decoder {
	return &Decoder{blocks: make(map[uint32]*decodeBlock)}
}

// AddShard ingests a framed shard packet. When the shard completes a decodable
// block it returns that block's data packets (once); otherwise it returns nil.
func (d *Decoder) AddShard(packet []byte) ([][]byte, error) {
	f, err := parseShard(packet)
	if err != nil {
		return nil, err
	}

	b := d.blocks[f.blockID]
	if b == nil {
		b = &decodeBlock{
			dataShards:   f.dataShards,
			parityShards: f.parityShards,
			shardSize:    len(f.shard),
			shards:       make([][]byte, f.dataShards+f.parityShards),
		}
		d.blocks[f.blockID] = b
		d.order = append(d.order, f.blockID)
		d.evictLocked()
	} else if b.dataShards != f.dataShards ||
		b.parityShards != f.parityShards ||
		b.shardSize != len(f.shard) {
		return nil, ErrShardBlockMismatch
	}
	if b.done || f.shardIndex >= len(b.shards) || b.shards[f.shardIndex] != nil {
		return nil, nil
	}

	b.shards[f.shardIndex] = append([]byte(nil), f.shard...)
	b.present++
	if b.present < b.dataShards {
		return nil, nil
	}

	packets, err := DecodePackets(&Block{
		DataShards:   b.dataShards,
		ParityShards: b.parityShards,
		ShardSize:    b.shardSize,
		Shards:       b.shards,
	})
	if err != nil {
		return nil, err
	}
	b.done = true
	b.shards = nil // free shard memory; keep the block marked done
	return packets, nil
}

func (d *Decoder) evictLocked() {
	for len(d.order) > maxTrackedBlocks {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.blocks, oldest)
	}
}
