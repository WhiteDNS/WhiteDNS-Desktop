// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package fec implements a Reed-Solomon block codec for forward error
// correction (tier 2 loss reducer). A block of N data packets is encoded into
// N data + K parity shards; the original packets are recoverable from any N of
// the N+K shards, so a block survives up to K losses with no retransmit.
//
// This package is intentionally standalone and transport-agnostic: it encodes
// and decodes byte-slice packets and knows nothing about DNS or ARQ. The
// transport wiring (block framing on the wire, loss-triggered activation) is a
// separate, later step.
// ==============================================================================

package fec

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/klauspost/reedsolomon"
)

var (
	ErrInvalidShardCounts = errors.New("fec: invalid shard counts")
	ErrPacketTooLarge     = errors.New("fec: packet exceeds 65535 bytes")
	ErrCorruptShard       = errors.New("fec: corrupt or undersized shard")
	ErrTooFewShards       = errors.New("fec: not enough shards to reconstruct block")
)

// lengthPrefix holds each packet's original length inside its padded shard so
// padding can be stripped after reconstruction.
const lengthPrefix = 2

// maxShards is the Reed-Solomon limit (data+parity must fit a single byte index).
const maxShards = 256

// Block is an encoded FEC block. Shards has length DataShards+ParityShards and
// every entry is ShardSize bytes; a nil entry marks a shard lost in transit.
type Block struct {
	DataShards   int
	ParityShards int
	ShardSize    int
	Shards       [][]byte
}

// EncodePackets packs variable-length packets into a Reed-Solomon block with
// parityShards recovery shards. Each packet is stored as [len:2][bytes] padded
// to a uniform shard size (the longest packet wins). The returned block can lose
// any parityShards of its shards and still be decoded.
func EncodePackets(packets [][]byte, parityShards int) (*Block, error) {
	dataShards := len(packets)
	if dataShards < 1 || parityShards < 1 || dataShards+parityShards > maxShards {
		return nil, ErrInvalidShardCounts
	}

	shardSize := lengthPrefix + 1
	for _, p := range packets {
		if len(p) > 0xFFFF {
			return nil, ErrPacketTooLarge
		}
		if lengthPrefix+len(p) > shardSize {
			shardSize = lengthPrefix + len(p)
		}
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}

	shards := make([][]byte, dataShards+parityShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}
	for i, p := range packets {
		binary.BigEndian.PutUint16(shards[i][0:2], uint16(len(p)))
		copy(shards[i][lengthPrefix:], p)
	}

	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return &Block{
		DataShards:   dataShards,
		ParityShards: parityShards,
		ShardSize:    shardSize,
		Shards:       shards,
	}, nil
}

// DecodePackets reconstructs the original packets from a block whose Shards may
// contain nil (lost) entries, provided at least DataShards shards are present.
func DecodePackets(b *Block) ([][]byte, error) {
	if b == nil || b.DataShards < 1 || b.ParityShards < 1 {
		return nil, ErrInvalidShardCounts
	}
	if len(b.Shards) != b.DataShards+b.ParityShards {
		return nil, ErrInvalidShardCounts
	}

	present := 0
	for _, s := range b.Shards {
		if s != nil {
			present++
		}
	}
	if present < b.DataShards {
		return nil, ErrTooFewShards
	}

	enc, err := reedsolomon.New(b.DataShards, b.ParityShards)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(b.Shards); err != nil {
		return nil, err
	}

	packets := make([][]byte, b.DataShards)
	for i := 0; i < b.DataShards; i++ {
		s := b.Shards[i]
		if len(s) < lengthPrefix {
			return nil, ErrCorruptShard
		}
		n := int(binary.BigEndian.Uint16(s[0:2]))
		if lengthPrefix+n > len(s) {
			return nil, ErrCorruptShard
		}
		packets[i] = append([]byte(nil), s[lengthPrefix:lengthPrefix+n]...)
	}
	return packets, nil
}

// MaxParity returns the largest parity-shard count a block of dataShards can
// carry within the Reed-Solomon 256-shard limit (at least 1). It is the hard
// ceiling any loss-driven parity scaling can reach.
func MaxParity(dataShards int) int {
	if dataShards < 1 {
		dataShards = 1
	}
	p := maxShards - dataShards
	if p < 1 {
		p = 1
	}
	return p
}

// ParityForLoss returns a parity-shard count that lets a block of dataShards
// survive the given loss fraction with a small safety margin. It is the bridge
// from the measured loss to a concrete code rate (e.g. 0.75 loss over 4 data
// shards -> enough parity that receiving ~25% still decodes).
func ParityForLoss(dataShards int, lossFrac float64) int {
	if dataShards < 1 {
		return 0
	}
	if lossFrac < 0 {
		lossFrac = 0
	}
	if lossFrac > 0.95 {
		lossFrac = 0.95
	}
	// Total shards T such that survivors (1-loss)*T >= dataShards, plus margin.
	survive := 1.0 - lossFrac
	if survive <= 0 {
		survive = 0.05
	}
	total := int(float64(dataShards)/survive + 0.999)
	parity := total - dataShards + 1 // +1 shard of margin
	if parity < 1 {
		parity = 1
	}
	if dataShards+parity > maxShards {
		parity = maxShards - dataShards
	}
	return parity
}

// ParityForLossTarget returns enough parity for a requested block-recovery
// probability under independent random loss. ParityForLoss guarantees only the
// expected survivor count plus one shard; at extreme loss that succeeds in
// roughly half of random blocks. Super-FEC uses this stronger calculation so an
// 84% link has a useful recovery probability instead of a merely possible one.
func ParityForLossTarget(dataShards int, lossFrac, recoveryTarget float64) int {
	if dataShards < 1 {
		return 0
	}
	if lossFrac < 0 {
		lossFrac = 0
	}
	if lossFrac > 0.95 {
		lossFrac = 0.95
	}
	if recoveryTarget <= 0 || recoveryTarget >= 1 {
		recoveryTarget = 0.90
	}
	minParity := ParityForLoss(dataShards, lossFrac)
	for total := dataShards + minParity; total <= maxShards; total++ {
		if shardRecoveryProbability(total, dataShards, 1-lossFrac) >= recoveryTarget {
			return total - dataShards
		}
	}
	return MaxParity(dataShards)
}

// shardRecoveryProbability is P(X >= required) for X surviving shards out of
// total under independent survival probability p.
func shardRecoveryProbability(total, required int, p float64) float64 {
	if required <= 0 {
		return 1
	}
	if total < required || p <= 0 {
		return 0
	}
	if p >= 1 {
		return 1
	}
	// Sum the failure tail P(X < required) using the binomial recurrence. With
	// at most 256 shards this is stable and far cheaper than an encode.
	q := 1 - p
	term := math.Pow(q, float64(total)) // P(X=0)
	failure := term
	for k := 0; k < required-1; k++ {
		term *= float64(total-k) / float64(k+1) * p / q
		failure += term
	}
	recovery := 1 - failure
	if recovery < 0 {
		return 0
	}
	if recovery > 1 {
		return 1
	}
	return recovery
}
