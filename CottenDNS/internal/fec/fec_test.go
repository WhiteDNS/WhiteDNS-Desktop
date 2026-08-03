// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package fec

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func samplePackets(n int) [][]byte {
	pkts := make([][]byte, n)
	for i := range pkts {
		// Deliberately uneven lengths to exercise per-packet padding.
		pkts[i] = []byte(fmt.Sprintf("packet-%d-%s", i, bytes.Repeat([]byte("x"), i%7)))
	}
	return pkts
}

func TestEncodeDecodeNoLoss(t *testing.T) {
	pkts := samplePackets(4)
	block, err := EncodePackets(pkts, 4)
	if err != nil {
		t.Fatalf("EncodePackets: %v", err)
	}
	got, err := DecodePackets(block)
	if err != nil {
		t.Fatalf("DecodePackets: %v", err)
	}
	for i := range pkts {
		if !bytes.Equal(got[i], pkts[i]) {
			t.Fatalf("packet %d mismatch: got %q want %q", i, got[i], pkts[i])
		}
	}
}

// The headline requirement: survive 75% packet loss. With N data shards and
// parity sized for 0.75 loss, dropping 75% of shards must still reconstruct.
func TestSurvives75PercentLoss(t *testing.T) {
	for _, dataShards := range []int{1, 2, 4, 8} {
		parity := ParityForLoss(dataShards, 0.75)
		pkts := samplePackets(dataShards)
		block, err := EncodePackets(pkts, parity)
		if err != nil {
			t.Fatalf("EncodePackets(N=%d,K=%d): %v", dataShards, parity, err)
		}

		total := dataShards + parity
		// Drop 75% of the shards (keep the first 25%, which is the worst case
		// for data — many data shards lost, only parity/sparse data left).
		keep := total - (total*3)/4
		if keep < dataShards {
			t.Fatalf("N=%d parity=%d: keep=%d < dataShards (not enough margin)", dataShards, parity, keep)
		}
		dropFromEnd := total - keep
		for i := 0; i < dropFromEnd; i++ {
			block.Shards[i] = nil // null the first shards (data first) -> worst case
		}

		got, err := DecodePackets(block)
		if err != nil {
			t.Fatalf("N=%d parity=%d after 75%% loss: DecodePackets: %v", dataShards, parity, err)
		}
		for i := range pkts {
			if !bytes.Equal(got[i], pkts[i]) {
				t.Fatalf("N=%d packet %d mismatch after loss", dataShards, i)
			}
		}
	}
}

// Super-FEC's upper supported operating point is 84% loss (just below the
// default 85% hopeless-link ceiling). Verify reconstruction with actual shards,
// not only the server's parity-selection arithmetic.
func TestSurvives84PercentLoss(t *testing.T) {
	for _, dataShards := range []int{1, 2, 4, 8} {
		parity := ParityForLoss(dataShards, 0.84)
		pkts := samplePackets(dataShards)
		block, err := EncodePackets(pkts, parity)
		if err != nil {
			t.Fatalf("EncodePackets(N=%d,K=%d): %v", dataShards, parity, err)
		}

		total := dataShards + parity
		drop := int(float64(total) * 0.84)
		if total-drop < dataShards {
			t.Fatalf("N=%d parity=%d leaves only %d shards", dataShards, parity, total-drop)
		}
		for i := 0; i < drop; i++ {
			block.Shards[i] = nil
		}

		got, err := DecodePackets(block)
		if err != nil {
			t.Fatalf("N=%d parity=%d after 84%% loss: DecodePackets: %v", dataShards, parity, err)
		}
		for i := range pkts {
			if !bytes.Equal(got[i], pkts[i]) {
				t.Fatalf("N=%d packet %d mismatch after 84%% loss", dataShards, i)
			}
		}
	}
}

func TestReorderAndPartialLossReconstructs(t *testing.T) {
	pkts := samplePackets(6)
	parity := 6
	block, err := EncodePackets(pkts, parity)
	if err != nil {
		t.Fatalf("EncodePackets: %v", err)
	}
	// Lose exactly `parity` shards spread across data and parity.
	for _, idx := range []int{0, 2, 5, 7, 9, 11} {
		block.Shards[idx] = nil
	}
	got, err := DecodePackets(block)
	if err != nil {
		t.Fatalf("DecodePackets: %v", err)
	}
	for i := range pkts {
		if !bytes.Equal(got[i], pkts[i]) {
			t.Fatalf("packet %d mismatch", i)
		}
	}
}

func TestTooFewShardsFails(t *testing.T) {
	pkts := samplePackets(4)
	block, err := EncodePackets(pkts, 4)
	if err != nil {
		t.Fatalf("EncodePackets: %v", err)
	}
	// Drop more than parity (5 of 8) -> only 3 < 4 dataShards remain.
	for _, idx := range []int{0, 1, 2, 3, 4} {
		block.Shards[idx] = nil
	}
	if _, err := DecodePackets(block); err == nil {
		t.Fatal("expected error when fewer than DataShards survive")
	}
}

func TestParityForLossMonotonic(t *testing.T) {
	prev := 0
	for _, loss := range []float64{0.1, 0.3, 0.5, 0.75, 0.9} {
		p := ParityForLoss(4, loss)
		if p < 1 {
			t.Fatalf("loss %.2f: parity %d < 1", loss, p)
		}
		if p < prev {
			t.Fatalf("parity should not decrease with loss: loss %.2f got %d after %d", loss, p, prev)
		}
		prev = p
	}
}

func TestLossyNetworkRecoveryEffectiveness(t *testing.T) {
	tests := []struct {
		name        string
		loss        float64
		parity      int
		minRecovery float64
	}{
		{
			name:        "auto-fec-40-percent",
			loss:        0.40,
			parity:      ParityForLoss(4, 0.40),
			minRecovery: 0.75,
		},
		{
			name:        "super-fec-84-percent",
			loss:        0.84,
			parity:      ParityForLossTarget(4, 0.84, 0.90),
			minRecovery: 0.85,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := samplePackets(4)
			encoded, err := EncodePackets(source, tc.parity)
			if err != nil {
				t.Fatal(err)
			}
			rng := rand.New(rand.NewSource(0xC077E))
			const trials = 1000
			recovered := 0
			rawSurvived := 0
			for trial := 0; trial < trials; trial++ {
				block := &Block{
					DataShards:   encoded.DataShards,
					ParityShards: encoded.ParityShards,
					ShardSize:    encoded.ShardSize,
					Shards:       make([][]byte, len(encoded.Shards)),
				}
				rawOK := true
				for i, shard := range encoded.Shards {
					if rng.Float64() < tc.loss {
						if i < encoded.DataShards {
							rawOK = false
						}
						continue
					}
					block.Shards[i] = append([]byte(nil), shard...)
				}
				if rawOK {
					rawSurvived++
				}
				got, decodeErr := DecodePackets(block)
				if decodeErr != nil {
					continue
				}
				ok := len(got) == len(source)
				for i := range source {
					ok = ok && bytes.Equal(got[i], source[i])
				}
				if ok {
					recovered++
				}
			}
			recoveryRate := float64(recovered) / trials
			rawRate := float64(rawSurvived) / trials
			if recoveryRate < tc.minRecovery {
				t.Fatalf("recovery %.1f%% below %.1f%% target (loss=%.0f%% parity=%d)",
					recoveryRate*100, tc.minRecovery*100, tc.loss*100, tc.parity)
			}
			if recoveryRate < rawRate+0.50 {
				t.Fatalf("FEC improvement too small: recovery=%.1f%% raw=%.1f%%", recoveryRate*100, rawRate*100)
			}
		})
	}
}

func TestSuperFECParityMeetsRecoveryTarget(t *testing.T) {
	for _, loss := range []float64{0.75, 0.80, 0.84} {
		parity := ParityForLossTarget(4, loss, 0.90)
		probability := shardRecoveryProbability(4+parity, 4, 1-loss)
		if probability < 0.90 {
			t.Fatalf("loss=%.0f%% parity=%d recovery=%.3f, want >= 0.90", loss*100, parity, probability)
		}
	}
}
