package fec

import (
	"fmt"
	"testing"
)

// TestBurstInterleaveSimulation is an experiment, not a wire-format change.
// It quantifies whether round-robin transmission of already-framed FEC blocks
// is worth implementing before adding buffering to the live server path.
func TestBurstInterleaveSimulation(t *testing.T) {
	const (
		blocks     = 4
		dataShards = 4
		parity     = 2
		burstStart = 6
		burstLen   = 4
	)

	encoder := NewEncoder(dataShards, parity)
	byBlock := make([][][]byte, 0, blocks)
	for block := 0; block < blocks; block++ {
		var frames [][]byte
		for packet := 0; packet < dataShards; packet++ {
			var err error
			frames, err = encoder.AddPacket([]byte(fmt.Sprintf("b%d-p%d", block, packet)))
			if err != nil {
				t.Fatalf("encode block %d: %v", block, err)
			}
		}
		if len(frames) != dataShards+parity {
			t.Fatalf("block %d emitted %d frames", block, len(frames))
		}
		byBlock = append(byBlock, frames)
	}

	sequential := make([][]byte, 0, blocks*(dataShards+parity))
	for _, frames := range byBlock {
		sequential = append(sequential, frames...)
	}
	interleaved := make([][]byte, 0, cap(sequential))
	for shard := 0; shard < dataShards+parity; shard++ {
		for block := 0; block < blocks; block++ {
			interleaved = append(interleaved, byBlock[block][shard])
		}
	}

	recoveredSequential := recoverOutsideBurst(t, sequential, burstStart, burstLen)
	recoveredInterleaved := recoverOutsideBurst(t, interleaved, burstStart, burstLen)
	t.Logf(
		"four-frame burst: sequential recovered=%d/%d, interleaved recovered=%d/%d",
		recoveredSequential,
		blocks*dataShards,
		recoveredInterleaved,
		blocks*dataShards,
	)
	if recoveredSequential != 3*dataShards {
		t.Fatalf("sequential recovery=%d, want %d", recoveredSequential, 3*dataShards)
	}
	if recoveredInterleaved != blocks*dataShards {
		t.Fatalf("interleaved recovery=%d, want %d", recoveredInterleaved, blocks*dataShards)
	}
}

func recoverOutsideBurst(t *testing.T, frames [][]byte, burstStart, burstLen int) int {
	t.Helper()
	decoder := NewDecoder()
	recovered := 0
	for index, frame := range frames {
		if index >= burstStart && index < burstStart+burstLen {
			continue
		}
		packets, err := decoder.AddShard(frame)
		if err != nil {
			t.Fatalf("decode frame %d: %v", index, err)
		}
		recovered += len(packets)
	}
	return recovered
}
