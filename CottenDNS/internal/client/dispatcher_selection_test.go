// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"fmt"
	"testing"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/mlq"
)

func benchStream(id uint16) *Stream_client {
	return &Stream_client{StreamID: id, txQueue: mlq.New[*clientStreamTXPacket](512)}
}

func dispatchEntries(ids ...int32) []dispatchEntry {
	entries := make([]dispatchEntry, 0, len(ids))
	for _, id := range ids {
		if id == -1 {
			entries = append(entries, dispatchEntry{id: -1})
			continue
		}
		entries = append(entries, dispatchEntry{id: id, stream: benchStream(uint16(id))})
	}
	return entries
}

func queue(t *testing.T, e dispatchEntry, packetType uint8, seq uint16) {
	t.Helper()
	p := &clientStreamTXPacket{PacketType: packetType, SequenceNum: seq}
	if !e.stream.txQueue.Push(2, uint64(e.id)<<32|uint64(seq), p) {
		t.Fatalf("push to stream %d failed", e.id)
	}
}

func TestSelectNextDispatchStreamRoundRobins(t *testing.T) {
	entries := dispatchEntries(0, 3, 7)
	for _, e := range entries {
		queue(t, e, Enums.PACKET_STREAM_DATA, 1)
		queue(t, e, Enums.PACKET_STREAM_DATA, 2)
	}

	cursor := int32(0)
	var got []int32
	for i := 0; i < 3; i++ {
		_, item, _, id := c_selectHelper(entries, &cursor)
		if item == nil {
			t.Fatalf("iteration %d: nothing selected", i)
		}
		got = append(got, id)
	}
	// Each stream is visited once before any is revisited.
	if got[0] == got[1] || got[1] == got[2] || got[0] == got[2] {
		t.Fatalf("round-robin revisited a stream early: %v", got)
	}
}

func TestSelectNextDispatchStreamSkipsEmptyAndFindsBusy(t *testing.T) {
	entries := dispatchEntries(0, 1, 2, 3, 4)
	queue(t, entries[3], Enums.PACKET_STREAM_DATA, 9)

	cursor := int32(0)
	selected, item, streamID, id := c_selectHelper(entries, &cursor)
	if item == nil || id != 3 || streamID != 3 || selected != entries[3].stream {
		t.Fatalf("expected the only busy stream (3), got id=%d item=%v", id, item)
	}
}

func TestSelectNextDispatchStreamReportsNothingWhenAllIdle(t *testing.T) {
	entries := dispatchEntries(0, 1, 2)
	cursor := int32(0)
	_, item, _, id := c_selectHelper(entries, &cursor)
	if item != nil || id != -2 {
		t.Fatalf("expected no work (id=-2, nil item), got id=%d item=%v", id, item)
	}
}

// A PING on the control stream must yield to real work on another stream.
func TestSelectNextDispatchStreamDefersControlPing(t *testing.T) {
	entries := dispatchEntries(0, 5)
	queue(t, entries[0], Enums.PACKET_PING, 1)
	queue(t, entries[1], Enums.PACKET_STREAM_DATA, 1)

	cursor := int32(0)
	_, item, _, id := c_selectHelper(entries, &cursor)
	if item == nil || id != 5 {
		t.Fatalf("PING on stream 0 should defer to stream 5, got id=%d", id)
	}

	// With no competing work the PING is sent.
	only := dispatchEntries(0)
	queue(t, only[0], Enums.PACKET_PING, 1)
	cursor = 0
	_, item, _, id = c_selectHelper(only, &cursor)
	if item == nil || id != 0 || item.PacketType != Enums.PACKET_PING {
		t.Fatalf("lone PING should be selected, got id=%d item=%v", id, item)
	}
}

func c_selectHelper(entries []dispatchEntry, cursor *int32) (*Stream_client, *clientStreamTXPacket, uint16, int32) {
	c := &Client{}
	return c.selectNextDispatchStream(entries, cursor)
}

// One busy stream among many idle ones — the normal browsing shape. The scan
// runs once per dispatched packet, so its cost is a direct throughput ceiling.
func BenchmarkSelectNextDispatchStream(b *testing.B) {
	for _, n := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			c := &Client{}
			entries := make([]dispatchEntry, 0, n)
			for i := 0; i < n; i++ {
				entries = append(entries, dispatchEntry{id: int32(i), stream: benchStream(uint16(i))})
			}
			busy := entries[n-1].stream
			busy.txQueue.Push(2, 1, &clientStreamTXPacket{PacketType: Enums.PACKET_STREAM_DATA, SequenceNum: 1})

			cursor := int32(0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.selectNextDispatchStream(entries, &cursor)
			}
		})
	}
}
