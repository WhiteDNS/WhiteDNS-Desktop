package arq

import (
	Enums "cottendns-go/internal/enums"
	"testing"
	"time"
)

type immediateDequeueEnqueuer struct {
	arq   *ARQ
	calls int
}

func (e *immediateDequeueEnqueuer) PushTXPacket(_ int, kind uint8, sn uint16, fragment, _ uint8, _ uint8, _ time.Duration, _ []byte) bool {
	e.calls++
	// A sender can dequeue and transmit before the producer returns from enqueue.
	e.arq.NoteTXPacketDequeued(kind, sn, fragment)
	return true
}

func TestRetransmitImmediateDequeueKeepsRetryArmed(t *testing.T) {
	enq := &immediateDequeueEnqueuer{}
	a := NewARQ(1, 1, enq, nil, 100, nil, Config{WindowSize: 32, RTO: 0.1, MaxRTO: 0.5})
	enq.arq = a
	now := time.Now()
	a.sndBuf[9] = &arqDataItem{Data: []byte("lost twice"), CreatedAt: now, LastSentAt: now.Add(-time.Second), Dispatched: true, CurrentRTO: 100 * time.Millisecond}
	a.checkRetransmits()
	if !a.sndBuf[9].Dispatched {
		t.Fatal("fast dequeue was overwritten; a lost retry can never be retransmitted")
	}
	a.sndBuf[9].LastSentAt = now.Add(-time.Second)
	a.minRetransmitAt = time.Time{}
	a.checkRetransmits()
	if enq.calls != 2 {
		t.Fatalf("lost retransmission did not retry: calls=%d", enq.calls)
	}
	if !a.HasPendingSequence(9) {
		t.Fatal("unacknowledged data disappeared")
	}
	a.ReceiveAck(Enums.PACKET_STREAM_DATA_ACK, 9)
	if a.HasPendingSequence(9) {
		t.Fatal("acknowledged data retained")
	}
}
