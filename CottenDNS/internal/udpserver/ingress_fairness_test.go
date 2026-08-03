package udpserver

import (
	"testing"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func ingressTestRequest(packetType uint8) request {
	return request{prepared: preparedIngress{packet: VpnProto.Packet{PacketType: packetType}}}
}

func TestIngressFairQueuesReserveControlCapacity(t *testing.T) {
	s := &Server{}
	queues := ingressQueues{control: make(chan request, 1), data: make(chan request, 2)}

	if !s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_STREAM_DATA), queues) ||
		!s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_STREAM_RESEND), queues) {
		t.Fatal("bulk packets should fill the data lane")
	}
	if s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_STREAM_DATA), queues) {
		t.Fatal("bulk packet borrowed reserved control capacity")
	}
	if !s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_PING), queues) {
		t.Fatal("control packet was not admitted through its reserved lane")
	}
	if got := len(queues.control); got != 1 {
		t.Fatalf("control depth = %d, want 1", got)
	}
}

func TestIngressControlCanBorrowUnusedDataCapacity(t *testing.T) {
	s := &Server{}
	queues := ingressQueues{control: make(chan request, 1), data: make(chan request, 2)}

	if !s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_PING), queues) {
		t.Fatal("first control packet was rejected")
	}
	if !s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_STREAM_DATA_ACK), queues) {
		t.Fatal("control packet could not borrow unused data capacity")
	}
	if s.enqueueIngressRequest(ingressTestRequest(Enums.PACKET_STREAM_DATA_NACK), queues) {
		t.Fatal("control duplication was allowed to build ahead of future user data")
	}
	if len(queues.control) != 1 || len(queues.data) != 1 {
		t.Fatalf("unexpected queue depths: control=%d data=%d", len(queues.control), len(queues.data))
	}
}

func TestIngressBulkClassificationIncludesDuplicates(t *testing.T) {
	for _, packetType := range []uint8{Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_FEC_SHARD} {
		if !isBulkIngressPacket(packetType) {
			t.Fatalf("packet type %d should use the throughput lane", packetType)
		}
	}
	if isBulkIngressPacket(Enums.PACKET_STREAM_DATA_ACK) {
		t.Fatal("ACK should use the latency-sensitive lane")
	}
}
