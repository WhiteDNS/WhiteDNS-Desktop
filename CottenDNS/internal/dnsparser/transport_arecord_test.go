// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"bytes"
	"testing"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestA2ARecordChannelRoundTrips(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)

	payload := bytes.Repeat([]byte("DATA-over-ipv4-"), 20) // ~300 bytes, fits A-record channel
	in := VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_DATA,
		StreamID:       7,
		SequenceNum:    3,
		TotalFragments: 1,
		Payload:        payload,
	}

	// allowARecord = true -> A-record answer for an A query.
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_A {
		t.Fatalf("answer type = %s, want A", Enums.DNSRecordTypeName(got))
	}

	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if out.PacketType != in.PacketType || !bytes.Equal(out.Payload, payload) {
		t.Fatalf("A-record round-trip mismatch: type=%d len=%d", out.PacketType, len(out.Payload))
	}
}

func TestA2ARecordReorderSafe(t *testing.T) {
	// Reassembly must not depend on answer order: shuffle the A records and the
	// index byte must still restore the original frame.
	frame := []byte("reorder-me-0123456789")
	records, ok := encodeFrameToARecords(frame)
	if !ok {
		t.Fatalf("encodeFrameToARecords failed")
	}

	// Build ResourceRecords in reversed order.
	answers := make([]ResourceRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		answers = append(answers, ResourceRecord{Type: Enums.DNS_RECORD_TYPE_A, RData: records[i]})
	}
	got, ok := decodeARecordFrame(answers)
	if !ok {
		t.Fatalf("decodeARecordFrame failed on reordered records")
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("reordered decode mismatch: got %q want %q", got, frame)
	}
}

func TestA2ARecordDisabledStaysCNAME(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)
	in := VpnProto.Packet{PacketType: Enums.PACKET_PONG, Payload: []byte("hi")}

	// allowARecord = false -> small A query still answered with CNAME.
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("answer type = %s, want CNAME (A-record disabled)", Enums.DNSRecordTypeName(got))
	}
}

func TestA2ARecordOversizedFallsBack(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)
	// Exceeds the A-record channel (766 bytes) and a single CNAME -> TXT.
	in := VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_DATA,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        bytes.Repeat([]byte("y"), 1000),
	}
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("oversized answer type = %s, want TXT fallback", Enums.DNSRecordTypeName(got))
	}
	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if len(out.Payload) != 1000 {
		t.Fatalf("fallback payload len = %d, want 1000", len(out.Payload))
	}
}
