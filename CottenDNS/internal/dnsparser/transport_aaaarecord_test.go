package dnsparser

import (
	"bytes"
	"testing"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestAAAARecordChannelRoundTrips(t *testing.T) {
	query := buildDNSQuery(0x6a6a, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_AAAA, true)
	in := VpnProto.Packet{SessionID: 22, PacketType: Enums.PACKET_PONG, Payload: bytes.Repeat([]byte{0x5a}, 900)}
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false, true)
	if err != nil {
		t.Fatalf("build AAAA response: %v", err)
	}
	parsed, err := ParsePacket(response)
	if err != nil || len(parsed.Answers) == 0 {
		t.Fatalf("parse AAAA response: answers=%d err=%v", len(parsed.Answers), err)
	}
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_AAAA || len(answer.RData) != 16 {
			t.Fatalf("unexpected answer type=%d len=%d", answer.Type, len(answer.RData))
		}
	}
	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("decode AAAA response: %v", err)
	}
	if out.SessionID != in.SessionID || out.PacketType != in.PacketType || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatal("AAAA channel changed tunnel packet")
	}
}

func TestAAAARecordChannelReordersAndCarriesMoreThanA(t *testing.T) {
	frame := bytes.Repeat([]byte{0xa5}, aRecordMaxFrame+500)
	records, ok := encodeFrameToAAAARecords(frame)
	if !ok || len(records) < 2 {
		t.Fatal("AAAA encoder rejected frame larger than A-channel capacity")
	}
	answers := make([]ResourceRecord, len(records))
	for i := range records {
		answers[len(records)-1-i] = ResourceRecord{Type: Enums.DNS_RECORD_TYPE_AAAA, RData: records[i]}
	}
	got, ok := decodeAAAARecordFrame(answers)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatal("AAAA decoder did not restore reordered frame")
	}
}

func TestAAAARecordChannelDisabledUsesFallback(t *testing.T) {
	query := buildDNSQuery(0x7b7b, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_AAAA, true)
	in := VpnProto.Packet{SessionID: 4, PacketType: Enums.PACKET_PONG, Payload: []byte("fallback")}
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(response)
	if err != nil || len(parsed.Answers) == 0 {
		t.Fatalf("parse fallback: %v", err)
	}
	if parsed.Answers[0].Type == Enums.DNS_RECORD_TYPE_AAAA {
		t.Fatal("disabled AAAA channel emitted AAAA payload")
	}
}
