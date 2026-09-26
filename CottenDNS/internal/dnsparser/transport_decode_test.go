package dnsparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestCNAMECompressedTargetRoundTrips(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		codec, _ := security.NewCodec(3, "response-secret")
		query := buildDNSQuery(4, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_MX, false)
		in := VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_PONG, Payload: []byte("compressed-target")}
		var response []byte
		var err error
		if encrypted {
			response, err = BuildEncryptedVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true, true, codec)
		} else {
			response, err = BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePacket(response)
		if err != nil {
			t.Fatal(err)
		}
		answer := parsed.Answers[0]
		suffix := encodeDNSName(cnameTestDomain)
		if !bytes.HasSuffix(answer.RData, suffix) {
			t.Fatal("CNAME target lacks domain")
		}
		suffixOffset := answer.rdataOffset + len(answer.RData) - len(suffix)
		compressed := append([]byte(nil), response[:suffixOffset]...)
		compressed = append(compressed, 0xc0, dnsHeaderSize+4) // domain after the abc label in the question
		compressed = append(compressed, response[answer.rdataOffset+len(answer.RData):]...)
		binary.BigEndian.PutUint16(compressed[answer.rdataOffset-2:answer.rdataOffset], uint16(len(answer.RData)-len(suffix)+2))
		var out VpnProto.Packet
		if encrypted {
			out, err = ExtractEncryptedVPNResponseMatching(compressed, false, []string{cnameTestDomain}, codec)
		} else {
			out, err = ExtractVPNResponseMatching(compressed, false, []string{cnameTestDomain})
		}
		if err != nil || out.SessionID != in.SessionID || !bytes.Equal(out.Payload, in.Payload) {
			t.Fatalf("encrypted=%v compressed CNAME failed: %v", encrypted, err)
		}
	}
}

func TestTunnelDecodeRejectsErrorOrIncompleteEnvelope(t *testing.T) {
	query := buildDNSQuery(4, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_TXT, false)
	response, err := BuildVPNResponsePacket(query, "abc."+cnameTestDomain, VpnProto.Packet{PacketType: Enums.PACKET_PONG}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []uint16{0x0100, 0x8300, 0x8900, 0x8105} {
		modified := append([]byte(nil), response...)
		binary.BigEndian.PutUint16(modified[2:4], flags)
		if _, err := ExtractVPNResponseMatching(modified, false, []string{cnameTestDomain}); err == nil {
			t.Fatalf("accepted envelope flags %#x", flags)
		}
		if _, err := ExtractVPNResponse(modified, false); err == nil {
			t.Fatalf("TXT-only decoder accepted envelope flags %#x", flags)
		}
	}
}

func TestTunnelDecodeAuthoritativeNoDataAndRefused(t *testing.T) {
	query := buildDNSQuery(4, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A, true)
	parsed, err := ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	nodata, err := BuildAuthoritativeNoDataFromLite(query, parsed, cnameTestDomain)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := BuildRefusedResponseFromLite(query, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range [][]byte{nodata, refused} {
		if _, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain}); !errors.Is(err, ErrTXTAnswerMissing) {
			t.Fatalf("control reply should have no tunnel payload: %v", err)
		}
	}
}
