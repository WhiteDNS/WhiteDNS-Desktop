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

// roundTripChannel builds a matching response for the given query type and
// asserts the answer RR type and a byte-exact payload round-trip.
func roundTripChannel(t *testing.T, qType, wantAnswerType uint16, payload []byte) {
	t.Helper()
	query := buildQueryWithType(t, "abc."+cnameTestDomain, qType)
	in := VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_DATA,
		StreamID:       3,
		SequenceNum:    9,
		TotalFragments: 1,
		Payload:        payload,
	}

	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != wantAnswerType {
		t.Fatalf("answer type = %s, want %s", Enums.DNSRecordTypeName(got), Enums.DNSRecordTypeName(wantAnswerType))
	}

	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if out.PacketType != in.PacketType || out.StreamID != in.StreamID || out.SequenceNum != in.SequenceNum {
		t.Fatalf("header round-trip mismatch: got type=%d stream=%d seq=%d", out.PacketType, out.StreamID, out.SequenceNum)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload round-trip: got %q want %q", out.Payload, payload)
	}
}

func TestNULLChannelRoundTrips(t *testing.T) {
	// NULL carries the frame verbatim; even a large payload that would overflow
	// CNAME stays on the NULL channel.
	roundTripChannel(t, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_NULL, bytes.Repeat([]byte("N"), 1200))
}

func TestHTTPSChannelRoundTrips(t *testing.T) {
	roundTripChannel(t, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_HTTPS, []byte("https-svcparam-tunnel-frame"))
}

func TestSVCBChannelRoundTrips(t *testing.T) {
	roundTripChannel(t, Enums.DNS_RECORD_TYPE_SVCB, Enums.DNS_RECORD_TYPE_SVCB, bytes.Repeat([]byte("S"), 900))
}

// TestNewChannelsAreServerAcceptedByDefault proves the server honors these
// channels with no configuration flags: the response RR type always matches the
// query type the client chose.
func TestNewChannelsAreServerAcceptedByDefault(t *testing.T) {
	cases := []struct {
		name   string
		qType  uint16
		expect uint16
	}{
		{"NULL", Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_NULL},
		{"HTTPS", Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_HTTPS},
		{"SVCB", Enums.DNS_RECORD_TYPE_SVCB, Enums.DNS_RECORD_TYPE_SVCB},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !Enums.IsTunnelTransportQueryType(tc.qType) {
				t.Fatalf("%s is not accepted as a tunnel transport query type", tc.name)
			}
			roundTripChannel(t, tc.qType, tc.expect, []byte("default-accept-"+tc.name))
		})
	}
}
