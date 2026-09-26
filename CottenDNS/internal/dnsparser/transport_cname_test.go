// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"bytes"
	"math"
	"testing"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const cnameTestDomain = "a.io"

func buildQueryWithType(t *testing.T, name string, qType uint16) []byte {
	t.Helper()
	q, err := BuildTXTQuestionPacket(name, qType, 0)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket(%q, %d): %v", name, qType, err)
	}
	return q
}

func answerTypeOf(t *testing.T, response []byte) uint16 {
	t.Helper()
	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if len(parsed.Answers) == 0 {
		t.Fatalf("response has no answers")
	}
	return parsed.Answers[0].Type
}

func TestA2NonTXTQueryGetsCNAMEAndRoundTrips(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)

	payload := []byte("hello-cname-tunnel")
	in := VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload,
	}

	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}

	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("answer type = %s, want CNAME (small payload on A query should use CNAME)", Enums.DNSRecordTypeName(got))
	}

	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if out.PacketType != in.PacketType {
		t.Fatalf("packet type round-trip: got %d want %d", out.PacketType, in.PacketType)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload round-trip: got %q want %q", out.Payload, payload)
	}
}

func TestA2TXTQueryStaysTXT(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_TXT)

	in := VpnProto.Packet{PacketType: Enums.PACKET_PONG, Payload: []byte("hi")}
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("TXT query answer type = %s, want TXT", Enums.DNSRecordTypeName(got))
	}

	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if out.PacketType != in.PacketType || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("TXT round-trip mismatch: got type=%d payload=%q", out.PacketType, out.Payload)
	}
}

func TestA2LargePayloadFallsBackToTXT(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)

	// Far larger than a single CNAME name can hold -> must fall back to TXT.
	payload := bytes.Repeat([]byte("x"), 1200)
	in := VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_DATA,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        payload,
	}

	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("large payload answer type = %s, want TXT fallback", Enums.DNSRecordTypeName(got))
	}

	out, err := ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
	if err != nil {
		t.Fatalf("ExtractVPNResponseMatching: %v", err)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("large payload round-trip mismatch: got %d bytes want %d", len(out.Payload), len(payload))
	}
}

func TestA2EmptyAnswerDomainStaysTXT(t *testing.T) {
	query := buildQueryWithType(t, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_A)
	in := VpnProto.Packet{PacketType: Enums.PACKET_PONG, Payload: []byte("hi")}

	// No answer domain -> cannot build a CNAME suffix -> TXT.
	response, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, "", in, false, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacketMatchingQuery: %v", err)
	}
	if got := answerTypeOf(t, response); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("empty answerDomain answer type = %s, want TXT", Enums.DNSRecordTypeName(got))
	}
}

func TestMatchingFrameCapacityMatchesEncoders(t *testing.T) {
	for _, domain := range []string{"v.io", "v.example.com", "tunnel.some-long-domain.example.org"} {
		c := MatchingFrameCapacity(buildDNSQuery(1, "abc."+domain, Enums.DNS_RECORD_TYPE_MX, true), domain, false, false)
		if c < 50 {
			t.Fatalf("%s: implausible CNAME capacity %d", domain, c)
		}
		if _, ok := encodeFrameToCNAMETarget(make([]byte, c), domain); !ok {
			t.Fatalf("%s: frame of capacity %d must fit a CNAME", domain, c)
		}
		if _, ok := encodeFrameToCNAMETarget(make([]byte, c+1), domain); ok {
			t.Fatalf("%s: frame of %d must not fit, capacity is too low", domain, c+1)
		}
	}
	if c := MatchingFrameCapacity(buildDNSQuery(1, "abc.v.io", Enums.DNS_RECORD_TYPE_TXT, false), "v.io", false, false); c != math.MaxInt {
		t.Fatalf("TXT must be unlimited, got %d", c)
	}

	// A records cost 16 wire bytes per 3 frame bytes, so the resolver's UDP size
	// decides the real capacity. Every frame at capacity must build an A answer
	// that fits the advertised size.
	for _, withEDNS := range []bool{false, true} {
		query := buildDNSQuery(1, "abc.v.io", Enums.DNS_RECORD_TYPE_A, withEDNS)
		limit := 512
		if withEDNS {
			limit = 4096
		}
		c := MatchingFrameCapacity(query, "v.io", true, false)
		response, err := BuildVPNResponsePacketMatchingQuery(query, "abc.v.io", "v.io", VpnProto.Packet{
			SessionID: 300, PacketType: Enums.PACKET_PONG, Payload: make([]byte, c-12),
		}, false, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(response) > limit {
			t.Fatalf("edns=%v: A answer of %d bytes exceeds the %d-byte limit", withEDNS, len(response), limit)
		}
		if withEDNS && c < 700 {
			t.Fatalf("EDNS 4096 should allow nearly the full A channel, got %d", c)
		}
	}
}