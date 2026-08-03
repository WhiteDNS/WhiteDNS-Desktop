// ==============================================================================
// CottenDNS
// Tests for client-only, server-transparent DNS query shaping:
//   - random transaction ID
//   - EDNS(0) client cookie
//   - DNS 0x20 mixed-case QNAME
// The guarantee under test is that an UNMODIFIED server still decodes shaped
// queries — i.e. these knobs never require a server redeploy. We prove it by
// reconstructing the tunnel payload the exact way the server does: lowercase the
// parsed QNAME, strip the base domain, remove dots, base32-decode.
// ==============================================================================

package dnsparser

import (
	"bytes"
	"strings"
	"testing"

	basecodec "cottendns-go/internal/basecodec"
	Enums "cottendns-go/internal/enums"
)

const shapingTestDomain = "v.example.com"

// serverStyleDecode mirrors what the server does to recover the payload from a
// tunnel query name (see domainmatcher.normalizeParsedDomain + stripLabelDots
// and basecodec.DecodeLowerBase32String).
func serverStyleDecode(t *testing.T, packet []byte) []byte {
	t.Helper()
	parsed, err := ParseDNSRequestLite(packet)
	if err != nil {
		t.Fatalf("ParseDNSRequestLite: %v", err)
	}
	name := strings.ToLower(strings.TrimSuffix(parsed.FirstQuestion.Name, "."))
	suffix := "." + shapingTestDomain
	if !strings.HasSuffix(name, suffix) {
		t.Fatalf("qname %q does not end with %q", name, suffix)
	}
	labels := strings.ReplaceAll(strings.TrimSuffix(name, suffix), ".", "")
	payload, err := basecodec.DecodeLowerBase32String(labels)
	if err != nil {
		t.Fatalf("DecodeLowerBase32String(%q): %v", labels, err)
	}
	return payload
}

func TestQueryShapingServerTransparentRoundTrip(t *testing.T) {
	original := []byte("the quick brown fox jumps over 13 lazy dogs while dns tunnels")
	encoded := basecodec.EncodeLowerBase32Bytes(original)

	normalized, qname, err := PrepareTunnelDomainQname(shapingTestDomain)
	if err != nil {
		t.Fatalf("PrepareTunnelDomainQname: %v", err)
	}

	cases := []struct {
		name    string
		shaping QueryShaping
	}{
		{"legacy", QueryShaping{EDNSUDPSize: 4096}},
		{"random-id", QueryShaping{EDNSUDPSize: 4096, RandomizeID: true}},
		{"cookie", QueryShaping{EDNSUDPSize: 4096, EDNSCookie: true}},
		{"case", QueryShaping{EDNSUDPSize: 4096, CaseRandomize: true}},
		{"all", QueryShaping{EDNSUDPSize: 1232, RandomizeID: true, EDNSCookie: true, CaseRandomize: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := BuildTunnelQuestionPacketShaped(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, tc.shaping)
			if err != nil {
				t.Fatalf("BuildTunnelQuestionPacketShaped: %v", err)
			}
			if got := serverStyleDecode(t, pkt); !bytes.Equal(got, original) {
				t.Fatalf("payload mismatch: got %q want %q", got, original)
			}
		})
	}
}

// TestQueryShapingCookiePresence verifies the OPT record carries a well-formed
// EDNS COOKIE option when enabled, and none when disabled.
func TestQueryShapingCookiePresence(t *testing.T) {
	normalized, qname, err := PrepareTunnelDomainQname(shapingTestDomain)
	if err != nil {
		t.Fatalf("PrepareTunnelDomainQname: %v", err)
	}
	encoded := basecodec.EncodeLowerBase32Bytes([]byte("payload"))

	withCookie, err := BuildTunnelQuestionPacketShaped(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, QueryShaping{EDNSUDPSize: 4096, EDNSCookie: true})
	if err != nil {
		t.Fatalf("build with cookie: %v", err)
	}
	noCookie, err := BuildTunnelQuestionPacketShaped(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, QueryShaping{EDNSUDPSize: 4096})
	if err != nil {
		t.Fatalf("build without cookie: %v", err)
	}

	// The cookie adds exactly 12 bytes (option-code + option-length + 8-byte
	// cookie) to the OPT record.
	if diff := len(withCookie) - len(noCookie); diff != 12 {
		t.Fatalf("cookie packet size delta = %d, want 12", diff)
	}

	// Both must still parse cleanly as DNS requests with a single additional RR.
	for _, pkt := range [][]byte{withCookie, noCookie} {
		parsed, err := ParseDNSRequestLite(pkt)
		if err != nil {
			t.Fatalf("ParseDNSRequestLite: %v", err)
		}
		if parsed.Header.ARCount != 1 {
			t.Fatalf("ARCount = %d, want 1 (OPT record)", parsed.Header.ARCount)
		}
	}
}

// rawNameHasUpper scans the raw wire QNAME (starting after the 12-byte header)
// for an uppercase ASCII letter, walking wire labels until the root. It inspects
// the packet bytes directly because the parser lowercases names on read.
func rawNameHasUpper(packet []byte) bool {
	pos := dnsHeaderSize
	for pos < len(packet) {
		l := int(packet[pos])
		if l == 0 {
			return false
		}
		pos++
		for i := 0; i < l && pos < len(packet); i, pos = i+1, pos+1 {
			if packet[pos] >= 'A' && packet[pos] <= 'Z' {
				return true
			}
		}
	}
	return false
}

// TestQueryShapingCaseRandomizationMixesCase asserts that 0x20 encoding actually
// varies the case of the encoded labels on the wire (statistically) while
// remaining decodable via the server's lowercase-first path. The parser
// lowercases names on read, so we check the raw packet bytes.
func TestQueryShapingCaseRandomizationMixesCase(t *testing.T) {
	// A long payload makes an all-same-case outcome astronomically unlikely.
	original := bytes.Repeat([]byte("abcdefghij"), 8)
	encoded := basecodec.EncodeLowerBase32Bytes(original)
	normalized, qname, err := PrepareTunnelDomainQname(shapingTestDomain)
	if err != nil {
		t.Fatalf("PrepareTunnelDomainQname: %v", err)
	}

	sawUpper := false
	for attempt := 0; attempt < 5 && !sawUpper; attempt++ {
		pkt, err := BuildTunnelQuestionPacketShaped(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, QueryShaping{EDNSUDPSize: 4096, CaseRandomize: true})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if rawNameHasUpper(pkt) {
			sawUpper = true
		}
		// Regardless of case, it must decode to the original payload.
		if got := serverStyleDecode(t, pkt); !bytes.Equal(got, original) {
			t.Fatalf("payload mismatch under case randomization")
		}
	}
	if !sawUpper {
		t.Fatalf("case randomization never produced an uppercase letter across attempts")
	}

	// The legacy path (no case randomization) must stay all-lowercase.
	legacy, err := BuildTunnelQuestionPacketShaped(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, QueryShaping{EDNSUDPSize: 4096})
	if err != nil {
		t.Fatalf("legacy build: %v", err)
	}
	if rawNameHasUpper(legacy) {
		t.Fatalf("legacy build unexpectedly produced uppercase letters")
	}
}
