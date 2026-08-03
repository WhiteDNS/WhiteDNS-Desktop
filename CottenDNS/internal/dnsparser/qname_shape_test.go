// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"strings"
	"testing"

	Enums "cottendns-go/internal/enums"
)

func TestShapeQNameLabelLengths_BoundsAndSum(t *testing.T) {
	defer SetQNameLabelLength(63)
	for _, l := range []int{63, 40, 20, 7, 1} {
		SetQNameLabelLength(l)
		for _, n := range []int{1, 50, 63, 64, 100, 200} {
			lengths := shapeQNameLabelLengths(n, uint64(n*7+l))
			sum := 0
			for _, x := range lengths {
				if x < 1 || x > maxDNSLabelLen {
					t.Fatalf("label length %d out of [1,63] (L=%d n=%d)", x, l, n)
				}
				sum += x
			}
			if sum != n {
				t.Fatalf("label lengths sum to %d, want %d (L=%d)", sum, n, l)
			}
			if len(lengths) != qnameLabelCount(n) {
				t.Fatalf("label count %d != qnameLabelCount %d (L=%d n=%d)", len(lengths), qnameLabelCount(n), l, n)
			}
		}
	}
}

// extractQNamePayload parses the question name out of a built query packet,
// strips the base domain, and concatenates the remaining labels — exactly what
// the server does to recover the encoded payload.
func extractQNamePayload(t *testing.T, packet []byte, domain string) string {
	t.Helper()
	name, _, err := parseName(packet, dnsHeaderSize)
	if err != nil {
		t.Fatalf("parseName: %v", err)
	}
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	suffix := "." + strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.HasSuffix(lower, suffix) {
		t.Fatalf("name %q does not end with domain %q", lower, suffix)
	}
	labels := lower[:len(lower)-len(suffix)]
	return strings.ReplaceAll(labels, ".", "")
}

func TestQNameShaping_RoundTripsRegardlessOfLabelLength(t *testing.T) {
	defer SetQNameLabelLength(63)
	const domain = "a.io"

	for _, l := range []int{63, 40, 20, 10} {
		SetQNameLabelLength(l)
		for _, n := range []int{1, 30, 63, 64, 120, 200} {
			enc := make([]byte, n)
			for i := range enc {
				enc[i] = byte('a' + (i % 26))
			}

			pkt, err := BuildTunnelTXTQuestionPacket(domain, enc, Enums.DNS_RECORD_TYPE_TXT, 0)
			if err == ErrInvalidName {
				continue // payload exceeds capacity at this label length — expected
			}
			if err != nil {
				t.Fatalf("BuildTunnelTXTQuestionPacket (L=%d n=%d): %v", l, n, err)
			}

			// The reconstructed payload must match regardless of how it was split.
			if got := extractQNamePayload(t, pkt, domain); got != string(enc) {
				t.Fatalf("round-trip mismatch (L=%d n=%d): got %q want %q", l, n, got, enc)
			}
		}
	}
}

func TestQNameShaping_DefaultIsGreedyMaxLabels(t *testing.T) {
	SetQNameLabelLength(63)
	defer SetQNameLabelLength(63)
	// 130 bytes at L=63 -> [63, 63, 4].
	got := shapeQNameLabelLengths(130, 12345)
	want := []int{63, 63, 4}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
