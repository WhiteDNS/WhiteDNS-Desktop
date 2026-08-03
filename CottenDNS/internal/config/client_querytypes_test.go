// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package config

import (
	"testing"

	Enums "cottendns-go/internal/enums"
)

func TestNormalizeQueryTypesDefaultsToTXT(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"  ", ""}} {
		codes, err := normalizeQueryTypes(in)
		if err != nil {
			t.Fatalf("normalizeQueryTypes(%v) error: %v", in, err)
		}
		if len(codes) != 1 || codes[0] != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("normalizeQueryTypes(%v) = %v, want [TXT]", in, codes)
		}
	}
}

func TestNormalizeQueryTypesParsesAndDedups(t *testing.T) {
	codes, err := normalizeQueryTypes([]string{"txt", "CNAME", "a", "AAAA", "TXT", "cname"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []uint16{
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_A,
		Enums.DNS_RECORD_TYPE_AAAA,
	}
	if len(codes) != len(want) {
		t.Fatalf("got %v, want %v", codes, want)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("index %d: got %d, want %d (full: %v)", i, codes[i], want[i], codes)
		}
	}
}

func TestNormalizeQueryTypesRejectsUnknown(t *testing.T) {
	if _, err := normalizeQueryTypes([]string{"TXT", "BOGUS"}); err == nil {
		t.Fatal("expected error for unknown query type, got nil")
	}
}

func TestDNSRecordTypeFromNameRoundTrips(t *testing.T) {
	for _, name := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "HTTPS", "SRV"} {
		code, ok := Enums.DNSRecordTypeFromName(name)
		if !ok {
			t.Fatalf("DNSRecordTypeFromName(%q) not recognized", name)
		}
		if got := Enums.DNSRecordTypeName(code); got != name {
			t.Fatalf("round-trip %q -> %d -> %q", name, code, got)
		}
	}
	if _, ok := Enums.DNSRecordTypeFromName("nope"); ok {
		t.Fatal("expected unknown name to return ok=false")
	}
}
