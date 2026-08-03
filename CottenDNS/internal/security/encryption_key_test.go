// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package security

import (
	"strings"
	"testing"
)

func TestKeyFingerprintIsStableShortAndNonReversible(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"

	fp := KeyFingerprint(key)
	if len(fp) != 8 {
		t.Fatalf("fingerprint should be 8 hex chars, got %q (len %d)", fp, len(fp))
	}
	// Deterministic for the same key.
	if fp != KeyFingerprint(key) {
		t.Fatal("fingerprint must be stable for the same key")
	}
	// The raw key must never appear inside the fingerprint (no accidental leak).
	if strings.Contains(fp, key) || strings.Contains(key, fp) {
		t.Fatalf("fingerprint %q must not expose the raw key", fp)
	}
	// Different key -> different fingerprint (collisions here would be a red flag).
	if KeyFingerprint("fedcba9876543210fedcba9876543210") == fp {
		t.Fatal("distinct keys should not share a fingerprint")
	}
	// Empty key -> empty fingerprint.
	if KeyFingerprint("") != "" {
		t.Fatal("empty key should yield empty fingerprint")
	}
}
