// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"encoding/hex"
	"math"
	"testing"
)

func samplePolicy() SessionAcceptClientPolicy {
	return SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: 3,
		MaxSetupDuplicationCount:  5,
		MaxUploadMTU:              200,
		MaxDownloadMTU:            1400,
		MaxRxTxWorkers:            16,
		MinPingAggressiveInterval: 0.20,
		MaxPacketsPerBatch:        8,
		MaxARQWindowSize:          2000,
		MaxARQDataNackMaxGap:      64,
		MinCompressionMinSize:     120,
		MinARQInitialRTOSeconds:   0.25,
	}
}

// The single most important property of this feature: a server that configured
// no ceilings must put exactly the bytes on the wire that it always has. If
// this breaks, every existing deployment changes behaviour on upgrade.
func TestNoPolicyLeavesAcceptPayloadUnchanged(t *testing.T) {
	verify := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	native := EncodeSessionAccept(300, 0x5A, 0x12, verify, SessionAcceptClientPolicy{}, false)
	if len(native) != 8 {
		t.Fatalf("native payload = %d bytes, want the historical 8", len(native))
	}
	if native[0] != 0x01 || native[1] != 0x2C { // 300 big endian
		t.Fatalf("native session ID mis-encoded: % x", native[:2])
	}
	if native[2] != 0x5A || native[3] != 0x12 {
		t.Fatalf("native cookie/compression mis-encoded: % x", native[2:4])
	}

	legacy := EncodeSessionAccept(200, 0x5A, 0x12, verify, SessionAcceptClientPolicy{}, true)
	if len(legacy) != 7 {
		t.Fatalf("legacy payload = %d bytes, want the MasterDNS base of 7", len(legacy))
	}
	if got := hex.EncodeToString(legacy); got != "c85a12deadbeef" {
		t.Fatalf("legacy payload = %s, want the MasterDNS golden c85a12deadbeef", got)
	}
}

// The block must land after the base payload at whichever width the session
// speaks, so both client generations find it where they look for it.
func TestPolicyAppendsAtCorrectOffsetForBothWireFormats(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}
	policy := samplePolicy()

	for _, legacy := range []bool{false, true} {
		payload := EncodeSessionAccept(42, 0x11, 0x22, verify, policy, legacy)

		wantBase := 8
		if legacy {
			wantBase = 7
		}
		if len(payload) != wantBase+SessionAcceptPolicyPayloadSize {
			t.Fatalf("legacy=%v: payload = %d bytes, want %d", legacy, len(payload), wantBase+SessionAcceptPolicyPayloadSize)
		}

		decoded, ok := DecodeSessionAcceptPolicy(payload, legacy)
		if !ok {
			t.Fatalf("legacy=%v: policy not found where the client will look", legacy)
		}
		if decoded.MaxARQWindowSize != policy.MaxARQWindowSize {
			t.Fatalf("legacy=%v: ARQ window = %d, want %d", legacy, decoded.MaxARQWindowSize, policy.MaxARQWindowSize)
		}
		if decoded.MaxPacketsPerBatch != policy.MaxPacketsPerBatch {
			t.Fatalf("legacy=%v: batch = %d, want %d", legacy, decoded.MaxPacketsPerBatch, policy.MaxPacketsPerBatch)
		}

		// A payload read at the wrong width must not be mistaken for a policy.
		if _, wrongOK := DecodeSessionAcceptPolicy(payload[:wantBase], legacy); wrongOK {
			t.Fatalf("legacy=%v: a base-only payload reported a policy", legacy)
		}
	}
}

func TestPolicyRoundTripsEveryField(t *testing.T) {
	policy := samplePolicy()
	block := EncodeSessionAcceptClientPolicy(policy)

	decoded, err := DecodeSessionAcceptClientPolicy(block[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.MaxPacketDuplicationCount != policy.MaxPacketDuplicationCount ||
		decoded.MaxSetupDuplicationCount != policy.MaxSetupDuplicationCount {
		t.Fatalf("duplication nibbles: got %+v", decoded)
	}
	if decoded.MaxUploadMTU != policy.MaxUploadMTU || decoded.MaxDownloadMTU != policy.MaxDownloadMTU {
		t.Fatalf("MTU: got up=%d down=%d", decoded.MaxUploadMTU, decoded.MaxDownloadMTU)
	}
	if decoded.MaxRxTxWorkers != policy.MaxRxTxWorkers ||
		decoded.MaxPacketsPerBatch != policy.MaxPacketsPerBatch ||
		decoded.MaxARQWindowSize != policy.MaxARQWindowSize ||
		decoded.MaxARQDataNackMaxGap != policy.MaxARQDataNackMaxGap ||
		decoded.MinCompressionMinSize != policy.MinCompressionMinSize {
		t.Fatalf("integer fields: got %+v", decoded)
	}

	// The two sub-second fields are quantised into one byte, so they come back
	// close rather than exact. The step is (1.00-0.05)/255 ≈ 0.0037s.
	const tolerance = 0.005
	if math.Abs(decoded.MinPingAggressiveInterval-policy.MinPingAggressiveInterval) > tolerance {
		t.Fatalf("ping interval = %v, want ~%v", decoded.MinPingAggressiveInterval, policy.MinPingAggressiveInterval)
	}
	if math.Abs(decoded.MinARQInitialRTOSeconds-policy.MinARQInitialRTOSeconds) > tolerance {
		t.Fatalf("initial RTO = %v, want ~%v", decoded.MinARQInitialRTOSeconds, policy.MinARQInitialRTOSeconds)
	}
}

// The scaled byte is shared with MasterDnsVPN, so its endpoints must match
// theirs exactly or the two sides would disagree on what a byte means.
func TestScaledByteMatchesMasterDNSRange(t *testing.T) {
	if got := EncodeSessionScaledByte(0.05); got != 0 {
		t.Fatalf("0.05s encoded as %d, want 0", got)
	}
	if got := EncodeSessionScaledByte(1.0); got != 255 {
		t.Fatalf("1.00s encoded as %d, want 255", got)
	}
	// Out-of-range values clamp rather than wrap.
	if got := EncodeSessionScaledByte(0.0); got != 0 {
		t.Fatalf("below-range encoded as %d, want 0", got)
	}
	if got := EncodeSessionScaledByte(50.0); got != 255 {
		t.Fatalf("above-range encoded as %d, want 255", got)
	}
	if got := DecodeSessionScaledByte(0); math.Abs(got-0.05) > 1e-9 {
		t.Fatalf("byte 0 decoded as %v, want 0.05", got)
	}
	if got := DecodeSessionScaledByte(255); math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("byte 255 decoded as %v, want 1.0", got)
	}
}

// A truncated block must read as "no policy stated" rather than as a set of
// zero ceilings, which a client would clamp itself to death against.
func TestTruncatedPolicyIsTreatedAsAbsent(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}
	payload := EncodeSessionAccept(42, 0x11, 0x22, verify, samplePolicy(), false)

	for cut := 1; cut <= SessionAcceptPolicyPayloadSize; cut++ {
		truncated := payload[:len(payload)-cut]
		if _, ok := DecodeSessionAcceptPolicy(truncated, false); ok {
			t.Fatalf("a payload short by %d bytes reported a usable policy", cut)
		}
	}
}
