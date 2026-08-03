// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	"cottendns-go/internal/compression"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
)

// A 32-char shared key works for every method: deriveKey hashes/pads it per
// method, so one key string interoperates across the whole set.
const autoDetectKey = "0123456789abcdef0123456789abcdef"

func TestParseFromLabelsAnyMatchingDefersInflation(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("compressible-native-payload-"), 32)
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:       300,
		PacketType:      Enums.PACKET_STREAM_DATA,
		SessionCookie:   9,
		StreamID:        4,
		SequenceNum:     7,
		CompressionType: compression.TypeZLIB,
		Payload:         payload,
	}, codec, 1)
	if err != nil {
		t.Fatal(err)
	}

	packet, _, err := ParseFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(Packet) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if !packet.HasCompressionType || packet.CompressionType != compression.TypeZLIB {
		t.Fatalf("compression metadata was not preserved: %+v", packet)
	}
	if bytes.Equal(packet.Payload, payload) {
		t.Fatal("admission parser inflated payload on the reader path")
	}
	inflated, err := InflatePayload(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inflated.Payload, payload) {
		t.Fatal("worker inflation did not restore the original payload")
	}
}

// aeadFirstMethods mirrors udpserver.SetCodecSet's trial ordering: authenticated
// (AES-GCM) methods first, then the unauthenticated ones. This is the order the
// server actually decodes with at ingress; the ascending AllMethods order is
// never used there. Ordering the trial set this way is what lets an authenticated
// frame be matched by its authenticating codec before any unauthenticated codec
// is reached.
func aeadFirstMethods(methods []int) []int {
	aead := make([]int, 0, len(methods))
	other := make([]int, 0, len(methods))
	for _, m := range methods {
		if security.IsAuthenticatedMethod(m) {
			aead = append(aead, m)
		} else {
			other = append(other, m)
		}
	}
	return append(aead, other...)
}

// Every method's encoded frame must be decoded by the auto-detect codec set, and
// the detected index must map back to the method that produced it — under the
// same conditions the server decodes with.
//
// The set is ordered AEAD-first exactly as udpserver.SetCodecSet orders it. Start
// indices mirror the server's ingress trial:
//
//   - Authenticated (AES-GCM) frames start cold at index 0. Because every AEAD
//     codec precedes every unauthenticated one, the correct method is found — and
//     authenticates — before any unauthenticated codec is ever tried, so an
//     authenticated frame can never be mis-claimed. This is the security-critical
//     guarantee and it is deterministic.
//   - Unauthenticated (None/XOR/ChaCha20) frames are NOT method-identifiable from
//     ciphertext alone: a wrong-method "decrypt" yields garbage that can
//     occasionally pass structural validation. The server copes by starting each
//     trial at the last-successful codec; this mirrors that steady state by
//     starting at the frame's own codec, whose decode of its own frame is always
//     correct. (Asserting exact detection from a cold start for these methods
//     would be testing something inherently undecidable.)
func TestParseInflatedFromLabelsAnyDetectsEveryMethod(t *testing.T) {
	ordered := aeadFirstMethods(security.AllMethods)
	set, err := security.NewCodecSet(ordered, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodecSet: %v", err)
	}

	payload := []byte("auto-detect-me-please")

	for setIdx, method := range ordered {
		codec, err := security.NewCodec(method, autoDetectKey)
		if err != nil {
			t.Fatalf("NewCodec(%d): %v", method, err)
		}

		labels, err := BuildEncodedAuto(BuildOptions{
			PacketType: Enums.PACKET_PING,
			Payload:    payload,
		}, codec, compression.DefaultMinSize)
		if err != nil {
			t.Fatalf("BuildEncodedAuto(method %d): %v", method, err)
		}

		start := 0
		if !security.IsAuthenticatedMethod(method) {
			start = setIdx
		}
		packet, detectedIdx, err := ParseInflatedFromLabelsAny(labels, set, start)
		if err != nil {
			t.Fatalf("method %d: ParseInflatedFromLabelsAny failed: %v", method, err)
		}
		if detectedIdx != setIdx {
			t.Fatalf("method %d: detected set index %d (method %d), want %d",
				method, detectedIdx, ordered[detectedIdx], setIdx)
		}
		if packet.PacketType != Enums.PACKET_PING {
			t.Fatalf("method %d: packet type = %d, want PING", method, packet.PacketType)
		}
		if !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("method %d: payload mismatch: got %q", method, packet.Payload)
		}
	}
}

func TestParseInflatedFromLabelsAnyPreferredFirstStillWorks(t *testing.T) {
	set, err := security.NewCodecSet(security.AllMethods, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodecSet: %v", err)
	}
	codec, err := security.NewCodec(3, autoDetectKey) // AES-128-GCM
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte("x"),
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	_, idx, err := ParseInflatedFromLabelsAny(labels, set, 3)
	if err != nil || idx != 3 {
		t.Fatalf("preferred-first: idx=%d err=%v, want idx=3", idx, err)
	}
}

func TestCodecTrialOrderNeverPlacesLegacyBeforeAEAD(t *testing.T) {
	set, err := security.NewCodecSet(security.AllMethods, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodecSet: %v", err)
	}

	for _, start := range []int{0, 1, 2, 3, 4, 5} {
		authenticatedDone := false
		authenticatedCount := 0
		for trial := 0; trial < len(set); trial++ {
			idx := codecTrialIndex(set, start, trial)
			if idx < 0 {
				t.Fatalf("start %d trial %d returned no codec", start, trial)
			}
			authenticated := security.IsAuthenticatedMethod(set[idx].Method())
			if !authenticated {
				authenticatedDone = true
				continue
			}
			if authenticatedDone {
				t.Fatalf("start %d put authenticated method %d after a legacy decoder", start, set[idx].Method())
			}
			authenticatedCount++
		}
		if authenticatedCount != 3 {
			t.Fatalf("start %d tried %d authenticated methods, want 3", start, authenticatedCount)
		}
	}
}

func TestParseInflatedFromLabelsAnyEmptySet(t *testing.T) {
	if _, _, err := ParseInflatedFromLabelsAny("abc", nil, 0); err == nil {
		t.Fatal("expected error for empty codec set")
	}
}

func TestMatchingParserKeepsUnambiguousNativeFastPath(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:     300,
		SessionCookie: 0x5A,
		PacketType:    Enums.PACKET_PONG,
		Payload:       []byte("native-fast-path"),
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	matchCalls := 0
	packet, _, err := ParseInflatedFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(Packet) bool {
		matchCalls++
		return false
	})
	if err != nil {
		t.Fatalf("ParseInflatedFromLabelsAnyMatching: %v", err)
	}
	if packet.SessionID != 300 || packet.LegacySessionID || packet.PacketType != Enums.PACKET_PONG {
		t.Fatalf("unexpected native packet: %+v", packet)
	}
	if matchCalls != 0 {
		t.Fatalf("unambiguous native frame performed %d session matches, want zero", matchCalls)
	}
}

func TestMatchingParserResolvesAmbiguousLegacyFrame(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:       16,
		SessionCookie:   6,
		PacketType:      Enums.PACKET_PING,
		Payload:         []byte("PO:test"),
		LegacySessionID: true,
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	packet, _, err := ParseInflatedFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(candidate Packet) bool {
		return candidate.LegacySessionID && candidate.SessionID == 16 && candidate.SessionCookie == 6
	})
	if err != nil {
		t.Fatalf("ParseInflatedFromLabelsAnyMatching: %v", err)
	}
	if !packet.LegacySessionID || packet.SessionID != 16 || packet.PacketType != Enums.PACKET_PING {
		t.Fatalf("unexpected resolved legacy packet: %+v", packet)
	}
}
