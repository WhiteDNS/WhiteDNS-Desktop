// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"

	"cottendns-go/internal/compression"
	"cottendns-go/internal/security"
)

var ErrInvalidCompressedPayload = errors.New("invalid compressed vpn payload")

func PreparePayload(packetType uint8, payload []byte, requestedCompression uint8, minSize int) ([]byte, uint8) {
	requestedCompression = compression.NormalizeAvailableType(requestedCompression)
	if requestedCompression == compression.TypeOff {
		return payload, compression.TypeOff
	}

	if !hasCompressionExtension(packetType) {
		return payload, compression.TypeOff
	}
	if len(payload) == 0 {
		return payload, compression.TypeOff
	}
	return compression.CompressPayload(payload, requestedCompression, minSize)
}

func InflatePayload(packet Packet) (Packet, error) {
	if !packet.HasCompressionType || packet.CompressionType == compression.TypeOff {
		return packet, nil
	}

	payload, ok := compression.TryDecompressPayload(packet.Payload, packet.CompressionType)
	if !ok {
		return Packet{}, ErrInvalidCompressedPayload
	}
	packet.Payload = payload
	return packet, nil
}

func ParseInflatedFromLabels(labels string, codec *security.Codec) (Packet, error) {
	packet, err := ParseFromLabels(labels, codec)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

// ParseInflatedFromLabelsAny decodes the upstream tunnel labels by trying each
// codec, beginning at startIdx and wrapping through the rest, and returns the
// first valid packet together with the index of the codec that succeeded. This
// supports server-side encryption-method auto-detection: the frame is fully
// encrypted, so the method is discovered by trial, with frame-structure
// validation in Parse as the success signal. Callers should pass the
// last-successful index as startIdx so the steady state costs one attempt.
//
// Authenticated (AES-GCM) methods fail cleanly on a wrong key/method; for
// unauthenticated methods (None/XOR/ChaCha20) the header validation in Parse is
// what rejects a wrong-method guess.
func ParseInflatedFromLabelsAny(labels string, codecs []*security.Codec, startIdx int) (Packet, int, error) {
	packet, idx, err := ParseFromLabelsAny(labels, codecs, startIdx)
	if err != nil {
		return Packet{}, idx, err
	}
	packet, err = InflatePayload(packet)
	if err != nil {
		return Packet{}, idx, err
	}
	return packet, idx, nil
}

// ParseInflatedFromLabelsAnyMatching resolves the rare frame that validates as
// both native and legacy by preferring the candidate accepted by match. The
// normal one-layout path returns before calling match, so native traffic pays
// no session lookup and creates no candidate slice; its legacy probe normally
// exits immediately on the alternate packet-type byte. This is intended for
// servers, which can check an ambiguous candidate's session ID, cookie and wire
// format against their active session table. When neither candidate matches it
// preserves ParseInflatedFromLabelsAny's native-first compatibility behavior.
func ParseInflatedFromLabelsAnyMatching(labels string, codecs []*security.Codec, startIdx int, match func(Packet) bool) (Packet, int, error) {
	packet, idx, err := parseFromLabelsAnyMatching(labels, codecs, startIdx, match, true)
	return packet, idx, err
}

// ParseFromLabelsAnyMatching is the non-inflating counterpart used by UDP
// ingress admission. It decrypts and resolves native/legacy header ambiguity
// exactly once, while leaving potentially expensive payload decompression to a
// bounded worker. The returned packet is otherwise fully parsed and safe to
// carry through the ingress queue.
func ParseFromLabelsAnyMatching(labels string, codecs []*security.Codec, startIdx int, match func(Packet) bool) (Packet, int, error) {
	return parseFromLabelsAnyMatching(labels, codecs, startIdx, match, false)
}

func parseFromLabelsAnyMatching(labels string, codecs []*security.Codec, startIdx int, match func(Packet) bool, inflate bool) (Packet, int, error) {
	n := len(codecs)
	if n == 0 {
		return Packet{}, -1, ErrCodecUnavailable
	}
	if startIdx < 0 || startIdx >= n {
		startIdx = 0
	}

	var (
		fallback    Packet
		fallbackIdx = -1
		lastErr     error
	)
	for trial := 0; trial < n; trial++ {
		idx := codecTrialIndex(codecs, startIdx, trial)
		if idx < 0 {
			break
		}
		codec := codecs[idx]
		raw, err := codec.DecodeStringAndDecrypt(labels)
		if err != nil {
			lastErr = err
			continue
		}

		var native, legacy Packet
		nativeOK := false
		legacyOK := false
		if candidate, parseErr := parseWidth(raw, 0, 2); parseErr == nil && plausibleNativeSessionID(candidate) {
			if inflate {
				candidate, parseErr = InflatePayload(candidate)
			}
			if parseErr == nil {
				native, nativeOK = candidate, true
			} else {
				lastErr = parseErr
			}
		} else if parseErr != nil {
			lastErr = parseErr
		}
		if candidate, parseErr := parseWidth(raw, 0, 1); parseErr == nil && candidate.SessionID <= maxLegacySessionID {
			if inflate {
				candidate, parseErr = InflatePayload(candidate)
			}
			if parseErr == nil {
				legacy, legacyOK = candidate, true
			} else {
				lastErr = parseErr
			}
		} else if parseErr != nil && !nativeOK {
			lastErr = parseErr
		}

		switch {
		case nativeOK && !legacyOK:
			// AEAD already proves the decoder. Legacy ciphers do not, so use
			// server session/pre-session semantics before allowing one of them
			// to claim ciphertext that may belong to another legacy method.
			if security.IsAuthenticatedMethod(codec.Method()) || match == nil || match(native) {
				return native, idx, nil
			}
			if fallbackIdx < 0 {
				fallback, fallbackIdx = native, idx
			}
		case legacyOK && !nativeOK:
			if security.IsAuthenticatedMethod(codec.Method()) || match == nil || match(legacy) {
				return legacy, idx, nil
			}
			if fallbackIdx < 0 {
				fallback, fallbackIdx = legacy, idx
			}
		case nativeOK && legacyOK:
			if match != nil {
				if match(native) {
					return native, idx, nil
				}
				if match(legacy) {
					return legacy, idx, nil
				}
			}
			if fallbackIdx < 0 {
				fallback, fallbackIdx = native, idx
			}
		}
	}
	if fallbackIdx >= 0 {
		return fallback, fallbackIdx, nil
	}
	if lastErr == nil {
		lastErr = ErrInvalidEncodedData
	}
	return Packet{}, -1, lastErr
}

// ParseFromLabelsAny performs only decoding, decryption and frame-header
// validation. Ingress admission uses this variant before queueing so hostile
// packets cannot trigger decompression or consume worker-queue memory.
func ParseFromLabelsAny(labels string, codecs []*security.Codec, startIdx int) (Packet, int, error) {
	n := len(codecs)
	if n == 0 {
		return Packet{}, -1, ErrCodecUnavailable
	}
	if startIdx < 0 || startIdx >= n {
		startIdx = 0
	}

	var lastErr error
	for trial := 0; trial < n; trial++ {
		idx := codecTrialIndex(codecs, startIdx, trial)
		if idx < 0 {
			break
		}
		packet, err := ParseFromLabels(labels, codecs[idx])
		if err == nil {
			return packet, idx, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrCodecUnavailable
	}
	return Packet{}, -1, lastErr
}

// codecTrialIndex preserves the preferred codec fast path within each security
// class while always exhausting authenticated codecs before attempting an
// unauthenticated decoder. This matters because XOR/ChaCha20/None cannot prove
// that decrypted bytes came from their method: random ciphertext can
// occasionally resemble a structurally valid frame. AES-GCM candidates do
// authenticate, so they must never be placed behind those ambiguous decoders.
//
// The codec set is tiny (at most the six supported methods), making this
// allocation-free two-phase walk cheaper than constructing a reordered slice
// for every DNS packet.
func codecTrialIndex(codecs []*security.Codec, startIdx, trial int) int {
	n := len(codecs)
	if n == 0 || trial < 0 {
		return -1
	}
	if startIdx < 0 || startIdx >= n {
		startIdx = 0
	}

	seen := 0
	for phase := 0; phase < 2; phase++ {
		wantAuthenticated := phase == 0
		for offset := 0; offset < n; offset++ {
			idx := (startIdx + offset) % n
			codec := codecs[idx]
			if codec == nil || security.IsAuthenticatedMethod(codec.Method()) != wantAuthenticated {
				continue
			}
			if seen == trial {
				return idx
			}
			seen++
		}
	}
	return -1
}

func ParseInflated(data []byte) (Packet, error) {
	packet, err := Parse(data)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

func BuildRawAuto(opts BuildOptions, minSize int) ([]byte, error) {
	payload, compressionType := PreparePayload(opts.PacketType, opts.Payload, opts.CompressionType, minSize)
	opts.Payload = payload
	opts.CompressionType = compressionType
	return BuildRaw(opts)
}

func BuildEncodedAuto(opts BuildOptions, codec *security.Codec, minSize int) (string, error) {
	raw, err := BuildRawAuto(opts, minSize)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncode(raw)
}
