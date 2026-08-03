// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// session_accept.go — the SESSION_ACCEPT payload, and the optional client
// policy block appended to it.
//
// Without a policy the server has no way to rein in a client that asks for a
// huge ARQ window, an aggressive ping interval, or heavy packet duplication: a
// single misconfigured client can take a disproportionate share of a public
// server. The policy block lets the server state its ceilings once, at
// handshake, and the client clamps itself to them.
//
// Two compatibility properties matter here and both are load-bearing:
//
//   - The block is OPTIONAL. A server with no policy configured appends
//     nothing and the payload is byte-for-byte what shipped before, so no
//     existing deployment changes behaviour by upgrading.
//   - The layout is byte-identical to MasterDnsVPN's, and sits after the base
//     payload at whichever width the session speaks (7 bytes for a legacy
//     one-byte session ID, 8 for a native two-byte one). A MasterDNS client
//     therefore reads a policy from a CottenDns server correctly, and both
//     client generations tolerate a longer payload than they know about.
// ==============================================================================

package vpnproto

import (
	"encoding/binary"
	"errors"
	"math"
)

const (
	// SessionAcceptPolicyPayloadSize is the fixed width of the policy block.
	SessionAcceptPolicyPayloadSize = 13

	// sessionPolicyScaledMin/Max bound the two sub-second fields that are
	// transmitted as a single byte. The range is fixed by the wire format and
	// shared with MasterDnsVPN; changing it would silently reinterpret the
	// values on the other side.
	sessionPolicyScaledMin = 0.05
	sessionPolicyScaledMax = 1.0
)

var ErrSessionAcceptPolicyTooShort = errors.New("session accept policy payload too short")

// SessionAcceptClientPolicy carries the server's ceilings (and two floors) for
// client-side resource use.
//
// Wire layout, relative to the start of the block:
//
//	[0]     lower nibble = max packet duplication, upper nibble = max setup duplication
//	[1]     max upload MTU (uint8)
//	[2:4]   max download MTU (uint16 BE)
//	[4]     max RX/TX workers (uint8)
//	[5]     min ping aggressive interval, scaled 0..255 => 0.05..1.00s
//	[6]     max packets per batch (uint8)
//	[7:9]   max ARQ window size (uint16 BE)
//	[9]     max ARQ data NACK max gap (uint8)
//	[10:12] min compression min-size (uint16 BE)
//	[12]    min ARQ initial RTO, scaled 0..255 => 0.05..1.00s
type SessionAcceptClientPolicy struct {
	MaxPacketDuplicationCount int
	MaxSetupDuplicationCount  int
	MaxUploadMTU              int
	MaxDownloadMTU            int
	MaxRxTxWorkers            int
	MinPingAggressiveInterval float64
	MaxPacketsPerBatch        int
	MaxARQWindowSize          int
	MaxARQDataNackMaxGap      int
	MinCompressionMinSize     int
	MinARQInitialRTOSeconds   float64
}

// IsZero reports that no ceiling was configured. A zero policy is never put on
// the wire: sending one would advertise ceilings of zero, which a client would
// clamp itself to death against.
func (p SessionAcceptClientPolicy) IsZero() bool {
	return p == SessionAcceptClientPolicy{}
}

// SessionAcceptBaseSize is the payload length before any policy block, which
// tracks the session-ID width the session speaks.
func SessionAcceptBaseSize(legacySessionID bool) int {
	return sessionIDWidth(legacySessionID) + 6 // sid + cookie + compression + verify(4)
}

// EncodeSessionAccept builds the SESSION_ACCEPT payload at the width this
// session speaks, appending the policy block only when one is configured.
func EncodeSessionAccept(sessionID uint16, cookie uint8, compressionPair uint8, verifyCode [4]byte, policy SessionAcceptClientPolicy, legacySessionID bool) []byte {
	base := SessionAcceptBaseSize(legacySessionID)
	size := base
	if !policy.IsZero() {
		size += SessionAcceptPolicyPayloadSize
	}

	buf := make([]byte, size)
	sessionIDLen := sessionIDWidth(legacySessionID)
	writeSessionID(buf, sessionID, sessionIDLen)
	buf[sessionIDLen] = cookie
	buf[sessionIDLen+1] = compressionPair
	copy(buf[sessionIDLen+2:], verifyCode[:])

	if !policy.IsZero() {
		block := EncodeSessionAcceptClientPolicy(policy)
		copy(buf[base:], block[:])
	}
	return buf
}

// DecodeSessionAcceptPolicy extracts the policy block from an accept payload,
// reporting false when the server did not send one. A short or absent block is
// not an error: it simply means the server states no ceilings.
func DecodeSessionAcceptPolicy(payload []byte, legacySessionID bool) (SessionAcceptClientPolicy, bool) {
	base := SessionAcceptBaseSize(legacySessionID)
	if len(payload) < base+SessionAcceptPolicyPayloadSize {
		return SessionAcceptClientPolicy{}, false
	}

	policy, err := DecodeSessionAcceptClientPolicy(payload[base : base+SessionAcceptPolicyPayloadSize])
	if err != nil {
		return SessionAcceptClientPolicy{}, false
	}
	return policy, true
}

func EncodeSessionAcceptClientPolicy(policy SessionAcceptClientPolicy) [SessionAcceptPolicyPayloadSize]byte {
	var payload [SessionAcceptPolicyPayloadSize]byte

	payload[0] = byte((clampPolicyInt(policy.MaxSetupDuplicationCount, 0, 15) << 4) |
		clampPolicyInt(policy.MaxPacketDuplicationCount, 0, 15))
	payload[1] = byte(clampPolicyInt(policy.MaxUploadMTU, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[2:4], uint16(clampPolicyInt(policy.MaxDownloadMTU, 0, 0xFFFF)))
	payload[4] = byte(clampPolicyInt(policy.MaxRxTxWorkers, 0, 0xFF))
	payload[5] = EncodeSessionScaledByte(policy.MinPingAggressiveInterval)
	payload[6] = byte(clampPolicyInt(policy.MaxPacketsPerBatch, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[7:9], uint16(clampPolicyInt(policy.MaxARQWindowSize, 0, 0xFFFF)))
	payload[9] = byte(clampPolicyInt(policy.MaxARQDataNackMaxGap, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[10:12], uint16(clampPolicyInt(policy.MinCompressionMinSize, 0, 0xFFFF)))
	payload[12] = EncodeSessionScaledByte(policy.MinARQInitialRTOSeconds)

	return payload
}

func DecodeSessionAcceptClientPolicy(payload []byte) (SessionAcceptClientPolicy, error) {
	if len(payload) < SessionAcceptPolicyPayloadSize {
		return SessionAcceptClientPolicy{}, ErrSessionAcceptPolicyTooShort
	}

	return SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: int(payload[0] & 0x0F),
		MaxSetupDuplicationCount:  int((payload[0] >> 4) & 0x0F),
		MaxUploadMTU:              int(payload[1]),
		MaxDownloadMTU:            int(binary.BigEndian.Uint16(payload[2:4])),
		MaxRxTxWorkers:            int(payload[4]),
		MinPingAggressiveInterval: DecodeSessionScaledByte(payload[5]),
		MaxPacketsPerBatch:        int(payload[6]),
		MaxARQWindowSize:          int(binary.BigEndian.Uint16(payload[7:9])),
		MaxARQDataNackMaxGap:      int(payload[9]),
		MinCompressionMinSize:     int(binary.BigEndian.Uint16(payload[10:12])),
		MinARQInitialRTOSeconds:   DecodeSessionScaledByte(payload[12]),
	}, nil
}

// EncodeSessionScaledByte compresses a sub-second duration into one byte across
// the fixed 0.05..1.00s range.
func EncodeSessionScaledByte(value float64) uint8 {
	clamped := clampPolicyFloat(value, sessionPolicyScaledMin, sessionPolicyScaledMax)
	normalized := (clamped - sessionPolicyScaledMin) / (sessionPolicyScaledMax - sessionPolicyScaledMin)
	return uint8(math.Round(normalized * 255.0))
}

func DecodeSessionScaledByte(value uint8) float64 {
	normalized := float64(value) / 255.0
	return sessionPolicyScaledMin + normalized*(sessionPolicyScaledMax-sessionPolicyScaledMin)
}

func clampPolicyInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampPolicyFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
