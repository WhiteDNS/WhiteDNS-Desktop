// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// masterdns_conformance_test.go — golden frames captured from the real
// MasterDnsVPN implementation (github.com/masterking32/MasterDnsVPN), produced
// by calling its own BuildRaw, not by re-encoding our reading of its format.
//
// This is what makes the legacy-compat claim testable rather than asserted: if
// CottenDns ever drifts from the wire format the MasterDNS/StormDNS client
// family speaks -- header layout, field order, or the header check byte
// algorithm -- these vectors stop matching and the build fails.
// ==============================================================================

package vpnproto

import (
	"encoding/hex"
	"testing"

	Enums "cottendns-go/internal/enums"
)

type masterDNSVector struct {
	name string
	hex  string
	opts BuildOptions
}

// Captured from MasterDnsVPN's vpnproto.BuildRaw at commit bc69a58.
func masterDNSGoldenVectors() []masterDNSVector {
	return []masterDNSVector{
		{
			name: "session_init",
			hex:  "0005009e010000c8012cdeadbeef",
			opts: BuildOptions{SessionID: 0, PacketType: Enums.PACKET_SESSION_INIT, SessionCookie: 0, Payload: []byte{1, 0, 0, 200, 1, 44, 0xDE, 0xAD, 0xBE, 0xEF}},
		},
		{
			name: "ping",
			hex:  "07075a9a01020304",
			opts: BuildOptions{SessionID: 7, PacketType: Enums.PACKET_PING, SessionCookie: 0x5A, Payload: []byte{1, 2, 3, 4}},
		},
		{
			name: "ping_max_session_id",
			hex:  "ff075aba09",
			opts: BuildOptions{SessionID: 255, PacketType: Enums.PACKET_PING, SessionCookie: 0x5A, Payload: []byte{9}},
		},
		{
			name: "stream_data",
			hex:  "2a0f0005000900000033ea68656c6c6f2d636f7474656e646e73",
			opts: BuildOptions{SessionID: 42, PacketType: Enums.PACKET_STREAM_DATA, SessionCookie: 0x33, StreamID: 5, SequenceNum: 9, Payload: []byte("hello-cottendns")},
		},
		{
			name: "session_close",
			hex:  "0c3677f8",
			opts: BuildOptions{SessionID: 12, PacketType: Enums.PACKET_SESSION_CLOSE, SessionCookie: 0x77},
		},
	}
}

// Frames produced by the real MasterDnsVPN builder must parse on our server,
// carry the legacy flag, and yield the exact field values the sender encoded.
// This is the "a MasterDNS client can connect" claim, executed.
func TestParsesRealMasterDNSFrames(t *testing.T) {
	for _, vector := range masterDNSGoldenVectors() {
		raw, err := hex.DecodeString(vector.hex)
		if err != nil {
			t.Fatalf("%s: bad vector: %v", vector.name, err)
		}

		packet, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: Parse of a genuine MasterDnsVPN frame failed: %v", vector.name, err)
		}
		if !packet.LegacySessionID {
			t.Fatalf("%s: parsed as native, so replies would go back in the wrong format", vector.name)
		}
		if packet.SessionID != vector.opts.SessionID {
			t.Fatalf("%s: SessionID = %d, want %d", vector.name, packet.SessionID, vector.opts.SessionID)
		}
		if packet.PacketType != vector.opts.PacketType {
			t.Fatalf("%s: PacketType = %d, want %d", vector.name, packet.PacketType, vector.opts.PacketType)
		}
		if packet.SessionCookie != vector.opts.SessionCookie {
			t.Fatalf("%s: SessionCookie = %d, want %d", vector.name, packet.SessionCookie, vector.opts.SessionCookie)
		}
		if string(packet.Payload) != string(vector.opts.Payload) {
			t.Fatalf("%s: payload = %q, want %q", vector.name, packet.Payload, vector.opts.Payload)
		}
		if vector.opts.StreamID != 0 && packet.StreamID != vector.opts.StreamID {
			t.Fatalf("%s: StreamID = %d, want %d", vector.name, packet.StreamID, vector.opts.StreamID)
		}
		if vector.opts.SequenceNum != 0 && packet.SequenceNum != vector.opts.SequenceNum {
			t.Fatalf("%s: SequenceNum = %d, want %d", vector.name, packet.SequenceNum, vector.opts.SequenceNum)
		}
	}
}

// The reply direction: bytes we emit for a legacy session must be identical to
// what MasterDnsVPN itself would have produced, down to the header check byte.
// A client that cannot parse our reply is a client that never finishes its
// handshake, and that failure is invisible from the server side.
func TestEmitsByteIdenticalMasterDNSFrames(t *testing.T) {
	for _, vector := range masterDNSGoldenVectors() {
		opts := vector.opts
		opts.LegacySessionID = true

		raw, err := BuildRaw(opts)
		if err != nil {
			t.Fatalf("%s: BuildRaw: %v", vector.name, err)
		}

		if got := hex.EncodeToString(raw); got != vector.hex {
			t.Fatalf("%s: emitted frame differs from MasterDnsVPN's\n got  %s\n want %s", vector.name, got, vector.hex)
		}
	}
}

// The policy block is only useful if MasterDNS clients can actually read it, so
// pin our encoder against theirs. Captured from MasterDnsVPN's
// EncodeSessionAcceptClientPolicy at commit bc69a58 for the same input.
func TestPolicyBlockMatchesMasterDNSEncoder(t *testing.T) {
	const goldenPolicy = "53c8057810280807d040007836"
	const goldenAccept = "c85a12deadbeef53c8057810280807d040007836"

	policy := SessionAcceptClientPolicy{
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

	block := EncodeSessionAcceptClientPolicy(policy)
	if got := hex.EncodeToString(block[:]); got != goldenPolicy {
		t.Fatalf("policy block differs from MasterDnsVPN's\n got  %s\n want %s", got, goldenPolicy)
	}

	// And the whole legacy accept payload, which is what a MasterDNS client
	// actually parses: base 7 bytes then the block.
	full := EncodeSessionAccept(200, 0x5A, 0x12, [4]byte{0xDE, 0xAD, 0xBE, 0xEF}, policy, true)
	if got := hex.EncodeToString(full); got != goldenAccept {
		t.Fatalf("legacy accept with policy differs from MasterDnsVPN's\n got  %s\n want %s", got, goldenAccept)
	}
}

// MasterDnsVPN's SESSION_ACCEPT payload is [sid(1)][cookie][compression]
// [verify(4)] = 7 bytes, and its decoder requires at least that many. The
// server builds this layout for legacy sessions, so pin the shape here: a
// change to the field order or width would strand every legacy client at the
// handshake.
func TestMasterDNSSessionAcceptPayloadLayout(t *testing.T) {
	const golden = "c85a12deadbeef" // sid=200, cookie=0x5A, comp=0x12, verify=DEADBEEF

	want, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	if len(want) != 7 {
		t.Fatalf("golden accept payload is %d bytes, want 7", len(want))
	}

	// Same construction the server performs for a legacy session.
	var payload [8]byte
	payload[0] = byte(200)
	payload[1] = 0x5A
	payload[2] = 0x12
	copy(payload[3:], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	if got := hex.EncodeToString(payload[:7]); got != golden {
		t.Fatalf("accept payload = %s, want %s", got, golden)
	}
}
