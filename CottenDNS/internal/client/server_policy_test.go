// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"testing"
	"time"

	"cottendns-go/internal/config"
	VpnProto "cottendns-go/internal/vpnproto"
)

func policyTestClient(cfg config.ClientConfig) *Client {
	return &Client{cfg: cfg}
}

// With no policy from the server, every governed value must be exactly what the
// operator configured. This is the path every existing deployment takes.
func TestNoServerPolicyLeavesConfiguredValuesAlone(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:                 4096,
		MaxPacketsPerBatch:            32,
		CompressionMinSize:            40,
		PingAggressiveIntervalSeconds: 0.08,
	})

	if got := c.effectiveARQWindowSize(); got != 4096 {
		t.Fatalf("ARQ window = %d, want the configured 4096", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 32 {
		t.Fatalf("batch = %d, want the configured 32", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 40 {
		t.Fatalf("compression min = %d, want the configured 40", got)
	}
	if got := c.effectivePingAggressiveInterval(); got != c.cfg.PingAggressiveInterval() {
		t.Fatalf("ping interval = %v, want the configured %v", got, c.cfg.PingAggressiveInterval())
	}
}

// A client asking for more than the server allows must be clamped down, and one
// asking for less than a server floor must be raised up.
func TestServerPolicyClampsGreedyClient(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:                 8000,
		MaxPacketsPerBatch:            64,
		CompressionMinSize:            10,
		PingAggressiveIntervalSeconds: 0.05,
	})

	policy := VpnProto.SessionAcceptClientPolicy{
		MaxARQWindowSize:          2000,
		MaxPacketsPerBatch:        8,
		MinCompressionMinSize:     120,
		MinPingAggressiveInterval: 0.20,
	}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 2000 {
		t.Fatalf("ARQ window = %d, want it clamped to the server's 2000", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 8 {
		t.Fatalf("batch = %d, want it clamped to the server's 8", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 120 {
		t.Fatalf("compression min = %d, want it raised to the server's 120", got)
	}
	want := time.Duration(0.20 * float64(time.Second))
	if got := c.effectivePingAggressiveInterval(); got != want {
		t.Fatalf("ping interval = %v, want it raised to the server's %v", got, want)
	}
}

// A modest client must not be inflated up to the server's ceiling: the policy
// states a limit, not a target.
func TestServerPolicyDoesNotRaiseModestClient(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:      256,
		MaxPacketsPerBatch: 4,
	})

	policy := VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 2000, MaxPacketsPerBatch: 8}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 256 {
		t.Fatalf("ARQ window = %d, want the client's own smaller 256", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 4 {
		t.Fatalf("batch = %d, want the client's own smaller 4", got)
	}
}

// A server that sets only some fields leaves the rest unstated. Unstated must
// mean "no limit", never "limit of zero" -- otherwise setting one field would
// silently zero out everything else and strangle the client.
func TestUnstatedPolicyFieldsAreNotTreatedAsZeroLimits(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:      4096,
		MaxPacketsPerBatch: 32,
		CompressionMinSize: 40,
	})

	// Only the ARQ window is stated.
	policy := VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 1000}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 1000 {
		t.Fatalf("ARQ window = %d, want the stated 1000", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 32 {
		t.Fatalf("batch = %d, want the configured 32 to survive an unstated ceiling", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 40 {
		t.Fatalf("compression min = %d, want the configured 40 to survive an unstated floor", got)
	}
}

// Config sizes the NACK gap against the configured window (gap <= window/4). A
// server ceiling shrinks the effective window, so without a re-clamp the gap
// could end up as wide as the whole window -- making the client NACK far more
// aggressively than it was tuned to, aimed at the server that just asked it to
// use less. The invariant must hold against the effective window.
func TestARQNackGapStaysProportionalToClampedWindow(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:        8000,
		ARQDataNackMaxGap:    2000, // a quarter of the configured window
		ARQMaxRTOSeconds:     8.0,
		ARQInitialRTOSeconds: 0.2,
	})

	policy := VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 2000}
	c.serverPolicy.Store(&policy)

	window := c.effectiveARQWindowSize()
	if window != 2000 {
		t.Fatalf("window = %d, want the clamped 2000", window)
	}
	if gap := c.effectiveARQDataNackMaxGap(); gap > window/4 {
		t.Fatalf("NACK gap %d exceeds a quarter of the effective window %d", gap, window)
	}
}

// The policy's own NACK-gap ceiling must be honoured too.
func TestARQNackGapHonoursServerCeiling(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:     8000,
		ARQDataNackMaxGap: 2000,
	})

	policy := VpnProto.SessionAcceptClientPolicy{MaxARQDataNackMaxGap: 64}
	c.serverPolicy.Store(&policy)

	if gap := c.effectiveARQDataNackMaxGap(); gap != 64 {
		t.Fatalf("NACK gap = %d, want the server's 64", gap)
	}
}

// ARQ_MAX_RTO_SECONDS may sit below one second while the policy floor reaches
// one second. The floor must never start a stream already past its own backoff
// ceiling.
func TestARQInitialRTONeverExceedsMaxRTO(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQInitialRTOSeconds: 0.1,
		ARQMaxRTOSeconds:     0.5,
	})

	policy := VpnProto.SessionAcceptClientPolicy{MinARQInitialRTOSeconds: 1.0}
	c.serverPolicy.Store(&policy)

	rto := c.effectiveARQInitialRTO()
	if rto > c.cfg.ARQMaxRTOSeconds {
		t.Fatalf("initial RTO %v exceeds max RTO %v", rto, c.cfg.ARQMaxRTOSeconds)
	}
}

// Without a policy the ARQ values must be exactly what was configured, so an
// unconfigured server leaves ARQ tuning untouched.
func TestARQValuesUnchangedWithoutPolicy(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:        2000,
		ARQDataNackMaxGap:    500,
		ARQInitialRTOSeconds: 0.2,
		ARQMaxRTOSeconds:     8.0,
	})

	if got := c.effectiveARQDataNackMaxGap(); got != 500 {
		t.Fatalf("NACK gap = %d, want the configured 500", got)
	}
	if got := c.effectiveARQInitialRTO(); got != 0.2 {
		t.Fatalf("initial RTO = %v, want the configured 0.2", got)
	}
}

// Sessions are re-established over a client's lifetime. If an operator removes
// the ceilings and restarts, the next accept carries no policy and the client
// must actually become unclamped again -- keeping the last one would leave it
// throttled forever against a server that no longer asks for it.
func TestPolicyIsClearedWhenServerStopsAdvertisingIt(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}
	c := policyTestClient(config.ClientConfig{ARQWindowSize: 4096})

	withPolicy := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify,
		VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 512}, false)
	c.applyServerClientPolicy(withPolicy)
	if got := c.effectiveARQWindowSize(); got != 512 {
		t.Fatalf("ARQ window = %d, want the advertised 512", got)
	}

	// Server restarts without ceilings; the client re-inits.
	bare := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
	c.applyServerClientPolicy(bare)

	if got := c.effectiveARQWindowSize(); got != 4096 {
		t.Fatalf("ARQ window = %d, want the configured 4096 back once the policy was withdrawn", got)
	}
	if c.serverPolicySnapshot() != nil {
		t.Fatal("a withdrawn policy is still being held")
	}
}

// The two sub-second fields cannot encode "unset": byte 0 decodes to 0.05, not
// to zero. That is only harmless because config clamps both corresponding knobs
// to a minimum of exactly 0.05, so the implied floor can never bind. Pin that
// relationship -- if either clamp is ever loosened below 0.05, setting any
// single unrelated ceiling would start silently raising these two.
func TestScaledPolicyFloorsCannotBindADefaultClient(t *testing.T) {
	// A server that configured only an unrelated ceiling.
	block := VpnProto.EncodeSessionAcceptClientPolicy(VpnProto.SessionAcceptClientPolicy{
		MaxARQWindowSize: 2000,
	})
	decoded, err := VpnProto.DecodeSessionAcceptClientPolicy(block[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Both scaled fields come back as the range minimum rather than zero.
	if decoded.MinPingAggressiveInterval > 0.05 {
		t.Fatalf("implied ping floor %v exceeds the config minimum 0.05", decoded.MinPingAggressiveInterval)
	}
	if decoded.MinARQInitialRTOSeconds > 0.05 {
		t.Fatalf("implied RTO floor %v exceeds the config minimum 0.05", decoded.MinARQInitialRTOSeconds)
	}

	// A client at the config minimum must therefore be left exactly alone.
	cfg := config.ClientConfig{PingAggressiveIntervalSeconds: 0.05, ARQInitialRTOSeconds: 0.05, ARQMaxRTOSeconds: 8.0}
	c := policyTestClient(cfg)
	c.serverPolicy.Store(&decoded)

	if got := c.effectivePingAggressiveInterval(); got != cfg.PingAggressiveInterval() {
		t.Fatalf("ping interval = %v, want the configured %v", got, cfg.PingAggressiveInterval())
	}
	if got := c.effectiveARQInitialRTO(); got != 0.05 {
		t.Fatalf("initial RTO = %v, want the configured 0.05", got)
	}
}

// maxPackedBlocks is derived from the batch size during MTU probing, which
// happens before SESSION_INIT is sent. Storing the policy afterwards is not
// enough: unless the derived value is recomputed, the server's batch ceiling is
// accepted and then silently ignored for the whole session.
func TestBatchCeilingReachesDerivedMaxPackedBlocks(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}

	c := policyTestClient(config.ClientConfig{MaxPacketsPerBatch: 32})
	c.syncedUploadMTU = 1200
	// Stand in for the MTU-probe stage, which runs before any policy exists.
	c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, c.cfg.MaxPacketsPerBatch)
	unclamped := c.maxPackedBlocks

	accept := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify,
		VpnProto.SessionAcceptClientPolicy{MaxPacketsPerBatch: 2}, false)
	c.applyServerClientPolicy(accept)

	if c.effectiveMaxPacketsPerBatch() != 2 {
		t.Fatalf("effective batch = %d, want the server's 2", c.effectiveMaxPacketsPerBatch())
	}
	want := VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, 2)
	if c.maxPackedBlocks != want {
		t.Fatalf("maxPackedBlocks = %d, want %d recomputed under the ceiling (was %d)", c.maxPackedBlocks, want, unclamped)
	}
}

// Withdrawing a policy must likewise restore the derived value, not leave the
// client pinned to the clamped batch size forever.
func TestWithdrawnPolicyRestoresDerivedMaxPackedBlocks(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}

	c := policyTestClient(config.ClientConfig{MaxPacketsPerBatch: 32})
	c.syncedUploadMTU = 1200

	clamped := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify,
		VpnProto.SessionAcceptClientPolicy{MaxPacketsPerBatch: 2}, false)
	c.applyServerClientPolicy(clamped)

	bare := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
	c.applyServerClientPolicy(bare)

	want := VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, 32)
	if c.maxPackedBlocks != want {
		t.Fatalf("maxPackedBlocks = %d, want the unclamped %d after the policy was withdrawn", c.maxPackedBlocks, want)
	}
}

// The end-to-end client path: a real accept payload carrying a policy must be
// picked up, and one without a policy must leave the client unconstrained.
func TestApplyServerClientPolicyFromAcceptPayload(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}

	withPolicy := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{
		MaxARQWindowSize: 512,
	}, false)

	c := policyTestClient(config.ClientConfig{ARQWindowSize: 4096})
	c.applyServerClientPolicy(withPolicy)
	if got := c.effectiveARQWindowSize(); got != 512 {
		t.Fatalf("ARQ window = %d, want the advertised 512", got)
	}

	bare := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
	c2 := policyTestClient(config.ClientConfig{ARQWindowSize: 4096})
	c2.applyServerClientPolicy(bare)
	if got := c2.effectiveARQWindowSize(); got != 4096 {
		t.Fatalf("ARQ window = %d, want the configured 4096 when no policy was sent", got)
	}
}

func TestPolicyClampsAndRestoresMTUAndWorkers(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}
	c := policyTestClient(config.ClientConfig{RX_TX_Workers: 12, MaxPacketsPerBatch: 32})
	c.applySyncedMTUState(200, 1400, 0)

	clamped := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{
		MaxUploadMTU:   120,
		MaxDownloadMTU: 900,
		MaxRxTxWorkers: 4,
	}, false)
	c.applyServerClientPolicy(clamped)
	if c.syncedUploadMTU != 120 || c.syncedDownloadMTU != 900 || c.tunnelRX_TX_Workers != 4 {
		t.Fatalf("clamped state = up %d, down %d, workers %d", c.syncedUploadMTU, c.syncedDownloadMTU, c.tunnelRX_TX_Workers)
	}

	bare := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
	c.applyServerClientPolicy(bare)
	if c.syncedUploadMTU != 200 || c.syncedDownloadMTU != 1400 || c.tunnelRX_TX_Workers != 12 {
		t.Fatalf("restored state = up %d, down %d, workers %d", c.syncedUploadMTU, c.syncedDownloadMTU, c.tunnelRX_TX_Workers)
	}
}

func TestSessionInitAdvertisesMeasuredMTUAfterPolicyClamp(t *testing.T) {
	c := policyTestClient(config.ClientConfig{RX_TX_Workers: 4, MaxPacketsPerBatch: 16})
	c.applySyncedMTUState(200, 1400, 0)
	policy := VpnProto.SessionAcceptClientPolicy{MaxUploadMTU: 120, MaxDownloadMTU: 900}
	c.serverPolicy.Store(&policy)
	c.refreshPolicyDerivedState()
	if c.syncedUploadMTU != 120 || c.syncedDownloadMTU != 900 {
		t.Fatalf("active MTUs were not clamped: up=%d down=%d", c.syncedUploadMTU, c.syncedDownloadMTU)
	}

	payload, _, _, err := c.buildSessionInitPayload()
	if err != nil {
		t.Fatalf("buildSessionInitPayload: %v", err)
	}
	if up := int(binary.BigEndian.Uint16(payload[2:4])); up != 200 {
		t.Fatalf("advertised upload MTU = %d, want measured 200", up)
	}
	if down := int(binary.BigEndian.Uint16(payload[4:6])); down != 1400 {
		t.Fatalf("advertised download MTU = %d, want measured 1400", down)
	}
}
