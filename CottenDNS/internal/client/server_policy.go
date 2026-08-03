// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_policy.go — client-side application of the ceilings a server states in
// SESSION_ACCEPT.
//
// The server cannot make a client behave, but it can say what it will tolerate,
// and a cooperating client clamps itself. This matters on a shared public
// server, where one client configured with a huge ARQ window or a very
// aggressive ping interval otherwise takes a disproportionate share.
//
// Why an atomic rather than rewriting c.cfg: the config value is read from
// several goroutines (stream setup builds an ARQ per stream, the send path
// reads the compression threshold, the ping manager reads its interval).
// Mutating it when SESSION_ACCEPT lands -- which happens on the init collector
// goroutine while those readers are already running -- would be a data race.
// Instead the policy is published once through an atomic pointer and the
// governed values are clamped where they are read, so no existing reader
// changes its synchronization.
//
// A server that configures no ceilings sends no policy block, the pointer stays
// nil, and every accessor returns the configured value untouched.
// ==============================================================================

package client

import (
	"time"

	VpnProto "cottendns-go/internal/vpnproto"
)

// applyServerClientPolicy publishes any policy carried by a SESSION_ACCEPT
// payload. Absent or truncated blocks are simply "no ceilings stated"; they are
// not an error, because a policy-less server is the normal case.
func (c *Client) applyServerClientPolicy(payload []byte, legacySessionID ...bool) {
	legacy := false
	if len(legacySessionID) > 0 {
		legacy = legacySessionID[0]
	}
	policy, ok := VpnProto.DecodeSessionAcceptPolicy(payload, legacy)
	if !ok {
		// Clear rather than keep what we had. Sessions are re-established over
		// the client's lifetime, so an operator who removes the ceilings and
		// restarts must actually get them removed -- retaining the last policy
		// would leave the client throttled indefinitely against a server that
		// no longer asks for it.
		c.serverPolicy.Store(nil)
		c.refreshPolicyDerivedState()
		return
	}

	c.serverPolicy.Store(&policy)
	c.refreshPolicyDerivedState()

	if c.log != nil {
		c.log.Debugf(
			"\U0001F4CB <blue>Server Client Policy Applied</blue> <magenta>|</magenta> <blue>ARQ Window Max</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Batch Max</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Ping Interval Min</blue>: <cyan>%.3fs</cyan>",
			policy.MaxARQWindowSize,
			policy.MaxPacketsPerBatch,
			policy.MinPingAggressiveInterval,
		)
	}
}

// refreshPolicyDerivedState recomputes the session state that was derived from
// a governed value before the policy existed.
//
// maxPackedBlocks is the case that matters: it is computed from the batch size
// during MTU probing, which happens before SESSION_INIT is even sent, so
// without this the server's batch ceiling would be stored and then never
// consulted -- the ceiling would silently do nothing for the whole session.
//
// Called from applyServerClientPolicy, which runs on the init collector
// goroutine before sessionReady is set, so this write lands before the send
// path can read it.
func (c *Client) refreshPolicyDerivedState() {
	if c == nil {
		return
	}
	if c.discoveredUploadMTU <= 0 {
		c.discoveredUploadMTU = c.syncedUploadMTU
	}
	if c.discoveredDownloadMTU <= 0 {
		c.discoveredDownloadMTU = c.syncedDownloadMTU
	}
	c.syncedUploadMTU = c.effectivePolicyMTU(c.discoveredUploadMTU, true)
	c.syncedDownloadMTU = c.effectivePolicyMTU(c.discoveredDownloadMTU, false)
	c.tunnelRX_TX_Workers = c.effectiveRxTxWorkers()
	if c.syncedUploadMTU <= 0 {
		return
	}
	c.safeUploadMTU = computeSafeUploadMTU(c.syncedUploadMTU, c.mtuCryptoOverhead)
	c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, c.effectiveMaxPacketsPerBatch())
}

func (c *Client) effectivePolicyMTU(discovered int, upload bool) int {
	if discovered <= 0 {
		return discovered
	}
	policy := c.serverPolicySnapshot()
	if policy == nil {
		return discovered
	}
	ceiling := policy.MaxDownloadMTU
	if upload {
		ceiling = policy.MaxUploadMTU
	}
	return policyMaxInt(discovered, ceiling)
}

func (c *Client) effectiveRxTxWorkers() int {
	workers := c.cfg.RX_TX_Workers
	if workers < 1 {
		workers = 1
	}
	if policy := c.serverPolicySnapshot(); policy != nil {
		workers = policyMaxInt(workers, policy.MaxRxTxWorkers)
	}
	return workers
}

// serverPolicySnapshot returns the active policy, or nil when the server stated
// none.
func (c *Client) serverPolicySnapshot() *VpnProto.SessionAcceptClientPolicy {
	if c == nil {
		return nil
	}
	return c.serverPolicy.Load()
}

// policyMaxInt clamps a configured value down to a server ceiling. A ceiling of
// zero means "unstated", never "forbid everything" -- treating it as a real
// limit would let a server that set only one field silently zero out the rest.
func policyMaxInt(configured, ceiling int) int {
	if ceiling <= 0 || configured <= ceiling {
		return configured
	}
	return ceiling
}

// policyMinInt raises a configured value up to a server floor.
func policyMinInt(configured, floor int) int {
	if floor <= 0 || configured >= floor {
		return configured
	}
	return floor
}

// effectiveARQWindowSize is the ARQ window after any server ceiling. The window
// bounds how much unacknowledged data the server must track per stream, which
// is why a server cares about it.
func (c *Client) effectiveARQWindowSize() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMaxInt(c.cfg.ARQWindowSize, policy.MaxARQWindowSize)
	}
	return c.cfg.ARQWindowSize
}

// effectiveARQDataNackMaxGap is the NACK scan span after any server ceiling,
// and after re-establishing the invariant config enforces at load time: the gap
// stays at or below a quarter of the window.
//
// That re-clamp is the point of this function. Config sizes the gap against the
// *configured* window, so a server ceiling that shrinks the effective window
// would otherwise leave a gap as wide as the whole window. The NACK scan spans
// dataNackMaxGap sequence numbers, so that would make the client NACK far more
// aggressively than it was tuned to -- more control traffic, aimed at the very
// server that just asked it to use less.
func (c *Client) effectiveARQDataNackMaxGap() int {
	gap := c.cfg.ARQDataNackMaxGap
	if policy := c.serverPolicySnapshot(); policy != nil {
		gap = policyMaxInt(gap, policy.MaxARQDataNackMaxGap)
	}

	if window := c.effectiveARQWindowSize(); window > 0 && gap > window/4 {
		gap = window / 4
	}
	return gap
}

// effectiveARQInitialRTO is the initial retransmit timeout after any server
// floor. A floor stops a client retransmitting so eagerly that it multiplies
// the query volume the server sees on a merely slow link.
func (c *Client) effectiveARQInitialRTO() float64 {
	policy := c.serverPolicySnapshot()
	if policy == nil || policy.MinARQInitialRTOSeconds <= 0 {
		return c.cfg.ARQInitialRTOSeconds
	}

	rto := c.cfg.ARQInitialRTOSeconds
	if rto < policy.MinARQInitialRTOSeconds {
		rto = policy.MinARQInitialRTOSeconds
	}

	// Never raise the initial RTO above the backoff ceiling. ARQ_MAX_RTO_SECONDS
	// may legitimately sit below one second, while the policy floor can reach
	// one second, so an unguarded floor could invert the two and start a stream
	// already past its own maximum.
	if c.cfg.ARQMaxRTOSeconds > 0 && rto > c.cfg.ARQMaxRTOSeconds {
		return c.cfg.ARQMaxRTOSeconds
	}
	return rto
}

// effectiveMaxPacketsPerBatch is the batch size after any server ceiling. The
// server performs the batching work, so it gets a say in the size.
func (c *Client) effectiveMaxPacketsPerBatch() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMaxInt(c.cfg.MaxPacketsPerBatch, policy.MaxPacketsPerBatch)
	}
	return c.cfg.MaxPacketsPerBatch
}

// effectiveCompressionMinSize is the compression threshold after any server
// floor. A floor stops a client from asking the server to compress every tiny
// packet.
func (c *Client) effectiveCompressionMinSize() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMinInt(c.cfg.CompressionMinSize, policy.MinCompressionMinSize)
	}
	return c.cfg.CompressionMinSize
}

// effectivePingAggressiveInterval is the aggressive ping interval after any
// server floor. This is the ceiling on how fast a client may poll, so it is the
// single most direct control a server has over the query rate it receives.
func (c *Client) effectivePingAggressiveInterval() time.Duration {
	configured := c.cfg.PingAggressiveInterval()
	policy := c.serverPolicySnapshot()
	if policy == nil || policy.MinPingAggressiveInterval <= 0 {
		return configured
	}

	floor := time.Duration(policy.MinPingAggressiveInterval * float64(time.Second))
	if configured < floor {
		return floor
	}
	return configured
}
