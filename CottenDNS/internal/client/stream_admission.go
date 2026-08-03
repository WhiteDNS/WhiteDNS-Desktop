// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Local-stream admission control. New local SOCKS/TCP streams are refused fast
// when the tunnel cannot currently carry them — no session, no valid resolvers,
// the active-stream cap is reached, or the tunnel has gone silent (sends with no
// responses past a bounded window). Failing fast lets the client (and the app
// UI) surface a dead tunnel immediately instead of hanging new connections on a
// path that transport recovery may still be repairing.
// ==============================================================================
package client

import (
	"fmt"
	"time"
)

const (
	streamAdmissionMinNoResponseWindow = 3 * time.Second
	streamAdmissionMaxNoResponseWindow = 15 * time.Second
	streamAdmissionRejectLogInterval   = 5 * time.Second
)

// resetTunnelActivity marks the tunnel live as of now. Called when the async
// runtime (re)opens its sockets so a fresh session does not start out looking
// stalled.
func (c *Client) resetTunnelActivity(now time.Time) {
	if c == nil {
		return
	}
	if now.IsZero() {
		now = c.now()
	}
	unixNano := now.UnixNano()
	c.lastTunnelSendUnix.Store(unixNano)
	c.lastTunnelResponseUnix.Store(unixNano)
	c.lastStreamAdmissionRejectLogUnix.Store(0)
}

// clearTunnelActivity zeroes the liveness markers on teardown so a stopped
// tunnel never counts as merely stalled.
func (c *Client) clearTunnelActivity() {
	if c == nil {
		return
	}
	c.lastTunnelSendUnix.Store(0)
	c.lastTunnelResponseUnix.Store(0)
	c.lastStreamAdmissionRejectLogUnix.Store(0)
}

func (c *Client) recordTunnelSend(now time.Time) {
	if c == nil {
		return
	}
	if now.IsZero() {
		now = c.now()
	}
	c.lastTunnelSendUnix.Store(now.UnixNano())
}

func (c *Client) recordTunnelResponse(now time.Time) {
	if c == nil {
		return
	}
	if now.IsZero() {
		now = c.now()
	}
	c.lastTunnelResponseUnix.Store(now.UnixNano())
	// A live tunnel response means the path is healthy again: cancel any
	// in-progress recovery escalation so a later, unrelated blip starts fresh with
	// a lightweight session restart instead of a full re-probe. See
	// requestTransportRecovery.
	if c.transportRecoveryStreak.Load() != 0 {
		c.transportRecoveryStreak.Store(0)
	}
}

// shouldAdmitNewLocalStream reports whether a new local SOCKS/TCP stream should
// be accepted right now, and if not, a short human reason for the log.
//
// It refuses a stream only on the hard concurrency cap or when the tunnel is
// *persistently* dead (sends going unanswered past the stall window). A
// transiently not-ready tunnel — the session re-initializing after a blip, or the
// resolver pool momentarily empty mid-recovery — is NOT refused: the stream is
// created and its SYN waits for the tunnel to return, matching the behavior before
// admission control existed. Refusing on those transient states turned brief
// reconnects into user-visible "connection refused".
func (c *Client) shouldAdmitNewLocalStream(now time.Time) (bool, string) {
	if c == nil {
		return false, "client unavailable"
	}
	if now.IsZero() {
		now = c.now()
	}
	if c.cfg.MaxActiveStreams > 0 {
		activeStreams := c.activeLocalStreamCount()
		if activeStreams >= c.cfg.MaxActiveStreams {
			return false, fmt.Sprintf("active stream limit reached (%d/%d)", activeStreams, c.cfg.MaxActiveStreams)
		}
	}
	if stalled, stalledFor := c.tunnelResponseStalled(now); stalled {
		return false, fmt.Sprintf("no tunnel response for %s", stalledFor.Round(time.Second))
	}
	return true, ""
}

// tunnelResponseStalled reports true only once a send has gone unanswered for
// longer than the admission window — i.e. the tunnel is genuinely silent, not
// merely between packets.
func (c *Client) tunnelResponseStalled(now time.Time) (bool, time.Duration) {
	if c == nil {
		return false, 0
	}
	lastSendUnix := c.lastTunnelSendUnix.Load()
	if lastSendUnix <= 0 {
		return false, 0
	}
	lastResponseUnix := c.lastTunnelResponseUnix.Load()
	if lastResponseUnix >= lastSendUnix {
		return false, 0
	}

	lastSendAt := time.Unix(0, lastSendUnix)
	window := c.streamAdmissionNoResponseWindow()
	if now.Sub(lastSendAt) < window {
		return false, 0
	}

	lastResponseAt := time.Unix(0, lastResponseUnix)
	stalledFor := now.Sub(lastResponseAt)
	if stalledFor < window {
		return false, 0
	}
	return true, stalledFor
}

// streamAdmissionNoResponseWindow scales the stall threshold to the configured
// tunnel packet timeout, clamped to a sane [3s, 15s] range.
func (c *Client) streamAdmissionNoResponseWindow() time.Duration {
	if c == nil {
		return streamAdmissionMaxNoResponseWindow
	}
	window := c.tunnelPacketTimeout
	if window <= 0 {
		window = 8 * time.Second
	}
	if window < streamAdmissionMinNoResponseWindow {
		return streamAdmissionMinNoResponseWindow
	}
	if window > streamAdmissionMaxNoResponseWindow {
		return streamAdmissionMaxNoResponseWindow
	}
	return window
}

// logNewStreamRejected logs an admission rejection, rate-limited so a burst of
// refused connections against a dead tunnel cannot flood the log.
func (c *Client) logNewStreamRejected(reason string) {
	if c == nil || c.log == nil {
		return
	}
	now := c.now()
	nowUnix := now.UnixNano()
	lastUnix := c.lastStreamAdmissionRejectLogUnix.Load()
	if lastUnix > 0 && now.Sub(time.Unix(0, lastUnix)) < streamAdmissionRejectLogInterval {
		return
	}
	if !c.lastStreamAdmissionRejectLogUnix.CompareAndSwap(lastUnix, nowUnix) {
		return
	}
	c.log.Warnf("<yellow>Rejecting new local stream: tunnel unhealthy (%s)</yellow>", reason)
}
