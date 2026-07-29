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
}

func (c *Client) shouldAdmitNewLocalStream(now time.Time) (bool, string) {
	if c == nil {
		return false, "client unavailable"
	}
	if now.IsZero() {
		now = c.now()
	}
	if !c.SessionReady() {
		return false, "session is not ready"
	}
	if c.balancer == nil || c.balancer.ValidCount() <= 0 {
		return false, "no active resolvers"
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

func (c *Client) activeLocalStreamCount() int {
	if c == nil {
		return 0
	}
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()

	count := 0
	for streamID, stream := range c.active_streams {
		if streamID == 0 || stream == nil {
			continue
		}
		switch stream.StatusValue() {
		case streamStatusCancelled,
			streamStatusDraining,
			streamStatusClosing,
			streamStatusTimeWait,
			streamStatusSocksFailed,
			streamStatusClosed:
			continue
		default:
			count++
		}
	}
	return count
}

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

func (c *Client) streamSetupTTL() time.Duration {
	return c.streamAdmissionNoResponseWindow()
}

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
