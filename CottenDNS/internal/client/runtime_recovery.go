package client

import (
	"strings"
	"time"
)

const (
	runtimeTransportRecoveryCooldown = 15 * time.Second
	runtimeSessionInitFailureLimit   = 3
	// transportRecoveryEscalateThreshold is how many consecutive recovery requests
	// (with no tunnel response in between) must occur before escalating from a
	// lightweight session restart to a full MTU re-probe. Sized so a persistent
	// failure — roughly a few ping-watchdog windows — escalates, while a transient
	// mobile blip that recovers on the first restart never does.
	transportRecoveryEscalateThreshold = 3
)

// transportCanFallback reports whether the configured mode authorizes moving
// between resolver transports. Explicit udp/tcp choices remain strict.
func (c *Client) transportCanFallback() bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.cfg.ResolverTransport)) {
	case "udp", "tcp":
		return false
	default:
		return true
	}
}

// requestTransportRecovery recovers a tunnel that has stopped getting responses.
//
// A transient loss (a mobile blip, a brief server hiccup) is recovered with a
// lightweight session restart that keeps the measured MTU/resolver state, so
// traffic resumes immediately. Only a *persistent* failure — at least
// transportRecoveryEscalateThreshold consecutive requests with no tunnel response
// in between — escalates to a full transport re-probe, which wipes MTU state and
// re-scans the whole fleet. The heavy path stays rate-limited on top of that. The
// streak is reset by recordTunnelResponse the instant traffic flows again, so
// unrelated blips never accumulate toward an escalation.
func (c *Client) requestTransportRecovery(reason string) {
	if c == nil {
		return
	}
	if c.transportRecoveryStreak.Add(1) < transportRecoveryEscalateThreshold {
		c.requestSessionRestart(reason)
		return
	}
	now := c.now()
	if last := c.lastTransportRecovery.Load(); last != 0 && now.Sub(time.Unix(0, last)) < runtimeTransportRecoveryCooldown {
		c.requestSessionRestart(reason)
		return
	}
	if c.transportRecoveryPending.CompareAndSwap(false, true) {
		c.lastTransportRecovery.Store(now.UnixNano())
		c.transportRecoveryCount.Add(1)
		c.transportRecoveryStreak.Store(0)
		if c.log != nil {
			c.log.Warnf("<yellow>Resolver path recovery armed</yellow> (persistent failure): <cyan>%s</cyan>", reason)
		}
	}
	c.requestSessionRestart(reason)
}

// activatePendingTransportRecovery runs only on the main loop after the async
// runtime has stopped, so resetting MTU state cannot race active send workers.
func (c *Client) activatePendingTransportRecovery() bool {
	if c == nil || !c.transportRecoveryPending.Swap(false) {
		return false
	}
	c.successMTUChecks = false
	c.connectionsHavePreknownMTU = false
	for i := range c.connections {
		c.prepareConnectionMTUScanState(&c.connections[i])
	}
	return true
}
