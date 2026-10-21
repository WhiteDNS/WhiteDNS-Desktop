package client

import (
	"cottendns-go/internal/config"
	"fmt"
	"slices"
	"strings"
	"time"
)

const resolverRuntimeStateHeartbeatInterval = 30 * time.Second

func (c *Client) logResolverRuntimeState() {
	if c == nil || c.log == nil {
		return
	}
	active, standby, valid := c.resolverRuntimeSnapshot()
	line := fmt.Sprintf("WD_RESOLVERS active=%s standby=%s valid=%s",
		formatResolverRuntimeList(active), formatResolverRuntimeList(standby), formatResolverRuntimeList(valid))
	if !c.shouldEmitResolverRuntimeState(line, c.now()) {
		return
	}
	c.log.Machinef("%s", line)
}

func (c *Client) shouldEmitResolverRuntimeState(line string, now time.Time) bool {
	if c == nil || line == "" {
		return false
	}
	c.resolverRuntimeLogMu.Lock()
	defer c.resolverRuntimeLogMu.Unlock()
	heartbeat := c.lastResolverRuntimeLogAt.IsZero() ||
		now.Sub(c.lastResolverRuntimeLogAt) >= resolverRuntimeStateHeartbeatInterval
	if line == c.lastResolverRuntimeLog && !heartbeat {
		return false
	}
	c.lastResolverRuntimeLog = line
	c.lastResolverRuntimeLogAt = now
	return true
}

func (c *Client) resolverRuntimeSnapshot() (active, standby, valid []string) {
	if c == nil {
		return nil, nil, nil
	}
	if c.cfg.TunnelMode == config.TunnelCottenMax {
		seenActive, seenValid := make(map[string]bool), make(map[string]bool)
		if engine := c.cottenMax.Load(); engine != nil {
			for _, p := range engine.PathStats() {
				if p.Verified && !seenValid[p.Resolver] {
					seenValid[p.Resolver] = true
					valid = append(valid, p.Resolver)
				}
				if p.Healthy && !seenActive[p.Resolver] {
					seenActive[p.Resolver] = true
					active = append(active, p.Resolver)
				}
			}
		}
		slices.Sort(active)
		slices.Sort(valid)
		return active, nil, valid
	}
	c.mtuStateMu.Lock()
	defer c.mtuStateMu.Unlock()
	// Discovery owns these records under mtuStateMu, while balancer updates
	// validity, MTU and backup fields under its own lock. Snapshot readers need
	// both, in the same order as discovery, even when copying unused fields.
	if c.balancer != nil {
		c.balancer.mu.Lock()
		defer c.balancer.mu.Unlock()
	}
	seenActive := make(map[string]struct{}, len(c.connections))
	seenValid := make(map[string]struct{}, len(c.connections))
	for _, conn := range c.connections {
		if conn.Key == "" || conn.ResolverLabel == "" {
			continue
		}
		if conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 {
			if _, ok := seenValid[conn.ResolverLabel]; !ok {
				seenValid[conn.ResolverLabel] = struct{}{}
				valid = append(valid, conn.ResolverLabel)
			}
		}
		if conn.IsValid {
			if _, ok := seenActive[conn.ResolverLabel]; !ok {
				seenActive[conn.ResolverLabel] = struct{}{}
				active = append(active, conn.ResolverLabel)
			}
		}
	}
	slices.Sort(active)
	slices.Sort(valid)
	return active, nil, valid
}

func formatResolverRuntimeList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}
