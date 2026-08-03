// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (mtu_logging.go) handles logging for MTU testing.
// ==============================================================================
package client

import (
	"fmt"
	"strings"
	"time"

	"cottendns-go/internal/logger"
)

func (c *Client) mtuDebugEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelDebug)
}

func (c *Client) mtuInfoEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelInfo)
}

func (c *Client) mtuWarnEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelWarn)
}

func (c *Client) logConnectionProgress(phase string, percent int, keyValues ...any) {
	if c == nil || c.log == nil || phase == "" {
		return
	}
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}
	var b strings.Builder
	fmt.Fprintf(&b, "WD_PROGRESS phase=%s percent=%d", phase, percent)
	for idx := 0; idx+1 < len(keyValues); idx += 2 {
		key, ok := keyValues[idx].(string)
		if ok && key != "" {
			fmt.Fprintf(&b, " %s=%v", key, keyValues[idx+1])
		}
	}
	c.log.Machinef("%s", b.String())
}

func (c *Client) logMTUProbe(isRetry bool, background bool, format string, args ...any) {
	if isRetry || background || !c.mtuDebugEnabled() {
		return
	}
	c.log.Debugf(format, args...)
}

func (c *Client) logMTUStart(workerCount int) {
	if !c.mtuInfoEnabled() {
		return
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<yellow>Testing MTU sizes for all resolver-domain pairs (parallel=%d)...</yellow>",
		workerCount,
	)
}

func (c *Client) logMTUCompletion(validConns []Connection) {
	if !c.mtuInfoEnabled() {
		return
	}
	maxFoundUpload := 0
	maxFoundDownload := 0
	for _, conn := range validConns {
		if conn.UploadMTUBytes > maxFoundUpload {
			maxFoundUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > maxFoundDownload {
			maxFoundDownload = conn.DownloadMTUBytes
		}
	}

	c.log.Infof("<green>MTU Testing Completed!</green>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof("<cyan>Valid Connections After MTU Testing:</cyan>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"%-20s %-12s %-12s %-10s %-14s %-30s",
		"Resolver",
		"Upload MTU",
		"Download MTU",
		"Loss",
		"Resolve Time",
		"Domain",
	)

	c.log.Infof("%s", strings.Repeat("-", 80))
	for _, conn := range validConns {
		resolveTime := "n/a"
		if conn.MTUResolveTime > 0 {
			resolveTime = formatResolverRTT(conn.MTUResolveTime)
		}

		c.log.Infof(
			"<cyan>%-20s</cyan> <green>%-12d</green> <green>%-12d</green> <yellow>%-10s</yellow> <yellow>%-14s</yellow> <blue>%-30s</blue>",
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			formatMTULoss(conn.UploadMTULoss, conn.DownloadMTULoss),
			resolveTime,
			conn.Domain,
		)
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<blue>Total valid resolvers after MTU testing: <cyan>%d</cyan> of <cyan>%d</cyan></blue>",
		len(validConns),
		len(c.connections),
	)
	uploadDup, downloadDup, uploadSetupDup, downloadSetupDup := c.directionalDuplicationCounts()
	c.log.Infof(
		"<blue>Note:</blue> Duplication counts — upload data: <yellow>%d</yellow>, download ACKs: <yellow>%d</yellow>, upload setup: <yellow>%d</yellow>, download setup/control: <yellow>%d</yellow>.",
		uploadDup,
		downloadDup,
		uploadSetupDup,
		downloadSetupDup,
	)

	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>%d</yellow> | Max Download MTU found: <yellow>%d</yellow>",
		maxFoundUpload,
		maxFoundDownload,
	)
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>%d</yellow> | Selected Synced Download MTU: <yellow>%d</yellow>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<green>Global MTU Configuration -> Upload: <cyan>%d</cyan>, Download: <cyan>%d</cyan></green>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
}

// logSelectedResolvers emits a single, concise summary of the resolvers the
// session actually connected through, at Warn level so it stays visible even
// when LOG_LEVEL is WARN. Without it, a WARN-level run shows only the per-
// resolver rejection lines (also Warn) and never reveals which resolvers won —
// the per-resolver "✅ Accepted" lines and the full completion table are Info.
// Must be called with mtuStateMu already held (it reads c.connections directly).
func (c *Client) logSelectedResolvers() {
	if c == nil || c.log == nil || !c.log.Enabled(logger.LevelWarn) {
		return
	}
	const maxListed = 20
	active := make([]string, 0, len(c.connections))
	reserve := 0
	for i := range c.connections {
		conn := &c.connections[i]
		if !conn.IsValid || conn.ResolverLabel == "" {
			continue
		}
		if conn.Backup {
			reserve++
			continue
		}
		active = append(active, conn.ResolverLabel)
	}
	if len(active) == 0 {
		return
	}
	listed := active
	suffix := ""
	if len(active) > maxListed {
		listed = active[:maxListed]
		suffix = fmt.Sprintf(", …(+%d more)", len(active)-maxListed)
	}
	c.log.Warnf(
		"<green>✅ Connected via <cyan>%d</cyan> active resolver(s)</green> (<yellow>%d</yellow> held in reserve): %s%s",
		len(active),
		reserve,
		strings.Join(listed, ", "),
		suffix,
	)
}

// logMTUOperatingPoint reports the Layer 3 best-group decision: the session MTU
// the client chose to run at, how many resolvers form the active pool, and how
// many slower resolvers were held back as backups (used only if the active pool
// is exhausted).
func (c *Client) logMTUOperatingPoint(uploadMTU, downloadMTU, poolSize, backups int) {
	if !c.mtuInfoEnabled() {
		return
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<green>[ADAPTIVE MTU]</green> Operating point chosen: upload=<cyan>%d</cyan> download=<cyan>%d</cyan> | active pool=<green>%d</green> resolver(s), <yellow>%d</yellow> slower resolver(s) kept as backups (used only if the active pool fails).",
		uploadMTU,
		downloadMTU,
		poolSize,
		backups,
	)
}

// logMTUGroups reports the resolver clusters from clusterConnectionsByMTU and
// marks which tier is the active data pool versus the demoted (slower) tiers, so
// the operator can see at a glance which resolvers passed with the best numbers
// and which passed only at lower MTUs.
func (c *Client) logMTUGroups(groups []mtuGroup) {
	if !c.mtuInfoEnabled() || len(groups) == 0 {
		return
	}

	adaptive := c.cfg.MTUAdaptiveGrouping
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<cyan>[MTU TIERS]</cyan> <yellow>%d</yellow> resolver tier(s) by viable download MTU (best first):",
		len(groups),
	)
	for i, g := range groups {
		// A tier is in the active pool when its (minimum) download MTU is at least
		// the session's applied download MTU; otherwise its members are backups.
		status := "<green>ACTIVE</green>"
		if adaptive && c.syncedDownloadMTU > 0 && g.DownloadMTU < c.syncedDownloadMTU {
			status = "<yellow>backup</yellow>"
		}
		c.log.Infof(
			"  <yellow>Tier %d</yellow> [%s]: download=<green>%d</green> upload=<green>%d</green> avg-loss=<cyan>%.0f%%</cyan> | <cyan>%d</cyan> resolver(s)",
			i+1,
			status,
			g.DownloadMTU,
			g.UploadMTU,
			averageGroupDownloadLoss(g)*100,
			len(g.Members),
		)
		if !c.mtuDebugEnabled() {
			continue
		}
		for _, m := range g.Members {
			c.log.Debugf(
				"      <cyan>%-20s</cyan> up=%d down=%d loss(up/down)=%.0f%%/%.0f%% | <blue>%s</blue>",
				m.ResolverLabel,
				m.UploadMTUBytes,
				m.DownloadMTUBytes,
				m.UploadMTULoss*100,
				m.DownloadMTULoss*100,
				m.Domain,
			)
		}
	}
	if !adaptive {
		c.log.Infof(
			"<blue>Note:</blue> adaptive grouping is disabled (MTU_ADAPTIVE_GROUPING=false); the session runs at the global minimum MTU (upload=<cyan>%d</cyan>, download=<cyan>%d</cyan>).",
			c.syncedUploadMTU,
			c.syncedDownloadMTU,
		)
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
}

func averageGroupDownloadLoss(g mtuGroup) float64 {
	if len(g.Members) == 0 {
		return 0
	}
	var sum float64
	for _, m := range g.Members {
		sum += m.DownloadMTULoss
	}
	return sum / float64(len(g.Members))
}

// formatMTULoss renders the upload/download loss measured at the selected MTU
// edge as "up%/down%". With loss-aware probing disabled both values are 0, which
// reads as "0%/0%" (i.e. the legacy pass/fail result).
func formatMTULoss(uploadLoss, downloadLoss float64) string {
	return fmt.Sprintf("%.0f%%/%.0f%%", uploadLoss*100, downloadLoss*100)
}

func formatResolverRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return "n/a"
	}

	if rtt < time.Millisecond {
		return "<1ms"
	}

	return rtt.Round(time.Millisecond).String()
}
