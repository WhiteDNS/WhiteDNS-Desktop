// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (mtu_logging.go) handles logging for MTU testing.
// ==============================================================================
package client

import (
	"fmt"
	"strings"
	"time"

	"stormdns-go/internal/logger"
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

func (c *Client) logMTUProbe(isRetry bool, background bool, format string, args ...any) {
	if isRetry || background || !c.mtuDebugEnabled() {
		return
	}
	c.log.Debugf(format, args...)
}

func (c *Client) logConnectionProgress(phase string, percent int, keyValues ...any) {
	if c == nil || c.log == nil || phase == "" {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	var b strings.Builder
	fmt.Fprintf(&b, "WD_PROGRESS phase=%s percent=%d", phase, percent)
	for idx := 0; idx+1 < len(keyValues); idx += 2 {
		key, ok := keyValues[idx].(string)
		if !ok || key == "" {
			continue
		}
		fmt.Fprintf(&b, " %s=%v", key, keyValues[idx+1])
	}
	c.log.Machinef("%s", b.String())
}

func (c *Client) logMTUProgress(counters *mtuScanCounters, total int) {
	if counters == nil || total < 0 {
		return
	}
	completed := int(counters.completed.Load())
	valid := int(counters.valid.Load())
	rejected := int(counters.rejectUpload.Load() + counters.rejectDownload.Load() + counters.rejectSession.Load())
	percent := 10
	if total > 0 {
		percent += (70 * completed) / total
	}
	if !c.shouldLogMTUProgress(completed, total, percent) {
		return
	}
	c.logConnectionProgress(
		"mtu",
		percent,
		"completed",
		completed,
		"total",
		total,
		"valid",
		valid,
		"rejected",
		rejected,
	)
}

func (c *Client) logMTUStart(workerCount int) {
	c.resetMTUProgressThrottle()
	if !c.mtuInfoEnabled() {
		return
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<yellow>Testing MTU sizes for all resolver-domain pairs (parallel=%d)...</yellow>",
		workerCount,
	)
}

func (c *Client) resetMTUProgressThrottle() {
	if c == nil {
		return
	}
	c.mtuProgressLogMu.Lock()
	c.lastMTUProgressPercent = -1
	c.lastMTUProgressAt = time.Time{}
	c.mtuProgressLogMu.Unlock()
}

func (c *Client) shouldLogMTUProgress(completed, total, percent int) bool {
	if c == nil {
		return true
	}
	if completed == 0 || (total > 0 && completed >= total) {
		c.mtuProgressLogMu.Lock()
		c.lastMTUProgressPercent = percent
		c.lastMTUProgressAt = c.now()
		c.mtuProgressLogMu.Unlock()
		return true
	}
	now := c.now()
	c.mtuProgressLogMu.Lock()
	defer c.mtuProgressLogMu.Unlock()
	if c.lastMTUProgressPercent != percent || c.lastMTUProgressAt.IsZero() || now.Sub(c.lastMTUProgressAt) >= mtuProgressInterval {
		c.lastMTUProgressPercent = percent
		c.lastMTUProgressAt = now
		return true
	}
	return false
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
		"%-20s %-15s %-15s %-14s %-30s",
		"Resolver",
		"Upload MTU",
		"Download MTU",
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
			"<cyan>%-20s</cyan> <green>%-15d</green> <green>%-15d</green> <yellow>%-14s</yellow> <blue>%-30s</blue>",
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
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

func formatResolverRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return "n/a"
	}

	if rtt < time.Millisecond {
		return "<1ms"
	}

	return rtt.Round(time.Millisecond).String()
}
