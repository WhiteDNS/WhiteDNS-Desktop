package client

import (
	"context"
	"os"
	"strings"
	"time"
)

const (
	mtuScanControlEnv     = "WHITEDNS_MTU_SCAN_CONTROL_FILE"
	fullInitialMTUScanEnv = "WHITEDNS_FULL_INITIAL_MTU_SCAN"
	skipInitialMTUScanEnv = "WHITEDNS_SKIP_INITIAL_MTU_SCAN"
)

func whitednsBoolEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (c *Client) mtuScanPaused() bool {
	if c == nil || strings.TrimSpace(c.mtuScanControlFile) == "" {
		return false
	}
	raw, err := os.ReadFile(c.mtuScanControlFile)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(string(raw))) {
	case "pause", "paused", "stop", "stopped":
		return true
	default:
		return false
	}
}

func (c *Client) waitIfMTUScanPaused(ctx context.Context) bool {
	loggedPaused := false
	for c.mtuScanPaused() {
		if !loggedPaused {
			loggedPaused = true
			if c.log != nil {
				c.log.Machinef("WD_MTU_SCAN paused=true")
				c.log.Infof("<yellow>Resolver MTU scanning paused</yellow>")
			}
		}
		if ctx == nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
	if loggedPaused && c.log != nil {
		c.log.Machinef("WD_MTU_SCAN paused=false")
		c.log.Infof("<green>Resolver MTU scanning resumed</green>")
	}
	return ctx == nil || ctx.Err() == nil
}
