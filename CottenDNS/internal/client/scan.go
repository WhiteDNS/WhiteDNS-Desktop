package client

import (
	"context"
	"cottendns-go/internal/config"
	"errors"
)

type ResolverScanSummary struct {
	Total    int
	Valid    int
	Rejected int
}

// RunResolverScan classifies resolvers without starting listeners or a session.
func (c *Client) RunResolverScan(ctx context.Context) (ResolverScanSummary, error) {
	defer c.closeResolverCacheLog()
	if c.cfg.TunnelMode == config.TunnelCottenMax {
		return c.runCottenMaxResolverScan(ctx)
	}
	summary := ResolverScanSummary{Total: len(c.connections)}
	if summary.Total == 0 {
		c.logResolverScanComplete(summary)
		return summary, nil
	}
	// Scan-only must classify the complete fleet even when the profile normally
	// enables Fast Connect.
	fastConnect := c.cfg.FastConnect
	c.cfg.FastConnect = false
	// Emit per-resolver WD_SCAN results as each probe finishes rather than in a
	// post-scan loop, so the UI's Valid/Rejected counters climb during the scan
	// instead of jumping only after every resolver has been tested. The
	// authoritative totals still arrive in the WD_SCAN event=complete line below.
	c.scanTelemetryActive.Store(true)
	if c.log != nil {
		c.log.Machinef("WD_SCAN event=started total=%d", summary.Total)
	}
	err := c.RunInitialMTUTests(ctx)
	c.scanTelemetryActive.Store(false)
	c.cfg.FastConnect = fastConnect
	if err != nil && !errors.Is(err, ErrNoValidConnections) {
		return summary, err
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	valid, _, _, _ := summarizeValidMTUConnections(c.connections)
	summary.Valid = len(valid)
	summary.Rejected = summary.Total - summary.Valid
	c.logResolverScanComplete(summary)
	return summary, nil
}

func (c *Client) emitScanTesting(resolver, transport string) {
	if c != nil && c.log != nil && c.scanTelemetryActive.Load() && resolver != "" {
		c.log.Machinef("WD_SCAN event=testing resolver=%s transport=%s", resolver, transport)
	}
}

// emitScanResult reports one resolver's outcome to the UI in real time while a
// -scan-only run is in progress. It is a no-op during a normal tunnel run, so
// the shared MTU probe path stays quiet unless RunResolverScan armed it.
func (c *Client) emitScanResult(resolverLabel string, valid bool) {
	if c == nil || c.log == nil || resolverLabel == "" || !c.scanTelemetryActive.Load() {
		return
	}
	if valid {
		c.log.Machinef("WD_SCAN event=valid resolver=%s", resolverLabel)
	} else {
		c.log.Machinef("WD_SCAN event=rejected resolver=%s", resolverLabel)
	}
	if c.cfg.TunnelMode != config.TunnelCottenMax {
		c.log.Machinef("WD_SCAN event=path resolver=%s transport=%s usable=%t", resolverLabel, c.cfg.ResolverTransport, valid)
	}
}

func (c *Client) logResolverScanComplete(summary ResolverScanSummary) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Machinef("WD_SCAN event=complete total=%d valid=%d rejected=%d",
		summary.Total, summary.Valid, summary.Rejected)
}
