package client

import (
	"context"
	"sync"

	"stormdns-go/internal/logger"
)

type ResolverScanSummary struct {
	Total    int
	Valid    int
	Rejected int
}

// RunResolverScan performs a blocking resolver scan and exits without starting
// the local SOCKS, DNS, session, or tunnel runtime.
func (c *Client) RunResolverScan(ctx context.Context) (ResolverScanSummary, error) {
	defer c.closeResolverCacheLog()

	total := len(c.connections)
	summary := ResolverScanSummary{Total: total}
	if total == 0 {
		c.logResolverScanComplete(summary)
		return summary, nil
	}

	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.MTUTestParallelism), total)
	c.logMTUStart(workerCount)
	for idx := range c.connections {
		c.prepareConnectionMTUScanState(&c.connections[idx])
	}
	c.resetResolverClassificationsPending()

	counters := &mtuScanCounters{}
	c.logMTUProgress(counters, total)
	c.runAllResolverScanWorkers(
		ctx,
		uploadCaps,
		workerCount,
		counters,
		c.logResolverScanValid,
		c.logResolverScanRejected,
	)
	if err := ctx.Err(); err != nil {
		return summary, err
	}

	validConns, _, _, _ := summarizeValidMTUConnections(c.connections)
	summary.Valid = len(validConns)
	summary.Rejected = total - summary.Valid

	c.logResolverScanComplete(summary)
	return summary, nil
}

func (c *Client) runAllResolverScanWorkers(
	ctx context.Context,
	uploadCaps map[string]int,
	workerCount int,
	counters *mtuScanCounters,
	onValid func(Connection),
	onRejected func(Connection),
) {
	total := len(c.connections)
	if workerCount <= 1 {
		for idx := range c.connections {
			if ctx.Err() != nil {
				return
			}
			if !c.waitIfMTUScanPaused(ctx) {
				return
			}
			conn := &c.connections[idx]
			c.runConnectionResolverScan(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
			if onValid != nil && conn.IsValid {
				c.markResolverValid(conn.Key)
				onValid(*conn)
			} else if onRejected != nil && !conn.IsValid && ctx.Err() == nil {
				c.markResolverRejected(conn.Key)
				onRejected(*conn)
			} else if conn.IsValid {
				c.markResolverValid(conn.Key)
			} else if ctx.Err() == nil {
				c.markResolverRejected(conn.Key)
			}
		}
		return
	}

	jobs := make(chan int, mtuJobBufferSize(workerCount, total))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				if !c.waitIfMTUScanPaused(ctx) {
					return
				}
				conn := &c.connections[idx]
				c.runConnectionResolverScan(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
				if onValid != nil && conn.IsValid {
					c.markResolverValid(conn.Key)
					onValid(*conn)
				} else if onRejected != nil && !conn.IsValid && ctx.Err() == nil {
					c.markResolverRejected(conn.Key)
					onRejected(*conn)
				} else if conn.IsValid {
					c.markResolverValid(conn.Key)
				} else if ctx.Err() == nil {
					c.markResolverRejected(conn.Key)
				}
			}
		}()
	}
	for idx := range c.connections {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
}

func (c *Client) runConnectionResolverScan(ctx context.Context, conn *Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if conn == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			conn.IsValid = false
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>Resolver Scan Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>",
					recovered,
					conn.ResolverLabel,
				)
			}
			if counters != nil {
				completed := counters.completed.Add(1)
				counters.rejectSession.Add(1)
				rejectedNow := c.totalRejectedMTU(counters)
				if c.log != nil && c.log.Enabled(logger.LevelWarn) {
					c.log.Warnf(
						"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed,
						total,
						conn.Domain,
						conn.ResolverLabel,
						counters.valid.Load(),
						rejectedNow,
					)
				}
				c.logMTUProgress(counters, total)
			}
		}
	}()

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<green>Testing Resolver: <cyan>%s</cyan> for Domain: <cyan>%s</cyan> (<cyan>%d / %d</cyan>)</green>",
			conn.ResolverLabel,
			conn.Domain,
			serverID,
			total,
		)
	}

	probeTransport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		conn.IsValid = false
		if counters == nil {
			return
		}
		completed := counters.completed.Add(1)
		counters.rejectUpload.Add(1)
		rejectedNow := c.totalRejectedMTU(counters)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				0,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	}
	defer probeTransport.conn.Close()

	result, reason := c.probeConnectionMTUWithTransport(ctx, conn, probeTransport, maxUploadPayload)
	if counters == nil {
		return
	}

	switch reason {
	case mtuRejectUpload:
		completed := counters.completed.Add(1)
		counters.rejectUpload.Add(1)
		rejectedNow := c.totalRejectedMTU(counters)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.UploadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	case mtuRejectDownload:
		completed := counters.completed.Add(1)
		counters.rejectDownload.Add(1)
		rejectedNow := c.totalRejectedMTU(counters)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.DownloadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	}

	if !c.verifyResolverSessionInit(ctx, conn, probeTransport, result) {
		conn.IsValid = false
		completed := counters.completed.Add(1)
		counters.rejectSession.Add(1)
		rejectedNow := c.totalRejectedMTU(counters)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>SESSION_INIT</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	}

	c.acceptConnectionMTUProbe(conn, result, counters, total)
}

func (c *Client) logResolverScanValid(conn Connection) {
	if c == nil || c.log == nil || conn.ResolverLabel == "" {
		return
	}
	c.log.Machinef("WD_SCAN event=valid resolver=%s", conn.ResolverLabel)
}

func (c *Client) logResolverScanRejected(conn Connection) {
	if c == nil || c.log == nil || conn.ResolverLabel == "" {
		return
	}
	c.log.Machinef("WD_SCAN event=rejected resolver=%s", conn.ResolverLabel)
}

func (c *Client) logResolverScanComplete(summary ResolverScanSummary) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Machinef(
		"WD_SCAN event=complete total=%d valid=%d rejected=%d",
		summary.Total,
		summary.Valid,
		summary.Rejected,
	)
}
