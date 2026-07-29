package client

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

const resolverRuntimeStateSampleLimit = 4096

type connectedScannerProgress struct {
	mu          sync.Mutex
	total       int
	completed   int
	valid       int
	rejected    int
	validSample []string
	lastLogAt   time.Time
}

type resolverRuntimeListSnapshot struct {
	Sample   []string
	Count    int
	Complete bool
}

func (c *Client) runConnectedResolverScan(ctx context.Context) error {
	if c == nil || c.scannerInputPath == "" {
		return nil
	}
	resolvers, _, err := config.LoadClientResolvers(c.scannerInputPath)
	if err != nil {
		return err
	}
	connections := c.buildScannerConnections(resolvers)
	c.logConnectedScannerStarted(len(connections))
	if len(connections) == 0 {
		c.logConnectedScannerState(0, 0, 0, 0, nil)
		return nil
	}

	c.resetScannerReportSeen()
	c.scannerReportActive.Store(true)
	defer c.scannerReportActive.Store(false)

	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.EffectiveMTUTestParallelism()), len(connections))
	progress := &connectedScannerProgress{total: len(connections)}
	counters := &mtuScanCounters{}
	c.logMTUStart(workerCount)
	c.prepareMTUSuccessOutputFile()
	c.logConnectedScannerState(len(connections), 0, 0, 0, nil)

	jobs := make(chan int, len(connections))
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
				conn := &connections[idx]
				c.scannerRunConnectionMTUTest(ctx, conn, idx+1, len(connections), uploadCaps[conn.Domain], counters)
				progress.record(c, *conn)
			}
		}()
	}
	for idx := range connections {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			progress.log(c, true)
			return nil
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
	progress.log(c, true)
	return nil
}

func (c *Client) buildScannerConnections(resolvers []config.ResolverAddress) []Connection {
	if c == nil || len(resolvers) == 0 || len(c.cfg.Domains) == 0 {
		return nil
	}
	total := len(c.cfg.Domains) * len(resolvers)
	connections := make([]Connection, 0, total)
	seen := make(map[string]struct{}, total)
	for _, domain := range c.cfg.Domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
			})
		}
	}
	return connections
}

func (c *Client) scannerRunConnectionMTUTest(ctx context.Context, conn *Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if c == nil || conn == nil || conn.Key == "" {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			conn.IsValid = false
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>",
					recovered,
					conn.ResolverLabel,
				)
			}
			if counters != nil {
				completed := counters.completed.Add(1)
				rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
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

	result, reason := c.runMTUProbe(ctx, *conn, maxUploadPayload)
	if counters == nil {
		return
	}
	decision := buildMTUDecision(result, reason)
	conn.UploadMTUBytes = decision.uploadBytes
	conn.UploadMTUChars = decision.uploadChars
	conn.DownloadMTUBytes = decision.downloadBytes
	conn.MTUResolveTime = decision.resolveTime
	conn.IsValid = decision.active

	switch reason {
	case mtuRejectUpload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				decision.rejectValue,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	case mtuRejectDownload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Add(1)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				decision.rejectValue,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		c.logMTUProgress(counters, total)
		return
	}

	completed := counters.completed.Add(1)
	validNow := counters.valid.Add(1)
	rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Load()
	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		c.log.Infof(
			"<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
			completed,
			total,
			conn.Domain,
			conn.ResolverLabel,
			decision.uploadBytes,
			decision.downloadBytes,
			validNow,
			rejectedNow,
		)
	}
	c.recordScannerReportValid(*conn)
	c.appendMTUSuccessLine(conn)
	c.logMTUProgress(counters, total)
}

func (p *connectedScannerProgress) record(c *Client, conn Connection) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.completed++
	if conn.IsValid {
		p.valid++
		if len(p.validSample) < resolverRuntimeStateSampleLimit {
			p.validSample = append(p.validSample, conn.ResolverLabel)
		}
	} else {
		p.rejected++
	}
	shouldLog := p.completed >= p.total || p.lastLogAt.IsZero() || time.Since(p.lastLogAt) >= mtuProgressInterval
	if shouldLog {
		p.lastLogAt = time.Now()
	}
	total, completed, valid, rejected := p.total, p.completed, p.valid, p.rejected
	sample := append([]string(nil), p.validSample...)
	p.mu.Unlock()
	if shouldLog {
		c.logConnectedScannerState(total, completed, valid, rejected, sample)
	}
}

func (p *connectedScannerProgress) log(c *Client, force bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	total, completed, valid, rejected := p.total, p.completed, p.valid, p.rejected
	sample := append([]string(nil), p.validSample...)
	p.mu.Unlock()
	if force {
		c.logConnectedScannerState(total, completed, valid, rejected, sample)
	}
}

func (c *Client) logConnectedScannerState(total int, completed int, valid int, rejected int, validSample []string) {
	if c == nil || c.log == nil {
		return
	}
	pending := total - completed
	if pending < 0 {
		pending = 0
	}
	active := resolverRuntimeListSnapshot{Sample: append([]string(nil), validSample...), Count: valid}
	validList := resolverRuntimeListSnapshot{Sample: append([]string(nil), validSample...), Count: valid}
	finalizeResolverRuntimeSnapshot(&active)
	finalizeResolverRuntimeSnapshot(&validList)
	c.log.Machinef(
		"WD_RESOLVERS total_count=%d active_count=%d active_sample=%s active_complete=%t standby_count=0 standby_sample=- standby_complete=true valid_count=%d valid_sample=%s valid_complete=%t rejected_count=%d pending_count=%d",
		total,
		valid,
		formatResolverRuntimeList(active.Sample),
		active.Complete,
		valid,
		formatResolverRuntimeList(validList.Sample),
		validList.Complete,
		rejected,
		pending,
	)
	c.logConnectionProgress(
		"mtu",
		scannerProgressPercent(total, completed),
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

func (c *Client) logResolverRuntimeState() {
	if c == nil || c.log == nil || c.balancer == nil {
		return
	}
	active, standby, valid, counts := c.resolverRuntimeSnapshot()
	c.log.Machinef(
		"WD_RESOLVERS total_count=%d active_count=%d active_sample=%s active_complete=%t standby_count=%d standby_sample=%s standby_complete=%t valid_count=%d valid_sample=%s valid_complete=%t rejected_count=%d pending_count=%d",
		counts.Total,
		active.Count,
		formatResolverRuntimeList(active.Sample),
		active.Complete,
		standby.Count,
		formatResolverRuntimeList(standby.Sample),
		standby.Complete,
		valid.Count,
		formatResolverRuntimeList(valid.Sample),
		valid.Complete,
		counts.Rejected,
		counts.Pending,
	)
}

func (c *Client) resolverRuntimeSnapshot() (active resolverRuntimeListSnapshot, standby resolverRuntimeListSnapshot, valid resolverRuntimeListSnapshot, counts resolverClassificationCounts) {
	if c == nil || c.balancer == nil {
		return active, standby, valid, counts
	}
	classifications := c.resolverClassificationSnapshot()
	for _, conn := range c.balancer.AllConnections() {
		if conn.Key == "" || strings.TrimSpace(conn.ResolverLabel) == "" {
			continue
		}
		counts.Total++
		classification, ok := classifications[conn.Key]
		if !ok {
			classification = fallbackResolverClassification(conn)
		}
		switch classification {
		case resolverClassificationValid:
			counts.Valid++
			addResolverRuntimeSample(&valid, conn.ResolverLabel)
		case resolverClassificationRejected:
			counts.Rejected++
		default:
			counts.Pending++
		}
		if conn.IsValid {
			addResolverRuntimeSample(&active, conn.ResolverLabel)
		}
	}
	finalizeResolverRuntimeSnapshot(&active)
	finalizeResolverRuntimeSnapshot(&standby)
	finalizeResolverRuntimeSnapshot(&valid)
	return active, standby, valid, counts
}

func (c *Client) logConnectedScannerStarted(total int) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Machinef("WD_SCAN event=started total=%d", total)
}

func scannerProgressPercent(total int, completed int) int {
	if total <= 0 {
		return 80
	}
	return 10 + (70 * completed / total)
}

func (c *Client) runScannerAfterConnectIfNeeded(ctx context.Context) (bool, error) {
	if c == nil || c.scannerInputPath == "" {
		return false, nil
	}
	if c.log != nil {
		c.log.Infof("<green>DNS scanner connected; scanning resolver input file...</green>")
	}
	if err := c.runConnectedResolverScan(ctx); err != nil {
		return true, fmt.Errorf("connected DNS scanner failed: %w", err)
	}
	c.notifySessionCloseBurst(time.Second)
	c.StopAsyncRuntime()
	return true, nil
}

func finalizeResolverRuntimeSnapshot(snapshot *resolverRuntimeListSnapshot) {
	if snapshot == nil {
		return
	}
	sort.Strings(snapshot.Sample)
	snapshot.Complete = snapshot.Count == len(snapshot.Sample)
}

func addResolverRuntimeSample(snapshot *resolverRuntimeListSnapshot, resolver string) {
	snapshot.Count++
	if len(snapshot.Sample) < resolverRuntimeStateSampleLimit {
		snapshot.Sample = append(snapshot.Sample, resolver)
	}
}

func formatResolverRuntimeList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}
