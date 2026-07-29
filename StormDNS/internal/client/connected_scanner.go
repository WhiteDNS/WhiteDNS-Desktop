package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"stormdns-go/internal/config"
)

type connectedScannerProgress struct {
	mu          sync.Mutex
	total       int
	completed   int
	valid       int
	rejected    int
	validSample []string
	lastLogAt   time.Time
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
	workerCount := min(max(1, c.cfg.MTUTestParallelism), len(connections))
	progress := &connectedScannerProgress{total: len(connections)}
	counters := &mtuScanCounters{}
	c.logMTUStart(workerCount)
	c.logConnectedScannerState(len(connections), 0, 0, 0, nil)

	jobs := make(chan int, mtuJobBufferSize(workerCount, len(connections)))
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
				c.runConnectionMTUTest(ctx, conn, idx+1, len(connections), uploadCaps[conn.Domain], counters)
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
