package client

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"cottendns-go/internal/config"
)

type cottenMaxScanJob struct{ resolver, transport string }
type cottenMaxScanResult struct {
	cottenMaxScanJob
	domain                            string
	valid, authenticated, transferred bool
	nameBytes, answerBytes            int
}

func (c *Client) runCottenMaxResolverScan(ctx context.Context) (ResolverScanSummary, error) {
	var resolvers []string
	seen := make(map[string]bool)
	add := func(raw string) {
		if addr, ok := cottenMaxResolverEndpoint(raw, c.cfg.ResolverIPMode); ok && !seen[addr] {
			seen[addr] = true
			resolvers = append(resolvers, addr)
		}
	}
	for _, r := range c.cfg.Resolvers {
		add(formatResolverEndpoint(r.IP, r.Port))
	}
	if len(resolvers) == 0 && c.cfg.ResolverDiscoveryEnabled {
		for _, r := range c.cottenMaxDiscovery(nil).CandidatesForScan() {
			add(r)
		}
	}
	summary := ResolverScanSummary{Total: len(resolvers)}
	transports := []string{c.cfg.ResolverTransport}
	if c.cfg.ResolverTransport == "auto" || c.cfg.ResolverTransport == "" {
		transports = []string{"udp", "tcp"}
	}
	c.scanTelemetryActive.Store(true)
	defer c.scanTelemetryActive.Store(false)
	if c.log != nil {
		c.log.Machinef("WD_SCAN event=started total=%d", summary.Total)
	}
	workers := min(max(1, c.cfg.MTUTestParallelism), 16)
	jobs := make(chan cottenMaxScanJob)
	results := make(chan cottenMaxScanResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				result := c.probeCottenMaxScanPath(ctx, job)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, r := range resolvers {
			for _, mode := range transports {
				select {
				case jobs <- cottenMaxScanJob{r, mode}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	counts, valid := make(map[string]int), make(map[string]bool)
	verifiedByDomain := make(map[string][]string)
	for result := range results {
		counts[result.resolver]++
		if result.valid {
			verifiedByDomain[result.domain] = append(verifiedByDomain[result.domain], result.resolver)
			if !valid[result.resolver] {
				valid[result.resolver] = true
				summary.Valid++
				c.emitScanResult(result.resolver, true)
			}
		}
		if c.log != nil {
			c.log.Machinef("WD_SCAN event=path resolver=%s transport=%s authenticated=%t transfer_verified=%t qname_bytes=%d answer_bytes=%d", result.resolver, result.transport, result.authenticated, result.transferred, result.nameBytes, result.answerBytes)
		}
		if counts[result.resolver] == len(transports) && !valid[result.resolver] {
			summary.Rejected++
			c.emitScanResult(result.resolver, false)
		}
		completed := summary.Valid + summary.Rejected
		if summary.Total > 0 {
			c.logConnectionProgress("mtu", 15+70*completed/summary.Total, "completed", completed, "total", summary.Total, "valid", summary.Valid, "rejected", summary.Rejected)
		}
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	for domain, good := range verifiedByDomain {
		if cache := c.cottenMaxDiscoveryForDomain(domain, resolvers).Cache; cache != nil {
			cache.Store(good)
		}
	}
	c.logResolverScanComplete(summary)
	return summary, nil
}

func (c *Client) probeCottenMaxScanPath(ctx context.Context, job cottenMaxScanJob) cottenMaxScanResult {
	result := cottenMaxScanResult{cottenMaxScanJob: job}
	for _, domain := range c.cfg.Domains {
		if ctx.Err() != nil {
			break
		}
		profile := &Client{cfg: c.cfg, log: c.log}
		profile.cfg.Domains = []string{domain}
		profile.cfg.StandbyDomains = nil
		profile.cfg.ResolverTransport = job.transport
		profile.cfg.ResolverDiscoveryEnabled = false
		host, port, _ := net.SplitHostPort(job.resolver)
		p, _ := strconv.Atoi(port)
		profile.cfg.Resolvers = []config.ResolverAddress{{IP: host, Port: p}}
		engine, err := profile.newCottenMaxEngine()
		if err != nil {
			profile.closeSharedEncryptedDNSClient()
			continue
		}
		// Each transport gets its own deadline, session and measured size state.
		// A slow/dead UDP path cannot consume the TCP path's probe budget.
		timeout := time.Duration(c.cfg.MTUTestTimeout*float64(time.Second)) * time.Duration(max(1, c.cfg.MTUTestRetries)) * 4
		if timeout < 5*time.Second {
			timeout = 5 * time.Second
		}
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		err = engine.Authenticate(probeCtx)
		if err == nil {
			result.authenticated = true
			result.domain = domain
			// Qualify a usable path with a small byte-exact transfer first. A
			// slow link may run out of the sizing budget and still be usable.
			result.transferred = engine.Probe(probeCtx, 256) == nil
			result.valid = result.transferred
			if result.valid {
				_ = engine.Probe(probeCtx, 8192)
			}
			for _, path := range engine.PathStats() {
				if path.Verified {
					result.nameBytes = max(result.nameBytes, min(path.NameLen, path.ObservedNameLen))
					result.answerBytes = max(result.answerBytes, min(path.AnswerLimit, path.ObservedAnswer))
				}
			}
		}
		cancel()
		engine.Close()
		profile.closeSharedEncryptedDNSClient()
		if result.valid {
			break
		}
	}
	return result
}
