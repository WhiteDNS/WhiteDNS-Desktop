package cottenmax

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	soar "cottendns-go/internal/cottenmax/engine"
)

// DomainStat describes an independently authenticated tunnel domain. In
// experimental parallel mode, the sum of MaxInflight is the configured total.
// ActiveStreams includes a reserved opening attempt; AssignedStreams counts
// successful stream assignments over the lifetime of the client.
type DomainStat struct {
	Domain          string          `json:"domain"`
	Started         bool            `json:"started"`
	Established     bool            `json:"established"`
	ActiveStreams   int             `json:"active_streams"`
	AssignedStreams uint64          `json:"assigned_streams"`
	MaxInflight     int             `json:"max_inflight"`
	Paths           []soar.PathStat `json:"paths"`
}

// DomainStats returns a stable configuration-order snapshot. Failover domains
// retain their existing independent cap; only parallel mode partitions it.
func (c *Client) DomainStats() []DomainStat {
	if c.failover == nil {
		return []DomainStat{{Domain: c.domain, Started: true, Established: c.engine.Established(), MaxInflight: c.maxInflight, Paths: c.engine.PathStats()}}
	}
	f := c.failover
	f.mu.Lock()
	slots := append([]domainClient(nil), f.domains...)
	budgets := append([]int(nil), f.budgets...)
	f.mu.Unlock()
	stats := make([]DomainStat, len(slots))
	for i, slot := range slots {
		stat := DomainStat{Domain: slot.domain, Started: slot.engine != nil, MaxInflight: c.maxInflight}
		if len(budgets) > 0 {
			stat.MaxInflight = budgets[i]
		}
		if slot.engine != nil {
			stat.Established = slot.engine.Established()
			stat.Paths = slot.engine.PathStats()
		}
		stats[i] = stat
	}
	if p := c.parallel; p != nil {
		p.mu.Lock()
		for i := range stats {
			stats[i].ActiveStreams = p.active[i]
			stats[i].AssignedStreams = p.assigned[i]
		}
		p.mu.Unlock()
	}
	return stats
}

func splitDomainBudget(total, count int) ([]int, error) {
	if count < 1 || total < count {
		return nil, fmt.Errorf("cottenmax: parallel domains need at least one inflight query per domain")
	}
	budgets := make([]int, count)
	for i := range budgets {
		budgets[i] = total / count
		if i < total%count {
			budgets[i]++
		}
	}
	return budgets, nil
}

// domainParallel balances new independent streams, never packets within one
// stream. Each domain has an independent engine, HELLO, PN/ACK space, congestion
// controller and FEC state. The fixed fair query partitions deliberately avoid
// multiplying the flight budget: an idle or failed domain's share is not borrowed.
// Default failover behavior does not construct this object or partition its cap.
type domainParallel struct {
	mu       sync.Mutex
	f        *domainFailover
	next     int
	active   []int
	assigned []uint64
	retryAt  []time.Time
}

func newDomainParallel(f *domainFailover) *domainParallel {
	n := len(f.domains)
	return &domainParallel{f: f, active: make([]int, n), assigned: make([]uint64, n), retryAt: make([]time.Time, n)}
}

// reserve uses least-active selection with round-robin ties. Reserving before
// opening prevents simultaneous callers all choosing the same domain.
func (p *domainParallel) reserve(tried []bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f.ctx.Err() != nil {
		return -1
	}
	best := -1
	now := time.Now()
	for step := range p.active {
		i := (p.next + step) % len(p.active)
		if tried[i] || now.Before(p.retryAt[i]) {
			continue
		}
		if best < 0 || p.active[i] < p.active[best] {
			best = i
		}
	}
	// If every untried domain is cooling down, make one real attempt rather
	// than fail forever without the opportunity to notice a recovered server.
	if best < 0 {
		for i := range p.active {
			if !tried[i] && (best < 0 || p.retryAt[i].Before(p.retryAt[best])) {
				best = i
			}
		}
	}
	if best >= 0 {
		p.active[best]++
		p.next = (best + 1) % len(p.active)
		tried[best] = true
	}
	return best
}

func (p *domainParallel) failed(index int) {
	p.mu.Lock()
	p.active[index]--
	p.retryAt[index] = time.Now().Add(p.f.after)
	p.mu.Unlock()
}

func (p *domainParallel) release(index int) {
	p.mu.Lock()
	p.active[index]--
	p.mu.Unlock()
}

func (p *domainParallel) succeeded(index int, stream bool) {
	p.mu.Lock()
	p.retryAt[index] = time.Time{}
	if stream {
		p.assigned[index]++
	} else {
		p.active[index]--
	}
	p.mu.Unlock()
}

func (p *domainParallel) dial(ctx context.Context, signed string, confirmed bool) (net.Conn, error) {
	tried := make([]bool, len(p.active))
	var failures []error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index := p.reserve(tried)
		if index < 0 {
			break
		}
		if err := p.f.admission.wait(ctx); err != nil {
			p.release(index)
			return nil, err
		}
		attempt, cancel := context.WithTimeout(ctx, p.f.after)
		stop := context.AfterFunc(p.f.ctx, cancel)
		engine, err := p.f.engineFor(attempt, index)
		var conn net.Conn
		if err == nil {
			conn, err = dialEngine(attempt, engine, signed, confirmed)
		}
		stop()
		cancel()
		if p.f.ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			p.release(index)
			return nil, net.ErrClosed
		}
		if err == nil {
			p.succeeded(index, true)
			return &domainCountedConn{Conn: conn, release: func() { p.release(index) }}, nil
		}
		p.failed(index)
		failures = append(failures, fmt.Errorf("%s: %w", p.f.domains[index].domain, err))
	}
	if p.f.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	return nil, fmt.Errorf("cottenmax: all parallel tunnel domains failed: %w", errors.Join(failures...))
}

func (p *domainParallel) authenticate(ctx context.Context) error {
	tried := make([]bool, len(p.active))
	var failures []error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		index := p.reserve(tried)
		if index < 0 {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, p.f.after)
		stop := context.AfterFunc(p.f.ctx, cancel)
		engine, err := p.f.engineFor(attempt, index)
		if err == nil {
			err = engine.Authenticate(attempt)
		}
		stop()
		cancel()
		if p.f.ctx.Err() != nil {
			p.release(index)
			return net.ErrClosed
		}
		if err == nil {
			p.succeeded(index, false)
			return nil
		}
		p.failed(index)
		failures = append(failures, fmt.Errorf("%s: %w", p.f.domains[index].domain, err))
	}
	if p.f.ctx.Err() != nil {
		return net.ErrClosed
	}
	return fmt.Errorf("cottenmax: no authenticated parallel tunnel domain: %w", errors.Join(failures...))
}

type domainCountedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *domainCountedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
