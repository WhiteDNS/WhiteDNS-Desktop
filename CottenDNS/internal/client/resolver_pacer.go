// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// resolver_pacer.go — intelligent, self-gating rate limiting per resolver. This
// is redistribution, NOT a global throttle: a resolver that signals overload
// (DNS RCODE != 0, i.e. REFUSED/SERVFAIL, or repeated timeouts) is put into a
// short, exponentially-growing cooldown window and deprioritized in selection,
// so its share shifts to resolvers with headroom. On sustained success the
// window shrinks back to zero (the resolver becomes fully un-paced again).
//
// Properties that make it safe ("can't hurt"):
//   - Self-gating: a healthy resolver has interval 0 and is never paced, so on a
//     clean network the pacer does nothing.
//   - Redistribute, don't idle: paced resolvers sink to the back of the candidate
//     list but are still used as a fallback when nothing else is available, so a
//     packet is never dropped or stalled just because resolvers are cooling down.
//   - AIMD: multiplicative backoff on overload, additive recovery on success —
//     it continuously probes for more headroom and never permanently caps anyone.
// ==============================================================================

package client

import (
	"sync"
	"time"
)

const (
	pacerBaseInterval = 8 * time.Millisecond
	// Cap on a single resolver's cooldown window. 400ms throttled a maxed-out
	// resolver to ~2.5 queries/sec; 200ms (~5/sec) still redistributes load off a
	// struggling resolver without starving aggregate throughput on lossy links.
	pacerMaxInterval = 200 * time.Millisecond
)

type resolverPacer struct {
	enabled bool

	mu     sync.Mutex
	states map[string]*pacerState
}

type pacerState struct {
	mu         sync.Mutex
	interval   time.Duration // current cooldown window; 0 == healthy / un-paced
	pacedUntil time.Time
}

func newResolverPacer(enabled bool) *resolverPacer {
	return &resolverPacer{enabled: enabled, states: make(map[string]*pacerState)}
}

func (p *resolverPacer) stateFor(key string) *pacerState {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.states[key]
	if s == nil {
		s = &pacerState{}
		p.states[key] = s
	}
	return s
}

// paced reports whether key is in a cooldown window right now. Non-consuming, so
// it is safe to call while merely inspecting candidates during selection.
func (p *resolverPacer) paced(key string, now time.Time) bool {
	if p == nil || !p.enabled || key == "" {
		return false
	}
	p.mu.Lock()
	s := p.states[key]
	p.mu.Unlock()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.pacedUntil)
}

// throttle grows the resolver's cooldown window (multiplicative backoff) after an
// overload signal and starts a fresh cooldown.
func (p *resolverPacer) throttle(key string, now time.Time) {
	if p == nil || !p.enabled || key == "" {
		return
	}
	s := p.stateFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.interval <= 0 {
		s.interval = pacerBaseInterval
	} else {
		s.interval *= 2
		if s.interval > pacerMaxInterval {
			s.interval = pacerMaxInterval
		}
	}
	s.pacedUntil = now.Add(s.interval)
}

// success shrinks the cooldown window (additive recovery); once it reaches zero
// the resolver is fully un-paced again.
func (p *resolverPacer) success(key string) {
	if p == nil || !p.enabled || key == "" {
		return
	}
	p.mu.Lock()
	s := p.states[key]
	p.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.interval <= 0 {
		return
	}
	// Multiplicative recovery mirrors the x2 backoff in throttle(): a recovering
	// resolver sheds its cooldown as fast as it accrued it. The old fixed 3ms step
	// could not keep pace with the doubling, so intervals ratcheted to the cap
	// under sustained loss and throttled throughput on long sessions.
	s.interval /= 2
	if s.interval < pacerBaseInterval {
		s.interval = 0
		s.pacedUntil = time.Time{}
	}
}

// orderByPacing returns candidates with currently-paced (throttling) resolvers
// moved to the back, so selection prefers resolvers with headroom but still falls
// back to paced ones rather than dropping the packet. Order within each group is
// preserved (so the underlying balancer strategy still applies).
func (c *Client) orderByPacing(candidates []Connection) []Connection {
	if c.pacer == nil || !c.pacer.enabled || len(candidates) < 2 {
		return candidates
	}
	now := c.now()
	ready := make([]Connection, 0, len(candidates))
	var paced []Connection
	for _, conn := range candidates {
		if c.pacer.paced(conn.Key, now) {
			paced = append(paced, conn)
		} else {
			ready = append(ready, conn)
		}
	}
	if len(paced) == 0 {
		return ready
	}
	return append(ready, paced...)
}
