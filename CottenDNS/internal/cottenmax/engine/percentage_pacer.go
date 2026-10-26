package soar

import (
	"math"
	"sync"
	"time"
)

// PercentagePacer shares one token bucket across all domain engines. Its rate
// comes from their unscaled congestion windows and RTT, never achieved paced
// throughput: measuring that would apply the reduction repeatedly toward zero.
// The target is approximate, especially when CPU or application work is limiting.
type PercentagePacer struct {
	mu           sync.Mutex
	reduction    int
	keep         float64
	references   map[*Client]percentageReference
	rate, tokens float64
	burst        float64
	last         time.Time
}

const percentageBurst = 4.0

// A nominal 1ms timer can wake several milliseconds late on a loaded/mobile
// host. Retaining a short bounded scheduling allowance avoids silently turning
// that timer jitter into an additional rate reduction. Scaled flight remains
// the hard upper bound, and idle time never accumulates beyond this allowance.
const percentageBurstInterval = 10 * time.Millisecond

// Warm starts learn a Full congestion reference from at most this many
// verified-path queries. Admission is bounded even if replies are delayed or
// lost; unauthenticated/scout replies never earn successful warm credit.
const percentageWarmReplies = 32

type percentageReference struct{ rate, flight float64 }

// NewPercentagePacer constructs a 10..90 percent reduction target.
func NewPercentagePacer(reduction int) *PercentagePacer {
	if reduction < 10 || reduction > 90 {
		panic("soar: reduction percent must be 10..90")
	}
	return &PercentagePacer{reduction: reduction, keep: float64(100-reduction) / 100, references: make(map[*Client]percentageReference), tokens: percentageBurst, burst: percentageBurst}
}

func (p *PercentagePacer) refillLocked(now time.Time) {
	if p.last.IsZero() {
		p.last = now
		return
	}
	if now.After(p.last) {
		p.tokens = min(p.burst, p.tokens+now.Sub(p.last).Seconds()*p.rate)
		p.last = now
	}
}

func (p *PercentagePacer) update(owner *Client, reference float64, now time.Time) {
	p.updateWithFlight(owner, reference, percentageBurst, now)
}

func (p *PercentagePacer) updateWithFlight(owner *Client, reference, flight float64, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refillLocked(now)
	if reference > 0 {
		p.references[owner] = percentageReference{reference, flight}
	} else {
		delete(p.references, owner)
	}
	p.rate, flight = 0, 0
	for _, reference := range p.references {
		p.rate += reference.rate * p.keep
		flight += reference.flight
	}
	// The event loop wakes at millisecond resolution, with OS scheduling jitter.
	// A four-token/nominal-1ms burst would impose an accidental extra rate cap.
	// Credit remains bounded by the current scaled aggregate congestion flight.
	p.burst = max(1, min(max(percentageBurst, math.Ceil(p.rate*percentageBurstInterval.Seconds())), math.Ceil(flight)))
	p.tokens = min(p.tokens, p.burst)
}

func (p *PercentagePacer) remove(owner *Client, now time.Time) { p.update(owner, 0, now) }

// TryTake is nonblocking and may be called under an engine's mutex. Only one
// shared burst can accumulate while idle. An initial burst permits bootstrap.
func (p *PercentagePacer) TryTake(now time.Time) (bool, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refillLocked(now)
	if p.tokens >= 1 {
		p.tokens--
		return true, time.Time{}
	}
	if p.rate <= 0 {
		return false, now.Add(time.Second)
	}
	wait := time.Duration(math.Ceil((1 - p.tokens) / p.rate * float64(time.Second)))
	return false, p.last.Add(max(wait, time.Nanosecond))
}

func (c *Client) percentageFlightLimit() int {
	if c.cfg.LowReductionPercent == 0 {
		return c.cfg.MaxInflight
	}
	return max(1, c.cfg.MaxInflight*(100-c.cfg.LowReductionPercent)/100)
}

func (c *Client) percentagePathWindow(p *path) float64 {
	if c.cfg.LowReductionPercent == 0 || c.percentageWarmStartLocked() {
		return p.cwnd
	}
	return max(1, min(p.cwnd, float64(c.cfg.MaxPathWindow))*float64(100-c.cfg.LowReductionPercent)/100)
}

func (c *Client) percentageWarmStartLocked() bool {
	return c.cfg.LowReductionPercent != 0 && c.sess != nil && c.sess.established && c.sess.lowWarmSends < percentageWarmReplies && c.sess.lowWarmSuccesses < percentageWarmReplies
}

func (c *Client) notePercentageAuthenticatedLocked(q *pendingQuery) {
	if c.cfg.LowReductionPercent != 0 && q.sess != nil && !q.hello && !q.scout && !q.expired && q.sess.lowWarmSuccesses < percentageWarmReplies {
		q.sess.lowWarmSuccesses++
	}
}

// updatePercentageReferenceLocked publishes only this engine's currently usable
// Full reference. p.srtt already excludes advertised server hold time. The RTT
// floor prevents near-zero loopback samples producing an unbounded token rate.
func (c *Client) updatePercentageReferenceLocked(now time.Time) {
	pacer := c.cfg.PercentagePacer
	if pacer == nil {
		return
	}
	select {
	case <-c.done:
		pacer.remove(c, now)
		return
	default:
	}
	cs := c.sess
	if cs == nil || (cs.established && cs.isClosed()) {
		pacer.remove(c, now)
		return
	}
	if cs.established && !cs.busy() && !now.Before(c.probeUntil) {
		pacer.remove(c, now)
		return
	}
	window, rate := 0.0, 0.0
	verified := c.anyUsableLocked(now)
	for _, path := range c.paths {
		if !path.usable(now) || (verified && !path.verified) {
			continue
		}
		w := min(path.cwnd, float64(c.cfg.MaxPathWindow))
		rtt := path.rto()
		if path.hasRTT {
			rtt = path.srtt
		}
		window += w
		rate += w / max(rtt, time.Millisecond).Seconds()
	}
	if window > float64(c.cfg.MaxInflight) {
		rate *= float64(c.cfg.MaxInflight) / window
	}
	flight := max(1, min(window*float64(100-c.cfg.LowReductionPercent)/100, float64(max(1, c.cfg.MaxInflight*(100-c.cfg.LowReductionPercent)/100))))
	pacer.updateWithFlight(c, rate, flight, now)
}
