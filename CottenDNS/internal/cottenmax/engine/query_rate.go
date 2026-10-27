package soar

import (
	"math"
	"sync"
	"time"
)

// QueryRateLimiter is a shared token bucket. A nil Config.QueryRateLimiter keeps
// the original unpaced scheduler. Sharing one pointer across domain engines
// prevents additional domains or resolver transports multiplying the allowance.
// TryTake never sleeps and is safe to call while holding one engine's mutex.
type QueryRateLimiter struct {
	mu        sync.Mutex
	perSecond float64
	burst     float64
	tokens    float64
	last      time.Time
}

// NewQueryRateLimiter constructs a positive-rate, positive-burst budget.
// Invalid arguments are programming errors; connection admission uses constants.
func NewQueryRateLimiter(perSecond float64, burst int) *QueryRateLimiter {
	if perSecond <= 0 || math.IsInf(perSecond, 0) || math.IsNaN(perSecond) || burst < 1 {
		panic("soar: rate and burst must be positive and finite")
	}
	return &QueryRateLimiter{perSecond: perSecond, burst: float64(burst), tokens: float64(burst)}
}

// TryTake consumes one token or reports the earliest time a token may exist.
// Availability is not reserved: another owner can consume it before that time.
// Stale timestamps cannot refill tokens or move the bucket clock backwards.
func (r *QueryRateLimiter) TryTake(now time.Time) (bool, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last.IsZero() {
		r.last = now
	} else if now.After(r.last) {
		r.tokens = min(r.burst, r.tokens+now.Sub(r.last).Seconds()*r.perSecond)
		r.last = now
	}
	if r.tokens >= 1 {
		r.tokens--
		return true, time.Time{}
	}
	wait := time.Duration(math.Ceil((1 - r.tokens) / r.perSecond * float64(time.Second)))
	return false, r.last.Add(max(wait, time.Nanosecond))
}

// takeQueryLocked runs before any packet-building or probe/HELLO state changes.
// A locally throttled packet must never enter ARQ's sent map or loss accounting.
func (c *Client) takeQueryLocked(now time.Time) bool {
	if c.cfg.PercentagePacer != nil {
		ok, next := c.cfg.PercentagePacer.TryTake(now)
		c.rateNext = next
		if !ok {
			return false
		}
	}
	return c.takeFixedRateQueryLocked(now)
}

func (c *Client) takeDataQueryLocked(p *path, now time.Time) bool {
	if c.percentageWarmStartLocked() && p.verified {
		c.rateNext = time.Time{}
		return c.takeFixedRateQueryLocked(now)
	}
	return c.takeQueryLocked(now)
}

func (c *Client) takeFixedRateQueryLocked(now time.Time) bool {
	if c.cfg.QueryRateLimiter == nil {
		return true
	}
	if c.rateNext.After(now) {
		return false
	}
	ok, next := c.cfg.QueryRateLimiter.TryTake(now)
	c.rateNext = next
	return ok
}
