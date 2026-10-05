// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// query_rate_limit.go — optional hard caps on outgoing DNS queries, for networks
// that drop or block DNS above a fixed rate. Every send path goes through it:
// data plane (dispatcher + writer), MTU probes, session init, health rechecks,
// one-way close bursts — over UDP, TCP, DoT and DoH alike.
//
// The firewall's counting rule is unknown, so each scope is its own knob and
// they stack (a query waits until every enabled scope allows it):
//   QUERY_RATE_LIMIT_PER_SECOND               total, per client
//   QUERY_RATE_LIMIT_PER_RESOLVER_PER_SECOND  per destination resolver IP
//   QUERY_RATE_LIMIT_PER_DOMAIN_PER_SECOND    per tunnel domain
// QUERY_RATE_LIMIT_BURST lets that many queries go back-to-back (default 1 =
// evenly spaced, which never exceeds the rate in any counting window).
// QUERY_TIMING_JITTER stretches each gap by a random 0..J fraction so traffic
// has no fixed rhythm; it only ever lengthens gaps, so caps still hold.
// Queries wait for a slot; they are never dropped.
// ==============================================================================

package client

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

type queryRateLimiter struct {
	global, resolver, domain time.Duration // gap per scope; 0 = scope off
	burst                    int
	jitter                   float64

	mu  sync.Mutex
	tat map[string]time.Time // GCRA theoretical arrival time per scope key
}

// newQueryRateLimiter returns nil (no limit) when every scope is off.
func newQueryRateLimiter(global, perResolver, perDomain float64, burst int, jitter float64) *queryRateLimiter {
	if global <= 0 && perResolver <= 0 && perDomain <= 0 {
		return nil
	}
	return &queryRateLimiter{
		global:   rateGap(global),
		resolver: rateGap(perResolver),
		domain:   rateGap(perDomain),
		burst:    max(burst, 1),
		jitter:   clampJitter(jitter),
		tat:      make(map[string]time.Time),
	}
}

func rateGap(perSecond float64) time.Duration {
	if perSecond <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / perSecond)
}

// perTarget reports whether the limit depends on which resolver/domain is used,
// i.e. whether picking a different target can avoid waiting.
func (l *queryRateLimiter) perTarget() bool {
	return l != nil && (l.resolver > 0 || l.domain > 0)
}

// schedule returns how long until a query to (resolver, domain) may go out.
// With book=true the slot is also claimed in every enabled scope.
func (l *queryRateLimiter) schedule(now time.Time, resolver, domain string, book bool) time.Duration {
	scopes := [3]struct {
		key string
		gap time.Duration
	}{{"*", l.global}, {"r:" + resolver, l.resolver}, {"d:" + domain, l.domain}}

	l.mu.Lock()
	defer l.mu.Unlock()
	sendAt := now
	for _, s := range scopes {
		if s.gap == 0 {
			continue
		}
		allow := l.tat[s.key].Add(-time.Duration(l.burst-1) * s.gap)
		if allow.After(sendAt) {
			sendAt = allow
		}
	}
	if book {
		stretch := 1.0
		if l.jitter > 0 {
			stretch += rand.Float64() * l.jitter
		}
		for _, s := range scopes {
			if s.gap == 0 {
				continue
			}
			tat := l.tat[s.key]
			if tat.Before(sendAt) {
				tat = sendAt
			}
			l.tat[s.key] = tat.Add(time.Duration(float64(s.gap) * stretch))
		}
	}
	return sendAt.Sub(now)
}

// delay peeks at the wait for (resolver, domain) without claiming a slot.
func (l *queryRateLimiter) delay(resolver, domain string) time.Duration {
	if l == nil {
		return 0
	}
	return l.schedule(time.Now(), resolver, domain, false)
}

// wait claims a slot for one query and blocks until it is due. False if ctx
// ended first.
func (l *queryRateLimiter) wait(ctx context.Context, resolver, domain string) bool {
	if l == nil {
		return true
	}
	return sleepCtx(ctx, l.schedule(time.Now(), resolver, domain, true))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// stretchDuration lengthens d by a random 0..jitter fraction (timing mask).
func stretchDuration(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 || d <= 0 {
		return d
	}
	return d + time.Duration(rand.Float64()*clampJitter(jitter)*float64(d))
}

func clampJitter(j float64) float64 {
	if j < 0 {
		return 0
	}
	if j > 1 {
		return 1
	}
	return j
}
