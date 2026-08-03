package udpserver

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dohByteGate bounds memory reserved by concurrently decoded request bodies.
type dohByteGate struct {
	used atomic.Int64
	max  int64
}

func (g *dohByteGate) reserve(n int64) bool {
	if n < 1 {
		n = 1
	}
	for {
		old := g.used.Load()
		if old > g.max-n {
			return false
		}
		if g.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}

func (g *dohByteGate) release(n int64) {
	if n > 0 {
		g.used.Add(-n)
	}
}

type dohRateState struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

// dohRateLimiter is a bounded per-client token bucket. Its map is pruned during
// normal traffic, preventing spoofed addresses from becoming persistent state.
type dohRateLimiter struct {
	mu     sync.Mutex
	states map[string]dohRateState
	rate   float64
	burst  float64
	lastGC time.Time
}

func newDoHRateLimiter(rate float64, burst int) *dohRateLimiter {
	return &dohRateLimiter{states: make(map[string]dohRateState), rate: rate, burst: float64(burst)}
}

func (l *dohRateLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.rate <= 0 || l.burst <= 0 {
		return true
	}
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastGC.IsZero() || now.Sub(l.lastGC) >= time.Minute {
		cutoff := now.Add(-5 * time.Minute)
		for k, st := range l.states {
			if st.seen.Before(cutoff) {
				delete(l.states, k)
			}
		}
		l.lastGC = now
	}
	st, ok := l.states[key]
	if !ok {
		st.tokens = l.burst
		st.last = now
	}
	if elapsed := now.Sub(st.last).Seconds(); elapsed > 0 {
		st.tokens = min(l.burst, st.tokens+elapsed*l.rate)
	}
	st.last = now
	st.seen = now
	allowed := st.tokens >= 1
	if allowed {
		st.tokens--
	}
	l.states[key] = st
	return allowed
}

type trustedProxySet struct {
	prefixes []netip.Prefix
}

func newTrustedProxySet(values []string) trustedProxySet {
	set := trustedProxySet{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			set.prefixes = append(set.prefixes, netip.PrefixFrom(addr.Unmap(), bits))
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			set.prefixes = append(set.prefixes, prefix.Masked())
		}
	}
	return set
}

func (s trustedProxySet) contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func dohRequestClientIP(r *http.Request, trusted trustedProxySet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !trusted.contains(host) {
		return host
	}
	// Only honor forwarding headers from explicitly trusted peers. The first
	// X-Forwarded-For entry is the original client in conventional proxy chains.
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if candidate := strings.TrimSpace(strings.Split(forwarded, ",")[0]); candidate != "" {
			if addr, err := netip.ParseAddr(candidate); err == nil {
				return addr.Unmap().String()
			}
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if addr, err := netip.ParseAddr(realIP); err == nil {
			return addr.Unmap().String()
		}
	}
	return host
}
