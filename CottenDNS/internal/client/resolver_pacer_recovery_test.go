package client

import (
	"testing"
	"time"
)

// Guards the pacer rebalance: recovery must keep pace with backoff so a resolver
// cannot ratchet to the cap and stay there under sustained loss (the cause of the
// long-session throughput collapse).
func TestResolverPacer_RecoveryKeepsPaceWithBackoff(t *testing.T) {
	p := newResolverPacer(true)
	now := time.Now()

	// Drive the resolver to the interval cap.
	for i := 0; i < 20; i++ {
		p.throttle("r1", now)
	}
	s := p.states["r1"]
	if s == nil || s.interval != pacerMaxInterval {
		t.Fatalf("expected interval pinned at cap %v, got %v", pacerMaxInterval, intervalOf(s))
	}

	// Multiplicative recovery clears a maxed interval in a handful of successes,
	// not hundreds — so a deprioritized resolver is not starved back to health.
	successes := 0
	for s.interval > 0 && successes < 100 {
		p.success("r1")
		successes++
	}
	if s.interval != 0 {
		t.Fatalf("resolver still paced after %d successes (interval=%v)", successes, s.interval)
	}
	if successes > 10 {
		t.Fatalf("recovery too slow: %d successes to clear the cap", successes)
	}

	// Anti-ratchet: alternating throttle/success (~50%% loss) must not pin the
	// interval at the cap the way the old additive recovery did.
	for i := 0; i < 100; i++ {
		p.throttle("r1", now)
		p.success("r1")
	}
	if s.interval >= pacerMaxInterval {
		t.Fatalf("interval ratcheted to cap under alternating load: %v", s.interval)
	}
}

func intervalOf(s *pacerState) time.Duration {
	if s == nil {
		return -1
	}
	return s.interval
}
