package client

import (
	"testing"
	"time"
)

func TestQueryRateLimiter(t *testing.T) {
	if newQueryRateLimiter(0, 0, 0, 1, 0) != nil || newQueryRateLimiter(-1, 0, 0, 1, 0) != nil {
		t.Fatal("no positive scope must disable the limiter")
	}
	now := time.Now()
	ms := time.Millisecond

	// Global 5/s: evenly spaced 200ms slots; idle time gives no burst credit.
	g := newQueryRateLimiter(5, 0, 0, 1, 0)
	for i, want := range []time.Duration{0, 200 * ms, 400 * ms} {
		if got := g.schedule(now, "1.1.1.1", "a", true); got != want {
			t.Fatalf("global slot %d: %v, want %v", i, got, want)
		}
	}
	if got := g.schedule(now.Add(10*time.Second), "1.1.1.1", "a", true); got != 0 {
		t.Fatalf("after idle: %v, want 0", got)
	}

	// Peeking must not claim a slot.
	p := newQueryRateLimiter(5, 0, 0, 1, 0)
	p.schedule(now, "", "", false)
	if got := p.schedule(now, "", "", true); got != 0 {
		t.Fatalf("peek consumed a slot: %v", got)
	}

	// Burst 3: three immediate, then spaced.
	b := newQueryRateLimiter(5, 0, 0, 3, 0)
	for i, want := range []time.Duration{0, 0, 0, 200 * ms} {
		if got := b.schedule(now, "", "", true); got != want {
			t.Fatalf("burst slot %d: %v, want %v", i, got, want)
		}
	}

	// Per resolver: a second resolver is not delayed by the first.
	r := newQueryRateLimiter(0, 5, 0, 1, 0)
	r.schedule(now, "1.1.1.1", "a", true)
	if got := r.schedule(now, "8.8.8.8", "a", true); got != 0 {
		t.Fatalf("other resolver delayed: %v", got)
	}
	if got := r.schedule(now, "1.1.1.1", "a", true); got != 200*ms {
		t.Fatalf("same resolver: %v, want 200ms", got)
	}

	// Stacked scopes: per-domain 2/s binds even across resolvers.
	d := newQueryRateLimiter(0, 5, 2, 1, 0)
	d.schedule(now, "1.1.1.1", "a", true)
	if got := d.schedule(now, "8.8.8.8", "a", true); got != 500*ms {
		t.Fatalf("domain scope: %v, want 500ms", got)
	}

	// Jitter only ever lengthens gaps, never more than (1+jitter)x.
	j := newQueryRateLimiter(5, 0, 0, 1, 0.5)
	prev := time.Duration(0)
	for i := 0; i < 50; i++ {
		got := j.schedule(now, "", "", true)
		if gap := got - prev; i > 0 && (gap < 200*ms || gap > 300*ms) {
			t.Fatalf("jittered gap %v outside [200ms, 300ms]", gap)
		}
		prev = got
	}
}
