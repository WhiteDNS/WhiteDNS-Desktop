package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// Verifies speculative discovery (re-probing never-valid, non-runtime-disabled
// resolvers) is trickled: at most one probe per batch, spaced by
// discoveryRecheckMinSpacing, so it never bursts bandwidth away from live traffic.
func TestDiscoveryRecheckIsThrottled(t *testing.T) {
	keys := []string{"a", "b", "c", "d", "e"}
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               30,
	}, keys...)
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	// Every resolver is a "normal" discovery candidate: invalid, due, NOT
	// runtime-disabled (so runtimePriority is false).
	for _, k := range keys {
		if !c.balancer.SetConnectionValidity(k, false) {
			t.Fatalf("failed to invalidate %s", k)
		}
	}
	c.initResolverRecheckMeta()
	c.resolverHealthMu.Lock()
	for _, k := range keys {
		c.resolverRecheck[k] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	}
	c.resolverHealthMu.Unlock()

	var probes atomic.Int32
	c.recheckConnectionFn = func(conn *Connection) bool {
		probes.Add(1)
		return false // stay invalid; we only count probe attempts
	}

	// Batch 1: exactly one discovery probe despite 5 due candidates.
	c.runResolverRecheckBatch(context.Background(), now)
	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		return probes.Load() >= 1
	}, "expected a discovery probe on the first batch")
	time.Sleep(60 * time.Millisecond)
	if got := probes.Load(); got != 1 {
		t.Fatalf("first batch should fire exactly 1 discovery probe, got %d", got)
	}

	// Batch 2 within the spacing window: blocked, still 1.
	c.runResolverRecheckBatch(context.Background(), now)
	time.Sleep(60 * time.Millisecond)
	if got := probes.Load(); got != 1 {
		t.Fatalf("discovery within min-spacing must be blocked, got %d probes", got)
	}

	// After the spacing window elapses: one more is allowed.
	now = now.Add(discoveryRecheckMinSpacing + time.Second)
	c.runResolverRecheckBatch(context.Background(), now)
	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		return probes.Load() >= 2
	}, "expected a second discovery probe after the spacing window")
}
