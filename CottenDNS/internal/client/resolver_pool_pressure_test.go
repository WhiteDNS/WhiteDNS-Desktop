package client

import (
	"fmt"
	"testing"
)

// Verifies the recovery side of the disable<->recover rebalance: when the valid
// resolver pool is depleted (at or below the pressure threshold) a single
// successful recheck is enough to reactivate a resolver, so a long/lossy session
// can refill the pool instead of ratcheting down to the floor. A healthy pool
// keeps the conservative two-success confirmation.
func TestReactivationSuccessThresholdScalesWithPoolPressure(t *testing.T) {
	makeClient := func(validConns int) *Client {
		conns := make([]*Connection, validConns)
		for i := range conns {
			conns[i] = &Connection{Key: fmt.Sprintf("r%d", i), IsValid: true}
		}
		b := NewBalancer(BalancingRoundRobinDefault)
		b.SetConnections(conns)
		return &Client{balancer: b}
	}

	cases := []struct {
		name       string
		validConns int
		want       int
	}{
		{"depleted below threshold", resolverPoolPressureThreshold - 1, 1},
		{"exactly at threshold", resolverPoolPressureThreshold, 1},
		{"healthy above threshold", resolverPoolPressureThreshold + 1, runtimeDisabledResolverReactivationSuccessThreshold},
		{"large healthy pool", 40, runtimeDisabledResolverReactivationSuccessThreshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeClient(tc.validConns)
			if got := c.reactivationSuccessThreshold(); got != tc.want {
				t.Fatalf("validConns=%d: reactivationSuccessThreshold() = %d, want %d",
					tc.validConns, got, tc.want)
			}
		})
	}
}
