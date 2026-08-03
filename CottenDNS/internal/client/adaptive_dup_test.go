// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import "testing"

func TestDuplicationForLoss(t *testing.T) {
	const target = 0.95
	cases := []struct {
		name     string
		base     int
		lossFrac float64
		want     int
	}{
		{"no loss signal returns base", 2, 0, 2},
		{"loss>=1 returns base", 2, 1.0, 2},
		{"10% loss -> 2 copies", 1, 0.10, 2},
		{"30% loss -> 3 copies", 1, 0.30, 3},
		{"50% loss -> 5 copies", 1, 0.50, 5},
		{"75% loss exceeds ceiling -> 8", 1, 0.75, 8},
		{"84% loss uses survival ceiling", 1, 0.84, 8},
		{"base higher than computed wins", 4, 0.10, 4},
		{"computed never below base", 6, 0.30, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := duplicationForLoss(tc.base, tc.lossFrac, target)
			if got != tc.want {
				t.Fatalf("duplicationForLoss(base=%d, loss=%.2f) = %d, want %d", tc.base, tc.lossFrac, got, tc.want)
			}
		})
	}
}

// With adaptive duplication enabled but no loss signal yet (fresh balancer),
// the runtime count must equal the configured base.
func TestAdaptiveDuplicationNoSignalKeepsBase(t *testing.T) {
	c := &Client{}
	c.cfg.AdaptiveDuplication = true
	c.cfg.AdaptiveDuplicationTargetDelivery = 0.95
	c.balancer = NewBalancer(1)

	if got := c.adaptiveDuplicationCount(3); got != 3 {
		t.Fatalf("no loss signal: got %d want 3 (base)", got)
	}
}
