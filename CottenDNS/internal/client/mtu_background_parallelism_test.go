// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import "testing"

// The FastConnect sweep must keep the initial scan parallel while the sweep that
// continues behind a live tunnel runs at MTU_BACKGROUND_PARALLELISM. This is the
// arithmetic that decides both, extracted from runFastConnectMTUTests.
func backgroundWorkersFor(configured, workerCount int) int {
	return min(max(1, configured), workerCount)
}

func TestBackgroundParallelismDefaultsToOneAndStaysUnderTheInitialCount(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		workers    int
		want       int
	}{
		{"default is a single resolver", 1, 100, 1},
		{"zero falls back to one", 0, 100, 1},
		{"negative falls back to one", -5, 100, 1},
		{"an explicit value is honored", 8, 100, 8},
		{"never exceeds the initial worker count", 50, 4, 4},
		{"a serial initial scan stays serial", 8, 1, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backgroundWorkersFor(tc.configured, tc.workers); got != tc.want {
				t.Fatalf("backgroundWorkersFor(%d, %d) = %d, want %d",
					tc.configured, tc.workers, got, tc.want)
			}
		})
	}
}
