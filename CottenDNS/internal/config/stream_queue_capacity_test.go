// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package config

import "testing"

// StreamQueueInitialCapacity sizes a map allocated once per local stream, so it
// must stay small however tempting it looks next to the global buffer knobs.
// At 65536 each stream costs ~2.3 MiB of census map; at 512 it costs ~19 KiB.
// A browser's worth of concurrent streams at the large value OOMs Android.
func TestStreamQueueInitialCapacityStaysPerStreamSafe(t *testing.T) {
	if got := defaultClientConfig().StreamQueueInitialCapacity; got > 4096 {
		t.Fatalf("default StreamQueueInitialCapacity = %d; cost is per stream, keep it small", got)
	}
}
