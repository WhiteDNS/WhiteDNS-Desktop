package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cottendns-go/internal/config"
)

// Exercise TOML -> finalized config -> runtime adapter, rather than testing a
// second copy of the mapping. Construction is lazy and sends no DNS packets.
func TestCottenMaxTrafficProfileRuntimePropagation(t *testing.T) {
	for _, tc := range []struct {
		profile string
		percent int
	}{
		{"full", 35},
		{"low", 10},
		{"low", 35},
		{"low", 90},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "client_config.toml")
			body := fmt.Sprintf("TUNNEL_MODE = \"cottenmax\"\nDOMAINS = [\"a.test\"]\nENCRYPTION_KEY = \"secret\"\nCOTTENMAX_TRAFFIC_PROFILE = %q\nCOTTENMAX_LOW_REDUCTION_PERCENT = %d\n", tc.profile, tc.percent)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("127.0.0.1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadClientConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{cfg: cfg}
			max, err := c.newCottenMaxEngine()
			if err != nil {
				t.Fatal(err)
			}
			defer max.Close()
			if max.TrafficProfile() != tc.profile {
				t.Fatalf("runtime profile=%q, want %q", max.TrafficProfile(), tc.profile)
			}
			if max.LowReductionPercent() != tc.percent {
				t.Fatalf("%s reduction did not reach Max engine: %d, want %d", tc.profile, max.LowReductionPercent(), tc.percent)
			}
		})
	}
}
