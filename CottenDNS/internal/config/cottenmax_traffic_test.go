package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trafficProfileConfigFile(t *testing.T, mode, profileLine string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.toml")
	body := fmt.Sprintf("TUNNEL_MODE = %q\nDOMAINS = [\"a.test\"]\nENCRYPTION_KEY = \"secret\"\n%s\n", mode, profileLine)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCottenMaxTrafficProfileConfig(t *testing.T) {
	for _, tc := range []struct {
		name, line, want string
	}{
		{"omitted", "", CottenMaxTrafficFull},
		{"blank", `COTTENMAX_TRAFFIC_PROFILE = "  "`, CottenMaxTrafficFull},
		{"full", `COTTENMAX_TRAFFIC_PROFILE = " Full "`, CottenMaxTrafficFull},
		{"low", `COTTENMAX_TRAFFIC_PROFILE = " LoW "`, CottenMaxTrafficLow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelCottenMax, tc.line))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CottenMaxTrafficProfile != tc.want {
				t.Fatalf("profile = %q, want %q", cfg.CottenMaxTrafficProfile, tc.want)
			}
			if cfg.CottenMaxLowReductionPercent != 35 {
				t.Fatalf("default Low reduction = %d, want 35", cfg.CottenMaxLowReductionPercent)
			}
			// Profile limits belong to the Max adapter; the persisted tuning
			// values remain intact so switching back to full restores them.
			if cfg.CottenMaxMaxInflight != 256 || cfg.CottenMaxMaxPathWindow != 256 || cfg.CottenMaxHoldMilliseconds != 500 {
				t.Fatalf("profile rewrote independent tuning values: inflight=%d path=%d hold=%d", cfg.CottenMaxMaxInflight, cfg.CottenMaxMaxPathWindow, cfg.CottenMaxHoldMilliseconds)
			}
		})
	}
}

func TestCottenMaxLowReductionRangeAndCommandLine(t *testing.T) {
	for _, value := range []int{10, 35, 90} {
		line := fmt.Sprintf("COTTENMAX_TRAFFIC_PROFILE = \"low\"\nCOTTENMAX_LOW_REDUCTION_PERCENT = %d", value)
		cfg, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelCottenMax, line))
		if err != nil || cfg.CottenMaxLowReductionPercent != value {
			t.Fatalf("reduction %d did not survive loading: cfg=%d err=%v", value, cfg.CottenMaxLowReductionPercent, err)
		}
	}
	for _, value := range []int{-1, 0, 9, 91, 100} {
		line := fmt.Sprintf("COTTENMAX_LOW_REDUCTION_PERCENT = %d", value)
		if _, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelCottenMax, line)); err == nil || !strings.Contains(err.Error(), "COTTENMAX_LOW_REDUCTION_PERCENT") {
			t.Fatalf("invalid reduction %d: %v", value, err)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	binder, err := NewClientConfigFlagBinder(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--cottenmax-low-reduction-percent", "70"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfigWithOverrides(trafficProfileConfigFile(t, TunnelCottenMax, ""), binder.Overrides())
	if err != nil || cfg.CottenMaxLowReductionPercent != 70 {
		t.Fatalf("CLI reduction lost: %d %v", cfg.CottenMaxLowReductionPercent, err)
	}
}

func TestCottenMaxTrafficProfileCommandLine(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	binder, err := NewClientConfigFlagBinder(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--cottenmax-traffic-profile", "low"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfigWithOverrides(trafficProfileConfigFile(t, TunnelCottenMax, ""), binder.Overrides())
	if err != nil || cfg.CottenMaxTrafficProfile != CottenMaxTrafficLow {
		t.Fatalf("CLI override did not reach final config: profile=%q err=%v", cfg.CottenMaxTrafficProfile, err)
	}
}

func TestCottenMaxTrafficProfileRejectsUnknown(t *testing.T) {
	_, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelCottenMax, `COTTENMAX_TRAFFIC_PROFILE = "turbo"`))
	if err == nil || !strings.Contains(err.Error(), "COTTENMAX_TRAFFIC_PROFILE") {
		t.Fatalf("unexpected validation result: %v", err)
	}
}

func TestCottenMaxTrafficProfileDoesNotChangeLegacyTuning(t *testing.T) {
	cfg, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelLegacy, `COTTENMAX_TRAFFIC_PROFILE = "low"`))
	if err != nil {
		t.Fatal(err)
	}
	full, err := LoadClientConfig(trafficProfileConfigFile(t, TunnelLegacy, `COTTENMAX_TRAFFIC_PROFILE = "full"`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QueryRateLimitPerSecond != full.QueryRateLimitPerSecond ||
		cfg.QueryRateLimitBurst != full.QueryRateLimitBurst ||
		cfg.MaxActiveStreams != full.MaxActiveStreams ||
		cfg.ResolverDiscoveryConcurrency != full.ResolverDiscoveryConcurrency ||
		cfg.ResolverDiscoveryPaceMilliseconds != full.ResolverDiscoveryPaceMilliseconds {
		t.Fatal("Max profile changed legacy tuning")
	}
}

func TestCottenMaxTrafficProfileOverrideAndGenericBudgets(t *testing.T) {
	path := trafficProfileConfigFile(t, TunnelCottenMax, "")
	cfg, err := LoadClientConfigWithOverrides(path, ClientConfigOverrides{Values: map[string]any{
		"CottenMaxTrafficProfile": " LOW ",
	}})
	if err != nil || cfg.CottenMaxTrafficProfile != CottenMaxTrafficLow {
		t.Fatalf("profile override did not reach final config: profile=%q err=%v", cfg.CottenMaxTrafficProfile, err)
	}
	_, err = LoadClientConfigWithOverrides(path, ClientConfigOverrides{Values: map[string]any{
		"CottenMaxTrafficProfile": CottenMaxTrafficLow,
		"QueryRateLimitPerSecond": float64(25),
	}})
	if err == nil || !strings.Contains(err.Error(), "QUERY_RATE_LIMIT_") {
		t.Fatalf("generic query budget must remain unsupported in Max: %v", err)
	}
}
