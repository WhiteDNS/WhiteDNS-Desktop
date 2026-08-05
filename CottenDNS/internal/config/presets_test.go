package config

import "testing"

// The high-latency preset exists because the stock ARQ timings assume a short
// round trip. It is server-only, and explicit keys must still win over it.
func TestServerHighLatencyPreset(t *testing.T) {
	cfg := &ServerConfig{ConfigPreset: "high-latency"}
	if err := applyServerConfigPreset(cfg, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if cfg.ARQInitialRTOSeconds != 1.0 || cfg.ARQMaxRTOSeconds != 4.0 {
		t.Fatalf("retransmit timeout was not widened for a long path: %v/%v",
			cfg.ARQInitialRTOSeconds, cfg.ARQMaxRTOSeconds)
	}
	if cfg.ARQWindowSize != 4096 || cfg.MaxPacketsPerBatch != 32 {
		t.Fatalf("window and batch must cover a full round trip: %d/%d",
			cfg.ARQWindowSize, cfg.MaxPacketsPerBatch)
	}
	if cfg.SessionTimeoutSecs != 0 {
		t.Fatalf("the preset must not extend session retention: %v", cfg.SessionTimeoutSecs)
	}

	// An operator's own value wins.
	explicit := &ServerConfig{ConfigPreset: "high-latency", ARQInitialRTOSeconds: 2.0}
	if err := applyServerConfigPreset(explicit, func(key string) bool {
		return key == "ARQ_INITIAL_RTO_SECONDS"
	}); err != nil {
		t.Fatal(err)
	}
	if explicit.ARQInitialRTOSeconds != 2.0 {
		t.Fatalf("explicit key was overwritten by the preset: %v", explicit.ARQInitialRTOSeconds)
	}

	// Aliases resolve, and the client must not accept a server-only preset.
	if normalizeConfigPresetName("HIGH_LATENCY") != "high-latency" {
		t.Fatal("alias did not normalize")
	}
	if isKnownConfigPreset("high-latency") {
		t.Fatal("high-latency must not be offered to clients")
	}
	if !isKnownServerConfigPreset("high-latency") {
		t.Fatal("server must accept high-latency")
	}
}
