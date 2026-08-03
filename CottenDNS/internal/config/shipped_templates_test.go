// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// shipped_templates_test.go — guards the config templates that the one-line
// installers deploy verbatim (server_config.toml.simple / client_config.toml.simple).
// They must parse cleanly through the real loaders and expose the newer feature
// knobs, so a fresh install always carries them.
// ==============================================================================

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(name string) string {
	// This test file lives in internal/config; the templates are two levels up.
	return filepath.Join("..", "..", name)
}

func TestShippedServerTemplateParsesWithFeatureKnobs(t *testing.T) {
	cfg, err := LoadServerConfig(repoFile("server_config.toml.simple"))
	if err != nil {
		t.Fatalf("server_config.toml.simple failed to load: %v", err)
	}
	// Auto-detect and the FEC defaults must be present and sane so a fresh
	// deploy honors whatever delivery/encryption method the client picks.
	if !cfg.EncryptionAutoDetect {
		t.Errorf("ENCRYPTION_AUTO_DETECT should default true in the shipped template")
	}
	if cfg.DataEncryptionMethod != 3 {
		t.Errorf("server DATA_ENCRYPTION_METHOD = %d, want authenticated AES-128-GCM method 3", cfg.DataEncryptionMethod)
	}
	if cfg.FECBlockSize <= 0 || cfg.FECParity <= 0 {
		t.Errorf("FEC defaults not finalized: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
	if cfg.FECBlockSize+cfg.FECParity > 256 {
		t.Errorf("FEC shard total exceeds 256: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
	if cfg.MaxPacketSize != 4096 {
		t.Errorf("MAX_PACKET_SIZE = %d, want DNS-sized 4096-byte ingress buffers", cfg.MaxPacketSize)
	}
	if cfg.MaxIngressQueueBytes != 64*1024*1024 {
		t.Errorf("MAX_INGRESS_QUEUE_BYTES = %d, want 64 MiB", cfg.MaxIngressQueueBytes)
	}
}

func TestLegacyServerPacketBufferIsClampedOnUpgrade(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MaxPacketSize = 65535
	finalized, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.MaxPacketSize != 4096 {
		t.Fatalf("legacy MAX_PACKET_SIZE was not clamped: got %d want 4096", finalized.MaxPacketSize)
	}
}

func TestShippedClientTemplateParses(t *testing.T) {
	// The shipped client template has a placeholder ENCRYPTION_KEY the user
	// fills in (it comes from the server), so a standalone load is expected to
	// fail at exactly that validation — and nowhere earlier. Reaching the
	// key-required check proves the TOML and QUERY_TYPES (incl. the new NULL /
	// HTTPS / SVCB names) are structurally valid.
	_, err := LoadClientConfig(repoFile("client_config.toml.simple"))
	if err == nil {
		return // a key was present; fully valid.
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Fatalf("client_config.toml.simple failed before the key check (template is malformed): %v", err)
	}
}

func TestShippedClientTemplateKeepsLongSessionRecoveryDefaults(t *testing.T) {
	cfg, err := loadClientConfigFile(repoFile("client_config.toml.simple"))
	if err != nil {
		t.Fatalf("client_config.toml.simple failed to load: %v", err)
	}
	if cfg.AutoDisableTimeoutWindowSeconds != 90.0 {
		t.Fatalf("AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS = %.1f, want 90.0", cfg.AutoDisableTimeoutWindowSeconds)
	}
	if cfg.ARQInactivityTimeoutSeconds != 600.0 {
		t.Fatalf("ARQ_INACTIVITY_TIMEOUT_SECONDS = %.1f, want 600.0", cfg.ARQInactivityTimeoutSeconds)
	}
}

func TestBundledPresetTemplatesParse(t *testing.T) {
	serverPresets := []string{
		"server_config.speed.toml",
		"server_config.survival.toml",
		"server_config.tcp-survival.toml",
	}
	for _, name := range serverPresets {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServerConfig(repoFile(name)); err != nil {
				t.Fatalf("%s failed to load: %v", name, err)
			}
		})
	}

	clientPresets := []string{
		"client_config.speed.toml",
		"client_config.survival.toml",
		"client_config.tcp-survival.toml",
	}
	for _, name := range clientPresets {
		t.Run(name, func(t *testing.T) {
			_, err := LoadClientConfig(repoFile(name))
			if err == nil {
				return
			}
			if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
				t.Fatalf("%s failed before the key check (template is malformed): %v", name, err)
			}
		})
	}
}
