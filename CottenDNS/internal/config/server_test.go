// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestServerClientPolicyRangesAreWireSafe(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MaxAllowedClientPacketDuplication = 99
	cfg.MaxAllowedClientSetupPacketDuplication = -2
	cfg.MaxAllowedClientUploadMTU = 70000
	cfg.MaxAllowedClientDownloadMTU = 70000
	cfg.MaxAllowedClientRxTxWorkers = 999
	cfg.MinAllowedClientPingAggressiveInterval = 8
	cfg.MaxAllowedClientPacketsPerBatch = 999
	cfg.MaxAllowedClientARQWindowSize = 999999
	cfg.MaxAllowedClientARQDataNackMaxGap = 999
	cfg.MinAllowedClientCompressionMinSize = 999999
	cfg.MinAllowedClientARQInitialRTOSeconds = 8

	got, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatalf("finalizeServerConfig: %v", err)
	}
	if got.MaxAllowedClientPacketDuplication != 15 || got.MaxAllowedClientSetupPacketDuplication != 0 ||
		got.MaxAllowedClientUploadMTU != 255 || got.MaxAllowedClientDownloadMTU != 4096 ||
		got.MaxAllowedClientRxTxWorkers != 255 || got.MinAllowedClientPingAggressiveInterval != 1 ||
		got.MaxAllowedClientPacketsPerBatch != 255 || got.MaxAllowedClientARQWindowSize != 65535 ||
		got.MaxAllowedClientARQDataNackMaxGap != 255 || got.MinAllowedClientCompressionMinSize != 65535 ||
		got.MinAllowedClientARQInitialRTOSeconds != 1 {
		t.Fatalf("policy was not clamped to wire-safe ranges: %+v", got)
	}
}

func TestLoadServerConfigWithOverridesAppliesFlagPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfigWithOverrides(configPath, ServerConfigOverrides{
		Values: map[string]any{
			"UDPPort":                           5300,
			"Domain":                            []string{"flag.example.com", "alt.example.com"},
			"DataEncryptionMethod":              2,
			"SupportedUploadCompressionTypes":   []int{0, 1},
			"SupportedDownloadCompressionTypes": []int{0, 1, 3},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigWithOverrides returned error: %v", err)
	}

	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected udp port override: got=%d want=%d", cfg.UDPPort, 5300)
	}
	if len(cfg.Domain) != 2 || cfg.Domain[0] != "flag.example.com" || cfg.Domain[1] != "alt.example.com" {
		t.Fatalf("unexpected domain override: %+v", cfg.Domain)
	}
	if cfg.DataEncryptionMethod != 2 {
		t.Fatalf("unexpected data encryption override: got=%d want=%d", cfg.DataEncryptionMethod, 2)
	}
	if len(cfg.SupportedUploadCompressionTypes) != 2 || cfg.SupportedUploadCompressionTypes[0] != 0 || cfg.SupportedUploadCompressionTypes[1] != 1 {
		t.Fatalf("unexpected upload compression override: %+v", cfg.SupportedUploadCompressionTypes)
	}
	if len(cfg.SupportedDownloadCompressionTypes) != 3 {
		t.Fatalf("unexpected download compression override: %+v", cfg.SupportedDownloadCompressionTypes)
	}
}

func TestLoadServerConfigAppliesPresetAndPreservesExplicitValues(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
CONFIG_PRESET = "tcp_survival"
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["v.domain.com"]
TCP_MAX_CONNS_PER_IP = 64
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 2]
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}

	if cfg.ConfigPreset != "tcp-survival" {
		t.Fatalf("unexpected preset: got=%q want=tcp-survival", cfg.ConfigPreset)
	}
	if !cfg.TCPListenerEnabled || cfg.TCPMaxConns != 4096 {
		t.Fatalf("tcp-survival preset did not tune listener: enabled=%v max=%d", cfg.TCPListenerEnabled, cfg.TCPMaxConns)
	}
	if cfg.TCPMaxConnsPerIP != 64 {
		t.Fatalf("explicit per-IP cap should win over preset, got %d", cfg.TCPMaxConnsPerIP)
	}
	if cfg.MaxPacketsPerBatch != 12 || cfg.ARQWindowSize != 3000 {
		t.Fatalf("tcp-survival throughput settings not applied: batch=%d window=%d", cfg.MaxPacketsPerBatch, cfg.ARQWindowSize)
	}
	if len(cfg.SupportedUploadCompressionTypes) != 2 || cfg.SupportedUploadCompressionTypes[1] != 2 {
		t.Fatalf("explicit upload compression list should win over preset: %+v", cfg.SupportedUploadCompressionTypes)
	}
	if !containsInt(cfg.SupportedDownloadCompressionTypes, 2) {
		t.Fatalf("preset download compression should include LZ4: %+v", cfg.SupportedDownloadCompressionTypes)
	}
}

func TestLoadServerConfigWithOverridesAppliesConfigPreset(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["v.domain.com"]
TCP_MAX_CONNS_PER_IP = 64
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfigWithOverrides(configPath, ServerConfigOverrides{
		Values: map[string]any{
			"ConfigPreset":     "speed",
			"TCPMaxConnsPerIP": 32,
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigWithOverrides returned error: %v", err)
	}

	if cfg.ConfigPreset != "speed" {
		t.Fatalf("unexpected preset: got=%q want=speed", cfg.ConfigPreset)
	}
	if cfg.TCPMaxConns != 4096 || cfg.MaxPacketsPerBatch != 12 {
		t.Fatalf("speed preset not applied: tcpMax=%d batch=%d", cfg.TCPMaxConns, cfg.MaxPacketsPerBatch)
	}
	if cfg.MaxConcurrentRequests != 16384 {
		t.Fatalf("speed preset queue count = %d, want byte-budget-compatible 16384", cfg.MaxConcurrentRequests)
	}
	if cfg.UDPReaders < 4 || cfg.UDPReaders > 16 || cfg.DNSRequestWorkers < 8 || cfg.DNSRequestWorkers > 64 {
		t.Fatalf("speed preset worker sizing out of range: readers=%d workers=%d", cfg.UDPReaders, cfg.DNSRequestWorkers)
	}
	if cfg.TCPMaxConnsPerIP != 32 {
		t.Fatalf("explicit override should win over preset, got %d", cfg.TCPMaxConnsPerIP)
	}
}

func TestServerConfigFlagBinderBuildsOverridesForSetFlagsOnly(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	binder, err := NewServerConfigFlagBinder(fs)
	if err != nil {
		t.Fatalf("NewServerConfigFlagBinder returned error: %v", err)
	}

	if err := fs.Parse([]string{
		"-udp-port=5300",
		"-domain=a.example.com,b.example.com",
		"-use-external-socks5",
		"-supported-upload-compression-types=0,1",
		"-data-encryption-method=2",
	}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	overrides := binder.Overrides()
	if got, ok := overrides.Values["UDPPort"].(int); !ok || got != 5300 {
		t.Fatalf("unexpected udp port override: %#v", overrides.Values["UDPPort"])
	}
	if got, ok := overrides.Values["UseExternalSOCKS5"].(bool); !ok || !got {
		t.Fatalf("unexpected socks5 override: %#v", overrides.Values["UseExternalSOCKS5"])
	}
	if got, ok := overrides.Values["DataEncryptionMethod"].(int); !ok || got != 2 {
		t.Fatalf("unexpected encryption method override: %#v", overrides.Values["DataEncryptionMethod"])
	}
	gotDomains, ok := overrides.Values["Domain"].([]string)
	if !ok || len(gotDomains) != 2 || gotDomains[0] != "a.example.com" || gotDomains[1] != "b.example.com" {
		t.Fatalf("unexpected domains override: %#v", overrides.Values["Domain"])
	}
	gotCompressions, ok := overrides.Values["SupportedUploadCompressionTypes"].([]int)
	if !ok || len(gotCompressions) != 2 || gotCompressions[0] != 0 || gotCompressions[1] != 1 {
		t.Fatalf("unexpected compression override: %#v", overrides.Values["SupportedUploadCompressionTypes"])
	}
	if _, exists := overrides.Values["UDPHost"]; exists {
		t.Fatalf("did not expect unset flag to appear in overrides: %#v", overrides.Values["UDPHost"])
	}
}

func containsInt(values []int, needle int) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
