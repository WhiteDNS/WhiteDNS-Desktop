package config

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	TunnelLegacy    = "legacy"
	TunnelCottenMax = "cottenmax"

	CottenMaxTrafficFull = "full"
	CottenMaxTrafficLow  = "low"
)

func normalizeCottenMaxTrafficProfile(profile string) (string, error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = CottenMaxTrafficFull
	}
	if profile != CottenMaxTrafficFull && profile != CottenMaxTrafficLow {
		return "", fmt.Errorf("invalid COTTENMAX_TRAFFIC_PROFILE %q (want full or low)", profile)
	}
	return profile, nil
}

func normalizeTunnelMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = TunnelLegacy
	}
	if mode != TunnelLegacy && mode != TunnelCottenMax {
		return "", fmt.Errorf("invalid TUNNEL_MODE %q (want legacy or cottenmax)", mode)
	}
	return mode, nil
}

func validateCottenMaxClient(c ClientConfig) error {
	if c.TunnelMode != TunnelCottenMax {
		return nil
	}
	if c.ResolverDiscoverySampleRanges < 0 || c.ResolverDiscoverySampleRanges > 4096 {
		return fmt.Errorf("RESOLVER_DISCOVERY_SAMPLE_RANGES must be 0..4096")
	}
	country := strings.ToLower(strings.TrimSpace(c.ResolverDiscoveryCountry))
	if country != "" && (len(country) != 2 || country[0] < 'a' || country[0] > 'z' || country[1] < 'a' || country[1] > 'z') {
		return fmt.Errorf("RESOLVER_DISCOVERY_COUNTRY must be a two-letter country code")
	}
	if c.QueryRateLimited() {
		return fmt.Errorf("experimental cottenmax does not yet support hard QUERY_RATE_LIMIT_* budgets; use legacy")
	}
	if strings.TrimSpace(c.EncryptionKey) == "" {
		return fmt.Errorf("cottenmax requires the existing ENCRYPTION_KEY")
	}
	if strings.TrimSpace(c.CottenMaxServerPublicKey) != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.CottenMaxServerPublicKey))
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid optional COTTENMAX_SERVER_PUBLIC_KEY")
		}
	}
	if c.CottenMaxHoldMilliseconds < 0 || c.CottenMaxHoldMilliseconds > 1500 || c.CottenMaxHoldMilliseconds%100 != 0 {
		return fmt.Errorf("COTTENMAX_HOLD_MILLISECONDS must be 0..1500 in 100ms steps")
	}
	if c.ResolverTLSInsecureSkipVerify && strings.TrimSpace(c.ResolverTLSPin) == "" &&
		(c.ResolverTransport == "dot" || c.ResolverTransport == "doh" || c.ResolverTransport == "doh3" || c.ResolverTransport == "doq") {
		return fmt.Errorf("cottenmax encrypted DNS requires certificate verification or RESOLVER_TLS_PIN")
	}
	domains := AppendNewDomains(append([]string(nil), c.Domains...), c.StandbyDomains, nil)
	if len(domains) < 1 || len(domains) > 8 {
		return fmt.Errorf("cottenmax requires 1..8 unique active/standby domains")
	}
	if c.CottenMaxFailoverAfterMilliseconds < 100 || c.CottenMaxFailoverAfterMilliseconds > 60000 {
		return fmt.Errorf("COTTENMAX_FAILOVER_AFTER_MILLISECONDS must be 100..60000")
	}
	if c.CottenMaxSafeQName < 64 || c.CottenMaxSafeQName > 253 || c.CottenMaxMaxQName < c.CottenMaxSafeQName || c.CottenMaxMaxQName > 253 {
		return fmt.Errorf("COTTENMAX_SAFE_QNAME/MAX_QNAME must satisfy 64 <= safe <= max <= 253")
	}
	if c.CottenMaxMaxAnswer < 512 || c.CottenMaxMaxAnswer > 1232 {
		return fmt.Errorf("COTTENMAX_MAX_ANSWER must be 512..1232")
	}
	if c.CottenMaxMaxPathWindow < 1 || c.CottenMaxMaxPathWindow > 1024 || c.CottenMaxMaxInflight < 1 || c.CottenMaxMaxInflight > 4096 {
		return fmt.Errorf("COTTENMAX_MAX_PATH_WINDOW must be 1..1024 and MAX_INFLIGHT 1..4096")
	}
	if c.CottenMaxFECDownloadEnabled && (c.CottenMaxFECDataShards < 2 || c.CottenMaxFECDataShards > 16 || c.CottenMaxFECParityShards < 1 || c.CottenMaxFECParityShards > 4) {
		return fmt.Errorf("COTTENMAX_FEC_DATA_SHARDS must be 2..16 and PARITY_SHARDS 1..4")
	}
	if c.CottenMaxSessionIdleMilliseconds < 1000 || c.CottenMaxSessionIdleMilliseconds > 90000 {
		return fmt.Errorf("COTTENMAX_SESSION_IDLE_MILLISECONDS must be 1000..90000")
	}
	if c.QNameLabelLength < 16 || c.QNameLabelLength > 63 {
		return fmt.Errorf("cottenmax QNAME_LABEL_LENGTH must be 16..63")
	}

	return nil
}

func (c ServerConfig) CottenMaxKeyPath() string {
	name := c.CottenMaxKeyFile
	if name == "" {
		name = "cottenmax_key.txt"
	}
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.ConfigDir, name)
}

func validateResolverOptions(c ClientConfig) error {
	if c.DNSPaddingBlockSize != 0 {
		if c.DNSPaddingBlockSize < 16 || c.DNSPaddingBlockSize > 4096 {
			return fmt.Errorf("DNS_PADDING_BLOCK_SIZE must be 0 (off) or 16..4096")
		}
		if c.ResolverTransport != "dot" && c.ResolverTransport != "doh" && c.ResolverTransport != "doh3" && c.ResolverTransport != "doq" {
			return fmt.Errorf("DNS_PADDING_BLOCK_SIZE requires an encrypted resolver transport")
		}
	}
	if c.ResolverDiscoveryWant < 1 || c.ResolverDiscoveryWant > 4096 || c.ResolverDiscoveryConcurrency < 1 || c.ResolverDiscoveryConcurrency > 64 || c.ResolverDiscoveryPaceMilliseconds < 1 || c.ResolverDiscoveryPaceMilliseconds > 60000 {
		return fmt.Errorf("discovery WANT must be 1..4096, CONCURRENCY 1..64 and PACE_MILLISECONDS 1..60000")
	}
	if len(c.ResolverDiscoveryCandidates) > 256 {
		return fmt.Errorf("RESOLVER_DISCOVERY_CANDIDATES is limited to 256 endpoints")
	}
	if len(c.ResolverDiscoveryNetworkID) > 256 {
		return fmt.Errorf("RESOLVER_DISCOVERY_NETWORK_ID is limited to 256 characters")
	}
	if c.QNameLabelJitter && c.TunnelMode != TunnelCottenMax {
		return fmt.Errorf("QNAME_LABEL_COUNT_JITTER currently requires cottenmax")
	}
	return nil
}
