// Package tunnelinfo describes the existing tunnel modes to terminal users.
// It contains presentation only; it never changes configuration or credentials.
package tunnelinfo

import (
	"fmt"
	"strings"

	"cottendns-go/internal/config"
)

func ModeLabel(mode string) string {
	if mode == config.TunnelCottenMax {
		return "CottenMax beta"
	}
	return "Normal CottenDNS"
}

// Client returns setup and fallback guidance without exposing credentials.
func Client(cfg config.ClientConfig) []string {
	lines := []string{
		"Mode: " + ModeLabel(cfg.TunnelMode) + " | resolver transport: " + cfg.ResolverTransport,
		"Normal and Max use the same client profile, delegated domains and ENCRYPTION_KEY.",
		"Switch TUNNEL_MODE between legacy and cottenmax, then restart the client. The server does not need a mode switch.",
	}
	if cfg.TunnelMode == config.TunnelCottenMax {
		lines = append(lines,
			"Beta: update the CottenDNS server first. Max does not work with old servers or automatically downgrade to normal mode.",
			"If Max cannot connect, select legacy and reconnect with the same profile; keep a working normal-mode backup.",
			"Max transports: auto (independent UDP/TCP DNS paths), udp, tcp, dot, doh, doh3 and doq.",
			"Max scan-only authenticates both DNS transports in auto mode and reports separate measured wire sizes; live traffic uses the same paths.",
			"Encrypted resolver modes require a compatible resolver and verified TLS/name or certificate pin; Max never falls back to plaintext DNS.",
			fmt.Sprintf("Options: discovery %s; cache %s; padding %s; label jitter %s; QNAME loss guard %s.", onOff(cfg.ResolverDiscoveryEnabled), onOff(strings.TrimSpace(cfg.ResolverDiscoveryCacheFile) != ""), padding(cfg.DNSPaddingBlockSize), onOff(cfg.QNameLabelJitter), onOff(cfg.CottenMaxQNameLossGuard)),
			"Optional settings: RESOLVER_DISCOVERY_*, DNS_PADDING_BLOCK_SIZE (encrypted modes only), QNAME_LABEL_COUNT_JITTER and COTTENMAX_QNAME_LOSS_GUARD.",
			"DOMAINS + STANDBY_DOMAINS allow up to 8 delegated domains. Failover applies to new connections; existing streams are not migrated.",
			"Keep defaults initially. Max does not support hard QUERY_RATE_LIMIT_* budgets; use normal mode when those budgets are required.",
		)
		if strings.TrimSpace(cfg.CottenMaxServerPublicKey) != "" {
			lines = append(lines, "An optional Max server public-key pin is configured. Preserve its matching server identity during migration.")
		}
	} else {
		lines = append(lines,
			"CottenMax beta is optional: update the server first, then set TUNNEL_MODE=cottenmax in this profile. No new domain or key is needed.",
			"The dashboard displays the active mode. Press h or ? for setup and advanced-option guidance.",
		)
	}
	return append(lines, "Guide: COTTENMAX_OPTIONS.md (docs/ in a source checkout; advanced settings and beta limitations).")
}

// Server describes the dual-mode server setup. Runtime startup logs remain the
// authority for domain-specific Max eligibility and listener readiness.
func Server(cfg config.ServerConfig) []string {
	lines := []string{
		"Modes: Normal CottenDNS + CottenMax beta; requests select the mode automatically on the same DNS listener.",
		"Clients choose TUNNEL_MODE=legacy or cottenmax. The server TUNNEL_MODE setting does not disable normal clients.",
		"Beta setup: update server and clients; keep the existing delegated DOMAIN and encrypt_key.txt credential. No additional Max service or delegation is required.",
		fmt.Sprintf("Capacity ceilings: %d sessions; normal %d streams/session; Max %d streams/session. Session counts are not guaranteed user capacity.", cfg.MaxActiveSessions, cfg.MaxStreamsPerSession, min(cfg.MaxStreamsPerSession, cfg.CottenMaxMaxStreams, 512)),
	}
	if strings.TrimSpace(cfg.CottenMaxKeyFile) != "" {
		lines = append(lines, "Compatibility Max identity override is configured. Keep matching client public-key pins until a coordinated migration to the existing shared credential.")
	} else {
		lines = append(lines, "Max derives its identity from the existing credential; no separate Max key or client public-key transfer is needed.")
	}
	return append(lines,
		"Check startup logs for Max availability and skipped long domains; normal CottenDNS remains available on those domains.",
		"HTTP3/DoQ are client-to-resolver options and do not create authoritative listeners. Existing server DoT/DoH listeners are configured separately.",
		"Guide: COTTENMAX_OPTIONS.md (docs/ in a source checkout). For beta fallback, clients select legacy and reconnect using the same profile.",
	)
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}
func padding(size int) string {
	if size == 0 {
		return "off"
	}
	return fmt.Sprintf("%d bytes", size)
}
