package config

// optionHelp supplements generated flag names with the constraints users need
// before choosing a tunnel mode. It does not change parsing or defaults.
func optionHelp(key string, server bool) string {
	if server {
		switch key {
		case "TUNNEL_MODE":
			return "Compatibility setting: updated server accepts normal CottenDNS and CottenMax beta together; clients choose their mode"
		case "COTTENMAX_KEY_FILE":
			return "Old experimental identity override only; normally leave empty and reuse the existing encryption credential"
		}
		return ""
	}
	switch key {
	case "COTTENMAX_FEC_DOWNLOAD_ENABLED":
		return "Optional Max download parity recovery; default off; FEC-capable server required; extra bandwidth"
	case "COTTENMAX_FEC_DATA_SHARDS":
		return "Max download FEC block size, 2..16; original data is never held for a full block"
	case "COTTENMAX_FEC_PARITY_SHARDS":
		return "Max download FEC recovery shards per block, 1..4"
	case "COTTENMAX_MAX_INFLIGHT":
		return "Max global query window, 1..4096; default 256; independent from candidate-list size"
	case "RESOLVER_DISCOVERY_WANT":
		return "Desired distinct healthy Max discovery resolvers, 1..4096; checks remain bounded and paced"
	case "TUNNEL_MODE":
		return "legacy (normal, default) or cottenmax (CottenMax beta); updated server required; same domain/key; restart client to switch"
	case "RESOLVER_TRANSPORT":
		return "auto, udp, tcp, dot, doh, doh3 (HTTP/3), doq; encrypted modes require a compatible resolver; Max does not downgrade to plaintext"
	case "RESOLVER_DISCOVERY_ENABLED":
		return "Opt-in authenticated resolver discovery for Max; default off"
	case "RESOLVER_DISCOVERY_CACHE_FILE":
		return "Optional Max resolver hint cache; re-authenticates candidates; separate network labels with RESOLVER_DISCOVERY_NETWORK_ID"
	case "DNS_PADDING_BLOCK_SIZE":
		return "Opt-in EDNS query padding: 0 off, 16..4096 bytes with encrypted resolver transport only"
	case "QNAME_LABEL_COUNT_JITTER":
		return "Opt-in Max label-count shaping; default off"
	case "COTTENMAX_QNAME_LOSS_GUARD":
		return "Experimental Max QNAME loss guard; default off; test on the affected network"
	case "COTTENMAX_SERVER_PUBLIC_KEY":
		return "Optional legacy Max identity pin; normally empty because Max reuses the existing encryption credential"
	case "COTTENMAX_FAILOVER_AFTER_MILLISECONDS":
		return "New-connection domain failover timeout, 100..60000 ms; existing streams are not migrated"
	}
	return ""
}
