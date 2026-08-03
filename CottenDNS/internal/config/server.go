// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"cottendns-go/internal/compression"
)

type ServerConfig struct {
	ConfigDir    string `toml:"-"`
	ConfigPath   string `toml:"-"`
	ConfigPreset string `toml:"CONFIG_PRESET"`
	ProtocolType string `toml:"PROTOCOL_TYPE"`
	UDPHost      string `toml:"UDP_HOST"`
	UDPPort      int    `toml:"UDP_PORT"`
	UDPReaders   int    `toml:"UDP_READERS"`
	// TCPListenerEnabled also serves DNS-over-TCP on the same host:port, so
	// clients on networks that filter or truncate UDP/53 can fall back to TCP/53.
	// Default true. TCPMaxConns caps concurrent TCP connections (0 = default).
	TCPListenerEnabled        bool    `toml:"TCP_LISTENER_ENABLED"`
	TCPMaxConns               int     `toml:"TCP_MAX_CONNS"`
	TCPMaxConnsPerIP          int     `toml:"TCP_MAX_CONNS_PER_IP"`
	TCPMaxQueriesPerConn      int     `toml:"TCP_MAX_QUERIES_PER_CONN"`
	TCPReadIdleTimeoutSeconds float64 `toml:"TCP_READ_IDLE_TIMEOUT_SECONDS"`
	TCPWriteTimeoutSeconds    float64 `toml:"TCP_WRITE_TIMEOUT_SECONDS"`

	// Encrypted DNS listeners. These are *optional add-ons*, not part of the
	// UDP/TCP-53 fallback chain: a client only uses DoT/DoH when it explicitly
	// selects that transport, and if it fails the client itself falls back to
	// UDP/TCP 53. Both share the exact transport-agnostic packet handler used by
	// the UDP/TCP paths, so all tunnel logic is identical. DoT is DNS-over-TLS
	// (RFC 7858): the same length-prefixed framing as TCP/53, wrapped in TLS.
	// DoH is DNS-over-HTTPS (RFC 8484): DNS wire-format in an HTTP/2 request body.
	DoTListenerEnabled bool   `toml:"DOT_LISTENER_ENABLED"`
	DoTListenHost      string `toml:"DOT_LISTEN_HOST"`
	DoTListenPort      int    `toml:"DOT_LISTEN_PORT"`
	DoHListenerEnabled bool   `toml:"DOH_LISTENER_ENABLED"`
	DoHListenHost      string `toml:"DOH_LISTEN_HOST"`
	DoHListenPort      int    `toml:"DOH_LISTEN_PORT"`
	// DoHPath is the request path the DoH endpoint answers on (RFC 8484 uses
	// /dns-query). Anything else 404s so the surface looks like a normal resolver.
	DoHPath string `toml:"DOH_PATH"`
	// DoHTLSEnabled chooses how DoH coexists on 443:
	//   true  (default) — CottenDNS terminates TLS itself. Combine with
	//                      DOH_SHARE_BACKEND to own 443 and SNI-route the rest.
	//   false           — "behind a proxy": CottenDNS serves plaintext HTTP/1.1 +
	//                      h2c on a LOCAL port, and the panel's own front (Xray
	//                      fallback / nginx / Caddy) terminates TLS on 443 and
	//                      forwards the DoH route here. This is the universally
	//                      compatible mode: the panel keeps 443 and every one of
	//                      its inbounds (VMess/VLESS/Trojan/xhttp/gRPC/ws/tls,
	//                      CDN-fronted, WireGuard-UDP) works untouched.
	DoHTLSEnabled bool `toml:"DOH_TLS_ENABLED"`
	// DoHShareBackend lets DoH share :443 with a co-hosted TLS service (Hiddify,
	// 3x-ui, ...). When set (e.g. "127.0.0.1:8443", where that service now
	// listens), the DoH listener peeks each connection's TLS SNI: SNI matching a
	// DOMAIN entry is served as DoH; every other connection is spliced untouched
	// to this backend so the co-hosted service keeps working. Empty = DoH owns its
	// port. The routing bias is fail-safe: any peek/parse uncertainty forwards to
	// the backend, so we never take 443 away from the other service.
	DoHShareBackend       string `toml:"DOH_SHARE_BACKEND"`
	DoHShareProxyProtocol bool   `toml:"DOH_SHARE_PROXY_PROTOCOL"`
	// DoHCoexistMode picks how DoH shares the box with a panel (3x-ui, Hiddify, ...):
	//
	//   "front"  (model B) — CottenDNS owns the TLS port, terminates TLS itself and
	//                        SNI-routes anything that is not ours to DOH_SHARE_BACKEND.
	//   "behind" (model A) — a panel owns 443; CottenDNS serves cleartext HTTP/1.1+h2c
	//                        on DOH_BEHIND_PORT and the panel's front forwards DoH to it.
	//   "auto"   (default) — decided at runtime by whoever holds the port: if the TLS
	//                        port binds we take model B, if it is already taken we fall
	//                        back to model A. Re-evaluated continuously, so installing
	//                        a panel later (or removing one) flips the model without a
	//                        config edit. This never takes 443 from an existing panel.
	DoHCoexistMode string `toml:"DOH_COEXIST_MODE"`
	// DoHBehindPort is the local cleartext port used whenever model A is active.
	DoHBehindPort int `toml:"DOH_BEHIND_PORT"`
	// Dedicated DoH admission limits. Reusing MAX_CONCURRENT_REQUESTS here can
	// permit roughly a gigabyte of request bodies, so HTTP has its own request,
	// byte, and per-client rate budgets.
	DoHMaxInflight       int      `toml:"DOH_MAX_INFLIGHT"`
	DoHMaxInflightBytes  int      `toml:"DOH_MAX_INFLIGHT_BYTES"`
	DoHRequestsPerSecond float64  `toml:"DOH_REQUESTS_PER_SECOND_PER_IP"`
	DoHRequestBurst      int      `toml:"DOH_REQUEST_BURST_PER_IP"`
	DoHTrustedProxyCIDRs []string `toml:"DOH_TRUSTED_PROXY_CIDRS"`
	// EncryptedMaxConns caps how many of TCP_MAX_CONNS the DoT/DoH listeners may
	// hold at once. The remainder stays permanently reserved for plain
	// DNS-over-TCP/53, so flooding the optional encrypted listeners can never
	// starve the survival fallback. 0 = three quarters of TCP_MAX_CONNS.
	EncryptedMaxConns int `toml:"ENCRYPTED_MAX_CONNS"`
	// TLS material for DoT/DoH. Resolution order (see buildStreamTLSConfig):
	//  1. TLSCertFile + TLSKeyFile when both are set — a real cert (best disguise).
	//  2. else ACME/Let's Encrypt for DOMAIN when ACMEEnabled — auto-obtained.
	//  3. else a self-signed cert generated at startup so the server still boots.
	TLSCertFile                  string `toml:"TLS_CERT_FILE"`
	TLSKeyFile                   string `toml:"TLS_KEY_FILE"`
	ACMEEnabled                  bool   `toml:"ACME_ENABLED"`
	ACMECacheDir                 string `toml:"ACME_CACHE_DIR"`
	ACMEEmail                    string `toml:"ACME_EMAIL"`
	SocketBufferSize             int    `toml:"SOCKET_BUFFER_SIZE"`
	MaxConcurrentRequests        int    `toml:"MAX_CONCURRENT_REQUESTS"`
	MaxIngressQueueBytes         int    `toml:"MAX_INGRESS_QUEUE_BYTES"`
	DNSRequestWorkers            int    `toml:"DNS_REQUEST_WORKERS"`
	DeferredSessionWorkers       int    `toml:"DEFERRED_SESSION_WORKERS"`
	DeferredSessionQueueLimit    int    `toml:"DEFERRED_SESSION_QUEUE_LIMIT"`
	SessionOrphanQueueInitialCap int    `toml:"SESSION_ORPHAN_QUEUE_INITIAL_CAPACITY"`
	StreamQueueInitialCapacity   int    `toml:"STREAM_QUEUE_INITIAL_CAPACITY"`
	DNSFragmentStoreCapacity     int    `toml:"DNS_FRAGMENT_STORE_CAPACITY"`
	SOCKS5FragmentStoreCapacity  int    `toml:"SOCKS5_FRAGMENT_STORE_CAPACITY"`
	MaxPacketSize                int    `toml:"MAX_PACKET_SIZE"`
	MaxStreamsPerSession         int    `toml:"MAX_STREAMS_PER_SESSION"`
	// MaxActiveSessions caps concurrent live tunnel sessions, protecting server
	// memory/CPU from being exhausted by session-init floods. The session-ID space
	// is 16-bit (65535 slots) but that many live sessions is far more load than a
	// single node should carry, so this defaults to 2048 (the TCP_MAX_CONNS ceiling).
	MaxActiveSessions int `toml:"MAX_ACTIVE_SESSIONS"`

	// Client policy ceilings, advertised to the client in SESSION_ACCEPT so it
	// clamps itself. Without them a single client configured with a huge ARQ
	// window, an aggressive ping interval, or heavy duplication can take a
	// disproportionate share of a public server.
	//
	// Every one of these defaults to 0, meaning "state no ceiling". When all of
	// them are 0 the server appends no policy block at all and SESSION_ACCEPT
	// is byte-for-byte what it was before, so upgrading changes nothing until
	// an operator opts in. The wire layout matches MasterDnsVPN's, so those
	// clients honour these ceilings too.
	MaxAllowedClientPacketDuplication      int     `toml:"MAX_ALLOWED_CLIENT_PACKET_DUPLICATION_COUNT"`
	MaxAllowedClientSetupPacketDuplication int     `toml:"MAX_ALLOWED_CLIENT_SETUP_PACKET_DUPLICATION_COUNT"`
	MaxAllowedClientUploadMTU              int     `toml:"MAX_ALLOWED_CLIENT_UPLOAD_MTU"`
	MaxAllowedClientDownloadMTU            int     `toml:"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU"`
	MaxAllowedClientRxTxWorkers            int     `toml:"MAX_ALLOWED_CLIENT_RX_TX_WORKERS"`
	MinAllowedClientPingAggressiveInterval float64 `toml:"MIN_ALLOWED_CLIENT_PING_AGGRESSIVE_INTERVAL_SECONDS"`
	MaxAllowedClientPacketsPerBatch        int     `toml:"MAX_ALLOWED_CLIENT_PACKETS_PER_BATCH"`
	MaxAllowedClientARQWindowSize          int     `toml:"MAX_ALLOWED_CLIENT_ARQ_WINDOW_SIZE"`
	MaxAllowedClientARQDataNackMaxGap      int     `toml:"MAX_ALLOWED_CLIENT_ARQ_DATA_NACK_MAX_GAP"`
	MinAllowedClientCompressionMinSize     int     `toml:"MIN_ALLOWED_CLIENT_COMPRESSION_MIN_SIZE"`
	MinAllowedClientARQInitialRTOSeconds   float64 `toml:"MIN_ALLOWED_CLIENT_ARQ_INITIAL_RTO_SECONDS"`

	MaxDNSResponseBytes               int      `toml:"MAX_DNS_RESPONSE_BYTES"`
	DropLogIntervalSecs               float64  `toml:"DROP_LOG_INTERVAL_SECONDS"`
	InvalidCookieWindowSecs           float64  `toml:"INVALID_COOKIE_WINDOW_SECONDS"`
	InvalidCookieErrorThreshold       int      `toml:"INVALID_COOKIE_ERROR_THRESHOLD"`
	SessionTimeoutSecs                float64  `toml:"SESSION_TIMEOUT_SECONDS"`
	SessionCleanupIntervalSecs        float64  `toml:"SESSION_CLEANUP_INTERVAL_SECONDS"`
	ClosedSessionRetentionSecs        float64  `toml:"CLOSED_SESSION_RETENTION_SECONDS"`
	SessionInitReuseTTLSeconds        float64  `toml:"SESSION_INIT_REUSE_TTL_SECONDS"`
	RecentlyClosedStreamTTLSeconds    float64  `toml:"RECENTLY_CLOSED_STREAM_TTL_SECONDS"`
	RecentlyClosedStreamCap           int      `toml:"RECENTLY_CLOSED_STREAM_CAP"`
	TerminalStreamRetentionSeconds    float64  `toml:"TERMINAL_STREAM_RETENTION_SECONDS"`
	MaxPacketsPerBatch                int      `toml:"MAX_PACKETS_PER_BATCH"`
	PacketBlockControlDuplication     int      `toml:"PACKET_BLOCK_CONTROL_DUPLICATION"`
	DNSUpstreamServers                []string `toml:"DNS_UPSTREAM_SERVERS"`
	DNSUpstreamTimeoutSecs            float64  `toml:"DNS_UPSTREAM_TIMEOUT"`
	DNSInflightWaitTimeoutSecs        float64  `toml:"DNS_INFLIGHT_WAIT_TIMEOUT_SECONDS"`
	SOCKSConnectTimeoutSecs           float64  `toml:"SOCKS_CONNECT_TIMEOUT"`
	DNSFragmentAssemblyTimeoutSecs    float64  `toml:"DNS_FRAGMENT_ASSEMBLY_TIMEOUT"`
	StreamSetupAckTTLSeconds          float64  `toml:"STREAM_SETUP_ACK_TTL_SECONDS"`
	StreamResultPacketTTLSeconds      float64  `toml:"STREAM_RESULT_PACKET_TTL_SECONDS"`
	StreamFailurePacketTTLSeconds     float64  `toml:"STREAM_FAILURE_PACKET_TTL_SECONDS"`
	DNSCacheMaxRecords                int      `toml:"DNS_CACHE_MAX_RECORDS"`
	DNSCacheTTLSeconds                float64  `toml:"DNS_CACHE_TTL_SECONDS"`
	UseExternalSOCKS5                 bool     `toml:"USE_EXTERNAL_SOCKS5"`
	SOCKS5Auth                        bool     `toml:"SOCKS5_AUTH"`
	SOCKS5User                        string   `toml:"SOCKS5_USER"`
	SOCKS5Pass                        string   `toml:"SOCKS5_PASS"`
	ForwardIP                         string   `toml:"FORWARD_IP"`
	ForwardPort                       int      `toml:"FORWARD_PORT"`
	Domain                            []string `toml:"DOMAIN"`
	MinVPNLabelLength                 int      `toml:"MIN_VPN_LABEL_LENGTH"`
	SupportedUploadCompressionTypes   []int    `toml:"SUPPORTED_UPLOAD_COMPRESSION_TYPES"`
	SupportedDownloadCompressionTypes []int    `toml:"SUPPORTED_DOWNLOAD_COMPRESSION_TYPES"`
	DataEncryptionMethod              int      `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionAutoDetect              bool     `toml:"ENCRYPTION_AUTO_DETECT"`
	ARecordDataDelivery               bool     `toml:"A_RECORD_DATA_DELIVERY"`
	EncryptionKeyFile                 string   `toml:"ENCRYPTION_KEY_FILE"`
	// FEC (forward error correction) on the download path (tier 2 loss reducer).
	// Opt-in; when enabled the server encodes outgoing STREAM_DATA into
	// Reed-Solomon blocks (FECBlockSize data + FECParity recovery shards) so the
	// client reconstructs lost data without a retransmit round-trip.
	FECDownloadEnabled bool `toml:"FEC_DOWNLOAD_ENABLED"`
	FECBlockSize       int  `toml:"FEC_BLOCK_SIZE"`
	FECParity          int  `toml:"FEC_PARITY"`
	// Loss-triggered FEC. When FECAutoEnabled is true (and FEC_DOWNLOAD_ENABLED is
	// not forcing FEC always-on), each download stream measures its own loss from
	// the retransmit rate and turns FEC on once that loss crosses
	// FECAutoLossThreshold, scaling parity to the measured loss (between FECParity
	// and FECAutoMaxParity). Below the threshold there is zero FEC overhead.
	FECAutoEnabled       bool    `toml:"FEC_AUTO_ENABLED"`
	FECAutoLossThreshold float64 `toml:"FEC_AUTO_LOSS_THRESHOLD"`
	FECAutoMaxParity     int     `toml:"FEC_AUTO_MAX_PARITY"`
	// Super-FEC: a last-ditch, maximum-parity band for extreme download loss. When
	// FECSuperEnabled and the measured loss enters [FECSuperLossFloor,
	// FECSuperLossCeil], parity is driven to FECAutoMaxParity for a best-effort
	// rebuild. Above FECSuperLossCeil the server stops escalating (relaxes to the
	// base rate) so it does not burn CPU protecting hopeless blocks — those are
	// left to ARQ. Defaults: floor 0.75, ceil 0.85.
	FECSuperEnabled   bool    `toml:"FEC_SUPER_ENABLED"`
	FECSuperLossFloor float64 `toml:"FEC_SUPER_LOSS_FLOOR"`
	FECSuperLossCeil  float64 `toml:"FEC_SUPER_LOSS_CEIL"`
	// FECSuperMaxParity caps per-block parity while inside the Super-FEC band. 0
	// auto-sizes to the Reed-Solomon hard limit for the block. Bounding it lets an
	// operator trade rebuild strength against the bandwidth amplification that very
	// high parity implies.
	FECSuperMaxParity              int     `toml:"FEC_SUPER_MAX_PARITY"`
	LogLevel                       string  `toml:"LOG_LEVEL"`
	ARQWindowSize                  int     `toml:"ARQ_WINDOW_SIZE"`
	ARQInitialRTOSeconds           float64 `toml:"ARQ_INITIAL_RTO_SECONDS"`
	ARQMaxRTOSeconds               float64 `toml:"ARQ_MAX_RTO_SECONDS"`
	ARQControlInitialRTOSeconds    float64 `toml:"ARQ_CONTROL_INITIAL_RTO_SECONDS"`
	ARQControlMaxRTOSeconds        float64 `toml:"ARQ_CONTROL_MAX_RTO_SECONDS"`
	ARQMaxControlRetries           int     `toml:"ARQ_MAX_CONTROL_RETRIES"`
	ARQInactivityTimeoutSeconds    float64 `toml:"ARQ_INACTIVITY_TIMEOUT_SECONDS"`
	ARQDataPacketTTLSeconds        float64 `toml:"ARQ_DATA_PACKET_TTL_SECONDS"`
	ARQControlPacketTTLSeconds     float64 `toml:"ARQ_CONTROL_PACKET_TTL_SECONDS"`
	ARQMaxDataRetries              int     `toml:"ARQ_MAX_DATA_RETRIES"`
	ARQDataNackMaxGap              int     `toml:"ARQ_DATA_NACK_MAX_GAP"`
	ARQDataNackInitialDelaySeconds float64 `toml:"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS"`
	ARQDataNackRepeatSeconds       float64 `toml:"ARQ_DATA_NACK_REPEAT_SECONDS"`
	ARQTerminalDrainTimeoutSec     float64 `toml:"ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS"`
	ARQTerminalAckWaitTimeoutSec   float64 `toml:"ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS"`
}

type ServerConfigOverrides struct {
	Values map[string]any
}

type ServerConfigFlagBinder struct {
	values      ServerConfig
	setFields   map[string]struct{}
	flagToField map[string]string
}

func defaultServerConfig() ServerConfig {
	workers := min(max(runtime.NumCPU(), 1), 16)

	readers := min(max(runtime.NumCPU()/2, 1), 4)

	return ServerConfig{
		ConfigPreset:                      "default",
		ProtocolType:                      "SOCKS5",
		UDPHost:                           "0.0.0.0",
		UDPPort:                           53,
		TCPListenerEnabled:                true,
		TCPMaxConns:                       2048,
		TCPMaxConnsPerIP:                  128,
		TCPMaxQueriesPerConn:              0,
		TCPReadIdleTimeoutSeconds:         30.0,
		TCPWriteTimeoutSeconds:            15.0,
		DoTListenerEnabled:                false,
		DoTListenHost:                     "0.0.0.0",
		DoTListenPort:                     853,
		DoHListenerEnabled:                false,
		DoHListenHost:                     "0.0.0.0",
		DoHListenPort:                     443,
		DoHPath:                           "/dns-query",
		DoHTLSEnabled:                     true,
		DoHCoexistMode:                    "auto",
		DoHBehindPort:                     8453,
		DoHMaxInflight:                    256,
		DoHMaxInflightBytes:               64 * 1024 * 1024,
		DoHRequestsPerSecond:              4096,
		DoHRequestBurst:                   8192,
		ACMEEnabled:                       true,
		ACMECacheDir:                      "acme-cache",
		UDPReaders:                        readers,
		SocketBufferSize:                  8 * 1024 * 1024,
		MaxConcurrentRequests:             16384,
		MaxIngressQueueBytes:              64 * 1024 * 1024,
		DNSRequestWorkers:                 workers,
		DeferredSessionWorkers:            8,
		DeferredSessionQueueLimit:         4096,
		SessionOrphanQueueInitialCap:      64,
		StreamQueueInitialCapacity:        128,
		DNSFragmentStoreCapacity:          256,
		SOCKS5FragmentStoreCapacity:       512,
		MaxPacketSize:                     4096,
		MaxStreamsPerSession:              4096,
		MaxActiveSessions:                 2048,
		MaxDNSResponseBytes:               32768,
		DropLogIntervalSecs:               2.0,
		InvalidCookieWindowSecs:           2.0,
		InvalidCookieErrorThreshold:       10,
		SessionTimeoutSecs:                300.0,
		SessionCleanupIntervalSecs:        30.0,
		ClosedSessionRetentionSecs:        600.0,
		SessionInitReuseTTLSeconds:        600.0,
		RecentlyClosedStreamTTLSeconds:    600.0,
		RecentlyClosedStreamCap:           2000,
		TerminalStreamRetentionSeconds:    45.0,
		MaxPacketsPerBatch:                8,
		PacketBlockControlDuplication:     1,
		DNSUpstreamServers:                []string{"1.1.1.1:53"},
		DNSUpstreamTimeoutSecs:            4.0,
		DNSInflightWaitTimeoutSecs:        8.0,
		SOCKSConnectTimeoutSecs:           8.0,
		DNSFragmentAssemblyTimeoutSecs:    300.0,
		StreamSetupAckTTLSeconds:          400.0,
		StreamResultPacketTTLSeconds:      300.0,
		StreamFailurePacketTTLSeconds:     120.0,
		DNSCacheMaxRecords:                20000,
		DNSCacheTTLSeconds:                300.0,
		UseExternalSOCKS5:                 false,
		SOCKS5Auth:                        false,
		SOCKS5User:                        "admin",
		SOCKS5Pass:                        "C0tt0n-C@ndy-Cl0ud!",
		ForwardIP:                         "",
		ForwardPort:                       1080,
		Domain:                            nil,
		MinVPNLabelLength:                 3,
		SupportedUploadCompressionTypes:   []int{0, 3},
		SupportedDownloadCompressionTypes: []int{0, 3},
		DataEncryptionMethod:              3,
		EncryptionAutoDetect:              true,
		FECAutoEnabled:                    true,
		FECAutoLossThreshold:              0.3,
		FECSuperEnabled:                   true,
		FECSuperLossFloor:                 0.75,
		FECSuperLossCeil:                  0.85,
		FECSuperMaxParity:                 0,
		EncryptionKeyFile:                 "encrypt_key.txt",
		LogLevel:                          "INFO",
		ARQWindowSize:                     2000,
		ARQInitialRTOSeconds:              1.0,
		ARQMaxRTOSeconds:                  8.0,
		ARQControlInitialRTOSeconds:       1.0,
		ARQControlMaxRTOSeconds:           8.0,
		ARQMaxControlRetries:              80,
		ARQInactivityTimeoutSeconds:       1800.0,
		ARQDataPacketTTLSeconds:           1800.0,
		ARQControlPacketTTLSeconds:        900.0,
		ARQMaxDataRetries:                 800,
		ARQDataNackMaxGap:                 0,
		ARQDataNackInitialDelaySeconds:    0.4,
		ARQDataNackRepeatSeconds:          1.0,
		ARQTerminalDrainTimeoutSec:        90.0,
		ARQTerminalAckWaitTimeoutSec:      60.0,
	}
}

func LoadServerConfig(filename string) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	return finalizeServerConfig(cfg)
}

func loadServerConfigFile(filename string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	path, err := filepath.Abs(filename)
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); err != nil {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	meta, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)
	if err := applyServerConfigPreset(&cfg, func(key string) bool {
		return meta.IsDefined(key)
	}); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadServerConfigWithOverrides(filename string, overrides ServerConfigOverrides) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	if len(overrides.Values) > 0 {
		if err := applyServerConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
		if _, ok := overrides.Values["ConfigPreset"]; ok {
			serverType := reflect.TypeOf(ServerConfig{})
			if err := applyServerConfigPreset(&cfg, func(key string) bool {
				return overrideValuesDefineTOMLKey(overrides.Values, serverType, key)
			}); err != nil {
				return cfg, err
			}
		}
	}
	return finalizeServerConfig(cfg)
}

func finalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.ConfigPreset = normalizeConfigPresetName(cfg.ConfigPreset)
	if !isKnownServerConfigPreset(cfg.ConfigPreset) {
		return cfg, fmt.Errorf("invalid CONFIG_PRESET: %q (valid: %s)", cfg.ConfigPreset, serverConfigPresetNames)
	}

	cfg.ProtocolType = defaultString(strings.ToUpper(strings.TrimSpace(cfg.ProtocolType)), "SOCKS5")

	switch cfg.ProtocolType {
	case "SOCKS5", "TCP":
	default:
		return cfg, fmt.Errorf("invalid PROTOCOL_TYPE: %q", cfg.ProtocolType)
	}

	if cfg.UDPHost == "" {
		cfg.UDPHost = "0.0.0.0"
	}

	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return cfg, fmt.Errorf("invalid UDP_PORT: %d", cfg.UDPPort)
	}

	cfg.TCPMaxConns = clampInt(defaultIntBelow(cfg.TCPMaxConns, 1, 2048), 1, 65535)
	cfg.TCPMaxConnsPerIP = clampInt(defaultIntBelow(cfg.TCPMaxConnsPerIP, 0, 128), 0, cfg.TCPMaxConns)
	if cfg.TCPMaxQueriesPerConn < 0 {
		cfg.TCPMaxQueriesPerConn = 0
	}
	cfg.TCPReadIdleTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.TCPReadIdleTimeoutSeconds, 30.0), 1.0, 3600.0)
	cfg.TCPWriteTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.TCPWriteTimeoutSeconds, 15.0), 1.0, 3600.0)

	if cfg.UDPReaders <= 0 {
		cfg.UDPReaders = defaultServerConfig().UDPReaders
	}

	if cfg.SocketBufferSize <= 0 {
		cfg.SocketBufferSize = 8 * 1024 * 1024
	}

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 4096
	}
	cfg.MaxIngressQueueBytes = clampInt(defaultIntBelow(cfg.MaxIngressQueueBytes, 1, 64*1024*1024), 1024*1024, 512*1024*1024)

	if cfg.DNSRequestWorkers <= 0 {
		cfg.DNSRequestWorkers = defaultServerConfig().DNSRequestWorkers
	}
	if cfg.DeferredSessionWorkers < 0 {
		cfg.DeferredSessionWorkers = 0
	}

	if cfg.DeferredSessionWorkers > 128 {
		cfg.DeferredSessionWorkers = 128
	}

	if cfg.DeferredSessionQueueLimit < 1 {
		cfg.DeferredSessionQueueLimit = 256
	}

	if cfg.DeferredSessionQueueLimit > 14336 {
		cfg.DeferredSessionQueueLimit = 14336
	}

	cfg.SessionOrphanQueueInitialCap = clampInt(defaultIntBelow(cfg.SessionOrphanQueueInitialCap, 1, 64), 4, 4096)
	cfg.StreamQueueInitialCapacity = clampInt(defaultIntBelow(cfg.StreamQueueInitialCapacity, 1, 128), 8, 65536)
	cfg.DNSFragmentStoreCapacity = clampInt(defaultIntBelow(cfg.DNSFragmentStoreCapacity, 1, 256), 16, 16384)
	cfg.SOCKS5FragmentStoreCapacity = clampInt(defaultIntBelow(cfg.SOCKS5FragmentStoreCapacity, 1, 512), 16, 16384)
	// Cotten upstream data lives in a DNS QNAME, whose full wire name is at
	// most 255 bytes. Keep generous EDNS/additional-record headroom without
	// allowing every queued UDP request to retain a 65,535-byte backing array.
	// TCP/53 uses its own length-framed buffer and is unaffected by this limit.
	cfg.MaxPacketSize = clampInt(defaultIntBelow(cfg.MaxPacketSize, 1, 4096), 512, 4096)
	cfg.MaxStreamsPerSession = clampInt(defaultIntBelow(cfg.MaxStreamsPerSession, 1, 4096), 16, 65535)
	cfg.MaxActiveSessions = clampInt(defaultIntBelow(cfg.MaxActiveSessions, 1, 2048), 1, 65535)
	cfg.MaxAllowedClientPacketDuplication = clampOptionalServerInt(cfg.MaxAllowedClientPacketDuplication, 1, 15)
	cfg.MaxAllowedClientSetupPacketDuplication = clampOptionalServerInt(cfg.MaxAllowedClientSetupPacketDuplication, 1, 15)
	cfg.MaxAllowedClientUploadMTU = clampOptionalServerInt(cfg.MaxAllowedClientUploadMTU, 10, 255)
	cfg.MaxAllowedClientDownloadMTU = clampOptionalServerInt(cfg.MaxAllowedClientDownloadMTU, 10, 4096)
	cfg.MaxAllowedClientRxTxWorkers = clampOptionalServerInt(cfg.MaxAllowedClientRxTxWorkers, 1, 255)
	cfg.MinAllowedClientPingAggressiveInterval = clampOptionalServerFloat(cfg.MinAllowedClientPingAggressiveInterval, 0.05, 1.0)
	cfg.MaxAllowedClientPacketsPerBatch = clampOptionalServerInt(cfg.MaxAllowedClientPacketsPerBatch, 1, 255)
	cfg.MaxAllowedClientARQWindowSize = clampOptionalServerInt(cfg.MaxAllowedClientARQWindowSize, 1, 65535)
	cfg.MaxAllowedClientARQDataNackMaxGap = clampOptionalServerInt(cfg.MaxAllowedClientARQDataNackMaxGap, 1, 255)
	cfg.MinAllowedClientCompressionMinSize = clampOptionalServerInt(cfg.MinAllowedClientCompressionMinSize, 1, 65535)
	cfg.MinAllowedClientARQInitialRTOSeconds = clampOptionalServerFloat(cfg.MinAllowedClientARQInitialRTOSeconds, 0.05, 1.0)
	cfg.MaxDNSResponseBytes = clampInt(defaultIntBelow(cfg.MaxDNSResponseBytes, 1, 32768), 512, 65535)

	// Encrypted-DNS listener ports. Clamp to valid range; fall back to the
	// standards (853 DoT, 443 DoH) on a bad value so a typo cannot silently
	// disable the listener or bind port 0.
	cfg.DoTListenPort = clampInt(defaultIntBelow(cfg.DoTListenPort, 1, 853), 1, 65535)
	cfg.DoHListenPort = clampInt(defaultIntBelow(cfg.DoHListenPort, 1, 443), 1, 65535)
	if cfg.DoHPath == "" || cfg.DoHPath[0] != '/' {
		cfg.DoHPath = "/dns-query"
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DoHCoexistMode)) {
	case "front", "behind", "auto":
		cfg.DoHCoexistMode = strings.ToLower(strings.TrimSpace(cfg.DoHCoexistMode))
	default:
		// An unknown value must not silently seize :443 from a co-hosted panel,
		// so fall back to the port-aware automatic decision.
		cfg.DoHCoexistMode = "auto"
	}
	cfg.DoHBehindPort = clampInt(defaultIntBelow(cfg.DoHBehindPort, 1, 8453), 1, 65535)
	if strings.TrimSpace(cfg.DoTListenHost) == "" {
		cfg.DoTListenHost = cfg.UDPHost
	}
	if strings.TrimSpace(cfg.DoHListenHost) == "" {
		cfg.DoHListenHost = cfg.UDPHost
	}
	cfg.DoHMaxInflight = clampInt(defaultIntBelow(cfg.DoHMaxInflight, 1, 256), 1, 4096)
	cfg.DoHMaxInflightBytes = clampInt(defaultIntBelow(cfg.DoHMaxInflightBytes, 1, 64*1024*1024), 1*1024*1024, 256*1024*1024)
	if cfg.DoHRequestsPerSecond <= 0 {
		cfg.DoHRequestsPerSecond = 4096
	}
	if cfg.DoHRequestsPerSecond > 1000000 {
		cfg.DoHRequestsPerSecond = 1000000
	}
	cfg.DoHRequestBurst = clampInt(defaultIntBelow(cfg.DoHRequestBurst, 1, 8192), 1, 1000000)
	if cfg.ACMECacheDir == "" {
		cfg.ACMECacheDir = "acme-cache"
	}

	if cfg.DropLogIntervalSecs <= 0 {
		cfg.DropLogIntervalSecs = 2.0
	}

	if cfg.InvalidCookieWindowSecs <= 0 {
		cfg.InvalidCookieWindowSecs = 2.0
	}

	if cfg.InvalidCookieErrorThreshold <= 0 {
		cfg.InvalidCookieErrorThreshold = 10
	}

	if cfg.SessionTimeoutSecs <= 0 {
		cfg.SessionTimeoutSecs = 300.0
	}

	if cfg.SessionCleanupIntervalSecs <= 0 {
		cfg.SessionCleanupIntervalSecs = 30.0
	}

	if cfg.ClosedSessionRetentionSecs <= 0 {
		cfg.ClosedSessionRetentionSecs = 600.0
	}
	cfg.SessionInitReuseTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitReuseTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.RecentlyClosedStreamTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamCap = clampInt(defaultIntBelow(cfg.RecentlyClosedStreamCap, 1, 2000), 1, 1000000)
	cfg.TerminalStreamRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.TerminalStreamRetentionSeconds, 45.0), 1.0, 86400.0)

	if cfg.MaxPacketsPerBatch < 1 {
		cfg.MaxPacketsPerBatch = 20
	}

	if cfg.PacketBlockControlDuplication < 1 {
		cfg.PacketBlockControlDuplication = 1
	}

	if cfg.PacketBlockControlDuplication > 4 {
		cfg.PacketBlockControlDuplication = 4
	}

	if len(cfg.DNSUpstreamServers) == 0 {
		cfg.DNSUpstreamServers = []string{"1.1.1.1:53"}
	}

	if cfg.DNSUpstreamTimeoutSecs <= 0 {
		cfg.DNSUpstreamTimeoutSecs = 4.0
	}
	cfg.DNSInflightWaitTimeoutSecs = clampFloat(defaultFloatAtMostZero(cfg.DNSInflightWaitTimeoutSecs, 8.0), 0.1, 120.0)

	if cfg.SOCKSConnectTimeoutSecs <= 0 {
		cfg.SOCKSConnectTimeoutSecs = 8.0
	}

	if cfg.DNSFragmentAssemblyTimeoutSecs <= 0 {
		cfg.DNSFragmentAssemblyTimeoutSecs = 300.0
	}
	cfg.StreamSetupAckTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamSetupAckTTLSeconds, 400.0), 1.0, 86400.0)
	cfg.StreamResultPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamResultPacketTTLSeconds, 300.0), 1.0, 86400.0)
	cfg.StreamFailurePacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamFailurePacketTTLSeconds, 120.0), 1.0, 86400.0)

	if cfg.DNSCacheMaxRecords < 1 {
		cfg.DNSCacheMaxRecords = 2000
	}

	if cfg.DNSCacheTTLSeconds <= 0 {
		cfg.DNSCacheTTLSeconds = 3600.0
	}

	if cfg.ForwardPort < 0 || cfg.ForwardPort > 65535 {
		return cfg, fmt.Errorf("invalid FORWARD_PORT: %d", cfg.ForwardPort)
	}

	if len(cfg.SOCKS5User) > 255 {
		return cfg, fmt.Errorf("SOCKS5_USER cannot exceed 255 bytes")
	}

	if len(cfg.SOCKS5Pass) > 255 {
		return cfg, fmt.Errorf("SOCKS5_PASS cannot exceed 255 bytes")
	}

	if cfg.SOCKS5Auth && (cfg.SOCKS5User == "" || cfg.SOCKS5Pass == "") {
		return cfg, fmt.Errorf("SOCKS5_AUTH requires both SOCKS5_USER and SOCKS5_PASS")
	}

	if cfg.UseExternalSOCKS5 {
		if cfg.ForwardIP == "" {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires FORWARD_IP")
		}
		if cfg.ForwardPort <= 0 {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires a valid FORWARD_PORT")
		}
	}

	if cfg.MinVPNLabelLength <= 0 {
		cfg.MinVPNLabelLength = 3
	}

	if cfg.FECBlockSize <= 0 {
		cfg.FECBlockSize = 4
	}
	if cfg.FECParity <= 0 {
		cfg.FECParity = 4
	}
	if cfg.FECBlockSize > 200 {
		cfg.FECBlockSize = 200
	}
	if cfg.FECBlockSize+cfg.FECParity > 256 {
		cfg.FECParity = 256 - cfg.FECBlockSize
	}
	if cfg.FECAutoLossThreshold <= 0 || cfg.FECAutoLossThreshold >= 1 {
		cfg.FECAutoLossThreshold = 0.3
	}
	if cfg.FECAutoMaxParity <= 0 {
		// Default auto cap: enough parity to ride out heavy loss (4x the block),
		// bounded by the Reed-Solomon shard limit.
		cfg.FECAutoMaxParity = cfg.FECBlockSize * 4
	}
	if cfg.FECBlockSize+cfg.FECAutoMaxParity > 256 {
		cfg.FECAutoMaxParity = 256 - cfg.FECBlockSize
	}
	if cfg.FECAutoMaxParity < cfg.FECParity {
		cfg.FECAutoMaxParity = cfg.FECParity
	}

	// Super-FEC band. Keep the floor within (threshold, 1) and the ceiling within
	// [floor, 1) so the "engage" band and the "give up" region are well-ordered.
	if cfg.FECSuperLossFloor <= 0 || cfg.FECSuperLossFloor >= 1 {
		cfg.FECSuperLossFloor = 0.75
	}
	if cfg.FECSuperLossFloor <= cfg.FECAutoLossThreshold {
		cfg.FECSuperLossFloor = cfg.FECAutoLossThreshold + 0.05
	}
	if cfg.FECSuperLossCeil <= 0 || cfg.FECSuperLossCeil >= 1 {
		cfg.FECSuperLossCeil = 0.85
	}
	if cfg.FECSuperLossCeil < cfg.FECSuperLossFloor {
		cfg.FECSuperLossCeil = cfg.FECSuperLossFloor
	}
	if cfg.FECSuperMaxParity < 0 {
		cfg.FECSuperMaxParity = 0
	}
	if cfg.FECSuperMaxParity > 0 && cfg.FECSuperMaxParity < cfg.FECAutoMaxParity {
		// The super cap should never be tighter than the normal auto ceiling, or
		// the band would protect *less* than ordinary auto-FEC.
		cfg.FECSuperMaxParity = cfg.FECAutoMaxParity
	}

	cfg.SupportedUploadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedUploadCompressionTypes)
	cfg.SupportedDownloadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedDownloadCompressionTypes)

	if cfg.DataEncryptionMethod < 0 || cfg.DataEncryptionMethod > 5 {
		cfg.DataEncryptionMethod = 3
	}

	if cfg.EncryptionKeyFile == "" {
		cfg.EncryptionKeyFile = "encrypt_key.txt"
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 2000), 1, 6000)
	cfg.ARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQMaxRTOSeconds, 8.0), cfg.ARQInitialRTOSeconds, 120.0)
	cfg.ARQControlInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQControlMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlMaxRTOSeconds, 8.0), cfg.ARQControlInitialRTOSeconds, 120.0)
	cfg.ARQMaxControlRetries = clampInt(defaultIntBelow(cfg.ARQMaxControlRetries, 1, 80), 5, 5000)
	cfg.ARQInactivityTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInactivityTimeoutSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQDataPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataPacketTTLSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQControlPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlPacketTTLSeconds, 900.0), 30.0, 86400.0)
	cfg.ARQMaxDataRetries = clampInt(defaultIntBelow(cfg.ARQMaxDataRetries, 1, 800), 60, 100000)
	cfg.ARQDataNackMaxGap = clampInt(defaultIntBelow(cfg.ARQDataNackMaxGap, 0, 0), 0, cfg.ARQWindowSize/4)
	cfg.ARQDataNackInitialDelaySeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackInitialDelaySeconds, 0.0), 0.2, 30.0)
	cfg.ARQDataNackRepeatSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackRepeatSeconds, 2.0), 0.3, 30.0)
	cfg.ARQTerminalDrainTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalDrainTimeoutSec, 90.0), 10.0, 3600.0)
	cfg.ARQTerminalAckWaitTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalAckWaitTimeoutSec, 60.0), 5.0, 3600.0)

	return cfg, nil
}

func clampOptionalServerInt(value, minValue, maxValue int) int {
	if value <= 0 {
		return 0
	}
	return clampInt(value, minValue, maxValue)
}

func clampOptionalServerFloat(value, minValue, maxValue float64) float64 {
	if value <= 0 {
		return 0
	}
	return clampFloat(value, minValue, maxValue)
}

func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.UDPHost, c.UDPPort)
}

func (c ServerConfig) DropLogInterval() time.Duration {
	return time.Duration(c.DropLogIntervalSecs * float64(time.Second))
}

func (c ServerConfig) TCPReadIdleTimeout() time.Duration {
	return time.Duration(c.TCPReadIdleTimeoutSeconds * float64(time.Second))
}

func (c ServerConfig) TCPWriteTimeout() time.Duration {
	return time.Duration(c.TCPWriteTimeoutSeconds * float64(time.Second))
}

func (c ServerConfig) InvalidCookieWindow() time.Duration {
	return time.Duration(c.InvalidCookieWindowSecs * float64(time.Second))
}

func (c ServerConfig) SessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionCleanupInterval() time.Duration {
	return time.Duration(c.SessionCleanupIntervalSecs * float64(time.Second))
}

func (c ServerConfig) ClosedSessionRetention() time.Duration {
	return time.Duration(c.ClosedSessionRetentionSecs * float64(time.Second))
}

func (c ServerConfig) DNSUpstreamTimeout() time.Duration {
	return time.Duration(c.DNSUpstreamTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSInflightWaitTimeout() time.Duration {
	return time.Duration(c.DNSInflightWaitTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SOCKSConnectTimeout() time.Duration {
	return time.Duration(c.SOCKSConnectTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSFragmentAssemblyTimeout() time.Duration {
	return time.Duration(c.DNSFragmentAssemblyTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionInitReuseTTL() time.Duration {
	return time.Duration(c.SessionInitReuseTTLSeconds * float64(time.Second))
}

func (c ServerConfig) RecentlyClosedStreamTTL() time.Duration {
	return time.Duration(c.RecentlyClosedStreamTTLSeconds * float64(time.Second))
}

func (c ServerConfig) TerminalStreamRetention() time.Duration {
	return time.Duration(c.TerminalStreamRetentionSeconds * float64(time.Second))
}

func (c ServerConfig) StreamSetupAckTTL() time.Duration {
	return time.Duration(c.StreamSetupAckTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamResultPacketTTL() time.Duration {
	return time.Duration(c.StreamResultPacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamFailurePacketTTL() time.Duration {
	return time.Duration(c.StreamFailurePacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) EncryptionKeyPath() string {
	if c.EncryptionKeyFile == "" {
		return filepath.Join(c.ConfigDir, "encrypt_key.txt")
	}
	if filepath.IsAbs(c.EncryptionKeyFile) {
		return c.EncryptionKeyFile
	}
	return filepath.Join(c.ConfigDir, c.EncryptionKeyFile)
}

func normalizeCompressionTypeList(values []int) []int {
	if len(values) == 0 {
		return []int{0}
	}

	seen := [4]bool{}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value < 0 || value > 3 || seen[value] || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func applyServerConfigOverrideValues(cfg *ServerConfig, values map[string]any) error {
	if cfg == nil || len(values) == 0 {
		return nil
	}

	elem := reflect.ValueOf(cfg).Elem()
	typ := elem.Type()
	for fieldName, rawValue := range values {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			return fmt.Errorf("unknown server config override field: %s", fieldName)
		}
		value := elem.FieldByName(fieldName)
		if !value.CanSet() {
			return fmt.Errorf("server config override field is not settable: %s", field.Name)
		}
		if err := assignServerConfigOverrideValue(value, rawValue, field.Name); err != nil {
			return err
		}
	}
	return nil
}

func assignServerConfigOverrideValue(target reflect.Value, rawValue any, fieldName string) error {
	if !target.IsValid() {
		return fmt.Errorf("invalid server config override target: %s", fieldName)
	}

	switch target.Kind() {
	case reflect.String:
		v, ok := rawValue.(string)
		if !ok {
			return fmt.Errorf("invalid string override for %s", fieldName)
		}
		target.SetString(v)
		return nil
	case reflect.Bool:
		v, ok := rawValue.(bool)
		if !ok {
			return fmt.Errorf("invalid bool override for %s", fieldName)
		}
		target.SetBool(v)
		return nil
	case reflect.Int:
		v, ok := rawValue.(int)
		if !ok {
			return fmt.Errorf("invalid int override for %s", fieldName)
		}
		target.SetInt(int64(v))
		return nil
	case reflect.Float64:
		v, ok := rawValue.(float64)
		if !ok {
			return fmt.Errorf("invalid float override for %s", fieldName)
		}
		target.SetFloat(v)
		return nil
	case reflect.Slice:
		switch target.Type().Elem().Kind() {
		case reflect.String:
			v, ok := rawValue.([]string)
			if !ok {
				return fmt.Errorf("invalid string slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]string(nil), v...)))
			return nil
		case reflect.Int:
			v, ok := rawValue.([]int)
			if !ok {
				return fmt.Errorf("invalid int slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]int(nil), v...)))
			return nil
		}
	}

	return fmt.Errorf("unsupported server config override type for %s", fieldName)
}

func NewServerConfigFlagBinder(fs *flag.FlagSet) (*ServerConfigFlagBinder, error) {
	if fs == nil {
		return nil, fmt.Errorf("flag set is required")
	}

	binder := &ServerConfigFlagBinder{
		values:      defaultServerConfig(),
		setFields:   make(map[string]struct{}),
		flagToField: make(map[string]string),
	}

	valueElem := reflect.ValueOf(&binder.values).Elem()
	valueType := valueElem.Type()
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		tomlTag := field.Tag.Get("toml")
		if tomlTag == "" || tomlTag == "-" {
			continue
		}

		flagName := clientConfigFlagName(tomlTag)
		binder.flagToField[flagName] = field.Name
		target := valueElem.Field(i)
		usage := fmt.Sprintf("Override %s from config file", tomlTag)

		switch target.Kind() {
		case reflect.String:
			fs.Var(newServerConfigStringFlag(target.Addr().Interface().(*string), binder, field.Name), flagName, usage)
		case reflect.Bool:
			fs.Var(newServerConfigBoolFlag(target.Addr().Interface().(*bool), binder, field.Name), flagName, usage)
		case reflect.Int:
			fs.Var(newServerConfigIntFlag(target.Addr().Interface().(*int), binder, field.Name), flagName, usage)
		case reflect.Float64:
			fs.Var(newServerConfigFloatFlag(target.Addr().Interface().(*float64), binder, field.Name), flagName, usage)
		case reflect.Slice:
			switch target.Type().Elem().Kind() {
			case reflect.String:
				fs.Var(newServerConfigStringSliceFlag(target.Addr().Interface().(*[]string), binder, field.Name), flagName, usage+" (comma-separated)")
			case reflect.Int:
				fs.Var(newServerConfigIntSliceFlag(target.Addr().Interface().(*[]int), binder, field.Name), flagName, usage+" (comma-separated)")
			}
		}
	}

	return binder, nil
}

func (b *ServerConfigFlagBinder) Overrides() ServerConfigOverrides {
	overrides := ServerConfigOverrides{
		Values: make(map[string]any, len(b.setFields)),
	}
	if b == nil {
		return overrides
	}

	valueElem := reflect.ValueOf(&b.values).Elem()
	for fieldName := range b.setFields {
		field := valueElem.FieldByName(fieldName)
		if !field.IsValid() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			overrides.Values[fieldName] = field.String()
		case reflect.Bool:
			overrides.Values[fieldName] = field.Bool()
		case reflect.Int:
			overrides.Values[fieldName] = int(field.Int())
		case reflect.Float64:
			overrides.Values[fieldName] = field.Float()
		case reflect.Slice:
			switch field.Type().Elem().Kind() {
			case reflect.String:
				src := field.Interface().([]string)
				overrides.Values[fieldName] = append([]string(nil), src...)
			case reflect.Int:
				src := field.Interface().([]int)
				overrides.Values[fieldName] = append([]int(nil), src...)
			}
		}
	}

	return overrides
}

func (b *ServerConfigFlagBinder) markSet(fieldName string) {
	if b == nil || fieldName == "" {
		return
	}
	b.setFields[fieldName] = struct{}{}
}

type serverConfigStringFlag struct {
	target    *string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringFlag(target *string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringFlag {
	return &serverConfigStringFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return *f.target
}

func (f *serverConfigStringFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	*f.target = value
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigBoolFlag struct {
	target    *bool
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigBoolFlag(target *bool, binder *ServerConfigFlagBinder, fieldName string) *serverConfigBoolFlag {
	return &serverConfigBoolFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigBoolFlag) String() string {
	if f == nil || f.target == nil {
		return "false"
	}
	return strconv.FormatBool(*f.target)
}

func (f *serverConfigBoolFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

func (f *serverConfigBoolFlag) IsBoolFlag() bool { return true }

type serverConfigIntFlag struct {
	target    *int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntFlag(target *int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntFlag {
	return &serverConfigIntFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.Itoa(*f.target)
}

func (f *serverConfigIntFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigFloatFlag struct {
	target    *float64
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigFloatFlag(target *float64, binder *ServerConfigFlagBinder, fieldName string) *serverConfigFloatFlag {
	return &serverConfigFloatFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigFloatFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.FormatFloat(*f.target, 'f', -1, 64)
}

func (f *serverConfigFloatFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigStringSliceFlag struct {
	target    *[]string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringSliceFlag(target *[]string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringSliceFlag {
	return &serverConfigStringSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringSliceFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return strings.Join(*f.target, ",")
}

func (f *serverConfigStringSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		items = append(items, part)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigIntSliceFlag struct {
	target    *[]int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntSliceFlag(target *[]int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntSliceFlag {
	return &serverConfigIntSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntSliceFlag) String() string {
	if f == nil || f.target == nil || len(*f.target) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*f.target))
	for _, item := range *f.target {
		parts = append(parts, strconv.Itoa(item))
	}
	return strings.Join(parts, ",")
}

func (f *serverConfigIntSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return err
		}
		items = append(items, parsed)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
}
