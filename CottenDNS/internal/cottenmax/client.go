package cottenmax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	soar "cottendns-go/internal/cottenmax/engine"
)

// Discovery retains the authenticated resolver-discovery behavior of Soar.
type Discovery = soar.Discovery

// MaxStreamsLimit bounds stream admission with space reserved for control frames.
const MaxStreamsLimit = soar.MaxStreamsLimit

type ClientConfig struct {
	// TrafficProfile is "full" (default), or "low" for reduced query traffic.
	// Full preserves the existing unpaced behavior; low shares percentage pacing
	// across every domain and resolver created by this client.
	TrafficProfile string
	// LowReductionPercent is an approximate speed reduction target, 10..90;
	// zero selects 35. Full retains the value without applying it.
	LowReductionPercent            int
	FECDownloadEnabled             bool
	FECDataShards, FECParityShards int
	Discovery                      Discovery
	// DiscoveryForDomain optionally isolates persisted discovery hints per zone.
	// It must return quickly; each candidate still authenticates to that zone.
	DiscoveryForDomain             func(string) Discovery
	Domain, PublicKey, Secret, TCP string
	Resolvers                      []string
	// Domains adds optional standby domains to Domain. The primary fast path is
	// unchanged; each standby gets its own authenticated session only on demand.
	Domains []string
	// DomainStrategy is "failover" (default), or experimental "parallel".
	// Parallel balances independent streams; it does not stripe one stream.
	DomainStrategy                 string
	FailoverAfter                  time.Duration
	QNameLabelLength               int
	QNameLabelJitter               bool
	QNameLossGuard                 bool
	EncryptedDNSPaddingBlockSize   int
	SafeQName, MaxQName, MaxAnswer int
	MaxPathWindow, MaxInflight     int
	SessionIdle                    time.Duration
	Hold                           time.Duration
	MaxStreams                     int
	ListenPacket                   func(context.Context, string, string) (net.PacketConn, error)
	DialTCP                        func(context.Context, string, string) (net.Conn, error)
}

type Client struct {
	engine              *soar.Client
	secret              string
	failover            *domainFailover
	parallel            *domainParallel
	domain              string
	maxInflight         int
	trafficProfile      string
	lowReductionPercent int
	admission           *dialAdmission
	transportAdmission  *dialAdmission
}

func NewClient(cfg ClientConfig) (*Client, error) {
	profile, limiter, err := applyTrafficProfile(&cfg)
	if err != nil {
		return nil, err
	}
	safeQName, maxQName := cfg.SafeQName, cfg.MaxQName
	if safeQName <= 0 {
		safeQName = 101
	}
	if maxQName <= 0 {
		maxQName = 253
	}
	domains, err := normalizeFailoverDomainsShaped(cfg.Domain, cfg.Domains, min(safeQName, maxQName, 253), cfg.QNameLabelLength, cfg.QNameLabelJitter)
	if err != nil {
		return nil, err
	}
	var key ed25519.PublicKey
	if strings.TrimSpace(cfg.PublicKey) == "" {
		identity, err := SharedIdentity(cfg.Secret)
		if err != nil {
			return nil, err
		}
		key = identity.Public().(ed25519.PublicKey)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.PublicKey))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cottenmax: invalid pinned server public key")
		}
		key = ed25519.PublicKey(decoded)
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("cottenmax: shared admission secret is required")
	}
	if cfg.Hold == 0 {
		cfg.Hold = time.Nanosecond
	} // explicitly disable held polls
	defaultListener := cfg.ListenPacket == nil
	if defaultListener {
		cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, network, address)
		}
	}
	if cfg.MaxPathWindow <= 0 {
		cfg.MaxPathWindow = 256
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 256
	}
	if defaultListener {
		cfg.ListenPacket = sizedPacketListener(cfg.ListenPacket, cfg.MaxInflight, cfg.MaxAnswer)
	}
	strategy := strings.ToLower(strings.TrimSpace(cfg.DomainStrategy))
	if strategy == "" {
		strategy = "failover"
	}
	if strategy != "failover" && strategy != "parallel" {
		return nil, fmt.Errorf("cottenmax: unknown domain strategy %q", cfg.DomainStrategy)
	}
	var domainBudgets []int
	if strategy == "parallel" && len(domains) > 1 {
		domainBudgets, err = splitDomainBudget(min(cfg.MaxInflight, 4096), len(domains))
		if err != nil {
			return nil, err
		}
	}
	discovery := cfg.Discovery
	if cfg.DiscoveryForDomain != nil {
		discovery = cfg.DiscoveryForDomain(domains[0])
	}
	engineCfg := soar.Config{
		PercentagePacer: limiter, DisableTailDuplication: profile == TrafficProfileLow,
		FECDownloadEnabled: cfg.FECDownloadEnabled, FECDataShards: cfg.FECDataShards, FECParityShards: cfg.FECParityShards,
		Zone: Zone(domains[0]), ServerKey: ed25519.PublicKey(key), Resolvers: cfg.Resolvers,
		TCP: cfg.TCP, Hold: cfg.Hold, MaxStreams: cfg.MaxStreams, Discovery: discovery,
		// Grow from the engine's small initial congestion window on delivered
		// queries. The old 32-query ceiling underfills a single delayed path.
		MaxPathWindow: cfg.MaxPathWindow, MaxInflight: cfg.MaxInflight,
		SafeQName: cfg.SafeQName, MaxQName: cfg.MaxQName, MaxAnswer: cfg.MaxAnswer,
		SessionIdle:  cfg.SessionIdle,
		ListenPacket: cfg.ListenPacket, DialTCP: cfg.DialTCP,
		QNameLabelLength: cfg.QNameLabelLength, QNameLabelJitter: cfg.QNameLabelJitter, QNameLossGuard: cfg.QNameLossGuard,
		DNSPaddingBlockSize: cfg.EncryptedDNSPaddingBlockSize,
	}
	var admission, transportAdmission *dialAdmission
	if profile == TrafficProfileLow {
		engineCfg.LowReductionPercent = cfg.LowReductionPercent
		admission = newLowDialAdmission()
		transportAdmission = newDialAdmission(LowTrafficStreamsPerSecond, LowTrafficTransportBurst)
		engineCfg.DialTCP = transportAdmission.wrapDial(cfg.DialTCP)
		engineCfg.InitialResolverLimit = 2
	}
	if len(domainBudgets) > 0 {
		engineCfg.MaxInflight = domainBudgets[0]
	}
	engine, err := soar.NewClient(engineCfg)
	if err != nil {
		if admission != nil {
			admission.cancel()
			transportAdmission.cancel()
		}
		return nil, err
	}
	client := &Client{engine: engine, secret: cfg.Secret, domain: domains[0], maxInflight: min(cfg.MaxInflight, 4096), trafficProfile: profile, lowReductionPercent: cfg.LowReductionPercent}
	client.admission, client.transportAdmission = admission, transportAdmission
	if len(domains) > 1 {
		client.failover = newDomainFailover(domains, cfg.FailoverAfter, engineCfg, engine, cfg.DiscoveryForDomain)
		client.failover.admission = client.admission
		if strategy == "parallel" {
			client.failover.budgets = domainBudgets
			client.parallel = newDomainParallel(client.failover)
		}
	}
	return client, nil
}

// TrafficProfile returns the normalized profile selected at construction.
func (c *Client) TrafficProfile() string { return c.trafficProfile }

// LowReductionPercent returns the retained target, including when Full ignores it.
func (c *Client) LowReductionPercent() int { return c.lowReductionPercent }

// Dial waits for the server to confirm the destination before a SOCKS/HTTP
// success is sent.
func (c *Client) Dial(ctx context.Context, target string) (net.Conn, error) {
	return c.dial(ctx, target, true)
}

// DialStream pipelines application bytes with OPEN for transparent protocols
// that do not report proxy connect success. Authentication is unchanged; a
// rejected destination resets the stream. SOCKS and HTTP retain confirmed Dial.
func (c *Client) DialStream(ctx context.Context, target string) (net.Conn, error) {
	return c.dial(ctx, target, false)
}

func (c *Client) dial(ctx context.Context, target string, confirmed bool) (net.Conn, error) {
	signed := signTarget(c.secret, target)
	if len(signed) > 255 {
		return nil, fmt.Errorf("cottenmax: destination descriptor exceeds 255 bytes")
	}
	if c.parallel != nil {
		return c.parallel.dial(ctx, signed, confirmed)
	}
	if c.failover != nil {
		return c.failover.dial(ctx, signed, confirmed)
	}
	if err := c.admission.wait(ctx); err != nil {
		return nil, err
	}
	return dialEngine(ctx, c.engine, signed, confirmed)
}

func (c *Client) Close() error {
	if c.admission != nil {
		c.admission.cancel()
		c.transportAdmission.cancel()
	}
	if c.failover != nil {
		return c.failover.close()
	}
	return c.engine.Close()
}

// PathStats describes the preferred failover domain, or every started domain
// in parallel mode. DomainStats retains the per-domain association.
func (c *Client) PathStats() []soar.PathStat {
	if c.parallel != nil {
		var paths []soar.PathStat
		for _, domain := range c.DomainStats() {
			paths = append(paths, domain.Paths...)
		}
		return paths
	}
	if c.failover != nil {
		return c.failover.preferredEngine().PathStats()
	}
	return c.engine.PathStats()
}

func (c *Client) Established() bool {
	if c.parallel != nil {
		for _, domain := range c.DomainStats() {
			if domain.Established {
				return true
			}
		}
		return false
	}
	if c.failover != nil {
		return c.failover.preferredEngine().Established()
	}
	return c.engine.Established()
}

func dialEngine(ctx context.Context, engine *soar.Client, signed string, confirmed bool) (net.Conn, error) {
	if confirmed {
		return engine.DialConfirmed(ctx, "tcp", signed)
	}
	return engine.DialContext(ctx, "tcp", signed)
}
