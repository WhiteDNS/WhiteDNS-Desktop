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

type ClientConfig struct {
	Discovery Discovery
	// DiscoveryForDomain optionally isolates persisted discovery hints per zone.
	// It must return quickly; each candidate still authenticates to that zone.
	DiscoveryForDomain             func(string) Discovery
	Domain, PublicKey, Secret, TCP string
	Resolvers                      []string
	// Domains adds optional standby domains to Domain. The primary fast path is
	// unchanged; each standby gets its own authenticated session only on demand.
	Domains                        []string
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
	engine   *soar.Client
	secret   string
	failover *domainFailover
}

func NewClient(cfg ClientConfig) (*Client, error) {
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
	if cfg.ListenPacket == nil {
		cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var lc net.ListenConfig
			pc, err := lc.ListenPacket(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if udp, ok := pc.(*net.UDPConn); ok {
				// A full flight can exceed the small Windows UDP default. Without
				// this, delayed paths deliver bursts that look like network loss.
				_ = udp.SetReadBuffer(256 << 10)
				_ = udp.SetWriteBuffer(256 << 10)
			}
			return pc, nil
		}
	}
	if cfg.MaxPathWindow <= 0 {
		cfg.MaxPathWindow = 256
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 256
	}
	discovery := cfg.Discovery
	if cfg.DiscoveryForDomain != nil {
		discovery = cfg.DiscoveryForDomain(domains[0])
	}
	engineCfg := soar.Config{
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
	engine, err := soar.NewClient(engineCfg)
	if err != nil {
		return nil, err
	}
	client := &Client{engine: engine, secret: cfg.Secret}
	if len(domains) > 1 {
		client.failover = newDomainFailover(domains, cfg.FailoverAfter, engineCfg, engine, cfg.DiscoveryForDomain)
	}
	return client, nil
}

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
	if c.failover != nil {
		return c.failover.dial(ctx, signed, confirmed)
	}
	return dialEngine(ctx, c.engine, signed, confirmed)
}

func (c *Client) Close() error {
	if c.failover != nil {
		return c.failover.close()
	}
	return c.engine.Close()
}

// PathStats describes the preferred domain's resolver paths. Domains have
// independent sessions; a successful failover changes this preferred domain.
func (c *Client) PathStats() []soar.PathStat {
	if c.failover != nil {
		return c.failover.preferredEngine().PathStats()
	}
	return c.engine.PathStats()
}

func (c *Client) Established() bool {
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
