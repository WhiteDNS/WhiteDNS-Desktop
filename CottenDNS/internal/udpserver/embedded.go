package udpserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
)

// EmbeddedConfig describes one isolated account. All egress belongs to the
// caller: there is no fallback to an unmetered socket when a hook rejects it.
type EmbeddedConfig struct {
	Domains     []string
	Domain      string
	Key         string
	DialContext func(context.Context, string, string) (net.Conn, error)
	ExchangeDNS func(context.Context, []byte) ([]byte, error)
	Allowed     func() bool
}

type Embedded struct {
	s       *Server
	ctx     context.Context
	cancel  context.CancelFunc
	allowed func() bool
	mu      sync.RWMutex
	once    sync.Once
	wg      sync.WaitGroup
}

func NewEmbedded(parent context.Context, in EmbeddedConfig) (*Embedded, error) {
	if parent == nil || in.Domain == "" || len(in.Domain) > 128 || strings.ContainsAny(in.Domain, " /\\\t\n") || len(in.Key) < 32 || in.DialContext == nil || in.ExchangeDNS == nil || in.Allowed == nil {
		return nil, errors.New("embedded server requires a domain, key and all account-policy hooks")
	}
	codec, err := security.NewCodec(5, in.Key)
	if err != nil {
		return nil, err
	}
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{in.Domain}
	if len(in.Domains) > 0 {
		if len(in.Domains) > 8 {
			return nil, errors.New("at most eight embedded domains")
		}
		for _, domain := range in.Domains {
			if domain == "" || len(domain) > 128 || strings.ContainsAny(domain, " /\\\t\n") {
				return nil, errors.New("invalid embedded domain")
			}
		}
		cfg.Domain = append([]string(nil), in.Domains...)
	}
	cfg.AdvertiseDomains = append([]string(nil), cfg.Domain...)
	cfg.DataEncryptionMethod, cfg.EncryptionAutoDetect = 5, false
	cfg.TCPListenerEnabled, cfg.UDPIPv6Enabled, cfg.TCPIPv6Enabled = false, false, false
	cfg.MinVPNLabelLength = 1
	cfg.MaxActiveSessions, cfg.MaxStreamsPerSession = 8, 128
	cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit = 2, 64
	cfg.SessionOrphanQueueInitialCap, cfg.StreamQueueInitialCapacity = 8, 16
	cfg.DNSFragmentStoreCapacity, cfg.SOCKS5FragmentStoreCapacity = 32, 32
	cfg.DNSCacheMaxRecords = 16
	cfg.RecentlyClosedStreamCap = 128
	cfg.ARQWindowSize = 256
	cfg.MaxAllowedClientDownloadMTU = 4096
	cfg.MaxDNSResponseBytes = 32768
	cfg.SessionCleanupIntervalSecs = 5
	ctx, cancel := context.WithCancel(parent)
	s := New(cfg, logger.New("Cotten account", "ERROR"), codec)
	s.embeddedDialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if ctx.Err() != nil || !in.Allowed() {
			return nil, net.ErrClosed
		}
		dialCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		defer stop()
		return in.DialContext(dialCtx, network, address)
	}
	s.dialStreamUpstreamFn = func(network, address string, _ time.Duration) (net.Conn, error) {
		return s.embeddedDialContext(ctx, network, address)
	}
	s.embeddedDNSExchange = func(raw []byte) ([]byte, error) {
		if ctx.Err() != nil || !in.Allowed() {
			return nil, net.ErrClosed
		}
		return in.ExchangeDNS(ctx, raw)
	}
	e := &Embedded{s: s, ctx: ctx, cancel: cancel, allowed: in.Allowed}
	s.deferredDNSSession.Start(ctx)
	s.deferredConnectSession.Start(ctx)
	e.wg.Add(1)
	go func() { defer e.wg.Done(); s.sessionCleanupLoop(ctx) }()
	return e, nil
}

// HandleDNS processes a complete wire-format DNS message over either transport.
// The caller owns framing, socket limits, queuing and domain-based routing.
func (e *Embedded) HandleDNS(query []byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.ctx.Err() != nil || len(query) > 65535 || !e.allowed() {
		return nil
	}
	return e.s.safeHandlePacket(query)
}

func (e *Embedded) Close() error {
	e.once.Do(func() {
		e.cancel()
		e.mu.Lock()
		defer e.mu.Unlock()
		e.s.deferredDNSSession.wait()
		e.s.deferredConnectSession.wait()
		e.wg.Wait()
		e.s.sessions.mu.RLock()
		ids := make([]uint16, 0, len(e.s.sessions.activeIDs))
		for id := range e.s.sessions.activeIDs {
			ids = append(ids, id)
		}
		e.s.sessions.mu.RUnlock()
		for _, id := range ids {
			if record, ok := e.s.sessions.Close(id, time.Now(), 0); ok {
				e.s.cleanupClosedSession(id, record)
			}
		}
	})
	return nil
}
