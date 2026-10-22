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

	// MaxActiveSessions bounds live sessions across native and legacy clients.
	// Zero preserves the embedded default of 64; valid explicit values are 1–65535.
	MaxActiveSessions int
	// MaxStreamsPerSession bounds data streams within each tunnel session.
	// Zero preserves the embedded default of 128; valid explicit values are 1–65535.
	MaxStreamsPerSession int
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
	if in.MaxActiveSessions < 0 || in.MaxActiveSessions > maxServerSessionSlots {
		return nil, errors.New("embedded session limit must be between 1 and 65535, or zero for the default")
	}
	if in.MaxStreamsPerSession < 0 || in.MaxStreamsPerSession > 65535 {
		return nil, errors.New("embedded stream limit must be between 1 and 65535, or zero for the default")
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
	cfg.MaxActiveSessions, cfg.MaxStreamsPerSession = 64, 128
	if in.MaxActiveSessions > 0 {
		cfg.MaxActiveSessions = in.MaxActiveSessions
	}
	if in.MaxStreamsPerSession > 0 {
		cfg.MaxStreamsPerSession = in.MaxStreamsPerSession
	}
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
	// A slow destination must not serialize all other connection attempts for
	// a shared account. Keep the previous 128 queued slots and 32 per-session
	// admissions, while allowing eight independent dials. DNS retains its
	// separately sized pool above.
	s.deferredConnectSession = newDeferredSessionProcessor(8, 16, s.log)
	s.embeddedAllowed = func() bool { return ctx.Err() == nil && in.Allowed() }
	s.embeddedDialContext = func(caller context.Context, network, address string) (net.Conn, error) {
		if ctx.Err() != nil || !in.Allowed() {
			return nil, net.ErrClosed
		}
		if caller == nil {
			caller = ctx
		}
		dialCtx, stop := context.WithTimeout(caller, 15*time.Second)
		defer stop()
		stopAccount := context.AfterFunc(ctx, stop)
		defer stopAccount()
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		conn, err := in.DialContext(dialCtx, network, address)
		if cancelled := dialCtx.Err(); cancelled != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, cancelled
		}
		return conn, err
	}
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		caller := ctx
		if timeout > 0 {
			var cancelTimeout context.CancelFunc
			caller, cancelTimeout = context.WithTimeout(caller, timeout)
			defer cancelTimeout()
		}
		return s.embeddedDialContext(caller, network, address)
	}
	s.embeddedDNSExchange = func(caller context.Context, raw []byte) ([]byte, error) {
		if ctx.Err() != nil || !in.Allowed() {
			return nil, net.ErrClosed
		}
		if caller == nil {
			caller = context.Background()
		}
		timeout := s.cfg.DNSUpstreamTimeout()
		if timeout <= 0 {
			timeout = 4 * time.Second
		}
		lookupCtx, cancelLookup := context.WithTimeout(caller, timeout)
		defer cancelLookup()
		stop := context.AfterFunc(ctx, cancelLookup)
		defer stop()
		return in.ExchangeDNS(lookupCtx, raw)
	}
	e := &Embedded{s: s, ctx: ctx, cancel: cancel, allowed: in.Allowed}
	s.deferredDNSSession.Start(ctx)
	s.deferredConnectSession.Start(ctx)
	e.wg.Add(1)
	go func() { defer e.wg.Done(); s.sessionCleanupLoop(ctx) }()
	return e, nil
}

// HandleDNS processes a complete wire-format UDP DNS message.
// The caller owns framing, socket limits, queuing and domain-based routing.
func (e *Embedded) HandleDNS(query []byte) []byte {
	return e.handleDNS(query, false)
}

// HandleDNSTCP preserves the larger response budget of a framed TCP transport.
func (e *Embedded) HandleDNSTCP(query []byte) []byte {
	return e.handleDNS(query, true)
}

func (e *Embedded) handleDNS(query []byte, tcp bool) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.ctx.Err() != nil || len(query) > 65535 || !e.allowed() {
		return nil
	}
	if tcp {
		return e.s.safeHandlePacketTCP(query)
	}
	return e.s.safeHandlePacket(query)
}

// SessionCount reports live native and legacy sessions for this account.
func (e *Embedded) SessionCount() int {
	e.s.sessions.mu.RLock()
	defer e.s.sessions.mu.RUnlock()
	return len(e.s.sessions.activeIDs)
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
