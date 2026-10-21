package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"cottendns-go/internal/cottenmax"
)

func (c *Client) runCottenMax(ctx context.Context) error {
	ctx, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()
	defer c.closeSharedEncryptedDNSClient()
	defer c.closeResolverCacheLog()
	if len(c.cfg.Domains) == 0 {
		return fmt.Errorf("cottenmax requires a tunnel domain")
	}
	c.runtimePhase.Store(clientPhaseConnecting)
	defer c.runtimePhase.Store(clientPhaseStopped)
	engine, err := c.newCottenMaxEngine()
	if err != nil {
		return err
	}
	c.cottenMax.Store(engine)
	defer engine.Close()
	c.log.Warnf("Experimental CottenMax: safe startup, held polls, ephemeral keys, byte-range retransmission and implicit upload ACKs; no automatic legacy downgrade")
	go c.runTrafficStatsReporter(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.logResolverRuntimeState()
			}
		}
	}()
	// Start authentication immediately so a client does not wait for a local
	// proxy request before learning its usable DNS paths. The proxy listener
	// still starts immediately; warmup never gates fast startup.
	go func() {
		warmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := engine.Authenticate(warmCtx); err != nil {
			if ctx.Err() == nil {
				c.log.Warnf("CottenMax authentication failed: no authenticated DNS path; check the Max server build, domain and shared key (%v)", err)
			}
			return
		}
		if ctx.Err() == nil {
			c.runtimePhase.Store(clientPhaseConnected)
			c.logConnectionProgress("connected", 100, "mode", "cottenmax")
		}
	}()
	listener := NewTCPListener(c, c.cfg.ProtocolType)
	if err := listener.Start(ctx, c.cfg.ListenIP, c.cfg.ListenPort); err != nil {
		return err
	}
	defer listener.Stop()
	if c.cfg.LocalDNSEnabled {
		c.ensureLocalDNSCachePersistence(ctx)
		dns := NewDNSListener(c)
		if err := dns.Start(ctx, c.cfg.LocalDNSIP, c.cfg.LocalDNSPort); err != nil {
			return err
		}
		defer dns.Stop()
	}
	defer c.clearPendingDNSQueries()
	<-ctx.Done()
	return nil
}

// DoT encrypts and authenticates the client-to-resolver hop. The resolver is
// dialed by its configured IP, avoiding a bootstrap lookup through intercepted
// system DNS. Explicit DoT never falls back to a plaintext resolver transport.
func (c *Client) dialCottenMaxDoT(ctx context.Context, network, address string) (net.Conn, error) {
	target := resolverHostWithPort(address, c.cfg.ResolverDoTPort)
	cfg := c.resolverTLSConfig()
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		cfg.ServerName = host
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	return dialer.DialContext(ctx, network, target)
}

func (c *Client) serveCottenMaxStream(ctx context.Context, local net.Conn, target string, version byte, replyConn net.Conn) {
	defer local.Close()
	active := c.cottenMaxStreams.Add(1)
	defer c.cottenMaxStreams.Add(-1)
	limit := c.cfg.MaxActiveStreams
	if limit <= 0 {
		limit = 64
	}
	var remote net.Conn
	var err error
	if active > int64(min(limit, 256)) {
		err = fmt.Errorf("cottenmax: stream limit reached")
	} else {
		dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if version == 0 {
			remote, err = c.cottenMax.Load().DialStream(dialCtx, target)
		} else {
			remote, err = c.cottenMax.Load().Dial(dialCtx, target)
		}
		cancel()
	}
	if err != nil {
		c.streamDialFailures.Add(1)
		c.cottenMaxReply(replyConn, version, false)
		return
	}
	defer remote.Close()
	c.runtimePhase.Store(clientPhaseConnected)
	if !c.cottenMaxReply(replyConn, version, true) {
		return
	}
	_ = local.SetDeadline(time.Time{})
	// Cancellation closes both directions, including an idle local socket.
	stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
	defer stop()
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, copyErr := io.Copy(cottenMaxCounter{remote, &c.txTotalBytes}, local)
		if copyErr != nil {
			remote.Close()
			local.Close()
			return
		}
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, copyErr := io.Copy(cottenMaxCounter{local, &c.rxTotalBytes}, remote)
	if copyErr != nil {
		local.Close()
		remote.Close()
	} else if cw, ok := local.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-uploadDone
}

type cottenMaxCounter struct {
	io.Writer
	count *atomic.Uint64
}

func (w cottenMaxCounter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.count.Add(uint64(n))
	return n, err
}

func (c *Client) cottenMaxReply(conn net.Conn, version byte, success bool) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(c.cfg.LocalHandshakeTimeout()))
	defer conn.SetWriteDeadline(time.Time{})
	var err error
	switch version {
	case SOCKS4_VERSION:
		err = c.sendSocks4Reply(conn, success)
	case SOCKS5_VERSION:
		reply := byte(SOCKS5_REPLY_GENERAL_FAILURE)
		if success {
			reply = SOCKS5_REPLY_SUCCESS
		}
		err = c.sendSocksReply(conn, reply, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
	case httpProxyCONNECT:
		if success {
			_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		} else {
			sendHTTPError(conn, 502)
		}
	case httpProxyPlain:
		if !success {
			sendHTTPError(conn, 502)
		}
	}
	return err == nil
}

// Stream transports can carry padding; never apply it to the plain DNS path.
func cottenMaxEnginePadding(transport string, block int) int {
	if transport == "dot" {
		return block
	}
	return 0 // HTTPS/QUIC adapters pad once, after the engine prepares its query.
}

// newCottenMaxEngine shares the exact runtime configuration with standalone
// authenticated scans; callers may restrict cfg.Resolvers/ResolverTransport.
func (c *Client) newCottenMaxEngine() (*cottenmax.Client, error) {
	if len(c.cfg.Domains) == 0 {
		return nil, fmt.Errorf("cottenmax requires a tunnel domain")
	}
	resolvers := make([]string, 0, len(c.cfg.Resolvers))
	for _, r := range c.cfg.Resolvers {
		if c.cfg.ResolverIPMode == "ipv4" && resolverAddressIsIPv6(r.IP) {
			continue
		}
		if c.cfg.ResolverIPMode == "ipv6" && !resolverAddressIsIPv6(r.IP) {
			continue
		}
		resolvers = append(resolvers, formatResolverEndpoint(r.IP, r.Port))
	}
	tcp := "auto"
	if c.cfg.ResolverTransport == "udp" {
		tcp = "off"
	}
	if c.cfg.ResolverTransport == "tcp" || c.cfg.ResolverTransport == "dot" {
		tcp = "only"
	}
	var dialTCP func(context.Context, string, string) (net.Conn, error)
	var listenPacket func(context.Context, string, string) (net.PacketConn, error)
	if c.cfg.ResolverTransport == "dot" {
		if c.cfg.ResolverTLSInsecureSkipVerify && strings.TrimSpace(c.cfg.ResolverTLSPin) == "" {
			return nil, fmt.Errorf("cottenmax DoT requires certificate verification or RESOLVER_TLS_PIN")
		}
		dialTCP = c.dialCottenMaxDoT
	}
	if c.cfg.ResolverTransport == "doh" || c.cfg.ResolverTransport == "doh3" || c.cfg.ResolverTransport == "doq" {
		listenPacket = c.newCottenMaxEncryptedPacketConn
		tcp = "off"
	}
	if len(resolvers) == 0 && !c.cfg.ResolverDiscoveryEnabled {
		return nil, fmt.Errorf("cottenmax: no resolvers for configured address family")
	}
	// Hard query budgets cannot be applied by blocking Soar's send callback:
	// it holds its session lock while sending. Reject until scheduled pacing
	// can be integrated without stalling answer processing or loss detection.
	if c.cfg.QueryRateLimited() {
		return nil, fmt.Errorf("experimental cottenmax does not yet support hard QUERY_RATE_LIMIT_* budgets; use legacy")
	}
	engine, err := cottenmax.NewClient(cottenmax.ClientConfig{
		Domain: c.cfg.Domains[0], PublicKey: c.cfg.CottenMaxServerPublicKey,
		Secret: c.cfg.EncryptionKey, Resolvers: resolvers, TCP: tcp,
		Domains:          append(append([]string(nil), c.cfg.Domains[1:]...), c.cfg.StandbyDomains...),
		FailoverAfter:    time.Duration(c.cfg.CottenMaxFailoverAfterMilliseconds) * time.Millisecond,
		QNameLabelLength: c.cfg.QNameLabelLength, QNameLabelJitter: c.cfg.QNameLabelJitter, QNameLossGuard: c.cfg.CottenMaxQNameLossGuard,
		SafeQName: c.cfg.CottenMaxSafeQName, MaxQName: c.cfg.CottenMaxMaxQName, MaxAnswer: c.cfg.CottenMaxMaxAnswer,
		MaxPathWindow: c.cfg.CottenMaxMaxPathWindow, MaxInflight: c.cfg.CottenMaxMaxInflight,
		SessionIdle:                  time.Duration(c.cfg.CottenMaxSessionIdleMilliseconds) * time.Millisecond,
		EncryptedDNSPaddingBlockSize: cottenMaxEnginePadding(c.cfg.ResolverTransport, c.cfg.DNSPaddingBlockSize),
		ListenPacket:                 listenPacket,
		DiscoveryForDomain:           func(domain string) cottenmax.Discovery { return c.cottenMaxDiscoveryForDomain(domain, resolvers) },
		Hold:                         time.Duration(c.cfg.CottenMaxHoldMilliseconds) * time.Millisecond,
		MaxStreams:                   min(c.cfg.MaxActiveStreams, 256),
		DialTCP:                      dialTCP,
		Discovery:                    c.cottenMaxDiscovery(resolvers),
	})
	if err != nil {
		return nil, err
	}
	return engine, nil
}
