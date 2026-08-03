// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/config"
	dnsCache "cottendns-go/internal/dnscache"
	domainMatcher "cottendns-go/internal/domainmatcher"
	fragmentStore "cottendns-go/internal/fragmentstore"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = 30
	mtuProbeMaxDownSize = 4096
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	codecs                   []*security.Codec // candidate codecs for encryption-method auto-detect
	preferredCodec           atomic.Int32      // index into codecs to try first
	codecAccepted            [6]atomic.Uint64  // successful ingress frames by encryption method
	domainMatcher            *domainMatcher.Matcher
	sessions                 *sessionStore
	deferredDNSSession       *deferredSessionProcessor
	deferredConnectSession   *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamHealthMu      sync.Mutex
	dnsUpstreamHealth        map[string]*dnsUpstreamHealthState
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentStore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentStore.Store[socks5FragmentKey]
	dnsFragmentTimeout       time.Duration
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	packetPool               sync.Pool
	deferredInflightMu       sync.Mutex
	deferredInflight         map[uint64]struct{}
	immediateConnectedLog    throttledLogState
	invalidSessionDropLog    throttledLogState
	droppedPackets           atomic.Uint64
	ingressRejectedPackets   atomic.Uint64
	ingressPreparedPackets   atomic.Uint64
	ingressInflateFailures   atomic.Uint64
	ingressControlDepth      atomic.Int64
	ingressDataDepth         atomic.Int64
	ingressControlHighWater  atomic.Uint64
	ingressDataHighWater     atomic.Uint64
	ingressLatencyNanos      atomic.Uint64
	ingressLatencySamples    atomic.Uint64
	sessionBusyResponses     atomic.Uint64
	lastDropLogUnix          atomic.Int64
	deferredDroppedPackets   atomic.Uint64
	lastDeferredDropLogUnix  atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32

	// Observability counters (Phase 8). Incremented by the corresponding
	// hardening paths so operators can observe how often each guard fires
	// without having to grep logs. Read via Stats(). The stream-cap
	// rejection counter lives on sessionStore (where the cap is enforced)
	// and the fragment-conflict counter lives on each fragmentStore
	// instance; both are surfaced through Stats().
	dnsResponseOversize     atomic.Uint64
	fragmentInvalidHeader   atomic.Uint64
	upstreamPanicsRecovered atomic.Uint64
	cleanupPanicsRecovered  atomic.Uint64
	dnsUpstreamQueries      atomic.Uint64
	dnsUpstreamFailures     atomic.Uint64
	dnsUpstreamHedges       atomic.Uint64
	dnsUpstreamTCPFallbacks atomic.Uint64
	streamConnBudget        *connectionBudget
	encryptedConnBudget     *connectionBudget
	tcpListenerUp           atomic.Uint64
	dotListenerUp           atomic.Uint64
	dohListenerUp           atomic.Uint64
	tlsHandshakeFailures    atomic.Uint64
	encryptedConnRejected   atomic.Uint64
	dohRequestRejected      atomic.Uint64
	sniPassthroughActive    atomic.Uint64
	sniPassthroughFailures  atomic.Uint64
	genericUDPActive        atomic.Uint64
	genericUDPTotal         atomic.Uint64
	genericUDPEndpoints     atomic.Uint64
	genericUDPUpDatagrams   atomic.Uint64
	genericUDPUpBytes       atomic.Uint64
	genericUDPDownDatagrams atomic.Uint64
	genericUDPDownBytes     atomic.Uint64
	genericUDPErrors        atomic.Uint64
	startedAt               time.Time
	running                 atomic.Bool

	// clientPolicy is the ceiling set advertised to clients in SESSION_ACCEPT.
	// Resolved once at construction because it never changes at runtime. A zero
	// value means the operator configured no ceilings, and no policy block is
	// put on the wire at all.
	clientPolicy VpnProto.SessionAcceptClientPolicy
}

// buildClientPolicy maps the MAX_ALLOWED_CLIENT_* / MIN_ALLOWED_CLIENT_* config
// keys onto the wire policy. It lives here rather than on ServerConfig because
// config cannot import vpnproto: vpnproto depends on security, which depends on
// config, so the accessor would close an import cycle.
func buildClientPolicy(cfg config.ServerConfig) VpnProto.SessionAcceptClientPolicy {
	return VpnProto.SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: cfg.MaxAllowedClientPacketDuplication,
		MaxSetupDuplicationCount:  cfg.MaxAllowedClientSetupPacketDuplication,
		MaxUploadMTU:              cfg.MaxAllowedClientUploadMTU,
		MaxDownloadMTU:            cfg.MaxAllowedClientDownloadMTU,
		MaxRxTxWorkers:            cfg.MaxAllowedClientRxTxWorkers,
		MinPingAggressiveInterval: cfg.MinAllowedClientPingAggressiveInterval,
		MaxPacketsPerBatch:        cfg.MaxAllowedClientPacketsPerBatch,
		MaxARQWindowSize:          cfg.MaxAllowedClientARQWindowSize,
		MaxARQDataNackMaxGap:      cfg.MaxAllowedClientARQDataNackMaxGap,
		MinCompressionMinSize:     cfg.MinAllowedClientCompressionMinSize,
		MinARQInitialRTOSeconds:   cfg.MinAllowedClientARQInitialRTOSeconds,
	}
}

// Stats is a point-in-time snapshot of operational counters and queue gauges
// maintained by the server. Total/high-water values are monotonic; current
// queue depths may rise and fall. Stats() is safe to call from any goroutine.
type Stats struct {
	DroppedPackets          uint64
	IngressRejectedPackets  uint64
	IngressPreparedPackets  uint64
	IngressInflateFailures  uint64
	IngressControlDepth     uint64
	IngressDataDepth        uint64
	IngressControlHighWater uint64
	IngressDataHighWater    uint64
	IngressLatencyNanos     uint64
	IngressLatencySamples   uint64
	DeferredDroppedPackets  uint64
	StreamCapRejections     uint64
	DNSResponseOversize     uint64
	FragmentConflictDrops   uint64
	FragmentInvalidHeader   uint64
	UpstreamPanicsRecovered uint64
	CleanupPanicsRecovered  uint64
	ActiveSessions          uint64
	NativeSessions          uint64
	LegacySessions          uint64
	ActiveStreams           uint64
	SessionBusyResponses    uint64
	DNSUpstreamQueries      uint64
	DNSUpstreamFailures     uint64
	DNSUpstreamHedges       uint64
	DNSUpstreamTCPFallbacks uint64
	TCPListenerUp           uint64
	DoTListenerUp           uint64
	DoHListenerUp           uint64
	TLSHandshakeFailures    uint64
	EncryptedConnRejected   uint64
	DoHRequestRejected      uint64
	SNIPassthroughActive    uint64
	SNIPassthroughFailures  uint64
	IngressControlCapacity  uint64
	IngressDataCapacity     uint64
	DeferredDNSPending      uint64
	DeferredDNSCapacity     uint64
	DeferredConnectPending  uint64
	DeferredConnectCapacity uint64
	StreamConnectionsActive uint64
	StreamConnectionsLimit  uint64
	EncryptedConnsActive    uint64
	EncryptedConnsLimit     uint64
	CodecAcceptedPackets    [6]uint64
	GenericUDPActive        uint64
	GenericUDPTotal         uint64
	GenericUDPEndpoints     uint64
	GenericUDPUpDatagrams   uint64
	GenericUDPUpBytes       uint64
	GenericUDPDownDatagrams uint64
	GenericUDPDownBytes     uint64
	GenericUDPErrors        uint64
}

// Stats returns a consistent snapshot of the server's observability counters.
func (s *Server) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	var fragmentConflicts uint64
	if s.dnsFragments != nil {
		fragmentConflicts += s.dnsFragments.ConflictCount()
	}
	if s.socks5Fragments != nil {
		fragmentConflicts += s.socks5Fragments.ConflictCount()
	}
	activeSessions, nativeSessions, legacySessions, activeStreams := s.sessions.operationalCounts()
	var controlCapacity, dataCapacity int
	// Preserve the documented zero-value Stats contract for unconfigured test
	// and embedding instances. Loaded production config always normalizes these
	// fields above zero before New constructs the server.
	if s.cfg.MaxConcurrentRequests > 0 && s.cfg.MaxPacketSize > 0 && s.cfg.MaxIngressQueueBytes > 0 {
		controlCapacity, dataCapacity = s.ingressQueueCapacities()
	}
	dnsPending, dnsCapacity := s.deferredDNSSession.snapshot()
	connectPending, connectCapacity := s.deferredConnectSession.snapshot()
	streamConnectionsActive, streamConnectionsLimit := s.streamConnBudget.snapshot()
	encryptedConnsActive, encryptedConnsLimit := s.encryptedConnBudget.snapshot()
	var codecAccepted [6]uint64
	for method := range codecAccepted {
		codecAccepted[method] = s.codecAccepted[method].Load()
	}
	return Stats{
		DroppedPackets:          s.droppedPackets.Load(),
		IngressRejectedPackets:  s.ingressRejectedPackets.Load(),
		IngressPreparedPackets:  s.ingressPreparedPackets.Load(),
		IngressInflateFailures:  s.ingressInflateFailures.Load(),
		IngressControlDepth:     uint64(max(s.ingressControlDepth.Load(), 0)),
		IngressDataDepth:        uint64(max(s.ingressDataDepth.Load(), 0)),
		IngressControlHighWater: s.ingressControlHighWater.Load(),
		IngressDataHighWater:    s.ingressDataHighWater.Load(),
		IngressLatencyNanos:     s.ingressLatencyNanos.Load(),
		IngressLatencySamples:   s.ingressLatencySamples.Load(),
		DeferredDroppedPackets:  s.deferredDroppedPackets.Load(),
		StreamCapRejections:     s.sessions.streamCapRejectionsCount(),
		DNSResponseOversize:     s.dnsResponseOversize.Load(),
		FragmentConflictDrops:   fragmentConflicts,
		FragmentInvalidHeader:   s.fragmentInvalidHeader.Load(),
		UpstreamPanicsRecovered: s.upstreamPanicsRecovered.Load(),
		CleanupPanicsRecovered:  s.cleanupPanicsRecovered.Load(),
		ActiveSessions:          activeSessions,
		NativeSessions:          nativeSessions,
		LegacySessions:          legacySessions,
		ActiveStreams:           activeStreams,
		SessionBusyResponses:    s.sessionBusyResponses.Load(),
		DNSUpstreamQueries:      s.dnsUpstreamQueries.Load(),
		DNSUpstreamFailures:     s.dnsUpstreamFailures.Load(),
		DNSUpstreamHedges:       s.dnsUpstreamHedges.Load(),
		DNSUpstreamTCPFallbacks: s.dnsUpstreamTCPFallbacks.Load(),
		TCPListenerUp:           s.tcpListenerUp.Load(),
		DoTListenerUp:           s.dotListenerUp.Load(),
		DoHListenerUp:           s.dohListenerUp.Load(),
		TLSHandshakeFailures:    s.tlsHandshakeFailures.Load(),
		EncryptedConnRejected:   s.encryptedConnRejected.Load(),
		DoHRequestRejected:      s.dohRequestRejected.Load(),
		SNIPassthroughActive:    s.sniPassthroughActive.Load(),
		SNIPassthroughFailures:  s.sniPassthroughFailures.Load(),
		IngressControlCapacity:  uint64(max(controlCapacity, 0)),
		IngressDataCapacity:     uint64(max(dataCapacity, 0)),
		DeferredDNSPending:      uint64(max(dnsPending, 0)),
		DeferredDNSCapacity:     uint64(max(dnsCapacity, 0)),
		DeferredConnectPending:  uint64(max(connectPending, 0)),
		DeferredConnectCapacity: uint64(max(connectCapacity, 0)),
		StreamConnectionsActive: uint64(max(streamConnectionsActive, 0)),
		StreamConnectionsLimit:  uint64(max(streamConnectionsLimit, 0)),
		EncryptedConnsActive:    uint64(max(encryptedConnsActive, 0)),
		EncryptedConnsLimit:     uint64(max(encryptedConnsLimit, 0)),
		CodecAcceptedPackets:    codecAccepted,
		GenericUDPActive:        s.genericUDPActive.Load(),
		GenericUDPTotal:         s.genericUDPTotal.Load(),
		GenericUDPEndpoints:     s.genericUDPEndpoints.Load(),
		GenericUDPUpDatagrams:   s.genericUDPUpDatagrams.Load(),
		GenericUDPUpBytes:       s.genericUDPUpBytes.Load(),
		GenericUDPDownDatagrams: s.genericUDPDownDatagrams.Load(),
		GenericUDPDownBytes:     s.genericUDPDownBytes.Load(),
		GenericUDPErrors:        s.genericUDPErrors.Load(),
	}
}

type request struct {
	buf      []byte
	size     int
	addr     *net.UDPAddr
	prepared preparedIngress
	admitted time.Time
	// conn is the socket the datagram arrived on, so the reply leaves by the
	// same one. With SO_REUSEPORT every socket shares the listen address, so
	// this is transmit-load spreading rather than a correctness requirement.
	conn *net.UDPConn
}

type ingressQueues struct {
	control chan request
	data    chan request
}

// errReusePortUnsupported reports that SO_REUSEPORT is unavailable, so the
// caller should fall back to a single shared listening socket.
var errReusePortUnsupported = errors.New("SO_REUSEPORT not supported on this platform")

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	streamBudget := newConnectionBudget(cfg.TCPMaxConns)
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	dnsDeferredWorkers, connectDeferredWorkers, dnsDeferredQueue, connectDeferredQueue := splitDeferredSessionPools(cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit)
	srv := &Server{
		cfg:                    cfg,
		log:                    log,
		codec:                  codec,
		codecs:                 []*security.Codec{codec}, // single-codec until SetCodecSet enables auto-detect
		domainMatcher:          domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:               newSessionStore(cfg.SessionOrphanQueueInitialCap, cfg.StreamQueueInitialCapacity, cfg.SessionInitReuseTTL(), cfg.RecentlyClosedStreamTTL(), cfg.RecentlyClosedStreamCap, cfg.MaxStreamsPerSession, cfg.MaxActiveSessions),
		deferredDNSSession:     newDeferredSessionProcessor(dnsDeferredWorkers, dnsDeferredQueue, log),
		deferredConnectSession: newDeferredSessionProcessor(connectDeferredWorkers, connectDeferredQueue, log),
		invalidCookieTracker:   newInvalidCookieTracker(),
		clientPolicy:           buildClientPolicy(cfg),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsUpstreamHealth:  make(map[string]*dnsUpstreamHealthState, len(cfg.DNSUpstreamServers)),
		dnsFragments:       fragmentStore.New[dnsFragmentKey](cfg.DNSFragmentStoreCapacity),
		socks5Fragments:    fragmentStore.New[socks5FragmentKey](cfg.SOCKS5FragmentStoreCapacity),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
		dialStreamUpstreamFn: func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
		deferredInflight: make(map[uint64]struct{}, 128),
		startedAt:        time.Now(),
		streamConnBudget: streamBudget,
		// DoT/DoH draw from a capped sub-share so that flooding the optional
		// encrypted listeners can never consume the connection headroom the
		// plain DNS-over-TCP/53 survival path depends on.
		encryptedConnBudget: newChildConnectionBudget(streamBudget, encryptedConnCeiling(cfg.TCPMaxConns, cfg.EncryptedMaxConns)),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}

	// The download ceiling is enforced server-side as well as advertised. The
	// upload value is retained on the session for accounting; compatible clients
	// enforce it before constructing subsequent tunnel queries.
	srv.sessions.setClientMTUCeilings(cfg.MaxAllowedClientUploadMTU, cfg.MaxAllowedClientDownloadMTU)

	return srv
}

// SetCodecSet enables encryption-method auto-detection by giving the server a
// codec per candidate method (all derived from the same shared key). The codecs
// are reordered into the trial order used at ingress: authenticated (AEAD)
// methods first — so an authenticated frame is never mis-decrypted by an
// unauthenticated codec — with the configured method placed first within its
// own class so the common single-method deployment costs one decrypt attempt.
// Passing a set with a single codec leaves the server behaving exactly as
// before. Call once during startup. preferred is the index of the configured
// method within the supplied slice.
func (s *Server) SetCodecSet(codecs []*security.Codec, preferred int) {
	if s == nil || len(codecs) == 0 {
		return
	}

	var preferredCodec *security.Codec
	if preferred >= 0 && preferred < len(codecs) {
		preferredCodec = codecs[preferred]
	}

	var aead, other []*security.Codec
	for i, codec := range codecs {
		if codec == nil || i == preferred {
			continue
		}
		if security.IsAuthenticatedMethod(codec.Method()) {
			aead = append(aead, codec)
		} else {
			other = append(other, codec)
		}
	}

	ordered := make([]*security.Codec, 0, len(codecs))
	switch {
	case preferredCodec != nil && security.IsAuthenticatedMethod(preferredCodec.Method()):
		ordered = append(ordered, preferredCodec) // preferred AEAD first
		ordered = append(ordered, aead...)
		ordered = append(ordered, other...)
	case preferredCodec != nil:
		ordered = append(ordered, aead...) // AEAD still ahead of any unauthenticated
		ordered = append(ordered, preferredCodec)
		ordered = append(ordered, other...)
	default:
		ordered = append(ordered, aead...)
		ordered = append(ordered, other...)
	}

	s.codecs = ordered
	s.codec = ordered[0]
	s.preferredCodec.Store(0)
}

type throttledLogState struct {
	mu   sync.Mutex
	last map[string]int64
}

const (
	throttledLogSoftCap = 1024
	throttledLogHardCap = 1536
)

func (s *throttledLogState) allow(key string, now time.Time, interval time.Duration) bool {
	if s == nil {
		return true
	}
	if interval <= 0 {
		interval = time.Second
	}

	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		s.last = make(map[string]int64, 64)
	}

	if len(s.last) > 0 {
		s.pruneLocked(nowUnixNano, interval)
	}

	last := s.last[key]

	if last != 0 && nowUnixNano-last < interval.Nanoseconds() {
		return false
	}

	s.last[key] = nowUnixNano
	return true
}

func (s *throttledLogState) pruneLocked(nowUnixNano int64, interval time.Duration) {
	if s == nil || len(s.last) == 0 {
		return
	}

	cutoff := nowUnixNano - interval.Nanoseconds()
	for key, last := range s.last {
		if last == 0 || last <= cutoff {
			delete(s.last, key)
		}
	}

	if len(s.last) <= throttledLogHardCap {
		return
	}

	target := throttledLogSoftCap
	for len(s.last) > target {
		oldestKey := ""
		oldestSeen := nowUnixNano
		for key, last := range s.last {
			if oldestKey == "" || last < oldestSeen {
				oldestKey = key
				oldestSeen = last
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.last, oldestKey)
	}
}

func splitDeferredSessionPools(totalWorkers int, totalQueue int) (dnsWorkers int, connectWorkers int, dnsQueue int, connectQueue int) {
	if totalWorkers <= 0 {
		totalWorkers = 1
	}
	if totalQueue <= 0 {
		totalQueue = 256
	}

	// DNS queries use a dedicated lightweight pool so connect-heavy work keeps
	// the full user-configured deferred capacity.
	dnsWorkers = 1
	connectWorkers = totalWorkers

	connectQueue = totalQueue
	dnsQueue = min(max(totalQueue/4, 64), 256)

	return dnsWorkers, connectWorkers, dnsQueue, connectQueue
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conns, err := s.listenUDP(&net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})

	if err != nil {
		return err
	}
	s.running.Store(true)
	defer s.running.Store(false)

	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	for _, conn := range conns {
		s.configureSocketBuffers(conn)
	}

	queueCapacity := s.ingressQueueCapacity()
	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Sockets: <cyan>%d</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan> <gray>(memory cap %d bytes)</gray></green>",
		s.cfg.Address(),
		len(conns),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		queueCapacity,
		s.cfg.MaxIngressQueueBytes,
	)

	controlCapacity, dataCapacity := s.ingressQueueCapacities()
	queues := ingressQueues{
		control: make(chan request, controlCapacity),
		data:    make(chan request, dataCapacity),
	}
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()

	s.deferredDNSSession.Start(runCtx)
	s.deferredConnectSession.Start(runCtx)
	s.startDNSWorkers(runCtx, queues, &workerWG)

	// DNS-over-TCP fallback on the same host:port, for clients on networks that
	// filter or truncate UDP/53. Shares the transport-agnostic packet handler.
	var tcpWG sync.WaitGroup
	if s.cfg.TCPListenerEnabled {
		tcpWG.Add(1)
		go func() {
			defer tcpWG.Done()
			if err := s.serveTCP(runCtx, s.cfg.UDPHost, s.cfg.UDPPort); err != nil && runCtx.Err() == nil {
				s.log.Warnf("<yellow>TCP listener stopped: <cyan>%v</cyan></yellow>", err)
			}
		}()
	}

	// Optional encrypted-DNS listeners (DoT/DoH). These are opt-in disguise
	// transports, not part of the UDP/TCP fallback chain — the client selects
	// them and falls back to UDP/TCP itself on failure. Both share one TLS config,
	// built once (manual cert -> ACME -> self-signed). A TLS build error only
	// disables the encrypted listeners; the UDP/TCP tunnel keeps serving.
	if s.cfg.DoTListenerEnabled || s.cfg.DoHListenerEnabled {
		// TLS material is only needed when we terminate TLS ourselves: DoT always,
		// and DoH unless it runs behind a TLS-terminating proxy (DoHTLSEnabled=false).
		var tlsCfg *tls.Config
		needTLS := s.cfg.DoTListenerEnabled || s.dohWillTerminateTLS()
		if needTLS {
			cfg, tlsErr := s.buildStreamTLSConfig()
			if tlsErr != nil {
				s.log.Errorf("<red>Encrypted-DNS TLS setup failed, TLS listeners disabled: <yellow>%v</yellow></red>", tlsErr)
			} else {
				tlsCfg = cfg
			}
		}
		if s.cfg.DoTListenerEnabled && tlsCfg != nil {
			tcpWG.Add(1)
			go func() {
				defer tcpWG.Done()
				if err := s.serveDoT(runCtx, s.cfg.DoTListenHost, s.cfg.DoTListenPort, dotTLSConfig(tlsCfg)); err != nil && runCtx.Err() == nil {
					s.log.Warnf("<yellow>DoT listener stopped: <cyan>%v</cyan></yellow>", err)
				}
			}()
		}
		// DoH starts whenever it is not TLS (behind-proxy) or TLS built successfully.
		// The supervisor owns the listener and keeps re-deciding model A vs model B
		// so a panel installed (or removed) later flips coexistence automatically.
		if s.cfg.DoHListenerEnabled && (!s.dohWillTerminateTLS() || tlsCfg != nil) {
			tcpWG.Add(1)
			go func() {
				defer tcpWG.Done()
				s.runDoHSupervisor(runCtx, dohTLSConfig(tlsCfg))
			}()
		}
	}

	go func() {
		<-runCtx.Done()
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	s.startReaders(runCtx, conns, queues, readErrCh, &readerWG)

	readerWG.Wait()
	close(queues.control)
	close(queues.data)
	workerWG.Wait()
	cancel()
	tcpWG.Wait()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}
