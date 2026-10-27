// Modified for CottenDNS, 2026-10-17. See NOTICE.cottendns.txt and LICENSE.
package soar

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	dnsparser "cottendns-go/internal/dnsparser"
)

// Config configures a tunnel client.
type Config struct {
	// Download FEC is explicitly requested by the client; disabled adds no wire overhead.
	FECDownloadEnabled             bool
	FECDataShards, FECParityShards int
	// Optional wire-transparent label shaping and encrypted-hop padding.
	QNameLabelLength int
	QNameLabelJitter bool
	// QNameLossGuard uses recent authenticated near-cap replies to avoid false
	// size downgrades under loss. Experimental and disabled by default.
	QNameLossGuard      bool
	DNSPaddingBlockSize int
	Zone                string
	ServerKey           ed25519.PublicKey
	// Resolvers are recursive resolvers (host:port) to tunnel through. All are used at once.
	// May be empty when Discovery is enabled.
	Resolvers []string
	// Discovery finds more resolvers that carry the tunnel.
	Discovery Discovery
	// SafeQName is the name length every path starts at; some networks drop longer names (Iran
	// ~101). Paths probe up to MaxQName. Defaults 101 and 253.
	SafeQName, MaxQName int
	// Hold is how long the server may hold an idle poll. Default 500ms.
	Hold time.Duration
	// MaxInflight caps queries outstanding across all paths. Default 128; at most 4,096, which
	// keeps pending queries well inside the DNS ID space.
	MaxInflight int
	// MaxPathWindow caps one path's queries outstanding. Default 32.
	MaxPathWindow int
	// QueryRateLimiter optionally paces ALL query kinds before packet building.
	// Nil retains current throughput behavior. Domain engines may share a budget.
	QueryRateLimiter *QueryRateLimiter
	// LowReductionPercent scales send admission while preserving Full's CC
	// estimates. Zero disables percentage pacing. Valid enabled targets: 10..90.
	LowReductionPercent int
	// PercentagePacer may be shared across independent domain engines.
	PercentagePacer *PercentagePacer
	// DisableTailDuplication suppresses proactive upload copies, not ARQ recovery.
	DisableTailDuplication bool
	// InitialResolverLimit defers excess explicit resolvers to paced discovery.
	// Zero retains eager startup. Deferred entries are not discarded or sampled.
	InitialResolverLimit int
	// MaxAnswer caps the DNS answer size (bytes) paths may probe up to. Every path starts at 512,
	// which every network delivers, and grows only while larger answers keep arriving: some
	// networks silently drop large DNS responses (they look like amplification). Default 1232.
	MaxAnswer    int
	StreamWindow uint64 // per-stream receive window. Default 256 KiB.
	SendBuffer   int    // per-stream send buffer. Default 64 KiB.
	MaxStreams   int    // Default 64; at most MaxStreamsLimit, with control queue headroom.
	// SessionIdle retires a session with no streams and no authenticated answer for this long:
	// the next Dial handshakes again rather than reuse a session the server may have ended
	// (an idle client sends nothing, and the reference server forgets a session after 2
	// minutes of silence). Keep it below the server's idle timeout. Default 90s.
	SessionIdle time.Duration
	// TCP controls DNS stream paths: "auto" (default) and "on" independently probe UDP
	// and TCP for every resolver, "only" uses TCP alone, "off" never uses TCP
	// (except for resolvers StreamOnly reports).
	TCP string
	// StreamOnly reports resolvers that only speak a stream transport (DNS over
	// TCP, or DNS over TLS through DialTCP, e.g. port 853): they get a TCP path
	// from the start and never a UDP one, which would only time out, whatever
	// TCP says, "off" included. Optional. It runs with the client's lock held, including
	// when discovery adds a resolver, so it must return quickly and not call the Client.
	StreamOnly func(resolver string) bool
	// ListenPacket opens the client's UDP socket, and DialTCP its TCP/53 connections; a VPN
	// client points them past its own tunnel, a test harness through a proxy. Defaults: net.
	ListenPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
	DialTCP      func(ctx context.Context, network, address string) (net.Conn, error)
	Logger       *slog.Logger
}

// maxLimitClass is the answer-size class for MaxAnswer (512 + 48*class bytes).
func (c *Config) maxLimitClass() int {
	if c.MaxAnswer <= 0 {
		return limitClasses - 1
	}
	return min(max((c.MaxAnswer-512)/48, 0), limitClasses-1)
}

func (c *Config) setDefaults() {
	if c.QNameLabelLength == 0 {
		c.QNameLabelLength = 63
	}
	if c.SafeQName <= 0 {
		c.SafeQName = 101
	}
	if c.MaxQName <= 0 {
		c.MaxQName = maxName
	}
	c.MaxQName = min(c.MaxQName, maxName)
	c.SafeQName = min(c.SafeQName, c.MaxQName)
	if c.Hold <= 0 {
		c.Hold = 500 * time.Millisecond
	}
	if c.FECDataShards == 0 {
		c.FECDataShards = 4
	}
	if c.FECParityShards == 0 {
		c.FECParityShards = 1
	}
	if c.MaxInflight <= 0 {
		c.MaxInflight = 128
	}
	c.MaxInflight = min(c.MaxInflight, maxInflightCap)
	if c.MaxPathWindow <= 0 {
		c.MaxPathWindow = 32
	}
	if c.StreamWindow == 0 {
		c.StreamWindow = 256 << 10
	}
	if c.SendBuffer <= 0 {
		c.SendBuffer = 64 << 10
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 64
	}
	if c.SessionIdle <= 0 {
		c.SessionIdle = 90 * time.Second
	}
	c.MaxStreams = min(c.MaxStreams, MaxStreamsLimit)
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.TCP == "" {
		c.TCP = "auto"
	}
	if c.ListenPacket == nil {
		var lc net.ListenConfig
		c.ListenPacket = lc.ListenPacket
	}
	if c.DialTCP == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		c.DialTCP = d.DialContext
	}
	c.Discovery.setDefaults()
}

const (
	// maxInflightCap caps MaxInflight whatever it's set to. With expired queries kept for
	// lateGrace too, pending queries stay far below the 65,536 DNS IDs.
	maxInflightCap = 4096
	// maxPending is a hard ceiling on pending queries (live and expired), so a free DNS ID
	// always exists and newTxnLocked's random pick always terminates.
	maxPending = 60000

	limitClasses  = 16 // answer limit = 512 + 48*class
	outcomeWindow = 20
	lateGrace     = 3 * time.Second
	helloRetry    = time.Second
	maxHelloPaths = 16
)

// Client tunnels streams through DNS.
type Client struct {
	cfg Config
	z   zone
	pc  net.PacketConn

	mu      sync.Mutex
	paths   []*path
	pending map[uint16]*pendingQuery
	sess    *clientSession
	wakeCh  chan struct{}
	done    chan struct{}
	once    sync.Once

	cands          []string // discovery candidates, in order
	candIdx        int
	lastCand       time.Time
	cachedVerified int
	cacheQ         chan []string // the latest verified set, for storeCache
	cacheDone      chan struct{} // closed once storeCache has flushed and exited
	tcpDialSlots   chan struct{} // bound simultaneous DNS TCP/TLS handshakes

	lastDump      time.Time
	probeUntil    time.Time // short authenticated startup probe, never an idle beacon
	scoutNext     int       // rotate through every configured path, including large resolver lists
	rateNext      time.Time // next locally budgeted send opportunity, never a loss deadline
	lastRateScout time.Time // bounded discovery progress while rate-limited data stays busy
	rateScoutNext uint64    // rotates the candidate given the next paced scout opportunity
}

type path struct {
	addr      *net.UDPAddr
	tcp       *tcpLink // nil for UDP
	sibling   bool     // a TCP path was added for this UDP path
	candidate bool     // added by discovery; pruned if it never answers
	created   time.Time
	qtype     uint16 // record type carrying answers: TXT, or AAAA where TXT is refused
	srtt      time.Duration
	rttvar    time.Duration
	hasRTT    bool
	cwnd      float64
	ssthresh  float64
	inflight  int
	outcomes  [outcomeWindow]bool // true = lost
	outIdx    int
	outN      int
	lastCut   time.Time
	consec    int
	suspended time.Time
	dead      bool

	nameLen           int // current QNAME cap
	observedNameLen   int
	observedAnswer    int
	lastLargeNameAuth time.Time // authenticated near-cap upload name, optional guard
	lastLargeNameLen  int
	probeFails        int
	probing           bool
	successes         int
	nameRetryAt       time.Time // retry size discovery after a path/forwarder change
	nameBackoffs      int

	// Answer size (class: 512+48*class bytes). sizeOK is the largest class shown to arrive and
	// sizeCeil the smallest shown not to (or one past maxClass). While probing, test is the class
	// under trial; queries alternate between it and sizeOK so the two are judged side by side.
	sizeOK      int
	sizeCeil    int
	maxClass    int
	test        int       // class on trial (0: none)
	sizeBlocked time.Time // no probing until then
	sizeSince   int       // successes at sizeOK since the last change
	sizeFails   int       // consecutive failed trials, for backoff
	testWin     outcomes  // outcomes at the class on trial (or at sizeOK, when guarding it)
	baseWin     outcomes  // outcomes of the comparison queries sent alongside
	alt         int
	lastHello   time.Time

	verified    bool // has answered at least once
	lastSuccess time.Time
	unanswered  time.Time // first query since authenticated path progress
	timeouts    int       // actual deadline expiries since that progress
	nextSeq     uint64
	maxAnswered uint64 // highest seq answered + 1
}

type pendingQuery struct {
	txn      uint16
	p        *path
	sess     *clientSession
	question []byte
	sent     time.Time
	deadline time.Time
	pn       uint64
	hello    bool
	probe    bool
	expired  bool
	seq      uint64 // per-path send order
	scout    bool   // carries no data: a hello or a probe of an unverified path
	// poll: carries no stream or control frames, so the server may hold it (SPEC §7.2) while
	// it answers later data queries at once.
	poll     bool
	errRcode int  // an error answer arrived (-1: none); it may be forged, so we keep waiting
	errTC    bool // that answer was truncated
	class    int  // the answer-size class this query asked for
}

type clientSession struct {
	*session
	sid         uint16
	eph         *ecdh.PrivateKey
	ready       chan struct{}
	established bool
	backlog     int
	used        bool      // a stream has been opened on it; guarded by session.mu
	firstHello  time.Time // when its first hello went out; guarded by Client.mu
	lastAuth    time.Time // last authenticated answer; guarded by Client.mu
	// unanswered is when the first query since the last authenticated answer went out (zero if
	// none has); guarded by Client.mu.
	unanswered       time.Time
	lowWarmSuccesses uint8 // authenticated non-scout replies; guarded by Client.mu
	lowWarmSends     uint8 // bounded verified-path warm admission; guarded by Client.mu
}

// errSessionIdle ends a session retired for idling; see Config.SessionIdle.
var errSessionIdle = errors.New("soar: session idle")

// unusedSessionIdle retires a session that has never carried a stream. The server ends such a
// session 15 s after its hello (SPEC 7.4), much sooner than an idle one. It is left behind when
// a Dial's context ends mid-handshake, as when another transport wins a race, and the
// handshake completes anyway.
const unusedSessionIdle = 10 * time.Second

// freshSessionGrace spares a session that has only just come up from unusedSessionIdle: a Dial
// waiting on its handshake is about to open a stream on it.
const freshSessionGrace = time.Second

// busy reports whether the session has streams open or frames still to deliver.
func (cs *clientSession) busy() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.busyLocked()
}

func (cs *clientSession) busyLocked() bool {
	return len(cs.streams) > 0 || len(cs.ctrlQ) > 0 || cs.dataInFlight()
}

// retireIfIdle ends an established session that has sat idle for limit, or for
// unusedSessionIdle if it never carried a stream, checking and closing under one lock so a
// stream can't open in between. Called with Client.mu held (for lastAuth and firstHello).
func (cs *clientSession) retireIfIdle(now time.Time, limit time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	since := cs.lastAuth
	if !cs.used {
		limit = min(limit, unusedSessionIdle)
		// The server times an unused session from its hello, and a retried hello gets the
		// same session back, so a slow handshake has already used up part of the limit.
		if !cs.firstHello.IsZero() && now.Sub(cs.lastAuth) >= freshSessionGrace {
			since = cs.firstHello
		}
	}
	if !cs.closed && now.Sub(since) >= limit && !cs.busyLocked() {
		cs.closeLocked(errSessionIdle)
	}
}

func (cs *clientSession) isClosed() bool {
	if cs.session == nil {
		return false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.closed
}

// NewClient starts a client. It handshakes lazily on the first Dial.
func NewClient(cfg Config) (*Client, error) {
	cfg.setDefaults()
	if cfg.LowReductionPercent != 0 && (cfg.LowReductionPercent < 10 || cfg.LowReductionPercent > 90) {
		return nil, errors.New("soar: low reduction percent must be 10..90")
	}
	if cfg.PercentagePacer != nil && cfg.PercentagePacer.reduction != cfg.LowReductionPercent {
		return nil, errors.New("soar: shared percentage pacer target differs from client")
	}
	if cfg.LowReductionPercent != 0 && cfg.PercentagePacer == nil {
		cfg.PercentagePacer = NewPercentagePacer(cfg.LowReductionPercent)
	}
	if cfg.InitialResolverLimit > 0 && len(cfg.Resolvers) > cfg.InitialResolverLimit {
		// Low traffic must also bound eager TCP/TLS connection fanout. Preserve
		// every configured resolver as a candidate, without enabling new bundled
		// sources when the caller explicitly disabled automatic discovery.
		d := cfg.Discovery
		if !d.Enabled {
			d.noBundled = true
			d.Candidates, d.Cache = nil, nil
		}
		d.Enabled = true
		deferred := make([]string, 0, len(cfg.Resolvers)-cfg.InitialResolverLimit)
		for _, resolver := range cfg.Resolvers[cfg.InitialResolverLimit:] {
			// Eager configured endpoints have always accepted hostnames. Resolve
			// them here too, before starting the scheduler, so an IP-only candidate
			// parser cannot silently lose them or block DNS lookup under Client.mu.
			addr, err := net.ResolveUDPAddr("udp", resolver)
			if err != nil {
				cfg.Logger.Warn("bad resolver", "resolver", resolver, "err", err)
				continue
			}
			deferred = append(deferred, addr.String())
		}
		d.Candidates = append(deferred, d.Candidates...)
		cfg.Resolvers = cfg.Resolvers[:cfg.InitialResolverLimit]
		cfg.Discovery = d
	}
	if cfg.FECDownloadEnabled && !validPacketFEC(cfg.FECDataShards, cfg.FECParityShards) {
		return nil, errors.New("soar: download FEC needs 2..16 data shards and 1..4 parity shards")
	}
	if len(cfg.ServerKey) != ed25519.PublicKeySize {
		return nil, errors.New("soar: client needs the server's Ed25519 public key")
	}
	z, err := parseZone(cfg.Zone)
	if err != nil {
		return nil, err
	}
	if cfg.QNameLabelLength < 1 || cfg.QNameLabelLength > 63 {
		return nil, errors.New("soar: invalid label length")
	}
	z.labelLength, z.labelJitter = cfg.QNameLabelLength, cfg.QNameLabelJitter
	if cfg.DNSPaddingBlockSize != 0 && (cfg.DNSPaddingBlockSize < 16 || cfg.DNSPaddingBlockSize > 4096) {
		return nil, errors.New("soar: invalid encrypted DNS padding block")
	}
	if z.maxPayload(cfg.SafeQName) < 2+pubLen {
		return nil, errors.New("soar: SafeQName too short to carry a handshake under this zone")
	}
	if len(cfg.Resolvers) == 0 && !cfg.Discovery.Enabled {
		return nil, errors.New("soar: no resolvers and discovery is off")
	}
	pc, err := cfg.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, z: z, pc: pc, pending: make(map[uint16]*pendingQuery), tcpDialSlots: make(chan struct{}, 16),
		wakeCh: make(chan struct{}, 1), done: make(chan struct{})}
	// A large configured pool must not repeatedly compare each new endpoint
	// with every UDP/TCP path already installed. Discovery still checks the
	// current live slice, because candidates can later be pruned and re-added.
	seen := make(map[string]bool, len(cfg.Resolvers))
	for _, r := range cfg.Resolvers {
		ua, err := net.ResolveUDPAddr("udp", r)
		if err != nil {
			cfg.Logger.Warn("bad resolver", "resolver", r, "err", err)
			continue
		}
		addr := ua.String()
		if seen[addr] {
			continue
		}
		seen[addr] = true
		c.appendPathLocked(ua, r)
	}
	if len(c.paths) == 0 && !cfg.Discovery.Enabled {
		pc.Close()
		return nil, errors.New("soar: no usable resolvers")
	}
	if cfg.Discovery.Enabled {
		c.cands = cfg.Discovery.candidates()
		if len(c.paths) == 0 && len(c.cands) == 0 {
			pc.Close()
			return nil, errors.New("soar: discovery has no resolver candidates for the configured family")
		}
		if cfg.Discovery.Cache != nil {
			c.cacheQ, c.cacheDone = make(chan []string, 1), make(chan struct{})
			go c.storeCache(cfg.Discovery.Cache)
		}
	}
	go c.readLoop()
	go c.run()
	return c, nil
}

func (c *Client) addPathLocked(r string) error {
	ua, err := net.ResolveUDPAddr("udp", r)
	if err != nil {
		return err
	}
	for _, p := range c.paths {
		if p.addr.String() == ua.String() {
			return nil
		}
	}
	c.appendPathLocked(ua, r)
	return nil
}

func (c *Client) appendPathLocked(ua *net.UDPAddr, resolver string) {
	if c.cfg.TCP == "only" || (c.cfg.StreamOnly != nil && c.cfg.StreamOnly(resolver)) {
		c.paths = append(c.paths, c.newPath(ua, true))
		return
	}
	c.paths = append(c.paths, c.newPath(ua, false))
	if c.cfg.TCP == "on" || c.cfg.TCP == "auto" {
		c.paths[len(c.paths)-1].sibling = true
		c.paths = append(c.paths, c.newPath(ua, true))
	}
}

func (c *Client) newPath(ua *net.UDPAddr, tcp bool) *path {
	p := &path{addr: ua, cwnd: 4, ssthresh: float64(c.cfg.MaxPathWindow), created: time.Now(),
		nameLen: c.cfg.SafeQName, sizeCeil: c.cfg.maxLimitClass() + 1, maxClass: c.cfg.maxLimitClass(), qtype: typeTXT}
	if tcp {
		p.tcp = c.startTCP(ua.String())
	}
	return p
}

// addTCPSiblingsLocked probes TCP after startup failure or after a formerly
// healthy UDP path stalls. A resolver can start intercepting UDP mid-session.
func (c *Client) addTCPSiblingsLocked() {
	if c.cfg.TCP != "auto" {
		return
	}
	now := time.Now()
	for _, p := range c.paths {
		startupFailure := !p.verified && p.outN >= 2
		stalled := p.verified && p.consec >= 3 &&
			now.Sub(p.lastSuccess) >= max(2*p.rto(), time.Second)
		if p.tcp == nil && !p.sibling && (startupFailure || stalled) {
			p.sibling = true
			tp := c.newPath(p.addr, true)
			tp.candidate = p.candidate
			c.paths = append(c.paths, tp)
		}
	}
}

// Close shuts the client down.
func (c *Client) Close() error {
	c.once.Do(func() {
		// Under c.mu, so no snapshot is queued for the cache after the worker's final flush.
		c.mu.Lock()
		close(c.done)
		if c.cfg.PercentagePacer != nil {
			c.cfg.PercentagePacer.remove(c, time.Now())
		}
		if c.sess != nil && c.sess.session != nil {
			c.sess.close(ErrClosed)
		}
		c.mu.Unlock()
		c.pc.Close()
		if c.cacheDone != nil {
			select {
			case <-c.cacheDone: // the newest verified set is stored
			case <-time.After(2 * time.Second):
			}
		}
	})
	return nil
}

func (c *Client) wake() { signal(c.wakeCh) }

// Authenticate starts the same handshake used by live streams, without opening
// an application connection. A short probe window also vets alternate paths.
func (c *Client) Authenticate(ctx context.Context) error {
	if _, err := c.session(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.probeUntil = time.Now().Add(2 * time.Second)
	c.mu.Unlock()
	c.wake()
	return nil
}

// DialContext opens a stream to addr (host:port) through the tunnel.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(addr) == 0 || len(addr) > 255 {
		return nil, errors.New("soar: bad address")
	}
	var cs *clientSession
	var st *stream
	for {
		var err error
		if cs, err = c.session(ctx); err != nil {
			return nil, err
		}
		cs.mu.Lock()
		st, err = cs.openStream()
		if err == nil {
			cs.used = true
			break
		}
		cs.mu.Unlock()
		// Another Dial retired the session as idle between our getting it and opening a stream:
		// the next call handshakes afresh.
		if !errors.Is(err, errSessionIdle) {
			return nil, err
		}
	}
	st.sbuf = append(append(st.sbuf, byte(len(addr))), addr...)
	st.spending.add(0, uint64(len(st.sbuf)))
	cs.mu.Unlock()
	c.wake()
	return &Conn{st: st, local: c.pc.LocalAddr(), remote: tunnelAddr(addr)}, nil
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "soar" }
func (a tunnelAddr) String() string  { return string(a) }

// session returns an established session, handshaking if needed.
func (c *Client) session(ctx context.Context) (*clientSession, error) {
	c.mu.Lock()
	cs := c.sess
	if cs != nil && cs.established {
		cs.retireIfIdle(time.Now(), c.cfg.SessionIdle)
	}
	if cs != nil && cs.isClosed() {
		cs = nil
	}
	if cs == nil {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		cs = &clientSession{eph: eph, ready: make(chan struct{})}
		c.sess = cs
		for _, p := range c.paths {
			p.lastHello = time.Time{}
		}
	}
	c.mu.Unlock()
	c.wake()
	select {
	case <-cs.ready:
		if cs.session == nil {
			return nil, ErrClosed
		}
		return cs, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrClosed
	}
}

func (c *Client) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		c.mu.Lock()
		c.expireLocked(now)
		if c.cfg.TCP != "off" || c.cfg.StreamOnly != nil {
			c.reconnectStalledTCPLocked(now)
		}
		c.checkLivenessLocked(now)
		c.discoverLocked(now)
		c.addTCPSiblingsLocked()
		c.fillLocked(now)
		if debugOn && now.Sub(c.lastDump) > 250*time.Millisecond {
			c.lastDump = now
			line := ""
			for _, p := range c.paths {
				tr := "u"
				if p.tcp != nil {
					tr = "t"
				}
				line += fmt.Sprintf(" [%s/%s cw=%.1f in=%d rtt=%v loss=%.2f v=%v]", p.addr.IP, tr, p.cwnd, p.inflight, p.srtt.Round(time.Millisecond), p.lossRate(), p.verified)
			}
			if c.sess != nil && c.sess.session != nil {
				c.sess.mu.Lock()
				line += fmt.Sprintf(" backlog=%d sent=%d lostQ=%d", c.sess.backlog, len(c.sess.sent), len(c.sess.lostQ))
				c.sess.mu.Unlock()
			}
			dbg("cli paths%s", line)
		}
		next := c.nextDeadlineLocked(now)
		c.mu.Unlock()
		timer.Reset(next)
		select {
		case <-c.wakeCh:
		case <-timer.C:
		case <-c.done:
			return
		}
	}
}

func (c *Client) nextDeadlineLocked(now time.Time) time.Duration {
	next := now.Add(time.Second)
	if c.rateNext.After(now) && c.rateNext.Before(next) {
		next = c.rateNext
	}
	for _, q := range c.pending {
		d := q.deadline
		if q.expired {
			d = d.Add(lateGrace)
		}
		if d.Before(next) {
			next = d
		}
	}
	for _, p := range c.paths {
		if p.suspended.After(now) && p.suspended.Before(next) {
			next = p.suspended
		}
	}
	// Discovery adds one candidate per pass: wake when the pace allows the next, or on a
	// network where nothing answers it would decay to this one-second default.
	if c.wantsCandidateLocked(now) {
		if t := c.lastCand.Add(c.cfg.Discovery.Pace); t.Before(next) {
			next = t
		}
	}
	return max(next.Sub(now), time.Millisecond)
}

func (p *path) usable(now time.Time) bool {
	return !p.dead && !p.suspended.After(now) && (p.tcp == nil || p.tcp.up.Load())
}

// rto is how long a query on p may take before it's presumed lost, excluding any hold.
func (p *path) rto() time.Duration {
	if !p.hasRTT {
		return time.Second
	}
	return min(max(p.srtt+max(4*p.rttvar, 50*time.Millisecond), 200*time.Millisecond), 3*time.Second)
}

func (p *path) lossRate() float64 {
	if p.outN == 0 {
		return 0
	}
	n := 0
	for i := range p.outN {
		if p.outcomes[i] {
			n++
		}
	}
	return float64(n) / float64(p.outN)
}

func (p *path) record(lost bool) {
	p.outcomes[p.outIdx] = lost
	p.outIdx = (p.outIdx + 1) % outcomeWindow
	p.outN = min(p.outN+1, outcomeWindow)
}

func (p *path) onSuccess(now time.Time, rtt time.Duration, maxWin int) {
	p.record(false)
	p.successes++
	p.observeAuthenticated(now, rtt)
	if p.cwnd < p.ssthresh {
		p.cwnd++
	} else {
		p.cwnd += 1 / p.cwnd
	}
	p.cwnd = min(p.cwnd, float64(maxWin))
}

// Even an answer past its old deadline measures the new path's delay. Keep
// this separate from delivery/congestion credit, which timeouts already used.
func (p *path) observeAuthenticated(now time.Time, rtt time.Duration) {
	p.consec = 0
	p.verified = true
	p.lastSuccess = now
	if p.tcp != nil {
		p.timeouts = 0
		p.unanswered = time.Time{}
		if p.inflight > 0 {
			p.unanswered = now
		}
	}
	if rtt > 0 {
		if !p.hasRTT {
			p.srtt, p.rttvar, p.hasRTT = rtt, rtt/2, true
		} else {
			d := p.srtt - rtt
			if d < 0 {
				d = -d
			}
			p.rttvar = (3*p.rttvar + d) / 4
			p.srtt = (7*p.srtt + rtt) / 8
		}
	}
}

// onLoss backs off on runs of losses. Random loss is scattered among successes; a resolver's
// rate limit drops every query past its budget, so overload shows up as consecutive losses.
func (p *path) onLoss(now time.Time) {
	p.record(true)
	p.consec++
	if p.consec >= 3 && now.Sub(p.lastCut) > p.rto() {
		p.cwnd = max(1, p.cwnd*0.7)
		p.ssthresh = max(2, p.cwnd)
		p.lastCut = now
	}
	if p.consec >= 5 && now.Sub(p.lastSuccess) > 2*time.Second {
		backoff := min(time.Duration(1<<min(p.consec-5, 4))*time.Second, 15*time.Second)
		p.suspended = now.Add(backoff)
		p.cwnd = 1
	}
}

// reconnectStalledTCPLocked replaces a connected but black-holed socket before
// the session's liveness limit when possible. It sends no additional probes.
// Only actual query deadlines count; fast loss inference is insufficient.
func (c *Client) reconnectStalledTCPLocked(now time.Time) {
	for _, p := range c.paths {
		if p.tcp == nil || !p.tcp.up.Load() || p.timeouts < 3 || p.unanswered.IsZero() {
			continue
		}
		if now.Sub(p.unanswered) >= max(3*p.rto()+c.cfg.Hold, 3*time.Second) {
			p.tcp.reconnect()
		}
	}
}

// linkDown accounts old-connection losses before redial publishes a new socket.
// Otherwise those delayed losses could suspend the newly usable connection.
func (c *Client) linkDown(l *tcpLink) {
	c.mu.Lock()
	now := time.Now()
	for _, q := range c.pending {
		if q.p.tcp == l && !q.expired {
			q.deadline, q.expired = now, true
			c.failLocked(q, now, false)
		}
	}
	for _, p := range c.paths {
		if p.tcp == l {
			p.suspended, p.unanswered, p.timeouts = time.Time{}, time.Time{}, 0
		}
	}
	// Nothing queued on the old socket should be replayed after reconnect.
	// Queries were just declared lost; the session will rebuild current data.
drain:
	for {
		select {
		case <-l.out:
		default:
			break drain
		}
	}
	c.mu.Unlock()
	c.wake()
}

func (c *Client) anyUsableLocked(now time.Time) bool {
	for _, o := range c.paths {
		if o.verified && o.usable(now) {
			return true
		}
	}
	return false
}

// Answer-size control works like path-MTU discovery, but every verdict is a side-by-side
// comparison, because the losses that matter here are size-specific: some networks silently drop
// large DNS answers (they look like amplification), sometimes only once there's volume. Rate
// limits, random loss and outages hit small and large answers alike and must not move the size.
//
// Trial: once sizeOK has earned it, queries alternate between a larger class and sizeOK — the
// largest allowed first, then binary search below a failure. The trial passes if the larger class
// loses about as much as sizeOK did meanwhile, and fails if it loses clearly more.
// Guard: at a proven size above 512, every 4th query is a 512-byte canary; if the proven size
// starts losing clearly more than the canaries, it fails the same way.
const (
	trialSamples = 16 // outcomes per side before a trial can pass
	earnTrial    = 8  // successes at sizeOK before a trial
)

// worse reports whether a loses significantly more than b: by over a quarter of queries and by
// more than 3 standard errors of the difference, so loss that hits both alike never counts.
// Callers judge once per full window, not after every outcome, so noise gets few chances.
func worse(a, b *outcomes) bool {
	ka, kb := a.lostCount(), b.lostCount()
	gap := float64(ka)/float64(a.n) - float64(kb)/float64(b.n)
	pool := float64(ka+kb) / float64(a.n+b.n)
	se := math.Sqrt(pool * (1 - pool) * (1/float64(a.n) + 1/float64(b.n)))
	return gap > max(0.25, 3*se)
}

// blatant catches heavy size-specific loss early, at fixed checkpoints so chance gets few
// tries: nearly all large answers lost while every small one arrived.
func blatant(a, b *outcomes) bool {
	return (a.n == 8 || a.n == 16 || a.n == 24) && b.n >= 4 && a.lostCount()*8 >= a.n*7 && b.lostCount() == 0
}

func (p *path) nextClass() int {
	p.alt++
	switch {
	case p.test > 0:
		if p.alt%2 == 0 {
			return p.test
		}
		return p.sizeOK
	case p.sizeOK > 0 && p.alt%4 == 0:
		return 0
	}
	return p.sizeOK
}

func (p *path) sizeOutcome(class int, lost bool, now time.Time) {
	switch {
	case p.test > 0: // a trial
		switch class {
		case p.test:
			p.testWin.record(lost)
		case p.sizeOK:
			p.baseWin.record(lost)
		default:
			return
		}
		full := p.testWin.n >= 2*trialSamples && p.baseWin.n >= 2*trialSamples
		switch {
		case blatant(&p.testWin, &p.baseWin) || full && worse(&p.testWin, &p.baseWin):
			p.sizeFailed(p.test, p.sizeOK, now)
		case full: // not measurably worse: keep the larger size
			p.sizeOK, p.test, p.sizeSince, p.sizeFails = p.test, 0, 0, 0
			p.testWin, p.baseWin = outcomes{}, outcomes{}
		}
	case p.sizeOK > 0 && (class == p.sizeOK || class == 0): // guarding a proven size
		if class == 0 {
			p.baseWin.record(lost)
		} else {
			p.testWin.record(lost)
		}
		full := p.testWin.n >= len(p.testWin.lost) && p.baseWin.n >= 8
		if blatant(&p.testWin, &p.baseWin) || full && worse(&p.testWin, &p.baseWin) {
			p.sizeFailed(p.sizeOK, 0, now)
			return
		}
		if full {
			p.testWin, p.baseWin = outcomes{}, outcomes{}
		}
		fallthrough
	default:
		if class == p.sizeOK && !lost {
			p.sizeSince++
		}
		if p.test == 0 && p.sizeSince >= earnTrial && now.After(p.sizeBlocked) && p.sizeOK+1 < p.sizeCeil {
			if p.sizeCeil > p.maxClass { // nothing has failed yet: try the largest
				p.test = p.maxClass
			} else {
				p.test = (p.sizeOK + p.sizeCeil) / 2
			}
			if p.test <= p.sizeOK {
				p.test = 0
				return
			}
			p.testWin, p.baseWin = outcomes{}, outcomes{}
		}
	}
}

// sizeFailed records that answers of class don't arrive: it becomes the ceiling and the path
// falls back to class back. Trials back off exponentially, since whatever polices large answers
// may penalise repeat offenders and a bigger size isn't worth provoking it.
func (p *path) sizeFailed(class, back int, now time.Time) {
	p.sizeCeil = min(p.sizeCeil, max(class, 1))
	p.sizeOK = min(back, p.sizeCeil-1)
	p.test, p.sizeSince = 0, 0
	p.testWin, p.baseWin = outcomes{}, outcomes{}
	backoff := min(10*time.Second*time.Duration(1<<(2*min(p.sizeFails, 4))), 30*time.Minute)
	p.sizeBlocked = now.Add(backoff)
	p.sizeFails++
}

// outcomes is a small sliding window of query fates.
type outcomes struct {
	lost [32]bool
	i, n int
}

func (o *outcomes) lostCount() int {
	k := 0
	for j := range o.n {
		if o.lost[j] {
			k++
		}
	}
	return k
}

func (o *outcomes) record(lost bool) {
	o.lost[o.i] = lost
	o.i = (o.i + 1) % len(o.lost)
	o.n = min(o.n+1, len(o.lost))
}

func (o *outcomes) rate() float64 {
	if o.n == 0 {
		return 0
	}
	k := 0
	for j := range o.n {
		if o.lost[j] {
			k++
		}
	}
	return float64(k) / float64(o.n)
}

// sizeTruncated: an answer of this class came back truncated (TC), so it's too big here.
func (p *path) sizeTruncated(class int, now time.Time) {
	if class > 0 {
		p.sizeFailed(class, min(p.sizeOK, class-1), now)
	}
}

func (c *Client) expireLocked(now time.Time) {
	for txn, q := range c.pending {
		if q.expired {
			if now.After(q.deadline.Add(lateGrace)) {
				delete(c.pending, txn)
			}
			continue
		}
		// Polls may spend the whole Hold interval at the server. Arrival order
		// differs from send order through a resolver, so even a later poll's
		// answer cannot prove loss. Keep their full hold-aware deadline.
		// Data queries are answered immediately; allow fast recovery only with
		// later answers and the RTO's variance margin (at least 50ms).
		early := !q.poll && q.p.hasRTT && q.p.maxAnswered >= q.seq+4 &&
			now.Sub(q.sent) > q.p.srtt+max(4*q.p.rttvar, 50*time.Millisecond)
		if now.Before(q.deadline) && !early {
			continue
		}
		q.expired = true
		// A held error answer may be forged, so it only counts once no real answer came in the
		// whole deadline; expired early by the packet threshold, the real one may yet arrive.
		trusted := !now.Before(q.deadline)
		if trusted && q.p.tcp != nil {
			q.p.timeouts++
		}
		if q.errTC && trusted {
			q.p.sizeTruncated(q.class, now) // answers this size get truncated here
		}
		c.failLocked(q, now, q.errRcode == rcodeRefused && trusted)
	}
}

// deadSessionAfter ends a session that gets no authenticated answer for this long while queries
// are outstanding. The server's signed "unknown session" reply is the fast path, but its signing
// is rate-limited, so this is what guarantees recovery when the server forgot us.
const deadSessionAfter = 15 * time.Second

// The clock runs from the first query sent since the last authenticated answer, not from the
// answer itself, so an idle session isn't presumed lost the moment traffic resumes.
func (c *Client) checkLivenessLocked(now time.Time) {
	cs := c.sess
	if cs == nil || !cs.established || cs.unanswered.IsZero() {
		return
	}
	if now.Sub(cs.unanswered) >= deadSessionAfter {
		cs.close(errors.New("soar: no authenticated answers; session presumed lost"))
	}
}

// failLocked handles a query that got no usable answer.
func (c *Client) failLocked(q *pendingQuery, now time.Time, refused bool) {
	p := q.p
	p.inflight--
	if q.probe {
		p.probing = false
		p.probeFails++
		if p.probeFails >= 2 {
			p.backoffNameProbe(now)
		}
	}
	// Keep the safe size after repeated failures, but allow a later, backed-off
	// probe: a resolver address can lead to a different forwarder after rerouting.
	if p.nameLen > c.cfg.SafeQName && p.consec >= 2 && (!c.cfg.QNameLossGuard || !p.freshLargeQNameProof(now, c.qnameProofSlack())) {
		p.nameLen = c.cfg.SafeQName
		p.backoffNameProbe(now)
	}
	if refused && p.qtype == typeTXT {
		// Some resolvers refuse TXT (seen in Iran): carry answers in AAAA records instead.
		p.qtype = typeAAAA
		p.outN, p.consec, p.suspended = 0, 0, time.Time{}
	} else {
		if refused {
			p.consec += 2
		}
		p.onLoss(now)
		p.sizeOutcome(q.class, true, now)
		// Never suspend every path: with nothing in flight nothing can recover, and the
		// session would be presumed lost. The last usable one keeps probing at a window of 1.
		if p.suspended.After(now) && !c.anyUsableLocked(now) {
			p.suspended = time.Time{}
		}
	}
	if q.hello || q.sess == nil || q.sess.session == nil {
		return
	}
	cs := q.sess
	cs.mu.Lock()
	cs.declareLost(q.pn)
	cs.lostQ = append(cs.lostQ, q.pn)
	cs.mu.Unlock()
}

func (p *path) backoffNameProbe(now time.Time) {
	// Keep recovery probes sparse, but do not strand a working path at the
	// minimum size for minutes after transient loss. Probes still require
	// authenticated successes and only run when the session has work.
	delay := min(10*time.Second*time.Duration(1<<min(p.nameBackoffs, 3)), time.Minute)
	p.nameRetryAt = now.Add(delay)
	p.nameBackoffs = min(p.nameBackoffs+1, 4)
	p.probeFails = 2
}

func (p *path) beginNameProbe(now time.Time, maxQName int) bool {
	if p.probing || p.successes < 3 || p.nameLen >= maxQName {
		return false
	}
	if p.probeFails >= 2 {
		if p.nameRetryAt.IsZero() || now.Before(p.nameRetryAt) {
			return false
		}
		// One trial per backoff interval after the initial two attempts.
		p.probeFails = 1
	}
	p.probing = true
	return true
}

// wantQueries is how many queries the session wants outstanding with nothing else to send.
func (cs *clientSession) wantQueries() int {
	if len(cs.streams) == 0 {
		if len(cs.toAck) > 0 || cs.dataInFlight() {
			return 1
		}
		return 0
	}
	return 2 + cs.backlog
}

func (c *Client) fillLocked(now time.Time) {
	if c.cfg.PercentagePacer != nil {
		c.updatePercentageReferenceLocked(now)
	}
	maxInflight := c.percentageFlightLimit()
	cs := c.sess
	if cs == nil || len(c.pending) >= maxPending {
		return
	}
	if !cs.established {
		c.sendHellosLocked(cs, now)
		return
	}
	if cs.isClosed() {
		return
	}
	// Discovery must not fill the whole flight before a working path can send
	// stream data. Count once, then reserve only a bounded batch of actual
	// candidates. The cursor gives every configured resolver a turn instead of
	// repeatedly refilling failed paths at the beginning of a large list.
	inflight, polls, scouts := 0, 0, 0
	for _, q := range c.pending {
		if q.expired {
			continue
		}
		inflight++
		if q.scout {
			scouts++
		} else {
			polls++
		}
	}
	scoutLimit := min(maxHelloPaths, max(maxInflight/8, 1), max(maxInflight-1, 0))
	if !c.anyUsableLocked(now) || (maxInflight == 1 && !c.productivePathLocked(now)) {
		// Without a verified path there is no application traffic to reserve for.
		scoutLimit = min(maxHelloPaths, maxInflight)
	}
	var candidates []*path
	if cs.busy() || now.Before(c.probeUntil) {
		limit := min(scoutLimit-scouts, maxInflight-inflight, maxPending-len(c.pending))
		for visited := 0; visited < len(c.paths) && len(candidates) < limit; visited++ {
			c.scoutNext %= len(c.paths)
			p := c.paths[c.scoutNext]
			c.scoutNext++
			if !p.verified && p.inflight == 0 && p.usable(now) {
				candidates = append(candidates, p)
			}
		}
	}
	// A continuously busy stream can otherwise consume every paced token before
	// scouts get their turn, preventing alternate-path recovery indefinitely.
	// Low mode gives one candidate an opportunity at most every 250ms (or the
	// configured slower discovery pace); full mode keeps its original order.
	if (c.cfg.QueryRateLimiter != nil || c.cfg.PercentagePacer != nil) && len(candidates) > 0 && now.Sub(c.lastRateScout) >= max(c.cfg.Discovery.Pace, 250*time.Millisecond) {
		index := int(c.rateScoutNext % uint64(len(candidates)))
		if sent := c.sendDataWithSlotsLocked(cs, candidates[index], now, false, maxInflight-inflight); sent > 0 {
			inflight += sent
			c.lastRateScout = now
			c.rateScoutNext++
			candidates = append(candidates[:index], candidates[index+1:]...)
		}
	}
	trafficLimit := maxInflight - len(candidates)
	for inflight < trafficLimit && len(c.pending) < maxPending {
		cs.mu.Lock()
		need := cs.hasData() || polls < cs.wantQueries()
		cs.mu.Unlock()
		if !need {
			break
		}
		p := c.pickPathLocked(now, nil)
		if p == nil {
			break
		}
		sent := c.sendDataWithSlotsLocked(cs, p, now, true, trafficLimit-inflight)
		if sent == 0 {
			break
		}
		inflight += sent
		polls += sent
	}
	for _, p := range candidates {
		inflight += c.sendDataWithSlotsLocked(cs, p, now, false, maxInflight-inflight)
	}
}

// pickPathLocked returns the verified path with a free slot and the earliest
// expected answer. Unverified paths are vetted by the separate scout budget.
func (c *Client) pickPathLocked(now time.Time, exclude *path) *path {
	var best *path
	var bestScore float64
	for _, p := range c.paths {
		if p == exclude {
			continue
		}
		if !p.verified || !p.usable(now) || float64(p.inflight) >= c.percentagePathWindow(p) {
			continue
		}
		rtt := p.rto()
		if p.hasRTT {
			rtt = p.srtt
		}
		score := float64(rtt) * (1 + float64(p.inflight)/p.cwnd) / (1 - min(p.lossRate(), 0.9))
		if best == nil || score < bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

func (c *Client) newTxnLocked() uint16 {
	for {
		var b [2]byte
		rand.Read(b[:])
		t := binary.BigEndian.Uint16(b[:])
		if _, ok := c.pending[t]; !ok {
			return t
		}
	}
}

// liveQueriesLocked counts queries awaiting an answer (not yet given up on).
func (c *Client) liveQueriesLocked() int {
	n := 0
	for _, q := range c.pending {
		if !q.expired {
			n++
		}
	}
	return n
}

func (c *Client) sendHellosLocked(cs *clientSession, now time.Time) {
	payload := make([]byte, 2, 2+pubLen)
	payload = append(payload, cs.eph.PublicKey().Bytes()...)
	sent := 0
	// Least recently tried first (never-tried paths before all), so with more resolvers than
	// maxHelloPaths the retries rotate through all of them.
	order := slices.Clone(c.paths)
	slices.SortStableFunc(order, func(a, b *path) int { return a.lastHello.Compare(b.lastHello) })
	for _, p := range order {
		if sent >= maxHelloPaths || c.liveQueriesLocked() >= c.percentageFlightLimit() || len(c.pending) >= maxPending {
			break
		}
		if !p.usable(now) || p.inflight > 0 || now.Sub(p.lastHello) < helloRetry {
			continue
		}
		if !c.takeQueryLocked(now) {
			break
		}
		p.lastHello = now
		if cs.firstHello.IsZero() {
			cs.firstHello = now
		}
		c.sendLocked(p, &pendingQuery{p: p, sess: cs, hello: true, scout: true}, payload, now, time.Second)
		sent++
	}
}

func (c *Client) sendDataLocked(cs *clientSession, p *path, now time.Time, allowDup bool) {
	c.sendDataWithSlotsLocked(cs, p, now, allowDup, c.percentageFlightLimit()-c.liveQueriesLocked())
}

// sendDataWithSlotsLocked returns the number of queries sent, including a tail
// copy, so fillLocked can account for its flight without rescanning pending.
func (c *Client) sendDataWithSlotsLocked(cs *clientSession, p *path, now time.Time, allowDup bool, slots int) int {
	// Checked here, before a packet is built, so every data send (fill, probes of unverified
	// paths, the tail copy) respects the ceiling; a packet built but never sent would sit in
	// the session's sent map with no query to fail it.
	if slots <= 0 || len(c.pending) >= maxPending {
		return 0
	}
	if c.cfg.LowReductionPercent != 0 && float64(p.inflight) >= c.percentagePathWindow(p) {
		return 0
	}
	warm := c.percentageWarmStartLocked() && p.verified
	if !c.takeDataQueryLocked(p, now) {
		return 0
	}
	nameLen := p.nameLen
	probe := false
	if p.beginNameProbe(now, c.cfg.MaxQName) {
		nameLen, probe = c.cfg.MaxQName, true
	}
	wireBudget := c.z.maxPayload(nameLen) - 4 - tagLen - 1
	budget := wireBudget
	if !p.verified {
		budget = 0 // don't strand application or control bytes on an unverified path
	}
	if probe {
		budget = 0 // a failed size trial must not delay retransmittable traffic
	}
	hold := c.cfg.Hold
	if !p.verified || probe {
		// Explicit path/size vetting should answer immediately, rather than
		// occupying a scout slot for the idle-poll hold interval.
		hold = 0
	}
	holdClass := min(int(hold/(100*time.Millisecond)), 15)
	class := 0
	if !probe {
		class = p.nextClass()
	}
	hdr := byte(holdClass<<4 | class)

	cs.mu.Lock()
	pn, plain, data, pkt := cs.build([]byte{hdr}, budget, now, 0)
	if probe {
		// Pad to the length under test (inside the seal), or a short probe would "prove" it.
		for len(plain) < 1+wireBudget {
			plain = append(plain, frPadding)
		}
	}
	dup := allowDup && !c.cfg.DisableTailDuplication && pkt != nil && len(pkt.streams) > 0 && p.verified && !cs.hasData()
	payload := cs.seal.sealUp(cs.sid, pn, plain)
	cs.mu.Unlock()
	dbg("cli send pn=%d path=%s plain=%x", pn, p.addr, plain)

	timeout := p.rto()
	if !data {
		timeout += hold
	}
	if cs.unanswered.IsZero() {
		cs.unanswered = now
	}
	before := len(c.pending)
	c.sendLocked(p, &pendingQuery{p: p, sess: cs, pn: pn, probe: probe, scout: !p.verified, poll: !data, class: class}, payload, now, timeout)
	if len(c.pending) == before {
		return 0
	}
	if warm {
		cs.lowWarmSends++
	}
	sent := 1
	// The tail of an upload (often a whole request) goes out twice, on another path if there is one.
	if dup && slots > 1 {
		// A different resolver, so the copies don't share a failure; the same one if it's all we have.
		p2 := c.pickPathLocked(now, p)
		if p2 == nil || !p2.verified {
			p2 = c.pickPathLocked(now, nil)
		}
		if p2 != nil && p2.verified {
			cs.mu.Lock()
			ok := cs.requeue(pkt)
			cs.mu.Unlock()
			if ok {
				sent += c.sendDataWithSlotsLocked(cs, p2, now, false, slots-1)
			}
		}
	}
	return sent
}

func (c *Client) sendLocked(p *path, q *pendingQuery, payload []byte, now time.Time, timeout time.Duration) {
	q.txn = c.newTxnLocked()
	q.errRcode = -1
	msg := appendQuery(make([]byte, 0, 300), q.txn, payload, c.z, p.qtype, 1232)
	if c.cfg.DNSPaddingBlockSize > 0 {
		padded, err := dnsparser.PadEncryptedDNSQuery(msg, c.cfg.DNSPaddingBlockSize)
		if err != nil {
			c.cfg.Logger.Warn("padding failed", "err", err)
			return
		}
		msg = padded
	}
	end, err := skipName(msg, hdrLen)
	if err != nil {
		return
	}
	q.question = msg[hdrLen : end+4]
	q.sent, q.deadline = now, now.Add(timeout)
	q.seq = p.nextSeq

	p.nextSeq++
	c.pending[q.txn] = q
	p.inflight++
	if p.tcp != nil {
		if p.unanswered.IsZero() {
			p.unanswered = now
		}
		p.tcp.send(msg)
		return
	}
	if _, err := c.pc.WriteTo(msg, p.addr); err != nil {
		c.cfg.Logger.Debug("send failed", "resolver", p.addr, "err", err)
	}
}

func (c *Client) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		c.onAnswer(buf[:n])
	}
}

func (c *Client) onAnswer(msg []byte) {
	a, err := parseAnswer(msg)
	if err != nil {
		dbg("cli parse err %v len=%d", err, len(msg))
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.wake()
	defer c.mu.Unlock()
	q := c.pending[a.txn]
	// Off-path injectors can't match the question; on-path ones fail authentication below.
	if q == nil || !bytes.EqualFold(a.question, q.question) {
		dbg("cli no match txn=%d q=%v", a.txn, q != nil)
		return
	}
	p := q.p
	late := q.expired
	if a.tc || a.rcode != rcodeOK || !a.hasTXT {
		if a.rcode == rcodeNXDomain {
			// Only a reply the server signed over this question ends the session; an unsigned
			// NXDOMAIN may be injected, so it's ignored like a forged NOERROR.
			cs := q.sess
			if !q.hello && cs != nil && cs.established && len(a.txt) == sigLen &&
				ed25519.Verify(c.cfg.ServerKey, unknownSessionMsg(q.question), a.txt) {
				cs.close(errors.New("soar: server lost the session"))
				if !late {
					delete(c.pending, a.txn)
					c.failLocked(q, now, false)
				}
			}
			return
		}
		if late || q.errRcode >= 0 {
			return
		}
		// An unauthenticated answer may be injected (China's GFW forges them on UDP/53), so it
		// never cuts the wait for the real one short or changes the path. It's only recorded:
		// if no authenticated answer comes by the deadline, it says why the query failed.
		dbg("cli err answer rcode=%d tc=%v txt=%v path=%s", a.rcode, a.tc, a.hasTXT, p.addr)
		q.errRcode, q.errTC = a.rcode, a.tc
		if a.tc {
			q.errRcode = rcodeServFail
		}
		return
	}
	if q.hello {
		// A signed HELLO is authenticated in onHelloLocked; record sizing there.
		c.onHelloLocked(q, a.txt, now)
		return
	}
	cs := q.sess
	if cs == nil || cs.session == nil {
		return
	}
	cs.mu.Lock()
	pn, plain, err := cs.open.openDown(a.txt, q.pn, func(trunc uint16) uint64 {
		return decodePN(cs.largestRecv, cs.haveRecv, trunc)
	})
	if err != nil || len(plain) < 2 {
		cs.mu.Unlock()
		dbg("cli auth fail pn=%d err=%v", pn, err)
		return // forged or corrupt: keep waiting for the real answer
	}
	c.notePercentageAuthenticatedLocked(q)
	c.observeWireSizeLocked(p, q, len(msg))
	delete(c.pending, a.txn)
	cs.lastAuth, cs.unanswered = now, time.Time{}
	// The liveness clock runs from the first query since the last authenticated answer. With
	// other queries still out it restarts now rather than stopping: if every path then goes
	// dead, nothing new is sent to restart it, and the session must still be presumed lost.
	for _, o := range c.pending {
		if !o.expired && !o.hello && o.sess == cs {
			cs.unanswered = now
			break
		}
	}
	p.maxAnswered = max(p.maxAnswered, q.seq+1)
	dbg("cli recv pn=%d for up=%d plain=%x", pn, q.pn, plain)
	held := time.Duration(plain[0]) * 10 * time.Millisecond
	cs.backlog = int(plain[1])
	if _, err := cs.receive(pn, plain[2:], now); err != nil {
		cs.closeLocked(err)
	}
	if sp := cs.sent[q.pn]; sp != nil {
		cs.acked(sp)
	}
	cs.mu.Unlock()
	if c.cfg.QNameLossGuard {
		c.noteAuthenticatedLargeQName(q, now)
	}
	if late {
		p.observeAuthenticated(now, now.Sub(q.sent)-held)
		return
	}
	p.inflight--
	if q.probe {
		p.probing = false
		p.nameLen = c.cfg.MaxQName
		p.probeFails, p.nameBackoffs, p.nameRetryAt = 0, 0, time.Time{}
	}
	p.onSuccess(now, now.Sub(q.sent)-held, c.cfg.MaxPathWindow)
	p.sizeOutcome(q.class, false, now)
}

func (c *Client) onHelloLocked(q *pendingQuery, reply []byte, now time.Time) {
	cs := q.sess
	p := q.p
	sid, up, down, err := clientFinish(c.cfg.ServerKey, cs.eph, reply)
	if err != nil {
		return // forged
	}
	c.observeWireSizeLocked(p, q, 0)
	delete(c.pending, q.txn)
	if !q.expired {
		p.inflight--
		p.onSuccess(now, now.Sub(q.sent), c.cfg.MaxPathWindow)
	} else {
		p.observeAuthenticated(now, now.Sub(q.sent))
	}
	if cs.established {
		return
	}
	cfg := streamConfig{StreamWindow: c.cfg.StreamWindow, SendBuffer: c.cfg.SendBuffer, MaxStreams: c.cfg.MaxStreams}
	if c.cfg.FECDownloadEnabled {
		cfg.FECDataShards, cfg.FECParityShards = c.cfg.FECDataShards, c.cfg.FECParityShards
	}
	cs.session = newSession(true, cfg, up, down)
	cs.wakeFn = c.wake
	cs.sid = sid
	cs.established = true
	cs.lastAuth = now
	close(cs.ready)
}

func (c *Client) observeWireSizeLocked(p *path, q *pendingQuery, answerBytes int) {
	if p.tcp != nil {
		p.tcp.authenticated.Add(1)
	}
	// question contains the wire name and four QTYPE/QCLASS bytes. A wire
	// name is two bytes longer than its presentation form without trailing dot.
	p.observedNameLen = max(p.observedNameLen, len(q.question)-6)
	p.observedAnswer = max(p.observedAnswer, answerBytes)
}

// A single-slot custom flight can scout a replacement once its only verified
// paths have stopped delivering; healthy single-slot transfers keep priority.
func (c *Client) productivePathLocked(now time.Time) bool {
	for _, p := range c.paths {
		if p.verified && p.usable(now) && (p.consec < 2 || now.Sub(p.lastSuccess) < max(2*p.rto(), time.Second)) {
			return true
		}
	}
	return false
}
