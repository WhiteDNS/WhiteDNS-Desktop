// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"cottendns-go/internal/arq"
	dnsCache "cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/netutil"
	VpnProto "cottendns-go/internal/vpnproto"
)

type dnsFragmentKey struct {
	SessionID   uint16
	SequenceNum uint16
}

type DNSListener struct {
	client   *Client
	conns    []*net.UDPConn
	stopChan chan struct{}
	stopOnce sync.Once
}

func NewDNSListener(c *Client) *DNSListener {
	return &DNSListener{
		client:   c,
		stopChan: make(chan struct{}),
	}
}

func (l *DNSListener) Start(ctx context.Context, ip string, port int) error {
	addresses := listenerAddressesForBind(ip, port)
	if len(addresses) == 0 {
		return errors.New("invalid DNS listener address")
	}
	listeners := make([]*net.UDPConn, 0, len(addresses))
	actualPort := port
	for idx, text := range addresses {
		// When port zero is used for tests or embedding, bind the second family to
		// the first listener's selected port so both loopbacks expose one endpoint.
		if idx > 0 && port == 0 && actualPort > 0 {
			host, _, splitErr := net.SplitHostPort(text)
			if splitErr == nil {
				text = net.JoinHostPort(host, strconv.Itoa(actualPort))
			}
		}
		addr, err := net.ResolveUDPAddr("udp", text)
		if err != nil {
			continue
		}
		network := "udp4"
		if addr.IP != nil && addr.IP.To4() == nil {
			network = "udp6"
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			if len(addresses) == 1 {
				return err
			}
			continue
		}
		listeners = append(listeners, conn)
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr != nil && localAddr.Port > 0 {
			actualPort = localAddr.Port
		}
	}
	if len(listeners) == 0 {
		return errors.New("failed to bind any DNS listener")
	}
	l.conns = listeners

	for _, conn := range listeners {
		l.client.log.Infof("🚀 <green>DNS server is listening on <cyan>%s</cyan></green>", conn.LocalAddr())
	}

	if hint := netutil.FormatListenHint(ip, actualPort); hint != "" {
		l.client.log.Infof("🌐 <green>DNS Server %s</green>", hint)
	}

	for _, conn := range listeners {
		go l.readLoop(ctx, conn)
	}

	return nil
}

func (l *DNSListener) readLoop(ctx context.Context, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	func() {
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-l.stopChan:
					return
				case <-ctx.Done():
					return
				default:
					if dnsListenerShouldRetryRead(err) {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					if l.client != nil && l.client.log != nil {
						l.client.log.Warnf("⚠️ <yellow>DNS listener stopped after read error: %v</yellow>", err)
					}
					return
				}
			}
			// Copy data for the handler to prevent overwrite race condition
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])
			go l.handleQuery(ctx, conn, dataCopy, peerAddr)
		}
	}()
}

func dnsListenerShouldRetryRead(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		type temporary interface {
			Temporary() bool
		}
		if tempErr, ok := any(netErr).(temporary); ok && tempErr.Temporary() {
			return true
		}
	}
	return false
}

func (l *DNSListener) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopChan)
		for _, conn := range l.conns {
			if conn != nil {
				_ = conn.Close()
			}
		}
		l.conns = nil
	})
}

// handleQuery manages incoming DNS queries by checking the local cache or redirecting to the tunnel.
func (l *DNSListener) handleQuery(ctx context.Context, conn *net.UDPConn, data []byte, addr *net.UDPAddr) {
	if l.client == nil {
		return
	}

	l.client.ProcessDNSQuery(data, addr, func(resp []byte) {
		if conn != nil {
			_, _ = conn.WriteToUDP(resp, addr)
		}
	})
}

// DNS Cache Persistence Methods

func (c *Client) hasPersistableLocalDNSCache() bool {
	return c != nil &&
		c.localDNSCache != nil &&
		c.localDNSCachePersist &&
		c.localDNSCachePath != ""
}

func (c *Client) ensureLocalDNSCacheLoaded() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.localDNSCacheLoadOnce.Do(func() {
		c.loadLocalDNSCache()
	})
}

func (c *Client) ensureLocalDNSCachePersistence(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.ensureLocalDNSCacheLoaded()
	c.localDNSCacheFlushOnce.Do(func() {
		go c.runLocalDNSCacheFlushLoop(ctx)
	})
}

func (c *Client) loadLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	loaded, err := c.localDNSCache.LoadFromFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Load Failed:</red> %v</yellow>", err)
		}
		if removeErr := os.Remove(c.localDNSCachePath); removeErr != nil && !os.IsNotExist(removeErr) && c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Purge Failed:</red> %v</yellow>", removeErr)
		}
		return
	}

	if loaded > 0 && c.log != nil {
		c.log.Infof("💾 <green>Local DNS Cache Loaded: <cyan>%d</cyan> records.</green>", loaded)
	}
}

func (c *Client) flushLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	saved, err := c.localDNSCache.SaveToFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Flush Failed:</red> %v</yellow>", err)
		}
		return
	}

	if saved > 0 && c.log != nil {
		c.log.Debugf("💾 <green>Local DNS Cache Flushed: <cyan>%d</cyan> records.</green>", saved)
	}
}

func (c *Client) runLocalDNSCacheFlushLoop(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	ticker := time.NewTicker(c.localDNSCacheFlushTick)
	defer ticker.Stop()
	defer c.flushLocalDNSCache()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushLocalDNSCache()
		}
	}
}

func (c *Client) HandleDNSQueryAck(packet VpnProto.Packet) error {
	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if ok && s0 != nil {
		if arqObj, ok := s0.Stream.(*arq.ARQ); ok {
			arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		}
	}
	return nil
}

func (c *Client) HandleDNSQueryRes(packet VpnProto.Packet) error {
	key := dnsFragmentKey{
		SessionID:   c.sessionID,
		SequenceNum: packet.SequenceNum,
	}

	assembled, ready, _ := c.dnsResponses.Collect(key, packet.Payload, packet.FragmentID, packet.TotalFragments, time.Now(), c.cfg.DNSResponseFragmentTimeout())
	if !ready {
		return nil
	}

	if c.localDNSCache != nil {
		lite, err := dnsParser.ParsePacketLite(assembled)
		if err == nil && lite.HasQuestion {
			cacheKey := dnsCache.BuildKey(lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class)
			c.localDNSCache.SetReady(cacheKey, lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class, assembled, time.Now())
		}
	}

	return nil
}

// ProcessDNSQuery handles a DNS query by checking the local cache or dispatching to the tunnel.
// It only responds on cache hits and uses "fire-and-forget" for misses.
func (c *Client) ProcessDNSQuery(query []byte, addr net.Addr, respond func([]byte)) bool {
	if c == nil || !c.SessionReady() {
		return false
	}

	// 1. Lite Parse DNS Query
	lite, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil || !lite.HasQuestion {
		return false
	}

	question := lite.FirstQuestion
	now := time.Now()

	// 2. Check Local Cache
	if c.localDNSCache != nil {
		key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
		res := c.localDNSCache.LookupOrCreatePending(key, question.Name, question.Type, question.Class, now)

		if res.Status == dnsCache.StatusReady && len(res.Response) > 0 {
			// Cache Hit - Rewrite Transaction ID and send back
			if respond != nil {
				resp := dnsCache.PatchResponseForQuery(res.Response, query)
				respond(resp)
			}
			if c.log != nil {
				c.log.Infof("🔍 <green>DNS Cache Hit: %s (%d)</green>", question.Name, question.Type)
			}
			return true
		}

		if res.Status == dnsCache.StatusPending && !res.DispatchNeeded {
			// Already pending in tunnel, don't re-dispatch
			if c.log != nil {
				c.log.Debugf("🔍 <yellow>DNS Query Pending: %s (%d)</yellow>", question.Name, question.Type)
			}
			return false
		}
	}

	// 3. Dispatch to Tunnel
	c.log.Infof("🔍 <yellow>DNS Query Request: %s (%d)</yellow>", question.Name, question.Type)
	c.dispatchDNSQueryToTunnel(query)
	return false
}

func (c *Client) dispatchDNSQueryToTunnel(query []byte) {
	if !c.SessionReady() {
		return
	}

	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if !ok || s0 == nil {
		return
	}

	arqObj, ok := s0.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	// Calculate target MTU for fragments
	fragments := fragmentPayload(query, c.syncedUploadMTU)
	total := uint8(len(fragments))

	// Generate a unique sequence number for this DNS query
	sn := uint16(c.mtuProbeCounter.Add(1) & 0xFFFF)

	for i, frag := range fragments {
		fragID := uint8(i)

		// Send via ARQ as a control packet
		arqObj.SendControlPacketWithTTL(Enums.PACKET_DNS_QUERY_REQ, sn, fragID, total, frag, Enums.DefaultPacketPriority(Enums.PACKET_DNS_QUERY_REQ), true, nil, 0)
	}
}
