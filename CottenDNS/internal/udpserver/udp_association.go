package udpserver

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"cottendns-go/internal/udpframe"
)

const (
	maxUDPAssociationTargets = 32
	maxUDPAssociationAliases = 4 * maxUDPAssociationTargets
	udpEndpointIdleTimeout   = 2 * time.Minute
	udpEndpointSweepInterval = 30 * time.Second
	udpResolveTimeout        = 5 * time.Second
)

type udpAssociationEndpoint struct {
	conn     net.Conn
	lastUsed time.Time
	done     chan struct{}
	once     sync.Once
}

func (e *udpAssociationEndpoint) close() {
	e.once.Do(func() {
		if e.done != nil {
			close(e.done)
		}
		_ = e.conn.Close()
	})
}

// udpAssociationConn adapts addressed UDP datagrams to the byte-stream
// interface used by ARQ. A connected UDP socket is retained per destination,
// preserving the stable remote 5-tuple required by QUIC, calls, and games.
type udpAssociationConn struct {
	mu           sync.Mutex
	writeBuffer  []byte
	readPending  []byte
	readDeadline time.Time
	endpoints    map[string]*udpAssociationEndpoint
	aliases      map[string]string
	rx           chan []byte
	closed       chan struct{}
	closeOnce    sync.Once
	monitor      *Server
}

func newUDPAssociationConn(monitors ...*Server) *udpAssociationConn {
	c := &udpAssociationConn{
		endpoints: make(map[string]*udpAssociationEndpoint),
		aliases:   make(map[string]string),
		rx:        make(chan []byte, 64),
		closed:    make(chan struct{}),
	}
	if len(monitors) > 0 {
		c.monitor = monitors[0]
	}
	if c.monitor != nil {
		c.monitor.genericUDPActive.Add(1)
		c.monitor.genericUDPTotal.Add(1)
	}
	go c.cleanupEndpoints(udpEndpointSweepInterval)
	return c
}

// Independent of cache misses: a long-lived association can keep using one
// known target while every other socket and alias becomes idle.
func (c *udpAssociationConn) cleanupEndpoints(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			c.expireEndpoints(now)
		case <-c.closed:
			return
		}
	}
}

func (c *udpAssociationConn) expireEndpoints(now time.Time) {
	var expired []*udpAssociationEndpoint
	c.mu.Lock()
	for key, endpoint := range c.endpoints {
		if now.Sub(endpoint.lastUsed) >= udpEndpointIdleTimeout {
			expired = append(expired, c.detachEndpointLocked(key))
		}
	}
	c.mu.Unlock()
	for _, endpoint := range expired {
		endpoint.close()
	}
}

func (c *udpAssociationConn) rememberAliasLocked(alias, key string) {
	if _, exists := c.aliases[alias]; !exists && len(c.aliases) >= maxUDPAssociationAliases {
		// Dropping an alias does not disturb its canonical destination socket.
		// A later request can resolve the name and find that same socket again.
		for oldest := range c.aliases {
			delete(c.aliases, oldest)
			break
		}
	}
	c.aliases[alias] = key
}

func (c *udpAssociationConn) detachEndpointLocked(key string) *udpAssociationEndpoint {
	endpoint := c.endpoints[key]
	if endpoint != nil {
		delete(c.endpoints, key)
		c.removeAliasesLocked(key)
		if c.monitor != nil {
			c.monitor.genericUDPEndpoints.Add(^uint64(0))
		}
	}
	return endpoint
}

func (c *udpAssociationConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	c.mu.Lock()
	c.writeBuffer = append(c.writeBuffer, p...)
	if len(c.writeBuffer) > udpframe.MaxFramePayload+2 {
		c.writeBuffer = nil
		c.mu.Unlock()
		return len(p), nil
	}
	var bodies [][]byte
	for {
		body, rest, ready, err := udpframe.Pop(c.writeBuffer)
		if err != nil {
			c.writeBuffer = nil
			break
		}
		if !ready {
			break
		}
		bodies = append(bodies, append([]byte(nil), body...))
		c.writeBuffer = rest
	}
	c.mu.Unlock()

	for _, body := range bodies {
		_, host, port, payload, err := udpframe.DecodeBody(body)
		if err != nil || len(payload) == 0 {
			continue
		}
		endpoint, err := c.endpointFor(host, port)
		if err != nil {
			if c.monitor != nil {
				c.monitor.genericUDPErrors.Add(1)
			}
			continue
		}
		if _, err := endpoint.conn.Write(payload); err == nil {
			if c.monitor != nil {
				c.monitor.genericUDPUpDatagrams.Add(1)
				c.monitor.genericUDPUpBytes.Add(uint64(len(payload)))
			}
			c.mu.Lock()
			endpoint.lastUsed = time.Now()
			c.mu.Unlock()
		} else {
			if c.monitor != nil {
				c.monitor.genericUDPErrors.Add(1)
			}
			c.removeEndpoint(endpoint)
		}
	}
	return len(p), nil
}

func (c *udpAssociationConn) endpointFor(host string, port uint16) (*udpAssociationEndpoint, error) {
	requestKey := net.JoinHostPort(strings.ToLower(host), strconv.Itoa(int(port)))
	now := time.Now()
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}
	if endpointKey := c.aliases[requestKey]; endpointKey != "" {
		if endpoint := c.endpoints[endpointKey]; endpoint != nil {
			endpoint.lastUsed = now
			c.mu.Unlock()
			return endpoint, nil
		}
		delete(c.aliases, requestKey)
	}
	c.mu.Unlock()

	addr, err := resolvePublicUDPAddr(host, port)
	if err != nil {
		return nil, err
	}
	key := addr.String()

	c.mu.Lock()
	if endpoint := c.endpoints[key]; endpoint != nil {
		endpoint.lastUsed = now
		c.rememberAliasLocked(requestKey, key)
		c.mu.Unlock()
		return endpoint, nil
	}
	c.mu.Unlock()

	network := "udp6"
	if addr.IP.To4() != nil {
		network = "udp4"
	}
	var conn net.Conn
	if c.monitor != nil && c.monitor.embeddedDialContext != nil {
		// The embedded wrapper already bounds upstream setup to 15 seconds and
		// cancels it with the account. DNS lookup's shorter budget must not cut
		// off a slow but valid proxy handshake.
		conn, err = c.monitor.embeddedDialContext(context.Background(), network, addr.String())
	} else {
		conn, err = net.DialUDP(network, nil, addr)
	}
	if err != nil {
		return nil, err
	}
	endpoint := &udpAssociationEndpoint{conn: conn, lastUsed: time.Now(), done: make(chan struct{})}

	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		endpoint.close()
		return nil, net.ErrClosed
	default:
	}
	if existing := c.endpoints[key]; existing != nil {
		existing.lastUsed = time.Now()
		c.rememberAliasLocked(requestKey, key)
		c.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	// Enforce the cap at insertion, after concurrent dials have finished.
	var evicted *udpAssociationEndpoint
	if len(c.endpoints) >= maxUDPAssociationTargets {
		var oldestKey string
		for candidate, current := range c.endpoints {
			if oldestKey == "" || current.lastUsed.Before(c.endpoints[oldestKey].lastUsed) {
				oldestKey = candidate
			}
		}
		evicted = c.detachEndpointLocked(oldestKey)
	}
	c.endpoints[key] = endpoint
	c.rememberAliasLocked(requestKey, key)
	if c.monitor != nil {
		c.monitor.genericUDPEndpoints.Add(1)
	}
	c.mu.Unlock()
	if evicted != nil {
		evicted.close()
	}
	go c.readEndpoint(endpoint)
	return endpoint, nil
}

func (c *udpAssociationConn) removeAliasesLocked(endpointKey string) {
	for requestKey, resolvedKey := range c.aliases {
		if resolvedKey == endpointKey {
			delete(c.aliases, requestKey)
		}
	}
}

func (c *udpAssociationConn) removeEndpoint(target *udpAssociationEndpoint) {
	if target == nil {
		return
	}
	c.mu.Lock()
	for endpointKey, endpoint := range c.endpoints {
		if endpoint == target {
			c.detachEndpointLocked(endpointKey)
			break
		}
	}
	c.mu.Unlock()
	target.close()
}

func resolvePublicUDPAddr(host string, port uint16) (*net.UDPAddr, error) {
	if err := validateSOCKSTargetHost(host); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), udpResolveTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if validateSOCKSTargetHost(address.IP.String()) == nil {
			return &net.UDPAddr{IP: address.IP, Zone: address.Zone, Port: int(port)}, nil
		}
	}
	return nil, &blockedSOCKSTargetError{host: host}
}

func (c *udpAssociationConn) readEndpoint(endpoint *udpAssociationEndpoint) {
	buffer := make([]byte, 65535)
	for {
		n, err := endpoint.conn.Read(buffer)
		if err != nil {
			c.removeEndpoint(endpoint)
			return
		}
		if n > 0 {
			c.mu.Lock()
			endpoint.lastUsed = time.Now()
			c.mu.Unlock()
		}
		remote, ok := endpoint.conn.RemoteAddr().(*net.UDPAddr)
		if !ok || remote == nil || n == 0 {
			continue
		}
		atyp := byte(udpframe.AddressTypeIPv6)
		if remote.IP.To4() != nil {
			atyp = udpframe.AddressTypeIPv4
		}
		frame, err := udpframe.Encode(atyp, remote.IP.String(), uint16(remote.Port), buffer[:n])
		if err != nil {
			continue
		}
		if c.monitor != nil {
			c.monitor.genericUDPDownDatagrams.Add(1)
			c.monitor.genericUDPDownBytes.Add(uint64(n))
		}
		select {
		case c.rx <- frame:
		case <-c.closed:
			return
		case <-endpoint.done:
			return
		}
	}
}

func (c *udpAssociationConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.readPending) > 0 {
			n := copy(p, c.readPending)
			c.readPending = c.readPending[n:]
			c.mu.Unlock()
			return n, nil
		}
		deadline := c.readDeadline
		c.mu.Unlock()

		var timer <-chan time.Time
		var stopTimer func()
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, &udpAssociationTimeoutError{}
			}
			t := time.NewTimer(remaining)
			timer = t.C
			stopTimer = func() { t.Stop() }
		}
		select {
		case frame := <-c.rx:
			if stopTimer != nil {
				stopTimer()
			}
			c.mu.Lock()
			c.readPending = frame
			c.mu.Unlock()
		case <-timer:
			return 0, &udpAssociationTimeoutError{}
		case <-c.closed:
			if stopTimer != nil {
				stopTimer()
			}
			return 0, io.EOF
		}
	}
}

func (c *udpAssociationConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *udpAssociationConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		var endpoints []*udpAssociationEndpoint
		c.mu.Lock()
		for key := range c.endpoints {
			endpoints = append(endpoints, c.detachEndpointLocked(key))
		}
		clear(c.aliases)
		c.writeBuffer = nil
		c.readPending = nil
		c.mu.Unlock()
		for _, endpoint := range endpoints {
			endpoint.close()
		}
		if c.monitor != nil {
			c.monitor.genericUDPActive.Add(^uint64(0))
		}
	})
	return nil
}

type udpAssociationTimeoutError struct{}

func (*udpAssociationTimeoutError) Error() string   { return "UDP association read timeout" }
func (*udpAssociationTimeoutError) Timeout() bool   { return true }
func (*udpAssociationTimeoutError) Temporary() bool { return true }

var _ io.ReadWriteCloser = (*udpAssociationConn)(nil)
