package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"cottendns-go/internal/resolvertransport"
)

func (c *Client) encryptedResolverOptions() resolvertransport.Options {
	return resolvertransport.Options{TLSConfig: c.resolverTLSConfig(), DoHPort: c.cfg.ResolverDoHPort, DoHPath: c.cfg.ResolverDoHPath, DoQPort: c.cfg.ResolverDoQPort, HTTP3Fallback: c.cfg.ResolverHTTP3Fallback, PaddingBlockSize: c.cfg.DNSPaddingBlockSize}
}

func (c *Client) sharedEncryptedDNSClient() (*resolvertransport.Client, error) {
	mode := "doh"
	switch c.activeTransport() {
	case transportDoH3:
		mode = "doh3"
	case transportDoQ:
		mode = "doq"
	}
	return c.sharedEncryptedDNSClientForMode(mode)
}
func (c *Client) sharedEncryptedDNSClientForMode(mode string) (*resolvertransport.Client, error) {
	c.encryptedDNSMu.Lock()
	defer c.encryptedDNSMu.Unlock()
	if c.encryptedDNS == nil {
		transport, err := resolvertransport.New(mode, c.encryptedResolverOptions())
		if err != nil {
			return nil, err
		}
		c.encryptedDNS = transport
	}
	return c.encryptedDNS, nil
}
func (c *Client) closeSharedEncryptedDNSClient() {
	c.encryptedDNSMu.Lock()
	old := c.encryptedDNS
	c.encryptedDNS = nil
	c.encryptedDNSMu.Unlock()
	if old != nil {
		old.Close()
	}
}
func (c *Client) exchangeEncryptedDNS(ctx context.Context, resolver string, query []byte) ([]byte, error) {
	t, err := c.sharedEncryptedDNSClient()
	if err != nil {
		return nil, err
	}
	return t.Exchange(ctx, resolver, query)
}

type encryptedQueryTransport struct {
	transport *resolvertransport.Client
	resolver  string
	ctx       context.Context
	cancel    context.CancelFunc
}

func (c *Client) newEncryptedQueryTransport(resolver string) (queryExchanger, error) {
	t, err := c.sharedEncryptedDNSClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &encryptedQueryTransport{transport: t, resolver: resolver, ctx: ctx, cancel: cancel}, nil
}
func (t *encryptedQueryTransport) exchange(query []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(t.ctx, timeout)
	defer cancel()
	return t.transport.Exchange(ctx, t.resolver, query)
}
func (t *encryptedQueryTransport) Close() error {
	if t != nil && t.cancel != nil {
		t.cancel()
	}
	return nil
}

// Soar sends while holding its session lock. This PacketConn copies and queues
// queries without waiting for TLS/QUIC, preserving its nonblocking scheduler.
// Replies retain the supplied resolver address and DNS transaction ID.
type encryptedPacketConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	transport     *resolvertransport.Client
	timeout       time.Duration
	send          chan encryptedPacket
	receive       chan encryptedPacket
	mu            sync.Mutex
	deadline      time.Time
	changed       chan struct{}
	once          sync.Once
	ownsTransport bool
}
type encryptedPacket struct {
	data []byte
	addr net.Addr
}

func (c *Client) newCottenMaxEncryptedPacketConn(ctx context.Context, _, _ string) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t, err := c.sharedEncryptedDNSClientForMode(c.cfg.ResolverTransport)
	if err != nil {
		return nil, err
	}
	// Match net.ListenConfig: ctx bounds socket creation, not the returned
	// socket's lifetime. Lazy domain creation uses a per-dial attempt context
	// that is cancelled as soon as Dial returns a working stream.
	p := newEncryptedPacketConn(context.Background(), t, c.resolverRequestTimeout())
	p.ownsTransport = false // retained across domain failover, closed by Client.Run
	if err := ctx.Err(); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}
func newEncryptedPacketConn(ctx context.Context, t *resolvertransport.Client, timeout time.Duration) *encryptedPacketConn {
	ctx, cancel := context.WithCancel(ctx)
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	p := &encryptedPacketConn{ctx: ctx, cancel: cancel, transport: t, timeout: timeout, send: make(chan encryptedPacket, 512), receive: make(chan encryptedPacket, 512), changed: make(chan struct{}), ownsTransport: true}
	// Bounded outstanding exchanges prevent a dead resolver accumulating work.
	for i := 0; i < 128; i++ {
		go p.worker()
	}
	return p
}
func (p *encryptedPacketConn) worker() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case job := <-p.send:
			ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
			response, err := p.transport.Exchange(ctx, job.addr.String(), job.data)
			cancel()
			if err == nil {
				select {
				case p.receive <- encryptedPacket{response, job.addr}:
				case <-p.ctx.Done():
					return
				default:
				}
			}
		}
	}
}
func (p *encryptedPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if p.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	if addr == nil || len(data) < 12 {
		return 0, errors.New("invalid encrypted resolver packet")
	}
	// Copy both address and packet: the engine reuses its outgoing buffers.
	target, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, err
	}
	job := encryptedPacket{append([]byte(nil), data...), net.UDPAddrFromAddrPort(target)}
	select {
	case <-p.ctx.Done():
		return 0, net.ErrClosed
	case p.send <- job:
		return len(data), nil
	default:
		return 0, &net.OpError{Op: "write", Net: "encrypted-dns", Err: errors.New("encrypted resolver queue full")}
	}
}
func (p *encryptedPacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed := p.deadline, p.changed
		p.mu.Unlock()
		var timer *time.Timer
		var expiry <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expiry = timer.C
		}
		stop := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case <-p.ctx.Done():
			stop()
			return 0, nil, net.ErrClosed
		case <-expiry:
			stop()
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			stop()
			continue
		case response := <-p.receive:
			stop()
			if len(response.data) > len(dst) {
				return 0, response.addr, errors.New("encrypted DNS receive buffer too small")
			}
			return copy(dst, response.data), response.addr, nil
		}
	}
}
func (p *encryptedPacketConn) Close() error {
	var err error
	p.once.Do(func() {
		p.cancel()
		if p.ownsTransport {
			err = p.transport.Close()
		}
	})
	return err
}
func (p *encryptedPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (p *encryptedPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *encryptedPacketConn) SetWriteDeadline(time.Time) error { return nil } // writes never wait
func (p *encryptedPacketConn) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }
