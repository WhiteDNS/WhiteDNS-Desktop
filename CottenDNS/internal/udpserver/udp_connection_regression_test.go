package udpserver

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/udpframe"
)

// Public-looking tunnel destinations are routed exclusively to this local test
// socket by the embedded dial callback. No public network is contacted.
func newUDPConnectionFixture(t *testing.T) (*udpAssociationConn, *Server, *net.UDPConn, *atomic.Int32, <-chan string) {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan string, 8)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buffer := make([]byte, 4096)
		for {
			n, from, err := peer.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			select {
			case observed <- from.String():
			default:
			}
			_, _ = peer.WriteToUDP(buffer[:n], from)
		}
	}()
	var dials atomic.Int32
	s := &Server{embeddedDialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	}}
	c := newUDPAssociationConn(s)
	t.Cleanup(func() {
		_ = c.Close()
		_ = peer.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("local UDP peer did not stop")
		}
	})
	return c, s, peer, &dials, observed
}

func udpConnectionRoundTrip(t *testing.T, c *udpAssociationConn, host string, payload []byte) {
	t.Helper()
	frame, err := udpframe.Encode(udpframe.AddressTypeIPv6, host, 443, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 4096)
	n, err := c.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	body, rest, ready, err := udpframe.Pop(buffer[:n])
	if err != nil || !ready || len(rest) != 0 {
		t.Fatalf("invalid reply frame: ready=%v rest=%d err=%v", ready, len(rest), err)
	}
	_, _, _, actual, err := udpframe.DecodeBody(body)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("UDP payload changed: got=%x want=%x err=%v", actual, payload, err)
	}
}

func TestUDPConnectionAliasChurnPreservesTupleAndExpiredTargetReconnects(t *testing.T) {
	c, s, _, dials, observed := newUDPConnectionFixture(t)
	host := "2606:4700::1111"
	udpConnectionRoundTrip(t, c, host, []byte("before aliases"))
	firstTuple := <-observed
	for i := 0; i < 1024; i++ {
		groups := make([]string, 5)
		for j := range groups {
			groups[j] = strings.Repeat("0", 1+((i>>(2*j))&3))
		}
		alias := fmt.Sprintf("2606:4700:%s:1111", strings.Join(groups, ":"))
		if _, err := c.endpointFor(alias, 443); err != nil {
			t.Fatal(err)
		}
	}
	udpConnectionRoundTrip(t, c, host, []byte("after aliases"))
	if tuple := <-observed; tuple != firstTuple || dials.Load() != 1 {
		t.Fatalf("active UDP tuple changed: before=%s after=%s dials=%d", firstTuple, tuple, dials.Load())
	}
	c.mu.Lock()
	for _, endpoint := range c.endpoints {
		endpoint.lastUsed = time.Now().Add(-udpEndpointIdleTimeout - time.Second)
	}
	c.mu.Unlock()
	c.expireEndpoints(time.Now())
	if s.genericUDPEndpoints.Load() != 0 {
		t.Fatal("expired socket remained accounted")
	}
	udpConnectionRoundTrip(t, c, host, []byte("reopened after idle"))
	if dials.Load() != 2 || s.genericUDPEndpoints.Load() != 1 {
		t.Fatalf("idle target did not reconnect: dials=%d endpoints=%d", dials.Load(), s.genericUDPEndpoints.Load())
	}
}

func TestUDPConnectionIncomingTrafficPreventsIdleRetirement(t *testing.T) {
	c, s, peer, _, _ := newUDPConnectionFixture(t)
	endpoint, err := c.endpointFor("8.8.8.8", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	endpoint.lastUsed = time.Now().Add(-udpEndpointIdleTimeout - time.Second)
	c.mu.Unlock()
	if _, err := peer.WriteToUDP([]byte("download without upload"), endpoint.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	c.expireEndpoints(time.Now())
	if s.genericUDPEndpoints.Load() != 1 {
		t.Fatal("incoming-only active UDP connection was retired")
	}
	if again, err := c.endpointFor("8.8.8.8", 443); err != nil || again != endpoint {
		t.Fatalf("incoming-only endpoint was replaced: %v", err)
	}
}

func TestUDPConnectionEmbeddedDialAllowsSlowProxyHandshake(t *testing.T) {
	var peer net.Conn
	s := &Server{embeddedDialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		// Panel already grants upstream setup 15 seconds. A six-second proxy
		// handshake must not be cut short by the DNS resolver's five-second cap.
		timer := time.NewTimer(6 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		local, remote := net.Pipe()
		peer = remote
		return local, nil
	}}
	c := newUDPAssociationConn(s)
	defer func() {
		_ = c.Close()
		if peer != nil {
			_ = peer.Close()
		}
	}()
	if _, err := c.endpointFor("8.8.8.8", 443); err != nil {
		t.Fatalf("slow but valid embedded UDP proxy handshake was rejected: %v", err)
	}
}

type queuedUDPConnection struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
	reads   atomic.Int32
	remotes atomic.Int32
}

func (c *queuedUDPConnection) Read(p []byte) (int, error) {
	select {
	case b := <-c.packets:
		c.reads.Add(1)
		return copy(p, b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *queuedUDPConnection) Write(p []byte) (int, error) { return len(p), nil }
func (c *queuedUDPConnection) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }
func (c *queuedUDPConnection) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (c *queuedUDPConnection) RemoteAddr() net.Addr {
	c.remotes.Add(1)
	return &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 443}
}
func (c *queuedUDPConnection) SetDeadline(time.Time) error      { return nil }
func (c *queuedUDPConnection) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedUDPConnection) SetWriteDeadline(time.Time) error { return nil }

func TestUDPConnectionFullReceiveQueueDoesNotRetainRetiredReader(t *testing.T) {
	s := &Server{}
	c := newUDPAssociationConn(s)
	defer c.Close()
	conn := &queuedUDPConnection{packets: make(chan []byte, cap(c.rx)+1), closed: make(chan struct{})}
	endpoint := &udpAssociationEndpoint{conn: conn, lastUsed: time.Now(), done: make(chan struct{})}
	c.mu.Lock()
	c.endpoints["8.8.8.8:443"] = endpoint
	s.genericUDPEndpoints.Store(1)
	c.mu.Unlock()
	finished := make(chan struct{})
	go func() { defer close(finished); c.readEndpoint(endpoint) }()
	for i := 0; i < cap(c.rx)+1; i++ {
		conn.packets <- []byte("unread reply")
	}
	deadline := time.Now().Add(2 * time.Second)
	for conn.remotes.Load() < int32(cap(c.rx)+1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(c.rx) != cap(c.rx) || conn.remotes.Load() != int32(cap(c.rx)+1) {
		t.Fatal("did not reach a reader blocked on the full receive queue")
	}
	// RemoteAddr is read after lastUsed is refreshed. The final remote call
	// therefore establishes that the reader is past its last activity update.
	c.mu.Lock()
	endpoint.lastUsed = time.Now().Add(-udpEndpointIdleTimeout - time.Second)
	c.mu.Unlock()
	c.expireEndpoints(time.Now())
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("retired UDP reader remained blocked on a full receive queue")
	}
	if s.genericUDPEndpoints.Load() != 0 {
		t.Fatal("retired endpoint remained accounted")
	}
}
