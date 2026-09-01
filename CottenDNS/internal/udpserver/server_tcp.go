// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_tcp.go — DNS-over-TCP listener on the same host:port as the UDP
// listener. Many restrictive networks filter or truncate UDP/53 but still allow
// TCP/53; serving both lets clients fall back to TCP without any change to the
// tunnel framing. Each TCP message is a standard RFC 1035 §4.2.2 length-prefixed
// DNS message (2-byte big-endian length, then the message). Responses use the
// same framing. The handler is the exact same transport-agnostic
// safeHandlePacket used by the UDP path, so all tunnel logic is shared.
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tcpReadIdleTimeout             = 30 * time.Second
	tcpWriteTimeout                = 15 * time.Second
	tcpMaxMessageLength            = 65535
	tcpMaxConcurrentQueriesPerConn = 32
)

type tcpServerOptions struct {
	readIdleTimeout   time.Duration
	writeTimeout      time.Duration
	maxQueriesPerConn int
	maxInFlight       int
}

func defaultTCPServerOptions() tcpServerOptions {
	return tcpServerOptions{
		readIdleTimeout: tcpReadIdleTimeout,
		writeTimeout:    tcpWriteTimeout,
		maxInFlight:     tcpMaxConcurrentQueriesPerConn,
	}
}

func (s *Server) tcpServerOptions() tcpServerOptions {
	opts := defaultTCPServerOptions()
	if s == nil {
		return opts
	}
	if timeout := s.cfg.TCPReadIdleTimeout(); timeout > 0 {
		opts.readIdleTimeout = timeout
	}
	if timeout := s.cfg.TCPWriteTimeout(); timeout > 0 {
		opts.writeTimeout = timeout
	}
	opts.maxQueriesPerConn = s.cfg.TCPMaxQueriesPerConn
	return opts
}

// serveTCP runs the DNS-over-TCP listener until ctx is cancelled. It mirrors the
// UDP listener but is connection-oriented: each accepted connection is serviced
// by its own goroutine that reads length-prefixed queries and writes
// length-prefixed responses. Returns when the listener is closed.
func (s *Server) serveTCP(ctx context.Context, host string, port int) error {
	// Plain DNS-over-TCP/53 only. The DoT/DoH listeners deliberately keep a
	// single socket: they may be coexisting with a panel behind the SNI router
	// on 443, and multiplying listeners there would interact with that
	// hand-off for no gain, since TLS connections are long-lived and accept
	// rate is not their bottleneck.
	ln, err := s.listenTCP53(host, port)
	if err != nil {
		return err
	}
	s.tcpListenerUp.Store(1)
	defer s.tcpListenerUp.Store(0)
	limited := newLimitedListenerWithBudget(ln, s.streamConnBudget, s.cfg.TCPMaxConns, s.cfg.TCPMaxConnsPerIP)
	return s.serveDNSOverStream(ctx, limited, "TCP")
}

// listenTCP53 opens the normal listener plus a distinct tcp6 listener when
// enabled. Both are presented as one logical listener so TCP_MAX_CONNS and the
// per-IP limit remain global across address families.
func (s *Server) listenTCP53(host string, port int) (net.Listener, error) {
	sockets := udpSocketCount(s.cfg.UDPReaders)
	trimmed := strings.TrimSpace(host)
	primaryNetwork := "tcp"
	if ip, parseErr := netip.ParseAddr(trimmed); parseErr == nil {
		if ip.Unmap().Is4() {
			primaryNetwork = "tcp4"
		} else {
			primaryNetwork = "tcp6"
		}
	}
	primary, err := s.listenTCPSharedNetwork(primaryNetwork, net.JoinHostPort(trimmed, itoaPort(port)), sockets)
	if err != nil {
		return nil, err
	}

	// An IPv6 primary already provides the requested family. Do not open the
	// same address twice, and do not assume it also accepts IPv4.
	if !s.cfg.TCPIPv6Enabled || primaryNetwork == "tcp6" {
		return primary, nil
	}
	ipv6Address := net.JoinHostPort(strings.TrimSpace(s.cfg.TCPIPv6Host), itoaPort(port))
	ipv6, ipv6Err := s.listenTCPSharedNetwork("tcp6", ipv6Address, sockets)
	if ipv6Err != nil {
		if s.log != nil {
			s.log.Warnf("<yellow>IPv6 TCP/53 listener unavailable; IPv4 TCP/53 remains active:</yellow> %v", ipv6Err)
		}
		return primary, nil
	}
	return newMultiListener([]net.Listener{primary, ipv6}), nil
}

// serveDNSOverStream runs the connection-oriented DNS accept loop on an already
// opened listener until ctx is cancelled. It is transport-agnostic: the plain
// TCP/53 listener and the TLS-wrapped DoT listener both feed it, so DoT inherits
// TCP's framing, per-IP limits, and load-shedding for free. transportName is
// only used for logging.
func (s *Server) serveDNSOverStream(ctx context.Context, ln net.Listener, transportName string) error {
	maxConns := s.cfg.TCPMaxConns
	if maxConns <= 0 {
		maxConns = 2048
	}

	addresses := ln.Addr().String()
	if multi, ok := ln.(interface{ Addresses() []net.Addr }); ok {
		items := multi.Addresses()
		parts := make([]string, 0, len(items))
		for _, address := range items {
			parts = append(parts, address.String())
		}
		if len(parts) > 0 {
			addresses = strings.Join(parts, ", ")
		}
	}
	s.log.Infof(
		"\U0001F4E1 <green>%s Listener Ready, Addr: <cyan>%s</cyan>, MaxConns: <cyan>%d</cyan></green>",
		transportName,
		addresses,
		maxConns,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var (
		conns      sync.WaitGroup
		active     atomic.Int64
		perIPMu    sync.Mutex
		activeByIP = make(map[string]int)
	)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		remoteIP := tcpRemoteIPKey(conn.RemoteAddr())
		// Shed load instead of unbounded growth under a connection flood.
		if active.Load() >= int64(maxConns) || !reserveTCPIPSlot(remoteIP, s.cfg.TCPMaxConnsPerIP, &perIPMu, activeByIP) {
			_ = conn.Close()
			continue
		}
		active.Add(1)
		conns.Add(1)
		go func(c net.Conn) {
			defer conns.Done()
			defer active.Add(-1)
			defer releaseTCPIPSlot(remoteIP, &perIPMu, activeByIP)
			s.handleTCPConn(ctx, c)
		}(conn)
	}

	conns.Wait()
	return nil
}

// handleTCPConn services one TCP connection using the server's packet handler.
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	serveTCPDNSMessagesWithOptions(ctx, conn, s.safeHandlePacket, s.tcpServerOptions())
}

// serveTCPDNSMessages reads a sequence of RFC 1035 §4.2.2 length-prefixed DNS
// messages from conn, runs each through handler, and writes the length-prefixed
// response. It tolerates pipelined queries and returns on idle, error, or
// context cancellation. Split out from handleTCPConn so the framing can be
// unit-tested with any net.Conn and handler.
func serveTCPDNSMessages(ctx context.Context, conn net.Conn, handler func([]byte) []byte) {
	serveTCPDNSMessagesWithOptions(ctx, conn, handler, defaultTCPServerOptions())
}

func serveTCPDNSMessagesWithOptions(ctx context.Context, conn net.Conn, handler func([]byte) []byte, opts tcpServerOptions) {
	if opts.readIdleTimeout <= 0 {
		opts.readIdleTimeout = tcpReadIdleTimeout
	}
	if opts.writeTimeout <= 0 {
		opts.writeTimeout = tcpWriteTimeout
	}
	if opts.maxInFlight <= 0 {
		opts.maxInFlight = tcpMaxConcurrentQueriesPerConn
	}

	lenBuf := make([]byte, 2)
	queries := 0
	inflight := make(chan struct{}, opts.maxInFlight)
	var handlers sync.WaitGroup
	var writeMu sync.Mutex
	defer handlers.Wait()
	for {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		if opts.maxQueriesPerConn > 0 && queries >= opts.maxQueriesPerConn {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(opts.readIdleTimeout))

		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return // EOF, idle timeout, or peer closed.
		}
		queries++
		msgLen := int(binary.BigEndian.Uint16(lenBuf))
		if msgLen == 0 || msgLen > tcpMaxMessageLength {
			return
		}

		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		if ctx == nil {
			inflight <- struct{}{}
		} else {
			select {
			case inflight <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
		handlers.Add(1)
		go func(query []byte) {
			defer handlers.Done()
			defer func() { <-inflight }()

			response := handler(query)
			if len(response) == 0 {
				// No tunnel response for this query; keep the connection open for
				// the next pipelined message rather than dropping it.
				return
			}
			if len(response) > tcpMaxMessageLength {
				response = response[:tcpMaxMessageLength]
			}

			out := make([]byte, 2+len(response))
			binary.BigEndian.PutUint16(out[:2], uint16(len(response)))
			copy(out[2:], response)

			writeMu.Lock()
			defer writeMu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(opts.writeTimeout))
			for len(out) > 0 {
				n, err := conn.Write(out)
				if err != nil || n <= 0 {
					_ = conn.Close()
					return
				}
				out = out[n:]
			}
		}(msg)
	}
}

func tcpRemoteIPKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return clientIPLimitKey(addr.String())
	}
	return clientIPLimitKey(host)
}

func reserveTCPIPSlot(ip string, limit int, mu *sync.Mutex, activeByIP map[string]int) bool {
	if limit <= 0 || ip == "" || mu == nil || activeByIP == nil {
		return true
	}
	mu.Lock()
	defer mu.Unlock()
	if activeByIP[ip] >= limit {
		return false
	}
	activeByIP[ip]++
	return true
}

func releaseTCPIPSlot(ip string, mu *sync.Mutex, activeByIP map[string]int) {
	if ip == "" || mu == nil || activeByIP == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	n := activeByIP[ip]
	if n <= 1 {
		delete(activeByIP, ip)
		return
	}
	activeByIP[ip] = n - 1
}

func itoaPort(port int) string {
	// Small, allocation-light int-to-string for a port number.
	if port <= 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for port > 0 {
		i--
		b[i] = byte('0' + port%10)
		port /= 10
	}
	return string(b[i:])
}
