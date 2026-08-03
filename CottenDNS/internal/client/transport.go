// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport.go — resolver query transport abstraction. The synchronous query
// paths (MTU probing, session init, health rechecks) talk to a resolver through
// a queryExchanger so they work identically over UDP or DNS-over-TCP/53. The
// active transport is chosen client-wide: RESOLVER_TRANSPORT = udp | tcp | auto,
// where "auto" tries UDP first and falls back to TCP when a full UDP MTU scan
// finds zero usable resolvers (see RunInitialMTUTests). The high-throughput data
// plane has its own persistent TCP path (tcp_data.go).
// ==============================================================================

package client

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const tcpQueryDialTimeout = 4 * time.Second

// queryExchanger is a synchronous DNS request/response transport to one resolver.
type queryExchanger interface {
	exchange(packet []byte, timeout time.Duration) ([]byte, error)
	Close() error
}

// resolverTransport is the client-wide active transport for the resolver hop.
// It is stored as an atomic int32 on the Client so every path (MTU probe,
// session init, health recheck, data plane) dispatches on one value.
type resolverTransport int32

const (
	transportUDP resolverTransport = iota
	transportTCP
	transportDoT
	transportDoH
)

func (t resolverTransport) String() string {
	switch t {
	case transportTCP:
		return "TCP/53"
	case transportDoT:
		return "DoT"
	case transportDoH:
		return "DoH"
	default:
		return "UDP/53"
	}
}

// resolverTransportFromName maps a RESOLVER_TRANSPORT value to the transport the
// client starts on. "auto" starts on UDP and is escalated to TCP by the fallback
// in RunInitialMTUTests.
func resolverTransportFromName(name string) resolverTransport {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "tcp":
		return transportTCP
	case "dot":
		return transportDoT
	case "doh":
		return transportDoH
	default:
		return transportUDP
	}
}

// activeTransport reports the transport currently in force.
func (c *Client) activeTransport() resolverTransport {
	return resolverTransport(c.transport.Load())
}

func (c *Client) setActiveTransport(t resolverTransport) {
	c.transport.Store(int32(t))
}

// usesStreamTransport reports whether the data plane runs over persistent
// per-resolver connections (TCP/DoT/DoH) instead of the UDP socket readers.
func (c *Client) usesStreamTransport() bool {
	return c.activeTransport() != transportUDP
}

// newQueryTransport opens a synchronous query transport to resolverLabel using
// the client's active transport.
func (c *Client) newQueryTransport(resolverLabel string) (queryExchanger, error) {
	switch c.activeTransport() {
	case transportDoH:
		return c.newDoHQueryTransport(resolverLabel)
	case transportDoT:
		conn, err := c.dialDoTResolver(resolverLabel, tcpQueryDialTimeout)
		if err != nil {
			return nil, err
		}
		// DoT is the TCP/53 wire format inside TLS, so the framing exchanger is
		// reused verbatim — only the dial differs.
		return &tcpQueryTransport{conn: conn}, nil
	case transportTCP:
		return newTCPQueryTransport(resolverLabel, tcpQueryDialTimeout)
	default:
		conn, err := dialUDPResolver(resolverLabel)
		if err != nil {
			return nil, err
		}
		return &udpQueryTransport{client: c, conn: conn}, nil
	}
}

// dialDoTResolver opens a TLS connection to a resolver's DoT port. The resolver
// is addressed by IP, so the port from the resolver label is replaced by
// RESOLVER_DOT_PORT and the SNI/verification name comes from configuration.
func (c *Client) dialDoTResolver(resolverLabel string, timeout time.Duration) (net.Conn, error) {
	target := resolverHostWithPort(resolverLabel, c.cfg.ResolverDoTPort)
	tlsCfg := c.resolverTLSConfig()
	if tlsCfg.ServerName == "" {
		// No configured name: fall back to the host we are dialing so SNI is at
		// least well-formed (an IP here means the cert needs an IP SAN or a pin).
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", target, tlsCfg)
}

// resolverHostWithPort rewrites a "host:port" resolver label to use port instead.
// Resolver entries carry the DNS port (53); the encrypted transports live on
// their own ports, so the host is what carries over, not the port.
func resolverHostWithPort(resolverLabel string, port int) string {
	host, _, err := net.SplitHostPort(resolverLabel)
	if err != nil {
		host = resolverLabel
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// tcpQueryTransport wraps a single persistent TCP connection to a resolver and
// exchanges RFC 1035 §4.2.2 length-prefixed DNS messages. The connection is
// reused across the many queries a probe sends, so there is no per-query
// handshake cost.
type tcpQueryTransport struct {
	conn net.Conn
}

func newTCPQueryTransport(resolverLabel string, dialTimeout time.Duration) (*tcpQueryTransport, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.Dial("tcp", resolverLabel)
	if err != nil {
		return nil, err
	}
	return &tcpQueryTransport{conn: conn}, nil
}

func (t *tcpQueryTransport) exchange(packet []byte, timeout time.Duration) ([]byte, error) {
	if t == nil || t.conn == nil {
		return nil, net.ErrClosed
	}
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := binary.BigEndian.Uint16(packet[:2])

	deadline := time.Now().Add(timeout)
	_ = t.conn.SetDeadline(deadline)

	if err := writeTCPDNSFramed(t.conn, packet); err != nil {
		return nil, err
	}

	// TCP is ordered, but tolerate a stray non-matching message defensively.
	for attempts := 0; attempts < 8; attempts++ {
		resp, err := readTCPDNSFramed(t.conn)
		if err != nil {
			return nil, err
		}
		if len(resp) >= 2 && binary.BigEndian.Uint16(resp[:2]) == expectedID {
			return resp, nil
		}
	}
	return nil, errors.New("too many mismatched dns responses over tcp")
}

func (t *tcpQueryTransport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// writeTCPDNSFramed writes a 2-byte length prefix followed by the DNS message.
func writeTCPDNSFramed(conn net.Conn, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("dns message too large for tcp framing")
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
	copy(framed[2:], msg)
	_, err := conn.Write(framed)
	return err
}

// readTCPDNSFramed reads one length-prefixed DNS message.
func readTCPDNSFramed(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 2 {
		return nil, errors.New("short tcp dns message")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
