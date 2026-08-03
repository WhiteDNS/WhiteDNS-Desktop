// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"time"

	"cottendns-go/internal/arq"
	Enums "cottendns-go/internal/enums"
)

// LocalSocksVersion sentinel values for HTTP proxy modes (above any real SOCKS version byte).
const (
	httpProxyCONNECT = byte(0xFE) // HTTP CONNECT tunnel: reply "200 Connection established"
	httpProxyPlain   = byte(0xFD) // plain HTTP request: no reply, inject rewritten request
)

// prependConn wraps a net.Conn so that reads first drain a fixed buffer then
// fall through to the underlying conn. Used to inject the rewritten HTTP
// request before the ARQ starts reading the original connection.
type prependConn struct {
	net.Conn
	r io.Reader
}

func (p *prependConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// HandleHTTPProxy handles a connection from a local HTTP proxy client.
// Supports CONNECT (HTTPS tunnelling) and plain-HTTP requests.
func (c *Client) HandleHTTPProxy(ctx context.Context, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		c.handleHTTPConnect(ctx, conn, req.Host)
		return
	}

	c.handleHTTPPlain(ctx, conn, br, req)
}

// handleHTTPConnect processes an HTTP CONNECT request (used by HTTPS).
func (c *Client) handleHTTPConnect(ctx context.Context, conn net.Conn, hostport string) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
		return
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil || port <= 0 || port > 65535 {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
		return
	}

	c.openHTTPTunnel(ctx, conn, host, uint16(port), httpProxyCONNECT, conn)
}

// handleHTTPPlain processes a plain HTTP proxy request (absolute URI).
func (c *Client) handleHTTPPlain(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request) {
	u := req.URL
	host := u.Hostname()
	port := 80
	if p := u.Port(); p != "" {
		if pp, e := net.LookupPort("tcp", p); e == nil && pp > 0 {
			port = pp
		}
	}
	if host == "" {
		// Fall back to Host header.
		h, p, e := net.SplitHostPort(req.Host)
		if e == nil {
			host = h
			if pp, e2 := net.LookupPort("tcp", p); e2 == nil && pp > 0 {
				port = pp
			}
		} else {
			host = req.Host
		}
	}
	if host == "" {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
		return
	}

	// Rewrite to a relative-URI request (strip scheme+authority).
	req.RequestURI = u.RequestURI()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		_ = conn.Close()
		return
	}

	// Drain anything already buffered in the reader (request body / pipelining).
	if n := br.Buffered(); n > 0 {
		rest := make([]byte, n)
		_, _ = io.ReadFull(br, rest)
		buf.Write(rest)
	}

	// Wrap conn so the ARQ reads the rewritten request first, then raw conn.
	wrapped := &prependConn{Conn: conn, r: io.MultiReader(&buf, conn)}
	c.openHTTPTunnel(ctx, wrapped, host, uint16(port), httpProxyPlain, conn)
}

// openHTTPTunnel allocates a stream and sends PACKET_SOCKS5_SYN to the server,
// using the same target-payload format as SOCKS5 CONNECT so the server-side
// handler can connect to the target without changes.
func (c *Client) openHTTPTunnel(ctx context.Context, streamConn net.Conn, host string, port uint16, proxyVersion byte, rawConn net.Conn) {
	streamID, ok := c.get_new_stream_id()
	if !ok {
		c.log.Errorf("❌ <red>Failed to get new stream ID for HTTP proxy</red>")
		sendHTTPError(rawConn, 503)
		_ = rawConn.Close()
		return
	}

	methodStr := "plain"
	if proxyVersion == httpProxyCONNECT {
		methodStr = "CONNECT"
	}
	c.log.Infof("🔌 <green>New HTTP %s to <cyan>%s:%d</cyan>, Stream ID: <cyan>%d</cyan></green>",
		methodStr, host, port, streamID)

	// Build SOCKS5-compatible target payload.
	var targetPayload []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			targetPayload = append([]byte{SOCKS5_ATYP_IPV4}, ip4...)
		} else {
			targetPayload = append([]byte{SOCKS5_ATYP_IPV6}, ip.To16()...)
		}
	} else {
		targetPayload = append([]byte{SOCKS5_ATYP_DOMAIN, byte(len(host))}, []byte(host)...)
	}
	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, port)
	targetPayload = append(targetPayload, pBuf...)

	s := c.new_stream(streamID, streamConn, nil)
	if s == nil {
		sendHTTPError(rawConn, 503)
		_ = rawConn.Close()
		return
	}
	s.LocalSocksVersion = proxyVersion

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	fragments := fragmentPayload(targetPayload, c.syncedUploadMTU)
	total := uint8(len(fragments))
	for i, frag := range fragments {
		arqObj.SendControlPacketWithTTL(
			Enums.PACKET_SOCKS5_SYN,
			uint16(0), uint8(i), total,
			frag,
			Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_SYN),
			true, nil,
			120*time.Second,
		)
	}
}

// sendHTTPError writes a minimal HTTP error response to conn.
func sendHTTPError(conn net.Conn, code int) {
	var status string
	switch code {
	case 400:
		status = "400 Bad Request"
	case 503:
		status = "503 Service Unavailable"
	default:
		status = "502 Bad Gateway"
	}
	_, _ = conn.Write([]byte("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\n\r\n"))
}
