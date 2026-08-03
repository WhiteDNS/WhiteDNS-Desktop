// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_sni_router.go — lets the DoH endpoint share :443 with a co-hosted TLS
// service (Hiddify, 3x-ui, a web server, ...). Only one process can bind :443,
// so "sharing" means CottenDNS owns the port and peeks each new connection's TLS
// ClientHello SNI *without terminating TLS*:
//
//   - SNI matches one of our tunnel DOMAINs  -> hand the connection to our own
//     TLS/DoH server (it terminates TLS and answers DoH).
//   - anything else (or any parse failure)   -> splice the raw bytes, ClientHello
//     included, to the configured backend, which does its own TLS. The other
//     service therefore sees an untouched connection.
//
// The bias is deliberately fail-safe: we only keep a connection when its SNI
// positively matches us, so a ClientHello we cannot parse is forwarded to the
// backend rather than swallowed — CottenDNS never takes 443 away from the
// co-hosted service. The tunnel payload is AEAD-encrypted and this hop is TLS,
// so a sniffer on the wire sees only ordinary encrypted DNS/HTTPS.
// ==============================================================================

package udpserver

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const (
	sniPeekTimeout    = 5 * time.Second
	tlsRecordHdrLen   = 5
	tlsHandshakeType  = 0x16
	clientHelloType   = 0x01
	sniExtensionType  = 0x0000
	maxClientHelloRec = 16640 // one TLS record ceiling (16384 payload + slop)
	maxClientHelloAll = 65536 // bounded multi-record ClientHello ceiling
	passthroughDial   = 5 * time.Second
)

var errNoClientHelloSNI = errors.New("no SNI in TLS ClientHello")

// sniRoutingListener wraps the :443 listener and routes by SNI (see file header).
type sniRoutingListener struct {
	net.Listener
	matches       func(sni string) bool
	backend       string
	proxyProtocol bool
	server        *Server
}

func newSNIRoutingListener(inner net.Listener, matches func(string) bool, backend string, proxyProtocol bool, server *Server) *sniRoutingListener {
	return &sniRoutingListener{Listener: inner, matches: matches, backend: backend, proxyProtocol: proxyProtocol, server: server}
}

// Accept returns only connections destined for our DoH server; connections for
// the co-hosted backend are spliced away inside this loop and never surface to
// the caller (net/http).
func (l *sniRoutingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		sni, buffered, perr := peekClientHelloSNI(conn)
		// prefixConn replays the bytes we consumed while peeking, so whoever
		// handles the connection next (our TLS server or the backend) still sees
		// a complete, untouched ClientHello.
		replayed := &prefixConn{Conn: conn, prefix: buffered}
		if perr == nil && l.matches(sni) {
			return replayed, nil
		}
		go l.passthrough(replayed, sni)
	}
}

// passthrough splices a non-matching connection to the co-hosted backend. The
// backend terminates its own TLS; we only shuttle bytes.
func (l *sniRoutingListener) passthrough(conn net.Conn, sni string) {
	defer conn.Close()
	if l.server != nil {
		l.server.sniPassthroughActive.Add(1)
		defer l.server.sniPassthroughActive.Add(^uint64(0))
	}
	back, err := net.DialTimeout("tcp", l.backend, passthroughDial)
	if err != nil {
		if l.server != nil {
			l.server.sniPassthroughFailures.Add(1)
			l.server.log.Debugf("SNI passthrough to %s failed (sni=%q): %v", l.backend, sni, err)
		}
		return
	}
	defer back.Close()
	if l.proxyProtocol {
		if _, err := io.WriteString(back, proxyV1Header(conn.RemoteAddr(), conn.LocalAddr())); err != nil {
			if l.server != nil {
				l.server.sniPassthroughFailures.Add(1)
			}
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(back, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, back); done <- struct{}{} }()
	<-done // return as soon as either half closes; defers tear the other down
}

// prefixConn is a net.Conn whose Read first drains a buffer of already-consumed
// bytes (the peeked ClientHello) before reading from the underlying connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// peekClientHelloSNI reads the bounded sequence of TLS records containing the ClientHello into a
// buffer and extracts the SNI. It always returns every byte it consumed so the
// caller can replay them, even on error. A read deadline bounds a slow-loris
// peek; it is cleared before returning so it does not leak into later I/O.
func peekClientHelloSNI(conn net.Conn) (sni string, buffered []byte, err error) {
	_ = conn.SetReadDeadline(time.Now().Add(sniPeekTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	handshake := make([]byte, 0, maxClientHelloRec)
	for len(buffered) < maxClientHelloAll {
		hdr := make([]byte, tlsRecordHdrLen)
		if n, rerr := io.ReadFull(conn, hdr); rerr != nil {
			buffered = append(buffered, hdr[:n]...)
			return "", buffered, rerr
		}
		buffered = append(buffered, hdr...)
		if hdr[0] != tlsHandshakeType {
			return "", buffered, errNoClientHelloSNI
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen < 1 || recLen > maxClientHelloRec || len(buffered)+recLen > maxClientHelloAll {
			return "", buffered, errNoClientHelloSNI
		}
		body := make([]byte, recLen)
		n, rerr := io.ReadFull(conn, body)
		buffered = append(buffered, body[:n]...)
		handshake = append(handshake, body[:n]...)
		if rerr != nil {
			return "", buffered, rerr
		}
		if len(handshake) < 4 {
			continue
		}
		hsLen := 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
		if hsLen < 4 || hsLen > maxClientHelloAll {
			return "", buffered, errNoClientHelloSNI
		}
		if len(handshake) >= hsLen {
			sni, perr := parseClientHelloSNI(handshake[:hsLen])
			return sni, buffered, perr
		}
	}
	return "", buffered, errNoClientHelloSNI
}

func proxyV1Header(source, destination net.Addr) string {
	if source == nil || destination == nil {
		return "PROXY UNKNOWN\r\n"
	}
	srcHost, srcPort, srcErr := net.SplitHostPort(source.String())
	dstHost, dstPort, dstErr := net.SplitHostPort(destination.String())
	if srcErr != nil || dstErr != nil {
		return "PROXY UNKNOWN\r\n"
	}
	proto := "TCP6"
	if ip := net.ParseIP(srcHost); ip != nil && ip.To4() != nil {
		proto = "TCP4"
	}
	return "PROXY " + proto + " " + srcHost + " " + dstHost + " " + srcPort + " " + dstPort + "\r\n"
}

// parseClientHelloSNI walks a TLS 1.x ClientHello handshake message (without the
// 5-byte record header) and returns the first host_name SNI. Every field length
// is bounds-checked so a malformed or hostile ClientHello returns an error
// instead of panicking.
func parseClientHelloSNI(b []byte) (string, error) {
	if len(b) < 4 || b[0] != clientHelloType {
		return "", errNoClientHelloSNI
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if hsLen < len(b) {
		b = b[:hsLen] // ignore trailing records; tolerate a truncated tail
	}

	// client_version(2) + random(32)
	if len(b) < 34 {
		return "", errNoClientHelloSNI
	}
	b = b[34:]

	// legacy_session_id
	sid, rest, ok := takeVector8(b)
	if !ok {
		return "", errNoClientHelloSNI
	}
	_ = sid
	b = rest

	// cipher_suites (uint16 length)
	_, b, ok = takeVector16(b)
	if !ok {
		return "", errNoClientHelloSNI
	}
	// legacy_compression_methods (uint8 length)
	_, b, ok = takeVector8(b)
	if !ok {
		return "", errNoClientHelloSNI
	}
	// extensions (uint16 length)
	ext, _, ok := takeVector16(b)
	if !ok {
		return "", errNoClientHelloSNI
	}

	for len(ext) >= 4 {
		extType := binary.BigEndian.Uint16(ext)
		extLen := int(binary.BigEndian.Uint16(ext[2:]))
		ext = ext[4:]
		if extLen > len(ext) {
			return "", errNoClientHelloSNI
		}
		payload := ext[:extLen]
		ext = ext[extLen:]
		if extType != sniExtensionType {
			continue
		}
		// server_name_list (uint16 length), then entries: type(1) + name(uint16).
		list, _, ok := takeVector16(payload)
		if !ok {
			return "", errNoClientHelloSNI
		}
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:]))
			list = list[3:]
			if nameLen > len(list) {
				return "", errNoClientHelloSNI
			}
			name := list[:nameLen]
			list = list[nameLen:]
			if nameType == 0 { // host_name
				return string(name), nil
			}
		}
		return "", errNoClientHelloSNI
	}
	return "", errNoClientHelloSNI
}

// takeVector8 splits a uint8-length-prefixed vector: returns (value, remainder, ok).
func takeVector8(b []byte) ([]byte, []byte, bool) {
	if len(b) < 1 {
		return nil, nil, false
	}
	n := int(b[0])
	if 1+n > len(b) {
		return nil, nil, false
	}
	return b[1 : 1+n], b[1+n:], true
}

// takeVector16 splits a uint16-length-prefixed vector: returns (value, remainder, ok).
func takeVector16(b []byte) ([]byte, []byte, bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if 2+n > len(b) {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// tlsSNIMatcher returns a matcher that accepts an SNI equal (case-insensitively)
// to any configured tunnel domain. Exact match only: the tunnel uses specific
// authoritative names, so wildcards or suffix matches would wrongly capture the
// co-hosted service's own hostnames.
func tlsSNIMatcher(domains []string) func(string) bool {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d != "" {
			set[d] = struct{}{}
		}
	}
	return func(sni string) bool {
		if sni == "" {
			return false
		}
		_, ok := set[strings.ToLower(strings.TrimSuffix(sni, "."))]
		return ok
	}
}
