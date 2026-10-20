// Package resolvertransport implements explicit encrypted DNS resolver hops.
// It changes only the client-to-recursive hop, never the CottenDNS wire protocol.
package resolvertransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cottendns-go/internal/dnsparser"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const ContentType = "application/dns-message"
const maxDNSMessage = 65535
const requestCancelled quic.StreamErrorCode = 3

type Options struct {
	TLSConfig        *tls.Config
	DoHPort          int
	DoHPath          string
	DoQPort          int
	HTTP3Fallback    bool // TLS DoH only; never falls back to plaintext DNS.
	PaddingBlockSize int
}

type doqSession struct {
	ready chan struct{}
	conn  *quic.Conn
	err   error
}

type Client struct {
	mode          string
	options       Options
	ctx           context.Context
	cancel        context.CancelFunc
	tlsHTTP       *http.Client
	h3HTTP        *http.Client
	h3            *http3.Transport
	mu            sync.Mutex
	closed        bool
	sessions      map[string]*doqSession
	h3Unavailable map[string]time.Time
}

func New(mode string, options Options) (*Client, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "doh" && mode != "doh3" && mode != "doq" {
		return nil, fmt.Errorf("unsupported encrypted resolver transport %q", mode)
	}
	if options.DoHPort == 0 {
		options.DoHPort = 443
	}
	if options.DoQPort == 0 {
		options.DoQPort = 853
	}
	if options.DoHPath == "" {
		options.DoHPath = "/dns-query"
	}
	if options.DoHPort < 1 || options.DoHPort > 65535 || options.DoQPort < 1 || options.DoQPort > 65535 {
		return nil, errors.New("invalid encrypted resolver port")
	}
	if !strings.HasPrefix(options.DoHPath, "/") || strings.ContainsAny(options.DoHPath, "\r\n#") {
		return nil, errors.New("invalid DoH path")
	}
	if options.PaddingBlockSize != 0 && (options.PaddingBlockSize < 16 || options.PaddingBlockSize > 4096) {
		return nil, errors.New("invalid DNS padding block size")
	}
	if options.TLSConfig == nil {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		options.TLSConfig = options.TLSConfig.Clone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{mode: mode, options: options, ctx: ctx, cancel: cancel, sessions: make(map[string]*doqSession), h3Unavailable: make(map[string]time.Time)}
	// Redirects are deliberately not followed: a resolver cannot redirect a DNS
	// POST to an unauthenticated endpoint or another hostname.
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	tr := &http.Transport{TLSClientConfig: options.TLSConfig.Clone(), ForceAttemptHTTP2: true, MaxIdleConns: 256, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 32, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 6 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableCompression: true, DialContext: (&net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	c.tlsHTTP = &http.Client{Transport: tr, CheckRedirect: noRedirect}
	if mode == "doh3" {
		tlsCfg := options.TLSConfig.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		c.h3 = &http3.Transport{TLSClientConfig: tlsCfg, QUICConfig: quicConfig(), DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
		c.h3HTTP = &http.Client{Transport: c.h3, CheckRedirect: noRedirect}
	}
	return c, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 6 * time.Second, MaxIdleTimeout: 90 * time.Second, MaxIncomingStreams: -1}
}

func endpoint(label string, port int) (string, error) {
	host, _, err := net.SplitHostPort(label)
	if err != nil {
		host = strings.Trim(strings.TrimSpace(label), "[]")
	}
	// Configured resolver IPs are the bootstrap path. Never perform an implicit
	// system-DNS lookup merely to establish an encrypted resolver connection.
	ipHost := host
	if i := strings.LastIndexByte(ipHost, '%'); i >= 0 {
		ipHost = ipHost[:i]
	}
	if net.ParseIP(ipHost) == nil {
		return "", fmt.Errorf("resolver must be a numeric IP address: %q", label)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (c *Client) Exchange(ctx context.Context, label string, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > maxDNSMessage || query[2]&0x80 != 0 {
		return nil, errors.New("invalid DNS query")
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	padded, err := dnsparser.PadEncryptedDNSQuery(query, c.options.PaddingBlockSize)
	if err != nil {
		return nil, err
	}
	if c.mode == "doq" {
		return c.exchangeDoQ(ctx, label, padded)
	}
	target, err := endpoint(label, c.options.DoHPort)
	if err != nil {
		return nil, err
	}
	url := "https://" + target + c.options.DoHPath
	if c.mode == "doh" {
		return ExchangeHTTP(ctx, c.tlsHTTP, url, padded)
	}
	c.mu.Lock()
	until := c.h3Unavailable[target]
	c.mu.Unlock()
	if !c.options.HTTP3Fallback || !time.Now().Before(until) {
		h3ctx := ctx
		h3cancel := func() {}
		if c.options.HTTP3Fallback {
			h3ctx, h3cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
		}
		answer, h3err := ExchangeHTTP(h3ctx, c.h3HTTP, url, padded)
		h3cancel()
		if h3err == nil {
			return answer, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !c.options.HTTP3Fallback {
			return nil, h3err
		}
		c.mu.Lock()
		c.h3Unavailable[target] = time.Now().Add(30 * time.Second)
		c.mu.Unlock()
	}
	return ExchangeHTTP(ctx, c.tlsHTTP, url, padded)
}

// ExchangeHTTP validates DNS media type, bounds, response flag and transaction
// ID as well as HTTPS. HTTP failures never become plaintext resolver requests.
func ExchangeHTTP(ctx context.Context, client *http.Client, url string, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > maxDNSMessage {
		return nil, errors.New("invalid DNS query")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" || req.URL.User != nil {
		return nil, errors.New("DoH requires an HTTPS endpoint")
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != ContentType {
		return nil, errors.New("invalid DoH response content type")
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, err
	}
	if len(answer) < 12 || len(answer) > maxDNSMessage || answer[2]&0x80 == 0 || !bytes.Equal(answer[:2], query[:2]) {
		return nil, errors.New("invalid or mismatched DoH DNS response")
	}
	return answer, nil
}

func (c *Client) doqConnection(ctx context.Context, target string) (*quic.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if s := c.sessions[target]; s != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ready:
		}
		if s.err != nil {
			return nil, s.err
		}
		if s.conn.Context().Err() == nil {
			return s.conn, nil
		}
		c.mu.Lock()
		if c.sessions[target] == s {
			delete(c.sessions, target)
		}
		c.mu.Unlock()
		return c.doqConnection(ctx, target)
	}
	s := &doqSession{ready: make(chan struct{})}
	c.sessions[target] = s
	c.mu.Unlock()
	cfg := c.options.TLSConfig.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{"doq"}
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = net.SplitHostPort(target)
	}
	qcfg := quicConfig()
	qcfg.MaxIncomingUniStreams = -1
	conn, err := quic.DialAddr(ctx, target, cfg, qcfg)
	c.mu.Lock()
	s.conn, s.err = conn, err
	if err != nil && c.sessions[target] == s {
		delete(c.sessions, target)
	}
	close(s.ready)
	closed := c.closed
	c.mu.Unlock()
	if closed && conn != nil {
		conn.CloseWithError(0, "")
		return nil, net.ErrClosed
	}
	return conn, err
}

func (c *Client) exchangeDoQ(ctx context.Context, label string, query []byte) ([]byte, error) {
	target, err := endpoint(label, c.options.DoQPort)
	if err != nil {
		return nil, err
	}
	conn, err := c.doqConnection(ctx, target)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(requestCancelled); stream.CancelWrite(requestCancelled) })
	defer stop()
	defer stream.CancelRead(requestCancelled)
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}
	// RFC 9250 requires ID=0 on the wire; the caller's original ID is restored
	// after validation so Soar and the normal tunnel retain exact correlation.
	wire := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(wire[:2], uint16(len(query)))
	copy(wire[2:], query)
	wire[2], wire[3] = 0, 0
	if _, err = io.Copy(stream, bytes.NewReader(wire)); err != nil {
		stream.CancelWrite(requestCancelled)
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err = io.ReadFull(stream, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 {
		conn.CloseWithError(2, "invalid DNS response")
		return nil, errors.New("short DoQ DNS response")
	}
	answer := make([]byte, n)
	if _, err = io.ReadFull(stream, answer); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, finErr := stream.Read(extra[:]); n != 0 || finErr != io.EOF {
		if ctx.Err() == nil {
			conn.CloseWithError(2, "invalid DNS stream termination")
		}
		return nil, errors.New("DoQ response missing FIN or contains multiple messages")
	}
	if answer[0] != 0 || answer[1] != 0 || answer[2]&0x80 == 0 {
		conn.CloseWithError(2, "invalid DNS response")
		return nil, errors.New("invalid DoQ response ID or flags")
	}
	copy(answer[:2], query[:2])
	return answer, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	sessions := make([]*quic.Conn, 0, len(c.sessions))
	for _, s := range c.sessions {
		if s.conn != nil {
			sessions = append(sessions, s.conn)
		}
	}
	c.mu.Unlock()
	for _, conn := range sessions {
		conn.CloseWithError(0, "")
	}
	c.tlsHTTP.CloseIdleConnections()
	if c.h3 != nil {
		return c.h3.Close()
	}
	return nil
}
