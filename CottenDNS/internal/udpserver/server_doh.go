// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_doh.go — DNS-over-HTTPS listener (RFC 8484). A DoH request carries a
// raw DNS wire-format message in an HTTP/2 request body (POST) or a base64url
// query parameter (GET); the response body is the raw DNS wire-format answer.
// The handler decodes the message, runs it through the exact same transport-
// agnostic packet handler (safeHandlePacket) as UDP/TCP/DoT, and writes the
// answer back — so DoH adds an HTTP framing shell and nothing else. Everything
// that is not the configured DoH path 404s, so the surface looks like a plain
// resolver endpoint rather than an open web server.
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	dohContentType          = "application/dns-message"
	dohMaxMessageSize       = 65535 // a DNS message length is a uint16
	dohRequestTimeout       = 20 * time.Second
	dohMaxConcurrentStreams = 256 // per-connection HTTP/2 stream cap
)

var errNoTLSConfig = errors.New("encrypted-DNS listener requires a TLS config")

// serveDoH runs the DNS-over-HTTPS listener until ctx is cancelled. It has two
// coexistence modes (see DoHTLSEnabled):
//
//   - TLS mode: CottenDNS terminates TLS itself (HTTP/2 over TLS). With
//     DOH_SHARE_BACKEND it owns 443 and SNI-routes non-matching connections to a
//     co-hosted service.
//   - behind-proxy mode: CottenDNS serves plaintext HTTP/1.1 + h2c on a local
//     port; the panel's own front (Xray fallback / nginx / Caddy) keeps 443,
//     terminates TLS, and forwards the DoH route here. This is the universal way
//     to coexist with the full inbound zoo (VMess/VLESS/Trojan/xhttp/gRPC/ws/tls,
//     CDN-fronted, WireGuard-UDP), since the panel's front handles all of it.
//
// A bounded concurrency gate mirrors the UDP/TCP ingress hardening so a request
// flood cannot spawn unbounded work.
// tlsMode selects which coexistence model is active for this run (see
// resolveDoHPlan): true = model B (we terminate TLS on the shared port), false =
// model A (a panel owns 443, we serve cleartext h2c behind it). preopened, when
// non-nil, is a listener the caller already bound while probing the port — it is
// used as-is so the port cannot be lost in the gap between probe and serve.
func (s *Server) serveDoH(ctx context.Context, host string, port int, tlsCfg *tls.Config, path string, tlsMode bool, preopened net.Listener) error {
	if path == "" {
		path = "/dns-query"
	}

	maxInflight := s.cfg.DoHMaxInflight
	if maxInflight < 1 {
		maxInflight = 256
	}
	gate := make(chan struct{}, maxInflight)
	bodyLimit := s.cfg.MaxPacketSize
	if bodyLimit < 12 || bodyLimit > dohMaxMessageSize {
		bodyLimit = min(4096, dohMaxMessageSize)
	}
	byteGate := &dohByteGate{max: int64(s.cfg.DoHMaxInflightBytes)}
	if byteGate.max < int64(bodyLimit) {
		byteGate.max = int64(bodyLimit)
	}
	rateLimiter := newDoHRateLimiter(s.cfg.DoHRequestsPerSecond, s.cfg.DoHRequestBurst)
	trustedProxies := newTrustedProxySet(s.cfg.DoHTrustedProxyCIDRs)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.allow(dohRequestClientIP(r, trustedProxies), time.Now()) {
			s.dohRequestRejected.Add(1)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			s.dohRequestRejected.Add(1)
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		reservation := int64(bodyLimit)
		if !byteGate.reserve(reservation) {
			s.dohRequestRejected.Add(1)
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		defer byteGate.release(reservation)
		s.handleDoHRequest(w, r, bodyLimit)
	})

	raw := preopened
	if raw == nil {
		listened, err := net.Listen("tcp", net.JoinHostPort(host, itoaPort(port)))
		if err != nil {
			return err
		}
		raw = listened
	}

	// Flood protection to match the TCP/DoT accept loop: cap total and per-IP
	// connections. Over-limit connections are dropped, not queued.
	perIPConnections := s.cfg.TCPMaxConnsPerIP
	if len(s.cfg.DoHTrustedProxyCIDRs) > 0 {
		// The HTTP request limiter uses the trusted forwarded client address. A
		// connection-level per-IP cap here would otherwise treat every user as the
		// proxy itself and impose one shared 128-connection ceiling.
		perIPConnections = 0
	}
	var ln net.Listener = newLimitedListenerWithBudget(raw, s.encryptedConnBudget, s.cfg.TCPMaxConns, perIPConnections).
		withRejectCallback(func() { s.encryptedConnRejected.Add(1) })
	s.dohListenerUp.Store(1)
	defer s.dohListenerUp.Store(0)

	srv := &http.Server{
		Handler:           mux,
		ReadTimeout:       dohRequestTimeout,
		WriteTimeout:      dohRequestTimeout,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	h2 := &http2.Server{MaxConcurrentStreams: dohMaxConcurrentStreams, IdleTimeout: 60 * time.Second}

	// Behind-proxy mode: no TLS here, the front already terminated it. Serve
	// HTTP/1.1 and h2c (cleartext HTTP/2) so a gRPC/HTTP2 fallback works too. No
	// SNI routing — the panel's front owns 443 and decides what reaches us.
	if !tlsMode {
		srv.Handler = h2c.NewHandler(mux, h2)
		s.log.Infof(
			"\U0001F4E1 <green>DoH Listener Ready (behind-proxy, cleartext h2c), Addr: <cyan>%s</cyan>, Path: <cyan>%s</cyan></green>",
			raw.Addr().String(), path,
		)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	// TLS mode.
	if tlsCfg == nil {
		return errNoTLSConfig
	}
	srv.TLSConfig = tlsCfg
	if err := http2.ConfigureServer(srv, h2); err != nil {
		return err
	}

	// Optional :443 sharing: SNI-route non-matching connections to a co-hosted
	// service so it keeps working on the same port.
	shareNote := ""
	if s.cfg.DoHShareBackend != "" {
		ln = newSNIRoutingListener(ln, tlsSNIMatcher(s.cfg.Domain), s.cfg.DoHShareBackend, s.cfg.DoHShareProxyProtocol, s)
		shareNote = ", Shared-With: " + s.cfg.DoHShareBackend
	}

	s.log.Infof(
		"\U0001F4E1 <green>DoH Listener Ready, Addr: <cyan>%s</cyan>, Path: <cyan>%s</cyan>%s</green>",
		raw.Addr().String(), path, shareNote,
	)

	// ServeTLS keeps net/http's native *tls.Conn path, including HTTP/2 ALPN.
	// Certificate acquisition failures are counted by buildStreamTLSConfig.
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handleDoHRequest extracts the DNS wire-format query from a POST body or a GET
// ?dns= parameter, runs it through the shared tunnel handler, and writes the
// wire-format answer. It is deliberately strict about size and content type so a
// malformed or oversized request is cheap to reject.
func (s *Server) handleDoHRequest(w http.ResponseWriter, r *http.Request, maxMessageSize int) {
	query, status := decodeDoHQueryLimit(r, maxMessageSize)
	if status != http.StatusOK {
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", "GET, POST")
		}
		http.Error(w, http.StatusText(status), status)
		return
	}

	response := s.safeHandlePacket(query)
	if len(response) == 0 {
		// No tunnel answer (e.g. a keepalive or an unrecognized query). Signal a
		// transient upstream failure so the client falls back rather than caching.
		http.Error(w, "no answer", http.StatusBadGateway)
		return
	}
	if len(response) > dohMaxMessageSize {
		response = response[:dohMaxMessageSize]
	}

	w.Header().Set("Content-Type", dohContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// decodeDoHQuery pulls the DNS wire-format message out of a DoH request. It
// returns the query and http.StatusOK on success, or an empty query and the
// HTTP status to reject with. Split out from handleDoHRequest so the parsing
// rules (method, content type, base64url, size) are unit-testable without a
// live TLS server or the tunnel handler.
func decodeDoHQuery(r *http.Request) ([]byte, int) {
	return decodeDoHQueryLimit(r, dohMaxMessageSize)
}

func decodeDoHQueryLimit(r *http.Request, maxMessageSize int) ([]byte, int) {
	if maxMessageSize < 12 || maxMessageSize > dohMaxMessageSize {
		maxMessageSize = dohMaxMessageSize
	}
	var (
		query []byte
		err   error
	)
	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != dohContentType {
			return nil, http.StatusUnsupportedMediaType
		}
		query, err = io.ReadAll(io.LimitReader(r.Body, int64(maxMessageSize)+1))
	case http.MethodGet:
		// RFC 8484 §4.1: unpadded base64url of the wire-format message.
		query, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	default:
		return nil, http.StatusMethodNotAllowed
	}

	if err != nil || len(query) < 12 || len(query) > maxMessageSize {
		return nil, http.StatusBadRequest
	}
	return query, http.StatusOK
}
