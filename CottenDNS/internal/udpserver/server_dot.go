// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_dot.go — DNS-over-TLS listener (RFC 7858). DoT is byte-for-byte the
// same 2-byte length-prefixed DNS framing as DNS-over-TCP/53, only wrapped in
// TLS, so it reuses the exact accept loop and packet handler as the TCP listener
// (serveDNSOverStream). This keeps all tunnel logic in one place: DoT is just
// "TCP/53 in a TLS coat" as far as the server is concerned.
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/tls"
	"net"
)

// serveDoT runs the DNS-over-TLS listener until ctx is cancelled. It layers TLS
// over a plain TCP listener and hands the resulting connections to the shared
// stream accept loop, so per-IP limits, framing, and load-shedding are identical
// to TCP/53.
func (s *Server) serveDoT(ctx context.Context, host string, port int, tlsCfg *tls.Config) error {
	if tlsCfg == nil {
		return errNoTLSConfig
	}
	raw, err := net.Listen("tcp", net.JoinHostPort(host, itoaPort(port)))
	if err != nil {
		return err
	}
	s.dotListenerUp.Store(1)
	defer s.dotListenerUp.Store(0)
	limited := newLimitedListenerWithBudget(raw, s.encryptedConnBudget, s.cfg.TCPMaxConns, s.cfg.TCPMaxConnsPerIP).
		withRejectCallback(func() { s.encryptedConnRejected.Add(1) })
	return s.serveDNSOverStream(ctx, newTLSMetricListener(limited, tlsCfg, &s.tlsHandshakeFailures), "DoT")
}
