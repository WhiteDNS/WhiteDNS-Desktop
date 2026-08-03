// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_doh_coexist.go — decides how DoH shares the machine with a panel
// (3x-ui, Hiddify, a web server, ...). Only one process can bind :443, so there
// are two models:
//
//   model A "behind" — CottenDNS never touches :443. It serves cleartext
//                      HTTP/1.1 + h2c on DOH_BEHIND_PORT and the panel's own
//                      front (Xray fallback / nginx / Caddy) forwards the DoH
//                      route in. Because the panel still owns the handshake,
//                      every inbound it supports keeps working untouched —
//                      VMess/VLESS/Trojan, xhttp/gRPC/raw/ws/tls, CDN-fronted —
//                      and WireGuard is UDP so it is unaffected either way.
//
//   model B "front"  — CottenDNS owns :443, terminates TLS, serves DoH for our
//                      DOMAIN(s), and SNI-splices every other connection to
//                      DOH_SHARE_BACKEND untouched.
//
// DOH_COEXIST_MODE="auto" (the default) resolves to model A. That is deliberate:
// model A cannot disturb anything, while model B would opportunistically claim
// :443 and then a panel installed later would fail to bind it. Owning the port
// is therefore an explicit decision ("front"), never something that happens by
// default.
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// dohSupervisorBackoff throttles restarts after the serving loop returns.
const dohSupervisorBackoff = 5 * time.Second

// runDoHSupervisor owns the DoH listener for the process lifetime, re-resolving
// the coexistence model and restarting after a failure.
func (s *Server) runDoHSupervisor(ctx context.Context, tlsCfg *tls.Config) {
	for ctx.Err() == nil {
		preopened, tlsMode := s.resolveDoHPlan()

		host, port := s.cfg.DoHListenHost, s.cfg.DoHListenPort
		if !tlsMode {
			port = s.cfg.DoHBehindPort
		}
		err := s.serveDoH(ctx, host, port, tlsCfg, s.cfg.DoHPath, tlsMode, preopened)
		if err != nil && ctx.Err() == nil {
			s.log.Warnf("<yellow>DoH listener stopped: <cyan>%v</cyan></yellow>", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(dohSupervisorBackoff):
		}
	}
}

// resolveDoHPlan picks the model for this run. The second return value reports
// whether this listener terminates TLS itself (model B). A non-nil listener is
// one the resolver already bound, handed over so the port cannot be lost between
// deciding and serving.
func (s *Server) resolveDoHPlan() (net.Listener, bool) {
	if !s.dohFrontConfigured() {
		// auto (default) and behind: never bind the TLS port at all.
		return nil, false
	}
	// Explicit front mode: serveDoH binds the port and reports a clear error if
	// another process already holds it, rather than silently degrading.
	return nil, true
}

// dohFrontConfigured reports whether the operator explicitly asked DoH to own
// the TLS port. Only "front" qualifies — "auto" resolves to the safe model A.
func (s *Server) dohFrontConfigured() bool {
	return strings.EqualFold(strings.TrimSpace(s.cfg.DoHCoexistMode), "front")
}

// dohWillTerminateTLS reports whether the DoH listener itself terminates TLS.
// Used to decide if TLS material must be built for DoH and whether a TLS build
// failure should block it: in model A it never needs a certificate.
func (s *Server) dohWillTerminateTLS() bool {
	return s.cfg.DoHListenerEnabled && s.cfg.DoHTLSEnabled && s.dohFrontConfigured()
}
