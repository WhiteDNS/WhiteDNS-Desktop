package udpserver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
)

// SetCottenMaxSecret supplies the existing shared credential before Run.
// It remains an access credential, never a session encryption key in max mode.
func (s *Server) SetCottenMaxSecret(secret string) { s.cottenMaxSecret = secret }

func (s *Server) startCottenMax(ctx context.Context) error {
	// Max is optional beside a legacy server. Keep the complete legacy domain
	// list untouched; only the Max adapter needs its stricter handshake budget.
	domains := make([]string, 0, len(s.cfg.Domain))
	for _, domain := range s.cfg.Domain {
		if err := cottenmax.ValidateServerDomain(domain); err != nil {
			if s.log != nil {
				s.log.Warnf("CottenMax skipped domain %q: %v; normal CottenDNS remains available", domain, err)
			}
			continue
		}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		if s.cfg.TunnelMode == config.TunnelCottenMax {
			return fmt.Errorf("cottenmax: no compatible configured domains; DOMAIN must leave enough DNS name capacity for the Max handshake")
		}
		if s.log != nil {
			s.log.Warnf("CottenMax disabled: no compatible tunnel domains; normal CottenDNS remains available")
		}
		return nil
	}
	key, err := cottenmax.SharedIdentity(s.cottenMaxSecret)
	// Explicit old experimental identities remain readable for migration.
	if strings.TrimSpace(s.cfg.CottenMaxKeyFile) != "" {
		key, err = cottenmax.LoadKey(s.cfg.CottenMaxKeyPath())
	}
	if err != nil {
		return err
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if strings.TrimSpace(s.cfg.CottenMaxKeyFile) != "" {
		if err := os.WriteFile(s.cfg.CottenMaxKeyPath()+".pub", []byte(pub+"\n"), 0o644); err != nil {
			return err
		}
	}
	s.cottenMax, err = cottenmax.NewServer(ctx, cottenmax.ServerConfig{
		Domains: domains, Key: key, Secret: s.cottenMaxSecret,
		MaxSessions: s.cfg.MaxActiveSessions, MaxStreams: min(s.cfg.MaxStreamsPerSession, s.cfg.CottenMaxMaxStreams, cottenmax.MaxStreamsLimit),
		Dial: s.dialCottenMaxTarget,
	})
	if err != nil {
		return err
	}
	if s.log != nil {
		s.log.Infof("CottenMax capacity: sessions=%d across %d domains, streams/session=%d", s.cfg.MaxActiveSessions, len(domains), min(s.cfg.MaxStreamsPerSession, s.cfg.CottenMaxMaxStreams, cottenmax.MaxStreamsLimit))
		if strings.TrimSpace(s.cfg.CottenMaxKeyFile) != "" {
			s.log.Warnf("CottenMax compatibility identity; optional server public key = %q", pub)
		} else {
			s.log.Infof("CottenMax available alongside normal CottenDNS using the existing credential")
		}
	}
	return nil
}

func (s *Server) dialCottenMaxTarget(ctx context.Context, target string) (net.Conn, error) {
	if target == cottenmax.DNSTarget {
		return s.cottenMaxDNSStream(), nil
	}
	if s.cfg.ProtocolType == "TCP" {
		if target != "forward:0" || s.cfg.ForwardIP == "" || s.cfg.ForwardPort <= 0 {
			return nil, fmt.Errorf("cottenmax: fixed forwarding target unavailable")
		}
		return s.dialTCPTargetContext(ctx, net.JoinHostPort(s.cfg.ForwardIP, strconv.Itoa(s.cfg.ForwardPort)))
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 || len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("cottenmax: invalid target")
	}
	payload := []byte{3, byte(len(host))}
	payload = append(payload, host...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(port))
	return s.dialSOCKSStreamTargetContext(ctx, host, uint16(port), payload)
}
