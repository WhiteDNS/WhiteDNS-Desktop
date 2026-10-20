package client

import (
	"cottendns-go/internal/config"
	"net"
	"strconv"
)

const (
	clientPhaseStarting int32 = iota
	clientPhaseDiscovering
	clientPhaseConnecting
	clientPhaseConnected
	clientPhaseRecovering
	clientPhaseStopped
)

// StatusSnapshot is a race-safe, presentation-neutral view of the live client.
// It lets terminal and desktop frontends render status without scraping logs.
type StatusSnapshot struct {
	TunnelMode          string
	Phase               string
	Transport           string
	FamilyMode          string
	ProxyAddress        string
	LocalDNSAddress     string
	LocalDNSEnabled     bool
	ConfiguredResolvers int
	ConfiguredIPv4      int
	ConfiguredIPv6      int
	ActiveResolvers     int
	ActiveIPv4          int
	ActiveIPv6          int
	UploadMTU           int
	DownloadMTU         int
	ActiveStreams       int
	TXBytes             uint64
	RXBytes             uint64
	LossPerMille        uint64
	RXDrops             uint64
	TXDrops             uint64
	Recoveries          uint64
	StreamDialFailures  uint64
	StreamWriteFailures uint64
	TXQueue             int
	EncodedQueue        int
	RXQueue             int
}

func (c *Client) TerminalUIMode() string {
	if c == nil {
		return "plain"
	}
	return c.cfg.TerminalUI
}

func (c *Client) StatusSnapshot() StatusSnapshot {
	if c == nil {
		return StatusSnapshot{Phase: "stopped"}
	}
	s := StatusSnapshot{
		TunnelMode:          c.cfg.TunnelMode,
		Phase:               clientPhaseName(c.runtimePhase.Load()),
		Transport:           c.activeTransport().String(),
		FamilyMode:          c.cfg.ResolverIPMode,
		ProxyAddress:        net.JoinHostPort(c.cfg.ListenIP, strconv.Itoa(c.cfg.ListenPort)),
		LocalDNSEnabled:     c.cfg.LocalDNSEnabled,
		ConfiguredResolvers: len(c.cfg.Resolvers),
		TXBytes:             c.txTotalBytes.Load(),
		RXBytes:             c.rxTotalBytes.Load(),
		LossPerMille:        c.tunnelLossPerMille(),
		RXDrops:             c.rxDroppedPackets.Load(),
		TXDrops:             c.txAdmissionDrops.Load(),
		Recoveries:          c.transportRecoveryCount.Load(),
		StreamDialFailures:  c.streamDialFailures.Load(),
		StreamWriteFailures: c.streamWriteFailures.Load(),
	}
	if c.ipv6FallbackActive.Load() {
		s.FamilyMode = "auto → ipv6 fallback"
	}
	if c.cfg.LocalDNSEnabled {
		s.LocalDNSAddress = net.JoinHostPort(c.cfg.LocalDNSIP, strconv.Itoa(c.cfg.LocalDNSPort))
	}
	for _, resolver := range c.cfg.Resolvers {
		if resolverAddressIsIPv6(resolver.IP) {
			s.ConfiguredIPv6++
		} else {
			s.ConfiguredIPv4++
		}
	}
	if c.balancer != nil {
		active := c.balancer.GetAllValidConnections()
		s.ActiveResolvers = len(active)
		for _, conn := range active {
			if resolverAddressIsIPv6(conn.Resolver) {
				s.ActiveIPv6++
			} else {
				s.ActiveIPv4++
			}
		}
	}
	s.UploadMTU = int(c.statusUploadMTU.Load())
	s.DownloadMTU = int(c.statusDownloadMTU.Load())
	c.streamsMu.RLock()
	s.ActiveStreams = len(c.active_streams)
	c.streamsMu.RUnlock()
	if c.txChannel != nil {
		s.TXQueue = len(c.txChannel)
	}
	if c.encodedTXChannel != nil {
		s.EncodedQueue = len(c.encodedTXChannel)
	}
	if c.rxChannel != nil {
		s.RXQueue = len(c.rxChannel)
	}
	if c.cfg.TunnelMode == config.TunnelCottenMax {
		s.Transport = "cottenmax/" + c.cfg.ResolverTransport
		s.ActiveStreams = int(c.cottenMaxStreams.Load())
		s.ActiveResolvers, s.ActiveIPv4, s.ActiveIPv6 = 0, 0, 0
		if engine := c.cottenMax.Load(); engine != nil {
			if s.Phase != "stopped" && !engine.Established() {
				s.Phase = "connecting"
			}
			var loss float64
			for _, p := range engine.PathStats() {
				if !p.Verified || p.Suspended {
					continue
				}
				s.ActiveResolvers++
				loss += p.Loss
				host, _, _ := net.SplitHostPort(p.Resolver)
				if resolverAddressIsIPv6(host) {
					s.ActiveIPv6++
				} else {
					s.ActiveIPv4++
				}
			}
			if s.ActiveResolvers > 0 {
				s.LossPerMille = uint64(1000 * loss / float64(s.ActiveResolvers))
			}
		}
	}
	return s
}

func clientPhaseName(phase int32) string {
	switch phase {
	case clientPhaseDiscovering:
		return "discovering resolvers"
	case clientPhaseConnecting:
		return "connecting"
	case clientPhaseConnected:
		return "connected"
	case clientPhaseRecovering:
		return "recovering"
	case clientPhaseStopped:
		return "stopped"
	default:
		return "starting"
	}
}
