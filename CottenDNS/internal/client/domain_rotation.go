// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// domain_rotation.go — keeps a client connected when its tunnel domains get
// blocked.
//
//   - Standby domains (STANDBY_DOMAINS, plus any the server advertised) are
//     never queried while the active domains work, so a firewall watching
//     traffic cannot block them in advance.
//   - After consecutive full scans find no working path, the next standby
//     domain becomes the only active one and the failed ones go to the back of
//     the standby list, so the client cycles instead of getting stuck.
//   - Once per session the client asks the server for its ADVERTISE_DOMAINS
//     and saves the new ones next to the config (one file per server key), so
//     users learn replacement domains while any domain still works.
// ==============================================================================

package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cottendns-go/internal/config"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	// One failed scan can be a network blip; switching shows a standby domain
	// to the firewall, so it takes two in a row.
	standbyPromoteAfterFailedScans = 2
	maxStandbyDomains              = 32
	domainListRetryAfter           = 30 * time.Second
)

// initDomainRotation loads the standby list: configured first, then learned.
func (c *Client) initDomainRotation() {
	standby := append([]string(nil), c.cfg.StandbyDomains...)
	if raw, err := os.ReadFile(c.learnedDomainsPath()); err == nil {
		standby = config.AppendNewDomains(standby, strings.Split(string(raw), "\n"), c.cfg.Domains)
	}
	c.standbyDomains = capDomains(standby)
}

// learnedDomainsPath is per server key, so domains learned from one server
// are never tried against another profile's server.
func (c *Client) learnedDomainsPath() string {
	sum := sha256.Sum256([]byte(c.cfg.EncryptionKey))
	return filepath.Join(c.cfg.ConfigDir, "learned_domains_"+hex.EncodeToString(sum[:6])+".txt")
}

// rotateDomainsAfterFailedScan is called when a full MTU scan found no working
// path. It reports whether the active domains were switched, in which case the
// caller should rescan immediately.
func (c *Client) rotateDomainsAfterFailedScan() bool {
	c.failedFullScans++
	if c.failedFullScans < standbyPromoteAfterFailedScans {
		return false
	}

	c.domainsMu.Lock()
	if len(c.standbyDomains) == 0 {
		c.domainsMu.Unlock()
		return false
	}
	next := c.standbyDomains[0]
	retired := c.cfg.Domains
	c.standbyDomains = capDomains(config.AppendNewDomains(c.standbyDomains[1:], retired, []string{next}))
	c.cfg.Domains = []string{next}
	left := len(c.standbyDomains)
	c.domainsMu.Unlock()

	c.failedFullScans = 0
	c.connectionsHavePreknownMTU = false
	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>Domain rotation to %s failed: %v</red>", next, err)
		}
		return false
	}
	if c.log != nil {
		c.log.Warnf(
			"\U0001F504 <yellow>No working path over %s; switching to standby domain <cyan>%s</cyan> (%d more in rotation)</yellow>",
			strings.Join(retired, ", "), next, left,
		)
	}
	return true
}

// failedScanRetryDelay rotates domains if due and returns how long to wait
// before the next scan: none after a switch, the usual 5s otherwise.
func (c *Client) failedScanRetryDelay() time.Duration {
	if c.rotateDomainsAfterFailedScan() {
		return 0
	}
	return 5 * time.Second
}

// requestDomainList asks the server for its advertised domains, once more
// after a while if the first reply was lost. Old servers never answer.
func (c *Client) requestDomainList(ctx context.Context) {
	if c.cfg.LegacySessionID {
		return // MasterDNS/StormDNS servers do not know the packet type
	}
	c.domainListAnswered.Store(false)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 && !sleepCtx(ctx, domainListRetryAfter) {
				return
			}
			if c.domainListAnswered.Load() || !c.SessionReady() {
				return
			}
			c.streamsMu.RLock()
			s0 := c.active_streams[0]
			c.streamsMu.RUnlock()
			payload, err := buildClientPingPayload() // random bytes keep the query name uncached
			if s0 == nil || err != nil {
				return
			}
			s0.PushTXPacket(
				Enums.DefaultPacketPriority(Enums.PACKET_DOMAIN_LIST_REQ),
				Enums.PACKET_DOMAIN_LIST_REQ, 0, 0, 0, 0, 0, payload,
			)
		}
	}()
}

// HandleDomainListRes adds the server's advertised domains to the standby
// list and saves them for the next start.
func (c *Client) HandleDomainListRes(packet VpnProto.Packet) error {
	c.domainListAnswered.Store(true)
	var valid []string
	for _, d := range strings.Split(string(packet.Payload), "\n") {
		if _, err := prepareTunnelDomain(d); err == nil && strings.Contains(d, ".") {
			valid = append(valid, d)
		}
	}

	c.domainsMu.Lock()
	before := len(c.standbyDomains)
	c.standbyDomains = capDomains(config.AppendNewDomains(c.standbyDomains, valid, c.cfg.Domains))
	added := len(c.standbyDomains) - before
	snapshot := strings.Join(c.standbyDomains, "\n")
	c.domainsMu.Unlock()

	if added <= 0 {
		return nil
	}
	if err := os.WriteFile(c.learnedDomainsPath(), []byte(snapshot+"\n"), 0o600); err != nil && c.log != nil {
		c.log.Debugf("Could not save learned domains: %v", err)
	}
	if c.log != nil {
		c.log.Infof("\U0001F4E5 <green>Learned %d standby domain(s) from the server</green>", added)
	}
	return nil
}

func capDomains(domains []string) []string {
	if len(domains) > maxStandbyDomains {
		return domains[:maxStandbyDomains]
	}
	return domains
}
