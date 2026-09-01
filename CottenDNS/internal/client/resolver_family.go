package client

import (
	"net/netip"
	"strings"
)

// resolverAddressIsIPv6 classifies resolver literals, including scoped IPv6
// addresses such as fe80::1%eth0. net.ParseIP deliberately rejects zone
// identifiers, even though net.ResolveUDPAddr accepts and needs them.
func resolverAddressIsIPv6(host string) bool {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().Is6()
}

func resolverIsIPv6(conn Connection) bool {
	return resolverAddressIsIPv6(conn.Resolver)
}

// resolverConnectionsForOperatingPoint returns the family pool that can
// actually carry the next session. Keeping MTU selection aligned with routing
// prevents a faster secondary family from negotiating packets too large for
// the preferred family. Dual mode intentionally retains the combined pool.
func (c *Client) resolverConnectionsForOperatingPoint(conns []Connection) []Connection {
	if c == nil || len(conns) == 0 || c.cfg.ResolverIPMode == "dual" {
		return conns
	}
	v4 := make([]Connection, 0, len(conns))
	v6 := make([]Connection, 0, len(conns))
	for _, conn := range conns {
		if resolverIsIPv6(conn) {
			v6 = append(v6, conn)
		} else {
			v4 = append(v4, conn)
		}
	}
	switch c.cfg.ResolverIPMode {
	case "ipv4":
		return v4
	case "ipv6":
		return v6
	case "auto":
		if c.ipv6FallbackActive.Load() {
			return v6
		}
		if len(v4) > 0 {
			return v4
		}
		return v6
	default:
		return conns
	}
}

// rotateResolverFamilyAfterSessionFailure handles the case where MTU probes
// succeeded over IPv4 but complete session setup is filtered. Auto mode first
// gives the configured IPv6 pool a full session attempt; if that also fails it
// returns to IPv4 rather than becoming stuck on either family.
func (c *Client) rotateResolverFamilyAfterSessionFailure() bool {
	if c == nil || c.cfg.ResolverIPMode != "auto" || c.balancer == nil {
		return false
	}
	has4, has6 := false, false
	for _, conn := range c.balancer.AllValidConnectionsIncludingBackup() {
		if !conn.IsValid {
			continue
		}
		if resolverIsIPv6(conn) {
			has6 = true
		} else {
			has4 = true
		}
	}
	if !c.ipv6FallbackActive.Load() {
		if !has6 {
			return false
		}
		c.ipv6FallbackActive.Store(true)
		c.balancer.SetFamilyMode("ipv6")
		if c.log != nil {
			c.log.Warnf("<yellow>IPv4 session setup failed; activating IPv6 resolver fallback</yellow>")
		}
		return true
	}
	if !has4 {
		return false
	}
	c.ipv6FallbackActive.Store(false)
	c.balancer.SetFamilyMode("auto")
	if c.log != nil {
		c.log.Warnf("<yellow>IPv6 fallback setup failed; returning to IPv4 preference</yellow>")
	}
	return true
}

func (c *Client) restoreConfiguredResolverFamilyMode() {
	if c == nil || c.balancer == nil {
		return
	}
	c.ipv6FallbackActive.Store(false)
	c.balancer.SetFamilyMode(c.cfg.ResolverIPMode)
}
