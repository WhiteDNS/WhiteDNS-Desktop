package main

import (
	"embed"
	"net"
	"net/netip"
	"strings"
)

// Snapshots from pinned Soar v0.2.3. The Android build verifies their bytes
// against that module. See data/THIRD_PARTY.md for provenance and licensing.
//
//go:embed data/resolvers/*.txt
var resolverSeeds embed.FS

func normalizedResolver(raw string) (string, bool) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		return net.JoinHostPort(ip.String(), "53"), true
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil && ap.Port() != 0 {
		return ap.String(), true
	}
	return "", false
}

func (c config) resolverPlan(configured []string) (initial, candidates []string) {
	if !c.Soar.Discovery {
		return configured, nil // A manual-only profile must remain manual-only.
	}
	seen := make(map[string]bool)
	var all []string
	for _, raw := range append(append([]string{}, c.SystemResolvers...), configured...) {
		if resolver, ok := normalizedResolver(raw); ok && !seen[resolver] {
			seen[resolver] = true
			all = append(all, resolver)
		}
	}
	if len(all) <= 8 {
		return all, nil // Upstream discovery supplies country/global candidates.
	}
	initial = all[:8]
	seen = make(map[string]bool)
	for _, resolver := range initial {
		seen[resolver] = true
	}
	add := func(raw string) {
		if resolver, ok := normalizedResolver(strings.TrimSpace(raw)); ok && !seen[resolver] {
			seen[resolver] = true
			candidates = append(candidates, resolver)
		}
	}
	// Avoid placing thousands of untested extras before the targeted country
	// and global lists, which would delay recovery on restricted networks.
	for _, country := range []string{strings.ToLower(c.Soar.Country), "global"} {
		if data, err := resolverSeeds.ReadFile("data/resolvers/" + country + ".txt"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				add(line)
			}
		}
	}
	for _, resolver := range all[8:] {
		add(resolver)
	}
	return initial, candidates
}
