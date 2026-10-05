// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// domain_rotation.go — server half of domain rotation: answers a client's
// PACKET_DOMAIN_LIST_REQ with the ADVERTISE_DOMAINS it can switch to when its
// configured domains get blocked.
// ==============================================================================

package udpserver

import (
	"math/rand/v2"
	"strings"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

// servedAdvertisedDomains keeps the advertised domains this server actually
// answers on: advertising one it does not serve would strand the client.
func servedAdvertisedDomains(served, advertised []string) []string {
	servedSet := make(map[string]struct{}, len(served))
	for _, d := range served {
		servedSet[normalizeAdvertisedDomain(d)] = struct{}{}
	}
	var out []string
	seen := make(map[string]struct{}, len(advertised))
	for _, d := range advertised {
		d = normalizeAdvertisedDomain(d)
		if _, ok := servedSet[d]; !ok || d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func normalizeAdvertisedDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// encodeDomainList packs as many domains as fit in budget bytes, in random
// order, so clients that can only take part of a long list still learn all of
// it over a few sessions.
func encodeDomainList(domains []string, budget int) []byte {
	order := rand.Perm(len(domains))
	var out []byte
	for _, i := range order {
		need := len(domains[i])
		if len(out) > 0 {
			need++ // separator
		}
		if len(out)+need > budget {
			continue
		}
		if len(out) > 0 {
			out = append(out, '\n')
		}
		out = append(out, domains[i]...)
	}
	return out
}

// handleDomainListRequest queues the reply on stream 0; the response to this
// same request usually carries it back. Nothing is queued when no domains are
// advertised, which looks the same to the client as an older server.
func (s *Server) handleDomainListRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || len(s.advertisedDomains) == 0 {
		return true
	}
	payload := encodeDomainList(s.advertisedDomains, sessionRecord.DownloadMTUBytes)
	if len(payload) == 0 {
		return true
	}
	return s.queueMainSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType: Enums.PACKET_DOMAIN_LIST_RES,
		Payload:    payload,
	})
}
