package client

import (
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func (c *Client) encryptedDownstream() bool {
	return c != nil && !c.cfg.LegacySessionID && c.codec != nil && c.codec.Method() != 0
}

func (c *Client) configuredResponseMode() uint8 {
	var mode uint8
	if c.cfg.BaseEncodeData {
		mode = mtuProbeBase64Reply
	}
	if c.encryptedDownstream() {
		mode |= security.DownstreamEncryptedFlag
	}
	return mode
}

func (c *Client) extractVPNResponse(data []byte, base64 bool) (VpnProto.Packet, error) {
	if c.encryptedDownstream() {
		return DnsParser.ExtractEncryptedVPNResponseMatching(data, base64, c.cfg.Domains, c.codec)
	}
	return DnsParser.ExtractVPNResponseMatching(data, base64, c.cfg.Domains)
}

// Reject stale/cross-session traffic before ACK generation, resolver scoring or
// stream dispatch. ERROR_DROP deliberately has no cookie for unknown sessions.
func (c *Client) acceptsSessionResponse(packet VpnProto.Packet) bool {
	if !c.sessionReady || packet.LegacySessionID != c.cfg.LegacySessionID || packet.SessionID != c.sessionID {
		return false
	}
	if packet.PacketType == Enums.PACKET_ERROR_DROP {
		return true
	}
	return packet.SessionCookie == c.sessionCookie
}
