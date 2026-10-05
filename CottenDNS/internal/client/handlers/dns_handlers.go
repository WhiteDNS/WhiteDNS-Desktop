// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package handlers

import (
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
	"net"
)

func init() {
	RegisterHandler(Enums.PACKET_DNS_QUERY_REQ_ACK, handleDNSQueryAck)
	RegisterHandler(Enums.PACKET_DNS_QUERY_RES, handleDNSQueryRes)
	RegisterHandler(Enums.PACKET_DOMAIN_LIST_RES, handleDomainListRes)
}

func handleDomainListRes(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDomainListRes(packet)
}

func handleDNSQueryAck(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryAck(packet)
}

func handleDNSQueryRes(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryRes(packet)
}
