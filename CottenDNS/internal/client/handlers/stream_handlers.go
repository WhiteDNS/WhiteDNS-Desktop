// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package handlers

import (
	"net"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func init() {
	streamTypes := []uint8{
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_CONNECTED,
		Enums.PACKET_STREAM_CONNECTED_ACK,
		Enums.PACKET_STREAM_CONNECT_FAIL,
		Enums.PACKET_STREAM_CONNECT_FAIL_ACK,
		Enums.PACKET_STREAM_CLOSE_WRITE,
		Enums.PACKET_STREAM_CLOSE_WRITE_ACK,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_CLOSE_READ_ACK,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_FEC_SHARD,
	}

	for _, pt := range streamTypes {
		RegisterHandler(pt, handleStreamPacket)
	}
}

func handleStreamPacket(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleStreamPacket(packet)
}
