// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package enums

import (
	"strconv"
	"strings"
)

// DNSRecordTypeFromName maps a case-insensitive record-type name (e.g. "TXT",
// "cname", "AAAA") to its numeric qType. It returns (code, true) on success and
// (0, false) for an unknown name. Only the types CottenDns can actually carry a
// tunnel query/response over are recognized.
func DNSRecordTypeFromName(name string) (uint16, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "A":
		return DNS_RECORD_TYPE_A, true
	case "AAAA":
		return DNS_RECORD_TYPE_AAAA, true
	case "NULL":
		return DNS_RECORD_TYPE_NULL, true
	case "CNAME":
		return DNS_RECORD_TYPE_CNAME, true
	case "MX":
		return DNS_RECORD_TYPE_MX, true
	case "NS":
		return DNS_RECORD_TYPE_NS, true
	case "PTR":
		return DNS_RECORD_TYPE_PTR, true
	case "SRV":
		return DNS_RECORD_TYPE_SRV, true
	case "SVCB":
		return DNS_RECORD_TYPE_SVCB, true
	case "CAA":
		return DNS_RECORD_TYPE_CAA, true
	case "NAPTR":
		return DNS_RECORD_TYPE_NAPTR, true
	case "SOA":
		return DNS_RECORD_TYPE_SOA, true
	case "TXT":
		return DNS_RECORD_TYPE_TXT, true
	case "HTTPS":
		return DNS_RECORD_TYPE_HTTPS, true
	default:
		return 0, false
	}
}

// IsTunnelTransportQueryType reports whether qType is a record type the VPN
// tunnel transport may use to carry a query (A1 query-type rotation). The
// tunnel payload always rides in the QNAME labels, so the server accepts any of
// these types as a tunnel candidate regardless of the answer encoding. This set
// must stay in sync with DNSRecordTypeFromName (the client-side parser).
//
// Note: this is distinct from IsSupportedTunnelDNSQuery in the dnsparser
// package, which gates the *DNS-over-tunnel* resolver feature and deliberately
// excludes TXT.
func IsTunnelTransportQueryType(qType uint16) bool {
	switch qType {
	case
		DNS_RECORD_TYPE_A,
		DNS_RECORD_TYPE_AAAA,
		DNS_RECORD_TYPE_NULL,
		DNS_RECORD_TYPE_CNAME,
		DNS_RECORD_TYPE_MX,
		DNS_RECORD_TYPE_NS,
		DNS_RECORD_TYPE_PTR,
		DNS_RECORD_TYPE_SRV,
		DNS_RECORD_TYPE_SVCB,
		DNS_RECORD_TYPE_CAA,
		DNS_RECORD_TYPE_NAPTR,
		DNS_RECORD_TYPE_SOA,
		DNS_RECORD_TYPE_TXT,
		DNS_RECORD_TYPE_HTTPS:
		return true
	default:
		return false
	}
}

func DNSRecordTypeName(qType uint16) string {
	switch qType {
	case DNS_RECORD_TYPE_A:
		return "A"
	case DNS_RECORD_TYPE_AAAA:
		return "AAAA"
	case DNS_RECORD_TYPE_NULL:
		return "NULL"
	case DNS_RECORD_TYPE_CNAME:
		return "CNAME"
	case DNS_RECORD_TYPE_MX:
		return "MX"
	case DNS_RECORD_TYPE_NS:
		return "NS"
	case DNS_RECORD_TYPE_PTR:
		return "PTR"
	case DNS_RECORD_TYPE_SRV:
		return "SRV"
	case DNS_RECORD_TYPE_SVCB:
		return "SVCB"
	case DNS_RECORD_TYPE_CAA:
		return "CAA"
	case DNS_RECORD_TYPE_NAPTR:
		return "NAPTR"
	case DNS_RECORD_TYPE_SOA:
		return "SOA"
	case DNS_RECORD_TYPE_TXT:
		return "TXT"
	case DNS_RECORD_TYPE_HTTPS:
		return "HTTPS"
	default:
		return "TYPE" + strconv.FormatUint(uint64(qType), 10)
	}
}

func PacketTypeName(packetType uint8) string {
	switch packetType {
	case PACKET_MTU_UP_REQ:
		return "PACKET_MTU_UP_REQ"
	case PACKET_MTU_UP_RES:
		return "PACKET_MTU_UP_RES"
	case PACKET_MTU_DOWN_REQ:
		return "PACKET_MTU_DOWN_REQ"
	case PACKET_MTU_DOWN_RES:
		return "PACKET_MTU_DOWN_RES"
	case PACKET_SESSION_INIT:
		return "PACKET_SESSION_INIT"
	case PACKET_SESSION_ACCEPT:
		return "PACKET_SESSION_ACCEPT"
	case PACKET_PING:
		return "PACKET_PING"
	case PACKET_PONG:
		return "PACKET_PONG"
	case PACKET_STREAM_SYN:
		return "PACKET_STREAM_SYN"
	case PACKET_STREAM_SYN_ACK:
		return "PACKET_STREAM_SYN_ACK"
	case PACKET_STREAM_CONNECTED:
		return "PACKET_STREAM_CONNECTED"
	case PACKET_STREAM_CONNECTED_ACK:
		return "PACKET_STREAM_CONNECTED_ACK"
	case PACKET_STREAM_CONNECT_FAIL:
		return "PACKET_STREAM_CONNECT_FAIL"
	case PACKET_STREAM_CONNECT_FAIL_ACK:
		return "PACKET_STREAM_CONNECT_FAIL_ACK"
	case PACKET_STREAM_DATA:
		return "PACKET_STREAM_DATA"
	case PACKET_STREAM_DATA_ACK:
		return "PACKET_STREAM_DATA_ACK"
	case PACKET_STREAM_RESEND:
		return "PACKET_STREAM_RESEND"
	case PACKET_PACKED_CONTROL_BLOCKS:
		return "PACKET_PACKED_CONTROL_BLOCKS"
	case PACKET_STREAM_CLOSE_WRITE:
		return "PACKET_STREAM_CLOSE_WRITE"
	case PACKET_STREAM_CLOSE_WRITE_ACK:
		return "PACKET_STREAM_CLOSE_WRITE_ACK"
	case PACKET_STREAM_CLOSE_READ:
		return "PACKET_STREAM_CLOSE_READ"
	case PACKET_STREAM_CLOSE_READ_ACK:
		return "PACKET_STREAM_CLOSE_READ_ACK"
	case PACKET_STREAM_RST:
		return "PACKET_STREAM_RST"
	case PACKET_STREAM_RST_ACK:
		return "PACKET_STREAM_RST_ACK"
	case PACKET_SOCKS5_SYN:
		return "PACKET_SOCKS5_SYN"
	case PACKET_SOCKS5_SYN_ACK:
		return "PACKET_SOCKS5_SYN_ACK"
	case PACKET_SOCKS5_CONNECT_FAIL:
		return "PACKET_SOCKS5_CONNECT_FAIL"
	case PACKET_SOCKS5_CONNECT_FAIL_ACK:
		return "PACKET_SOCKS5_CONNECT_FAIL_ACK"
	case PACKET_SOCKS5_RULESET_DENIED:
		return "PACKET_SOCKS5_RULESET_DENIED"
	case PACKET_SOCKS5_RULESET_DENIED_ACK:
		return "PACKET_SOCKS5_RULESET_DENIED_ACK"
	case PACKET_SOCKS5_NETWORK_UNREACHABLE:
		return "PACKET_SOCKS5_NETWORK_UNREACHABLE"
	case PACKET_SOCKS5_HOST_UNREACHABLE:
		return "PACKET_SOCKS5_HOST_UNREACHABLE"
	case PACKET_SOCKS5_HOST_UNREACHABLE_ACK:
		return "PACKET_SOCKS5_HOST_UNREACHABLE_ACK"
	case PACKET_SOCKS5_CONNECTION_REFUSED:
		return "PACKET_SOCKS5_CONNECTION_REFUSED"
	case PACKET_SOCKS5_CONNECTION_REFUSED_ACK:
		return "PACKET_SOCKS5_CONNECTION_REFUSED_ACK"
	case PACKET_SOCKS5_TTL_EXPIRED:
		return "PACKET_SOCKS5_TTL_EXPIRED"
	case PACKET_SOCKS5_TTL_EXPIRED_ACK:
		return "PACKET_SOCKS5_TTL_EXPIRED_ACK"
	case PACKET_SOCKS5_COMMAND_UNSUPPORTED:
		return "PACKET_SOCKS5_COMMAND_UNSUPPORTED"
	case PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK:
		return "PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK"
	case PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED:
		return "PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED"
	case PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK:
		return "PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK"
	case PACKET_SOCKS5_AUTH_FAILED:
		return "PACKET_SOCKS5_AUTH_FAILED"
	case PACKET_SOCKS5_AUTH_FAILED_ACK:
		return "PACKET_SOCKS5_AUTH_FAILED_ACK"
	case PACKET_SOCKS5_UPSTREAM_UNAVAILABLE:
		return "PACKET_SOCKS5_UPSTREAM_UNAVAILABLE"
	case PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return "PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK"
	case PACKET_SOCKS5_CONNECTED:
		return "PACKET_SOCKS5_CONNECTED"
	case PACKET_SOCKS5_CONNECTED_ACK:
		return "PACKET_SOCKS5_CONNECTED_ACK"
	case PACKET_DNS_QUERY_REQ:
		return "PACKET_DNS_QUERY_REQ"
	case PACKET_DNS_QUERY_RES:
		return "PACKET_DNS_QUERY_RES"
	case PACKET_DNS_QUERY_REQ_ACK:
		return "PACKET_DNS_QUERY_REQ_ACK"
	case PACKET_DNS_QUERY_RES_ACK:
		return "PACKET_DNS_QUERY_RES_ACK"
	case PACKET_SESSION_CLOSE:
		return "PACKET_SESSION_CLOSE"
	case PACKET_SESSION_BUSY:
		return "PACKET_SESSION_BUSY"
	case PACKET_FEC_SHARD:
		return "PACKET_FEC_SHARD"
	case PACKET_STREAM_DATA_NACK:
		return "PACKET_STREAM_DATA_NACK"
	case PACKET_ERROR_DROP:
		return "PACKET_ERROR_DROP"
	default:
		return "PACKET_" + strconv.FormatUint(uint64(packetType), 10)
	}
}
