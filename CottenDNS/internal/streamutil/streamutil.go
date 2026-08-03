// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package streamutil

import "net"

func SafeClose(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
}

func CloseWrite(conn net.Conn) {
	if conn == nil {
		return
	}
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := conn.(closeWriter); ok {
		_ = writer.CloseWrite()
		return
	}
	_ = conn.Close()
}

func SequenceSeenOrOlder(last uint16, current uint16) bool {
	diff := uint16(current - last)
	return diff == 0 || diff >= 0x8000
}
