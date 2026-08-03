//go:build !windows

// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import "syscall"

func isConnBrokenErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return true
	}
	return false
}
