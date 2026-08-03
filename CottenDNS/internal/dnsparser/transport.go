// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport.go — shared declarations for the DNS tunnel transport (errors,
// size limits, and strict DNS-name encoding). The build/parse logic lives in
// the sibling files:
//   - transport_query.go    : outbound question packet construction
//   - transport_response.go : tunnel response construction & payload reassembly
//   - transport_txtchunk.go : TXT answer chunk encode/decode
// ==============================================================================

package dnsparser

import (
	"errors"
	"strings"
)

var (
	ErrTXTAnswerMissing   = errors.New("dns txt answer missing")
	ErrTXTAnswerMalformed = errors.New("dns txt answer malformed")
	ErrTXTAnswerTooLarge  = errors.New("dns txt answer too large")
)

const (
	maxDNSNameLen       = 253
	maxDNSLabelLen      = 63
	maxTXTAnswerPayload = 255
	maxTXTEncodedChunk  = 191
)

func encodeDNSNameStrict(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	encoded := make([]byte, len(name)+2)
	writeOffset := 0
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			continue
		}
		labelLen := i - labelStart
		if labelLen == 0 || labelLen > maxDNSLabelLen {
			return nil, ErrInvalidName
		}
		encoded[writeOffset] = byte(labelLen)
		writeOffset++
		writeOffset += copy(encoded[writeOffset:], name[labelStart:i])
		labelStart = i + 1
	}
	encoded[writeOffset] = 0
	writeOffset++
	return encoded[:writeOffset], nil
}
