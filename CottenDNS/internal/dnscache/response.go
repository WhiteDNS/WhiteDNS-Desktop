package dnscache

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"time"

	dnsParser "cottendns-go/internal/dnsparser"
)

// BuildQueryKey retains all DNS request policy, including RD/CD, EDNS flags,
// options and response size. Only the transaction ID and uncompressed QNAME
// case are ignored, so equivalent requests can share cached/in-flight work.
func BuildQueryKey(query []byte, base string) string {
	canonical := append([]byte(nil), query...)
	if len(canonical) >= 2 {
		canonical[0], canonical[1] = 0, 0
	}
	if len(canonical) >= 12 && binary.BigEndian.Uint16(canonical[4:6]) == 1 {
		for offset := 12; offset < len(canonical); {
			n := int(canonical[offset])
			offset++
			if n == 0 || n > 63 || offset+n > len(canonical) {
				break
			}
			for i := offset; i < offset+n; i++ {
				if canonical[i] >= 'A' && canonical[i] <= 'Z' {
					canonical[i] += 'a' - 'A'
				}
			}
			offset += n
		}
	}
	hash := sha256.Sum256(canonical)
	return base + string(hash[:])
}

// responseLifetime validates a complete cacheable answer and records its TTL
// fields once. OPT's TTL word contains EDNS flags and must never be aged.
func responseLifetime(wire []byte, domain string, qType, qClass uint16) ([]int, time.Duration, bool) {
	if len(wire) > 65535 {
		return nil, 0, false
	}
	parsed, err := dnsParser.ParsePacketLite(wire)
	if err != nil || parsed.Header.QR != 1 || parsed.Header.TC != 0 || parsed.Header.QDCount != 1 ||
		wire[2]&0x78 != 0 || (parsed.Header.RCode != 0 && parsed.Header.RCode != 3) ||
		!strings.EqualFold(strings.TrimSuffix(parsed.FirstQuestion.Name, "."), strings.TrimSuffix(domain, ".")) ||
		parsed.FirstQuestion.Type != qType || parsed.FirstQuestion.Class != qClass {
		return nil, 0, false
	}
	negative := parsed.Header.RCode == 3 || parsed.Header.ANCount == 0
	minimum := uint32(1<<31 - 1)
	var fields []int
	hasSOA := false
	offset := parsed.QuestionEndOffset
	count := int(parsed.Header.ANCount) + int(parsed.Header.NSCount) + int(parsed.Header.ARCount)
	for i := 0; i < count; i++ {
		var ok bool
		offset, ok = responseNameEnd(wire, offset)
		if !ok || offset+10 > len(wire) {
			return nil, 0, false
		}
		kind := binary.BigEndian.Uint16(wire[offset : offset+2])
		ttl := binary.BigEndian.Uint32(wire[offset+4 : offset+8])
		end := offset + 10 + int(binary.BigEndian.Uint16(wire[offset+8:offset+10]))
		if end > len(wire) {
			return nil, 0, false
		}
		if kind == 41 {
			if ttl>>24 != 0 { // extended RCODE: not a successful DNS answer
				return nil, 0, false
			}
		} else {
			if ttl == 0 || ttl >= 1<<31 {
				return nil, 0, false
			}
			minimum = min(minimum, ttl)
			fields = append(fields, offset+4)
			// A negative answer needs a structurally valid authority SOA. Its
			// MINIMUM and RR TTL jointly bound negative caching (RFC 2308).
			if kind == 6 && i >= int(parsed.Header.ANCount) && i < int(parsed.Header.ANCount)+int(parsed.Header.NSCount) {
				pos, valid := responseNameEnd(wire, offset+10)
				if valid && pos <= end {
					pos, valid = responseNameEnd(wire, pos)
				}
				if !valid || pos+20 != end {
					return nil, 0, false
				}
				hasSOA = true
				if negative {
					minimum = min(minimum, binary.BigEndian.Uint32(wire[end-4:end]))
				}
			}
		}
		offset = end
	}
	if offset != len(wire) || len(fields) == 0 || minimum == 0 || negative && !hasSOA {
		return nil, 0, false
	}
	return fields, time.Duration(minimum) * time.Second, true
}

func responseNameEnd(wire []byte, offset int) (int, bool) {
	start := offset
	for offset < len(wire) {
		n := int(wire[offset])
		offset++
		if n == 0 {
			return offset, offset-start <= 255
		}
		if n&0xc0 == 0xc0 {
			if offset >= len(wire) {
				return 0, false
			}
			pointer := (n&0x3f)<<8 | int(wire[offset])
			return offset + 1, pointer < offset-1 && offset-start <= 255
		}
		if n > 63 || offset+n > len(wire) || offset+n-start > 255 {
			return 0, false
		}
		offset += n
	}
	return 0, false
}

func responseForQuery(entry *Entry, query []byte, now time.Time) []byte {
	response := PatchResponseForQuery(entry.Response, query)
	age := uint32(max(now.Sub(entry.CreatedAt)/time.Second, 0))
	remaining := uint32(max(entry.ExpiresAt.Sub(now)/time.Second, 0))
	for _, offset := range entry.ttlFields {
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		binary.BigEndian.PutUint32(response[offset:offset+4], min(ttl-min(ttl, age), remaining))
	}
	return response
}
