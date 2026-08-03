// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// query.go — construction of outbound DNS (tunnel) question packets and the
// helpers for encoding tunnel payload into the QNAME. Split out of transport.go.
// ==============================================================================

package dnsparser

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"

	Enums "cottendns-go/internal/enums"
)

// QueryShaping holds the client-only, server-transparent DNS fingerprint knobs
// applied when building a tunnel question packet. Every field is safe against an
// unmodified server: the transaction ID is echoed but never validated, the QNAME
// is lowercased server-side before decoding, and the EDNS cookie is stripped by
// the recursive resolver before the query ever reaches the server.
type QueryShaping struct {
	// EDNSUDPSize is the requestor's UDP payload size advertised in the OPT
	// record. 0 omits the OPT record entirely.
	EDNSUDPSize uint16
	// RandomizeID uses a random DNS transaction ID per query instead of the
	// process-global sequential counter.
	RandomizeID bool
	// EDNSCookie adds an RFC 7873 EDNS Client Cookie option (8 random bytes) to
	// the OPT record. Requires EDNSUDPSize > 0.
	EDNSCookie bool
	// CaseRandomize applies DNS 0x20 mixed-case encoding to the QNAME.
	CaseRandomize bool
}

// ednsCookieOptionCode is the EDNS(0) COOKIE option code (RFC 7873).
const ednsCookieOptionCode uint16 = 10

// ednsOptRecordLen returns the byte length of the OPT record for the given
// shaping (0 when no OPT record is emitted).
func ednsOptRecordLen(shaping QueryShaping) int {
	if shaping.EDNSUDPSize == 0 {
		return 0
	}
	n := 11 // root name(1) + type(2) + udpsize(2) + ttl(4) + rdlength(2)
	if shaping.EDNSCookie {
		n += 12 // option-code(2) + option-length(2) + 8-byte client cookie
	}
	return n
}

// writeEDNSOPT writes the OPT pseudo-record at offset and returns the new
// offset. It is a no-op (returns offset unchanged) when no OPT is requested.
func writeEDNSOPT(packet []byte, offset int, shaping QueryShaping) int {
	if shaping.EDNSUDPSize == 0 {
		return offset
	}
	packet[offset] = 0x00 // root name
	offset++
	binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
	offset += 2
	binary.BigEndian.PutUint16(packet[offset:offset+2], shaping.EDNSUDPSize) // requestor UDP size
	offset += 2
	offset += 4 // extended-RCODE + EDNS version + flags, all zero
	if shaping.EDNSCookie {
		binary.BigEndian.PutUint16(packet[offset:offset+2], 12) // RDLENGTH
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsCookieOptionCode)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], 8) // OPTION-LENGTH (client cookie)
		offset += 2
		binary.BigEndian.PutUint64(packet[offset:offset+8], secureRandomUint64())
		offset += 8
	} else {
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0) // RDLENGTH
		offset += 2
	}
	return offset
}

// queryTransactionID returns the DNS ID for the next query per the shaping.
func queryTransactionID(shaping QueryShaping) uint16 {
	if shaping.RandomizeID {
		return secureRandomUint16()
	}
	return nextDNSRequestID()
}

func secureRandomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return uint16(mathrand.Uint32())
}

func secureRandomUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint64(b[:])
	}
	return mathrand.Uint64()
}

// randomizeQNameCase applies DNS 0x20 mixed-case encoding in place, walking the
// wire-format labels from start until the root label (0x00). Only ASCII letters
// are flipped; length bytes and non-letters are left untouched. The server
// lowercases the whole name before decoding, so this never affects correctness.
func randomizeQNameCase(packet []byte, start int) {
	pos := start
	var bits uint64
	var have uint
	for pos < len(packet) {
		l := int(packet[pos])
		if l == 0 {
			return
		}
		pos++
		for i := 0; i < l && pos < len(packet); i, pos = i+1, pos+1 {
			c := packet[pos]
			if c < 'a' || c > 'z' {
				continue
			}
			if have == 0 {
				bits = mathrand.Uint64()
				have = 64
			}
			if bits&1 == 1 {
				packet[pos] = c - ('a' - 'A')
			}
			bits >>= 1
			have--
		}
	}
}

func BuildTXTQuestionPacket(name string, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	qname, err := encodeDNSNameStrict(name)
	if err != nil {
		return nil, err
	}

	requestID := nextDNSRequestID()

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func BuildTunnelTXTQuestionPacket(domain string, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	normalizedDomain, domainQname, err := PrepareTunnelDomainQname(domain)
	if err != nil {
		return nil, err
	}

	return BuildTunnelTXTQuestionPacketPrepared(normalizedDomain, domainQname, encodedFrame, qType, ednsUDPSize)
}

// BuildTunnelTXTQuestionPacketPrepared preserves the legacy signature (sequential
// ID, bare OPT, all-lowercase QNAME). New callers should use
// BuildTunnelQuestionPacketShaped to opt into query-shaping.
func BuildTunnelTXTQuestionPacketPrepared(normalizedDomain string, domainQname []byte, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	return BuildTunnelQuestionPacketShaped(normalizedDomain, domainQname, encodedFrame, qType, QueryShaping{EDNSUDPSize: ednsUDPSize})
}

// BuildTunnelQuestionPacketShaped builds a tunnel question packet, applying the
// given client-only shaping (transaction ID, EDNS OPT/cookie, QNAME case). It
// handles both the payload-carrying case and the empty-frame case (a bare query
// for the base domain). The payload always rides in the QNAME labels, so qType is
// free to vary and the shaping never affects how the server decodes the frame.
func BuildTunnelQuestionPacketShaped(normalizedDomain string, domainQname []byte, encodedFrame []byte, qType uint16, shaping QueryShaping) ([]byte, error) {
	if normalizedDomain == "" || len(domainQname) == 0 {
		return nil, ErrInvalidName
	}

	requestID := queryTransactionID(shaping)

	var labelLengths []int
	payloadLen := len(encodedFrame)
	if payloadLen > 0 {
		if encodedQNameLen(payloadLen, len(normalizedDomain)) > maxDNSNameLen {
			return nil, ErrInvalidName
		}
		// Shape the encoded payload into labels (lengths jittered per query).
		// Label count comes from qnameLabelCount so it matches encodedQNameLen.
		labelLengths = shapeQNameLabelLengths(payloadLen, uint64(requestID))
	}
	labelCount := len(labelLengths)
	qnameLen := payloadLen + labelCount + len(domainQname)

	arCount := uint16(0)
	optLen := ednsOptRecordLen(shaping)
	if optLen > 0 {
		arCount = 1
	}

	packet := make([]byte, dnsHeaderSize+qnameLen+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	qnameStart := offset
	pos := 0
	for _, ll := range labelLengths {
		packet[offset] = byte(ll)
		offset++
		offset += copy(packet[offset:], encodedFrame[pos:pos+ll])
		pos += ll
	}
	offset += copy(packet[offset:], domainQname)
	if shaping.CaseRandomize {
		randomizeQNameCase(packet, qnameStart)
	}
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	writeEDNSOPT(packet, offset, shaping)

	return packet, nil
}

func PrepareTunnelDomainQname(domain string) (string, []byte, error) {
	normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normalizedDomain == "" {
		return "", nil, ErrInvalidName
	}

	domainQname, err := encodeDNSNameStrict(normalizedDomain)
	if err != nil {
		return "", nil, err
	}
	return normalizedDomain, domainQname, nil
}

func CalculateMaxEncodedQNameChars(domain string) int {
	domainLen := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLen <= 0 {
		return maxDNSNameLen
	}

	low := 0
	high := maxDNSNameLen
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if encodedQNameLen(mid, domainLen) <= maxDNSNameLen {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func EncodeDataToLabels(data string) string {
	labelLen := qnameLabelLen()
	if len(data) <= labelLen {
		return data
	}

	var b strings.Builder
	b.Grow(len(data) + len(data)/labelLen)
	for start := 0; start < len(data); start += labelLen {
		if start > 0 {
			b.WriteByte('.')
		}
		end := start + labelLen
		if end > len(data) {
			end = len(data)
		}
		b.WriteString(data[start:end])
	}
	return b.String()
}

func BuildTunnelQuestionName(domain string, encodedFrame string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", ErrInvalidName
	}
	if encodedFrame == "" {
		return domain, nil
	}

	name := EncodeDataToLabels(encodedFrame) + "." + domain
	if len(name) > maxDNSNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func encodedQNameLen(encodedChars int, domainLen int) int {
	if encodedChars <= 0 {
		return domainLen
	}
	// encodedChars data bytes + one length byte per label + the trailing dot
	// before the base domain + the domain itself. qnameLabelCount is the shared
	// source of truth with the wire builder, so this stays exact under reshaping.
	return encodedChars + qnameLabelCount(encodedChars) + domainLen
}

var dnsIDCounter atomic.Uint32
var dnsIDInit sync.Once

func nextDNSRequestID() uint16 {
	dnsIDInit.Do(func() {
		var seed [4]byte
		if _, err := rand.Read(seed[:]); err == nil {
			dnsIDCounter.Store(uint32(binary.BigEndian.Uint32(seed[:])))
		}
	})
	return uint16(dnsIDCounter.Add(1))
}
