package dnsparser

import (
	"encoding/binary"
	"sort"

	baseCodec "cottendns-go/internal/basecodec"
	Enums "cottendns-go/internal/enums"
)

// UDPResponseLimit is the requestor's advertised DNS message size. Without
// EDNS, or with an advertisement below the DNS minimum, the limit is 512.
func UDPResponseLimit(question []byte) int {
	limit := 512
	if len(question) < dnsHeaderSize {
		return limit
	}
	header := parseHeader(question)
	_, _, end := extractQuestionSection(question, header)
	if start, size := findOPTRecordRange(question, header, end); size >= 5 && question[start] == 0 {
		limit = max(limit, int(binary.BigEndian.Uint16(question[start+3:start+5])))
	}
	return limit
}

// BoundUDPResponse keeps the question and OPT, but never a partial tunnel frame,
// when a control/probe response cannot fit. TC permits a recursive resolver to
// retry the original question over TCP. Queued data is sized before dequeue.
func BoundUDPResponse(question, response []byte) []byte {
	if len(response) <= UDPResponseLimit(question) {
		return response
	}
	if len(question) < dnsHeaderSize {
		return nil
	}
	header := parseHeader(question)
	questions, count, end := extractQuestionSection(question, header)
	optStart, optLen := findOPTRecordRange(question, header, end)
	out := make([]byte, dnsHeaderSize+len(questions)+optLen)
	copy(out[:2], question[:2])
	binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(header.Flags, 0)|0x0200)
	binary.BigEndian.PutUint16(out[4:6], count)
	binary.BigEndian.PutUint16(out[10:12], uint16(getARCount(optLen)))
	copy(out[dnsHeaderSize:], questions)
	if optLen > 0 {
		copy(out[dnsHeaderSize+len(questions):], question[optStart:optStart+optLen])
	}
	if len(out) > UDPResponseLimit(question) {
		return nil
	}
	return out
}

// ResponseFrameCapacity accounts for the whole answer, including TXT chunk
// indices, optional base64, DNS records and encryption's opaque-frame framing.
// The caller subtracts VPN and cipher overhead from the returned frame size.
func ResponseFrameCapacity(question []byte, domain string, allowA, allowAAAA, baseEncoded, encrypted, tcp bool, reserveQuestionHeadroom ...bool) int {
	qtype, ok := firstQuestionQType(question)
	if !ok || len(question) < dnsHeaderSize {
		return 0
	}
	limit := UDPResponseLimit(question)
	if tcp {
		limit = 65535
	}
	header := parseHeader(question)
	questions, _, end := extractQuestionSection(question, header)
	_, optLen := findOPTRecordRange(question, header, end)
	budget := limit - dnsHeaderSize - len(questions) - optLen
	if len(reserveQuestionHeadroom) > 0 && reserveQuestionHeadroom[0] {
		// Session init names are short. Later upload-bearing questions can use
		// the full 255-byte QNAME plus QTYPE/QCLASS; reserve that echo overhead
		// when negotiating a session-wide downstream packet size.
		budget -= max(0, 255+4-len(questions))
	}
	if qtype == Enums.DNS_RECORD_TYPE_A || qtype == Enums.DNS_RECORD_TYPE_AAAA ||
		(qtype != Enums.DNS_RECORD_TYPE_TXT && qtype != Enums.DNS_RECORD_TYPE_NULL && qtype != Enums.DNS_RECORD_TYPE_HTTPS && qtype != Enums.DNS_RECORD_TYPE_SVCB) {
		// These carriers also have a DNS-name/record-count ceiling. Their
		// builders already apply the question's UDP budget, including over TCP.
		capacity := cnameFrameCapacity(domain, budget)
		if qtype == Enums.DNS_RECORD_TYPE_A && allowA {
			capacity = max(capacity, aFrameCapacity(budget))
		}
		if qtype == Enums.DNS_RECORD_TYPE_AAAA && allowAAAA {
			capacity = max(capacity, aaaaFrameCapacity(budget))
		}
		return max(0, min(capacity, MatchingFrameCapacity(question, domain, allowA, allowAAAA)))
	}
	if qtype == Enums.DNS_RECORD_TYPE_NULL {
		return max(0, min(rrChannelMaxFrame, budget-12))
	}
	if qtype == Enums.DNS_RECORD_TYPE_HTTPS || qtype == Enums.DNS_RECORD_TYPE_SVCB {
		return max(0, min(rrChannelMaxFrame, budget-12-svcbHeaderLen))
	}
	return max(0, sort.Search(65536, func(n int) bool {
		return txtFrameAnswerSize(n, baseEncoded, encrypted) > budget
	})-1)
}

func txtFrameAnswerSize(size int, baseEncoded, encrypted bool) int {
	chunk := maxTXTAnswerPayload
	if baseEncoded {
		chunk = maxTXTEncodedChunk
	}
	encodedSize := func(n int) int {
		if baseEncoded {
			return baseCodec.EncodedRawBase64Len(n)
		}
		return n
	}
	if !encrypted && size <= chunk {
		return 12 + 1 + encodedSize(size)
	}
	total := 0
	for first := true; size > 0; first = false {
		prefix := 1
		if encrypted || first {
			prefix = 2
		}
		n := min(size, chunk-prefix)
		total += 12 + 1 + encodedSize(prefix+n)
		size -= n
	}
	return total
}
