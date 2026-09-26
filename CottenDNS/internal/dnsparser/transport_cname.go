// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_cname.go — A2 response-type matching. When a tunnel query uses a
// non-TXT record type, the server answers with a CNAME whose target name
// carries the (lowerbase36-encoded) VPN frame, so the answer RR type is a legal
// match for the question. CNAME RDATA is a single DNS name with a hard size
// limit, so frames that do not fit fall back to the TXT encoding.
//
// The server writes an uncompressed CNAME target. Recursive resolvers may
// compress it, so decoding resolves names against the complete DNS message.
// ==============================================================================

package dnsparser

import (
	"encoding/binary"
	"math"
	"sort"
	"strings"

	baseCodec "cottendns-go/internal/basecodec"
	"cottendns-go/internal/compression"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

// firstQuestionQType returns the qType of the first question in a raw DNS
// packet. ok is false if the packet is malformed or has no parseable question.
func firstQuestionQType(packet []byte) (uint16, bool) {
	if len(packet) < dnsHeaderSize {
		return 0, false
	}
	_, nextOffset, err := parseName(packet, dnsHeaderSize)
	if err != nil || nextOffset+4 > len(packet) {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[nextOffset : nextOffset+2]), true
}

// FirstQuestionQType returns the QTYPE of the first question in a DNS packet. A
// tunnel response echoes the query's record type, so the client uses this to
// attribute a decoded response to the carrier (record type) that delivered it.
func FirstQuestionQType(packet []byte) (uint16, bool) {
	return firstQuestionQType(packet)
}

// BuildVPNResponsePacketMatchingQuery builds a tunnel response whose answer RR
// type matches the query type when possible (A2):
//
//   - TXT query, or unknown/missing qType, or no answerDomain -> TXT answer
//     (the historical behavior, via BuildVPNResponsePacket).
//   - any other tunnel-transport query type -> a single CNAME answer carrying
//     the frame in its target name, when the frame fits one DNS name; otherwise
//     it falls back to the TXT answer (e.g. large data packets exceed CNAME
//     capacity).
//
// answerDomain is the tunnel base domain appended as the CNAME target suffix so
// the client can strip it before decoding.
func BuildVPNResponsePacketMatchingQuery(questionPacket []byte, answerName, answerDomain string, packet VpnProto.Packet, baseEncode, allowARecord bool, allowAAAARecord ...bool) ([]byte, error) {
	qType, ok := firstQuestionQType(questionPacket)
	if !ok || qType == Enums.DNS_RECORD_TYPE_TXT {
		return BuildVPNResponsePacket(questionPacket, answerName, packet, baseEncode)
	}

	rawFrame, err := VpnProto.BuildRawAuto(VpnProto.BuildOptions{
		SessionID:       packet.SessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   packet.SessionCookie,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
		LegacySessionID: packet.LegacySessionID,
	}, compression.DefaultMinSize)
	if err != nil {
		return nil, err
	}

	if response, matched, err := buildMatchingRawResponse(questionPacket, answerName, answerDomain, rawFrame, allowARecord, len(allowAAAARecord) > 0 && allowAAAARecord[0]); matched || err != nil {
		return response, err
	}
	return BuildVPNResponsePacket(questionPacket, answerName, packet, baseEncode)
}

// buildMatchingRawResponse carries an already serialized frame without
// interpreting its bytes. Encrypted responses use exactly the same carriers.
func buildMatchingRawResponse(questionPacket []byte, answerName, answerDomain string, rawFrame []byte, allowARecord, allowAAAARecord bool) ([]byte, bool, error) {
	qType, ok := firstQuestionQType(questionPacket)
	if !ok || qType == Enums.DNS_RECORD_TYPE_TXT {
		return nil, false, nil
	}
	matched := func(response []byte, err error) ([]byte, bool, error) {
		return response, true, err
	}

	// A2 supplementary channel: an A query with A-record delivery enabled is
	// answered with IPv4 A records when the frame fits the channel capacity.
	// A records carry the frame directly and need no answer domain.
	// Both are also bounded by the resolver's advertised UDP size: record
	// overhead is 4-5x the payload, so a frame the channel accepts can still
	// produce a response the resolver truncates. Oversized frames use CNAME.
	if allowARecord && qType == Enums.DNS_RECORD_TYPE_A && len(rawFrame) <= aFrameCapacity(answerBudget(questionPacket)) {
		if records, fits := encodeFrameToARecords(rawFrame); fits {
			return matched(buildARecordResponsePacket(questionPacket, answerName, records))
		}
	}

	if allowAAAARecord && qType == Enums.DNS_RECORD_TYPE_AAAA && len(rawFrame) <= aaaaFrameCapacity(answerBudget(questionPacket)) {
		if records, fits := encodeFrameToAAAARecords(rawFrame); fits {
			return matched(buildAAAARecordResponsePacket(questionPacket, answerName, records))
		}
	}

	// NULL channel: the frame rides verbatim in the answer RDATA. Honored by
	// default whenever the client sends a NULL query.
	if qType == Enums.DNS_RECORD_TYPE_NULL && len(rawFrame) <= rrChannelMaxFrame {
		return matched(buildNULLResponsePacket(questionPacket, answerName, rawFrame))
	}

	// HTTPS / SVCB channel: the frame rides in a service-binding SvcParam value.
	if qType == Enums.DNS_RECORD_TYPE_HTTPS || qType == Enums.DNS_RECORD_TYPE_SVCB {
		if _, fits := encodeFrameToSVCBRData(rawFrame); fits {
			return matched(buildSVCBResponsePacket(questionPacket, answerName, qType, rawFrame))
		}
	}

	// Otherwise match with a CNAME (needs the tunnel base domain as suffix).
	if answerDomain != "" && len(rawFrame) <= cnameFrameCapacity(answerDomain, answerBudget(questionPacket)) {
		if target, fits := encodeFrameToCNAMETarget(rawFrame, answerDomain); fits {
			return matched(buildCNAMEResponsePacket(questionPacket, answerName, target))
		}
	}

	// Fall back to the TXT encoding, which chunks across multiple answer strings.
	return nil, false, nil
}

// MatchingFrameCapacity is the largest raw frame the answer to a qType query can
// carry in a record of a matching type, following the same order as
// BuildVPNResponsePacketMatchingQuery. A larger frame falls back to TXT, and
// resolvers strip a TXT answer to a non-TXT question, so the frame is lost.
// Senders must keep frames on such a query at or below this size. It is
// math.MaxInt for carriers that hold any frame (TXT/NULL/HTTPS/SVCB).
func MatchingFrameCapacity(questionPacket []byte, answerDomain string, allowARecord, allowAAAARecord bool) int {
	qType, ok := firstQuestionQType(questionPacket)
	if !ok {
		return math.MaxInt // the builder answers with TXT
	}
	cnameCap := cnameFrameCapacity(answerDomain, answerBudget(questionPacket))
	switch qType {
	case Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_SVCB:
		return math.MaxInt
	case Enums.DNS_RECORD_TYPE_A:
		if allowARecord {
			return max(aFrameCapacity(answerBudget(questionPacket)), cnameCap)
		}
	case Enums.DNS_RECORD_TYPE_AAAA:
		if allowAAAARecord {
			return max(aaaaFrameCapacity(answerBudget(questionPacket)), cnameCap)
		}
	}
	return cnameCap
}

// answerBudget is how many answer-section bytes fit in a UDP response to
// questionPacket: the EDNS payload size it advertises (512 without EDNS) minus
// the header, question and OPT the response echoes back. A larger response is
// truncated by the resolver and the frame is lost.
func answerBudget(questionPacket []byte) int {
	if len(questionPacket) < dnsHeaderSize {
		return 0
	}
	limit := 512
	header := parseHeader(questionPacket)
	_, _, questionEnd := extractQuestionSection(questionPacket, header)
	// OPT owner is the root (one zero byte); its CLASS is the UDP payload size.
	if start, n := findOPTRecordRange(questionPacket, header, questionEnd); n >= 5 && questionPacket[start] == 0 {
		limit = max(limit, int(binary.BigEndian.Uint16(questionPacket[start+3:start+5])))
	}
	return limit - len(questionPacket)
}

// aFrameCapacity: each A record costs 16 wire bytes (owner pointer, fixed
// fields, 4-byte RDATA) and carries 3 frame bytes; the stream has a 2-byte
// length prefix.
func aFrameCapacity(budget int) int {
	return max(0, min(aRecordMaxFrame, budget/(2+10+aRecordRDataLen)*aRecordDataPerRec-2))
}

func aaaaFrameCapacity(budget int) int {
	return max(0, min(aaaaRecordMaxFrame, budget/(2+10+aaaaRecordRDataLen)*aaaaRecordDataPerRec-2))
}

func cnameFrameCapacity(answerDomain string, budget int) int {
	domainLen := len(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(answerDomain)), "."))
	if domainLen == 0 {
		return 0
	}
	// The compressed owner/fixed fields cost 12 bytes; the target wire name
	// costs two more bytes than its dotted spelling. Long questions can make
	// this stricter than the DNS name limit on non-EDNS paths.
	nameLimit := min(maxDNSNameLen, budget-14)
	return sort.Search(maxDNSNameLen, func(n int) bool {
		return encodedQNameLen(baseCodec.EncodedLenLowerBase36(n+1), domainLen) > nameLimit
	})
}

// encodeFrameToCNAMETarget lowerbase36-encodes rawFrame and lays it out as
// label segments under domain, returning the full CNAME target FQDN. fits is
// false when the encoded name would exceed the DNS name length limit (the
// caller should then fall back to TXT) or when inputs are empty.
func encodeFrameToCNAMETarget(rawFrame []byte, domain string) (string, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || len(rawFrame) == 0 {
		return "", false
	}

	// Cheap length pre-check before doing the (big-integer) base36 encode.
	encodedLen := baseCodec.EncodedLenLowerBase36(len(rawFrame))
	if encodedLen <= 0 || encodedQNameLen(encodedLen, len(domain)) > maxDNSNameLen {
		return "", false
	}

	encoded := baseCodec.EncodeLowerBase36(rawFrame)
	if encoded == "" {
		return "", false
	}
	return EncodeDataToLabels(encoded) + "." + domain, true
}

func buildCNAMEResponsePacket(questionPacket []byte, answerName, targetName string) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	// Uncompressed target name so the client can decode it straight from RDATA.
	targetBytes, err := encodeDNSNameStrict(targetName)
	if err != nil {
		return nil, err
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(targetBytes)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_CNAME)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(targetBytes)))
	offset += 10
	offset += copy(response[offset:], targetBytes)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

// ExtractVPNResponseMatching decodes a tunnel response that may carry its
// payload either as a CNAME answer (A2) or as TXT answer chunks (default). For
// CNAME answers the supplied domains are used to strip the target suffix before
// decoding; pass the client's configured tunnel domains. With no CNAME answer
// it behaves exactly like ExtractVPNResponse.
func ExtractVPNResponseMatching(packet []byte, baseEncoded bool, domains []string) (VpnProto.Packet, error) {
	parsed, err := parseTunnelResponse(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	if raw, matched, err := extractMatchingRawResponse(packet, parsed, domains); matched || err != nil {
		if err != nil {
			return VpnProto.Packet{}, err
		}
		return VpnProto.ParseInflated(raw)
	}
	rawAnswers := extractTXTAnswerPayloads(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}
	return assembleVPNResponse(rawAnswers, baseEncoded)
}

func extractMatchingRawResponse(packet []byte, parsed Packet, domains []string) ([]byte, bool, error) {
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_CNAME {
			continue
		}
		name, end, err := parseName(packet, answer.rdataOffset)
		if err != nil || end != answer.rdataOffset+len(answer.RData) {
			return nil, true, ErrTXTAnswerMalformed
		}
		raw, ok := decodeCNAMETarget(name, domains)
		if !ok {
			return nil, true, ErrTXTAnswerMalformed
		}
		return raw, true, nil
	}
	if raw, ok := decodeARecordFrame(parsed.Answers); ok {
		return raw, true, nil
	}
	if raw, ok := decodeAAAARecordFrame(parsed.Answers); ok {
		return raw, true, nil
	}
	for _, answer := range parsed.Answers {
		if answer.Type == Enums.DNS_RECORD_TYPE_NULL && len(answer.RData) > 0 {
			return answer.RData, true, nil
		}
	}
	for _, answer := range parsed.Answers {
		if answer.Type == Enums.DNS_RECORD_TYPE_HTTPS || answer.Type == Enums.DNS_RECORD_TYPE_SVCB {
			if raw, ok := decodeSVCBFrame(answer.RData); ok {
				return raw, true, nil
			}
		}
	}
	return nil, false, nil
}

// decodeCNAMEFrame parses the uncompressed CNAME target from rData, strips the
// longest matching tunnel domain suffix, and lowerbase36-decodes the remaining
// label data back into the raw VPN frame.
func decodeCNAMEFrame(rData []byte, domains []string) ([]byte, bool) {
	name, end, err := parseName(rData, 0)
	if err != nil || end != len(rData) {
		return nil, false
	}
	return decodeCNAMETarget(name, domains)
}

func decodeCNAMETarget(name string, domains []string) ([]byte, bool) {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	if lower == "" {
		return nil, false
	}

	bestData := ""
	bestDomainLen := -1
	for _, d := range domains {
		dd := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if dd == "" {
			continue
		}
		if !strings.HasSuffix(lower, "."+dd) {
			continue
		}
		if len(dd) > bestDomainLen {
			bestDomainLen = len(dd)
			bestData = lower[:len(lower)-len(dd)-1]
		}
	}
	if bestDomainLen < 0 || bestData == "" {
		return nil, false
	}

	encoded := strings.ReplaceAll(bestData, ".", "")
	decoded, err := baseCodec.DecodeLowerBase36String(encoded)
	if err != nil {
		return nil, false
	}
	return decoded, true
}
