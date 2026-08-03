// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_response.go — construction of DNS (tunnel) response packets and
// extraction / reassembly of the tunnel payload carried in the answer section.
// Split out of transport.go. (Distinct from response.go, which builds DNS
// control responses such as FORMERR / SERVFAIL.)
// ==============================================================================

package dnsparser

import (
	"encoding/binary"
	"fmt"
	"strings"

	baseCodec "cottendns-go/internal/basecodec"
	"cottendns-go/internal/compression"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func BuildTXTResponsePacket(questionPacket []byte, answerName string, answerPayloads [][]byte) ([]byte, error) {
	if len(answerPayloads) == 1 {
		return buildSingleTXTResponsePacket(questionPacket, answerName, answerPayloads[0])
	}

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

	answerLen := 0
	useAnswerNameCompression := len(answerPayloads) > 1
	for i, payload := range answerPayloads {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(payload)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerPayloads)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, payload := range answerPayloads {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_TXT)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(payload)))
		offset += 10
		offset += copy(response[offset:], payload)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func BuildVPNResponsePacket(questionPacket []byte, answerName string, packet VpnProto.Packet, baseEncode bool) ([]byte, error) {
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

	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}
	if len(rawFrame) <= maxChunk {
		return buildSingleTXTResponsePacket(questionPacket, answerName, buildTXTAnswerChunk(rawFrame, baseEncode))
	}

	answerPayloads, err := buildTXTAnswerChunks(rawFrame, baseEncode)
	if err != nil {
		return nil, err
	}

	return BuildTXTResponsePacket(questionPacket, answerName, answerPayloads)
}

func buildSingleTXTResponsePacket(questionPacket []byte, answerName string, answerPayload []byte) ([]byte, error) {
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

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(answerPayload)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_TXT)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerPayload)))
	offset += 10
	offset += copy(response[offset:], answerPayload)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func responseAnswerNameBytes(questionPacket []byte, answerName string) ([]byte, error) {
	rawName, parsedName, ok := extractFirstQuestionNameWire(questionPacket)
	if ok && sameDNSName(parsedName, answerName) {
		return rawName, nil
	}
	return encodeDNSNameStrict(answerName)
}

func extractFirstQuestionNameWire(packet []byte) ([]byte, string, bool) {
	if len(packet) < dnsHeaderSize {
		return nil, "", false
	}
	header := parseHeader(packet)
	if header.QDCount == 0 {
		return nil, "", false
	}

	name, nextOffset, err := parseName(packet, dnsHeaderSize)
	if err != nil || nextOffset <= dnsHeaderSize || nextOffset > len(packet) {
		return nil, "", false
	}

	return packet[dnsHeaderSize:nextOffset], name, true
}

func sameDNSName(a string, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	return strings.EqualFold(a, b)
}

func ExtractVPNResponse(packet []byte, baseEncoded bool) (VpnProto.Packet, error) {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	rawAnswers := extractTXTAnswerPayloads(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}

	return assembleVPNResponse(rawAnswers, baseEncoded)
}

func DescribeResponseWithoutTunnelPayload(packet []byte) string {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return fmt.Sprintf("unparseable dns response: %v", err)
	}

	qName := "-"
	if len(parsed.Questions) > 0 && parsed.Questions[0].Name != "" {
		qName = parsed.Questions[0].Name
	}

	answerKinds := summarizeRecordTypes(parsed.Answers)
	if answerKinds == "" {
		answerKinds = "none"
	}

	return fmt.Sprintf(
		"RCODE=%d QD=%d AN=%d NS=%d AR=%d QName=%s Answers=%s",
		parsed.Header.RCode,
		parsed.Header.QDCount,
		parsed.Header.ANCount,
		parsed.Header.NSCount,
		parsed.Header.ARCount,
		qName,
		answerKinds,
	)
}

func summarizeRecordTypes(records []ResourceRecord) string {
	if len(records) == 0 {
		return ""
	}

	counts := make(map[uint16]int, len(records))
	order := make([]uint16, 0, len(records))
	for _, rr := range records {
		if _, ok := counts[rr.Type]; !ok {
			order = append(order, rr.Type)
		}
		counts[rr.Type]++
	}

	parts := make([]string, 0, len(order))
	for _, rrType := range order {
		parts = append(parts, fmt.Sprintf("%s x%d", Enums.DNSRecordTypeName(rrType), counts[rrType]))
	}
	return strings.Join(parts, ", ")
}

func assembleVPNResponse(rawAnswers [][]byte, baseEncoded bool) (VpnProto.Packet, error) {
	if len(rawAnswers) == 1 {
		raw := rawAnswers[0]
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		return VpnProto.ParseInflated(raw)
	}

	var chunks [256][]byte
	totalExpected := 0
	seenChunks := 0
	var header VpnProto.Packet
	headerSeen := false

	for _, raw := range rawAnswers {
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		if len(raw) == 0 {
			continue
		}

		if raw[0] == 0x00 {
			if len(raw) < 3 {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			totalExpected = int(raw[1])
			if totalExpected <= 0 || totalExpected > len(chunks) {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			parsed, err := VpnProto.ParseAtOffset(raw, 2)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			header = parsed
			headerSeen = true
			if chunks[0] == nil {
				seenChunks++
			}
			chunks[0] = parsed.Payload
			continue
		}

		chunkID := int(raw[0])
		if chunkID >= len(chunks) {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
		if chunks[chunkID] == nil {
			seenChunks++
		}
		chunks[chunkID] = raw[1:]
	}

	if !headerSeen || totalExpected <= 0 || seenChunks != totalExpected {
		return VpnProto.Packet{}, ErrTXTAnswerMalformed
	}
	for i := range totalExpected {
		if chunks[i] == nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}
	for i := totalExpected; i < len(chunks); i++ {
		if chunks[i] != nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}

	payloadLen := 0
	for i := range totalExpected {
		payloadLen += len(chunks[i])
	}

	payload := make([]byte, 0, payloadLen)
	for i := range totalExpected {
		payload = append(payload, chunks[i]...)
	}
	header.Payload = payload
	return VpnProto.InflatePayload(header)
}
