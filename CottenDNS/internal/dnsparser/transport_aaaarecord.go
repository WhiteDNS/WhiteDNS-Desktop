package dnsparser

import (
	"encoding/binary"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

// The first octet is a reorder-safe record index; the remaining 15 octets are
// tunnel data. This gives AAAA five times the payload density of the A channel.
const (
	aaaaRecordRDataLen   = 16
	aaaaRecordDataPerRec = aaaaRecordRDataLen - 1
	aaaaRecordMaxRecords = 256
	aaaaRecordMaxStream  = aaaaRecordMaxRecords * aaaaRecordDataPerRec
	aaaaRecordMaxFrame   = aaaaRecordMaxStream - 2
)

func encodeFrameToAAAARecords(rawFrame []byte) ([][]byte, bool) {
	if len(rawFrame) == 0 || len(rawFrame) > aaaaRecordMaxFrame {
		return nil, false
	}
	stream := make([]byte, 2+len(rawFrame))
	binary.BigEndian.PutUint16(stream[:2], uint16(len(rawFrame)))
	copy(stream[2:], rawFrame)
	records := make([][]byte, 0, (len(stream)+aaaaRecordDataPerRec-1)/aaaaRecordDataPerRec)
	for i, off := 0, 0; off < len(stream); i, off = i+1, off+aaaaRecordDataPerRec {
		record := make([]byte, aaaaRecordRDataLen)
		record[0] = byte(i)
		copy(record[1:], stream[off:min(off+aaaaRecordDataPerRec, len(stream))])
		records = append(records, record)
	}
	return records, true
}

func buildAAAARecordResponsePacket(questionPacket []byte, answerName string, records [][]byte) ([]byte, error) {
	if len(records) == 0 {
		return nil, ErrTXTAnswerMalformed
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
	for i := range records {
		nameLen := len(nameBytes)
		if i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + aaaaRecordRDataLen
	}
	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(records)))
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))
	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstNameOffset := offset
	for i, record := range records {
		if i > 0 && firstNameOffset <= 0x3fff {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xc000|firstNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_AAAA)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], aaaaRecordRDataLen)
		offset += 10
		offset += copy(response[offset:], record)
	}
	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}
	return response, nil
}

func decodeAAAARecordFrame(answers []ResourceRecord) ([]byte, bool) {
	var slots [aaaaRecordMaxRecords][]byte
	maxIdx, count := -1, 0
	for _, answer := range answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_AAAA || len(answer.RData) != aaaaRecordRDataLen {
			continue
		}
		idx := int(answer.RData[0])
		if slots[idx] == nil {
			count++
		}
		slots[idx] = answer.RData[1:]
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	if maxIdx < 0 || count != maxIdx+1 {
		return nil, false
	}
	stream := make([]byte, 0, count*aaaaRecordDataPerRec)
	for i := 0; i <= maxIdx; i++ {
		if slots[i] == nil {
			return nil, false
		}
		stream = append(stream, slots[i]...)
	}
	if len(stream) < 2 {
		return nil, false
	}
	frameLen := int(binary.BigEndian.Uint16(stream[:2]))
	if frameLen <= 0 || frameLen+2 > len(stream) {
		return nil, false
	}
	return stream[2 : frameLen+2], true
}

func extractAAAARecordFrame(parsed Packet) (VpnProto.Packet, bool, error) {
	raw, ok := decodeAAAARecordFrame(parsed.Answers)
	if !ok {
		return VpnProto.Packet{}, false, nil
	}
	packet, err := VpnProto.ParseInflated(raw)
	return packet, true, err
}
