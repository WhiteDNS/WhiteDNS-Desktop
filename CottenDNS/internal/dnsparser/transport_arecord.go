// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_arecord.go — A2 supplementary delivery: carry a tunnel frame over a
// set of IPv4 A records (an additional channel alongside TXT/CNAME, opt-in).
// IPv6/AAAA is intentionally not used because the target networks block IPv6.
//
// Encoding: the frame is prefixed with its 2-byte length and split into 3-byte
// chunks; each chunk becomes one A record whose 4-byte RDATA is
//
//	[ index(1) | data(3) ]
//
// so records survive resolver reordering (the index restores order). With a
// 1-byte index the channel holds up to 256 records => 768 stream bytes =>
// 766 frame bytes; larger frames fall back to TXT.
// ==============================================================================

package dnsparser

import (
	"encoding/binary"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	aRecordRDataLen   = 4 // IPv4 address width
	aRecordDataPerRec = aRecordRDataLen - 1
	aRecordMaxRecords = 256                                    // 1-byte index
	aRecordMaxStream  = aRecordMaxRecords * aRecordDataPerRec  // 768
	aRecordMaxFrame   = aRecordMaxStream - 2                   // minus 2-byte length prefix
)

// encodeFrameToARecords packs rawFrame into A-record RDATAs. ok is false when
// the frame is empty or exceeds the A-record channel capacity (caller falls
// back to TXT).
func encodeFrameToARecords(rawFrame []byte) ([][]byte, bool) {
	if len(rawFrame) == 0 || len(rawFrame) > aRecordMaxFrame {
		return nil, false
	}

	stream := make([]byte, 2+len(rawFrame))
	binary.BigEndian.PutUint16(stream[0:2], uint16(len(rawFrame)))
	copy(stream[2:], rawFrame)

	records := make([][]byte, 0, (len(stream)+aRecordDataPerRec-1)/aRecordDataPerRec)
	for i, off := 0, 0; off < len(stream); i, off = i+1, off+aRecordDataPerRec {
		rec := make([]byte, aRecordRDataLen)
		rec[0] = byte(i)
		copy(rec[1:], stream[off:min(off+aRecordDataPerRec, len(stream))])
		records = append(records, rec)
	}
	return records, true
}

func buildARecordResponsePacket(questionPacket []byte, answerName string, records [][]byte) ([]byte, error) {
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

	// Each answer: name (or 0xC0 pointer for i>0) + type/class/ttl/rdlen(10) + 4.
	useNameCompression := len(records) > 1
	answerLen := 0
	for i := range records {
		nameLen := len(nameBytes)
		if useNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + aRecordRDataLen
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(records)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstNameOffset := offset

	for i, rec := range records {
		if useNameCompression && i > 0 && firstNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_A)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], aRecordRDataLen)
		offset += 10
		offset += copy(response[offset:], rec)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}
	return response, nil
}

// decodeARecordFrame reassembles the tunnel frame from A-record RDATAs, ordering
// them by their index byte and trimming to the embedded length prefix.
func decodeARecordFrame(answers []ResourceRecord) ([]byte, bool) {
	var slots [aRecordMaxRecords][]byte
	maxIdx := -1
	count := 0
	for _, ans := range answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_A || len(ans.RData) != aRecordRDataLen {
			continue
		}
		idx := int(ans.RData[0])
		if slots[idx] == nil {
			count++
		}
		slots[idx] = ans.RData[1:]
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	if maxIdx < 0 || count != maxIdx+1 {
		return nil, false
	}

	stream := make([]byte, 0, count*aRecordDataPerRec)
	for i := 0; i <= maxIdx; i++ {
		if slots[i] == nil {
			return nil, false
		}
		stream = append(stream, slots[i]...)
	}
	if len(stream) < 2 {
		return nil, false
	}

	frameLen := int(binary.BigEndian.Uint16(stream[0:2]))
	if frameLen <= 0 || 2+frameLen > len(stream) {
		return nil, false
	}
	return stream[2 : 2+frameLen], true
}

// extractARecordFrame returns the decoded+inflated packet from A-record answers,
// or ok=false if the response carries no usable A-record payload.
func extractARecordFrame(parsed Packet) (VpnProto.Packet, bool, error) {
	raw, ok := decodeARecordFrame(parsed.Answers)
	if !ok {
		return VpnProto.Packet{}, false, nil
	}
	pkt, err := VpnProto.ParseInflated(raw)
	if err != nil {
		return VpnProto.Packet{}, true, err
	}
	return pkt, true, nil
}
