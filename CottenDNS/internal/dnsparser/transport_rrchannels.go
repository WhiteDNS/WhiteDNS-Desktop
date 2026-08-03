// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_rrchannels.go — additional response-type channels that complement
// TXT/CNAME/A (A2 response-type matching). When a tunnel query uses one of these
// record types, the server answers with the matching RR type carrying the VPN
// frame, so the answer RR type is a legal match for the question. The client
// auto-detects and decodes whichever channel the server used, so no negotiation
// is needed — the client picks the delivery method by choosing the query type
// and the server always honors it.
//
//   - NULL (type 10): the frame rides verbatim in the answer's RDATA. Highest
//     capacity and zero encoding overhead; ideal for a direct (non-recursive)
//     resolver path. (dnscat2-style.)
//   - HTTPS / SVCB (types 65 / 64): the frame rides inside a single SvcParam
//     value using a private SvcParamKey, with a root TargetName. These look like
//     ordinary service-binding records on the wire.
//
// Both channels are honored by default (no server flag); they only activate when
// the client actually sends that query type.
// ==============================================================================

package dnsparser

import (
	"encoding/binary"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	// svcbPriority is a non-zero (ServiceMode) priority for the synthetic
	// HTTPS/SVCB answer.
	svcbPriority = 1
	// svcbFrameParamKey is a private-use SvcParamKey (range 65280-65534) that
	// carries the VPN frame as its value.
	svcbFrameParamKey = 65280
	// svcbHeaderLen is priority(2) + root target name(1) + key(2) + len(2).
	svcbHeaderLen = 7
	// rrChannelMaxFrame bounds a single-answer RDATA frame defensively.
	rrChannelMaxFrame = 0xFFFF - svcbHeaderLen
)

// buildSingleRDATAResponsePacket emits a DNS response with exactly one answer of
// the given RR type whose RDATA is the supplied bytes verbatim. It mirrors the
// header/question/OPT handling of the CNAME/A builders.
func buildSingleRDATAResponsePacket(questionPacket []byte, answerName string, rrType uint16, rdata []byte) ([]byte, error) {
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

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(rdata)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], rrType)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(rdata)))
	offset += 10
	offset += copy(response[offset:], rdata)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}
	return response, nil
}

// ---- NULL channel -----------------------------------------------------------

// buildNULLResponsePacket answers with a single NULL record whose RDATA is the
// raw frame. fits is implicit: any frame within rrChannelMaxFrame is accepted.
func buildNULLResponsePacket(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error) {
	return buildSingleRDATAResponsePacket(questionPacket, answerName, Enums.DNS_RECORD_TYPE_NULL, rawFrame)
}

// extractNULLFrame returns the inflated packet from the first NULL answer, or
// ok=false when the response carries no NULL answer.
func extractNULLFrame(parsed Packet) (VpnProto.Packet, bool, error) {
	for _, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_NULL || len(ans.RData) == 0 {
			continue
		}
		pkt, err := VpnProto.ParseInflated(ans.RData)
		if err != nil {
			return VpnProto.Packet{}, true, err
		}
		return pkt, true, nil
	}
	return VpnProto.Packet{}, false, nil
}

// ---- HTTPS / SVCB channel ---------------------------------------------------

// encodeFrameToSVCBRData lays the frame into a service-binding RDATA:
//
//	SvcPriority(2) | TargetName(root=0x00) | SvcParamKey(2) | ValueLen(2) | frame
func encodeFrameToSVCBRData(rawFrame []byte) ([]byte, bool) {
	if len(rawFrame) == 0 || len(rawFrame) > rrChannelMaxFrame {
		return nil, false
	}
	rdata := make([]byte, svcbHeaderLen+len(rawFrame))
	binary.BigEndian.PutUint16(rdata[0:2], svcbPriority)
	rdata[2] = 0x00 // root target name
	binary.BigEndian.PutUint16(rdata[3:5], svcbFrameParamKey)
	binary.BigEndian.PutUint16(rdata[5:7], uint16(len(rawFrame)))
	copy(rdata[svcbHeaderLen:], rawFrame)
	return rdata, true
}

func buildSVCBResponsePacket(questionPacket []byte, answerName string, rrType uint16, rawFrame []byte) ([]byte, error) {
	rdata, ok := encodeFrameToSVCBRData(rawFrame)
	if !ok {
		return nil, ErrTXTAnswerMalformed
	}
	return buildSingleRDATAResponsePacket(questionPacket, answerName, rrType, rdata)
}

// decodeSVCBFrame extracts the frame from a service-binding RDATA produced by
// encodeFrameToSVCBRData. It skips the priority and (uncompressed) target name,
// then scans SvcParams for svcbFrameParamKey.
func decodeSVCBFrame(rData []byte) ([]byte, bool) {
	// priority(2) + at least the root target name(1).
	if len(rData) < 3 {
		return nil, false
	}
	off := 2 // skip SvcPriority

	// Skip the uncompressed TargetName (length-prefixed labels until a 0x00).
	for off < len(rData) {
		l := int(rData[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointers are not used here
			return nil, false
		}
		off += l
		if off > len(rData) {
			return nil, false
		}
	}

	// Walk SvcParams looking for our private key.
	for off+4 <= len(rData) {
		key := binary.BigEndian.Uint16(rData[off : off+2])
		vlen := int(binary.BigEndian.Uint16(rData[off+2 : off+4]))
		off += 4
		if off+vlen > len(rData) {
			return nil, false
		}
		if key == svcbFrameParamKey {
			return rData[off : off+vlen], true
		}
		off += vlen
	}
	return nil, false
}

// extractSVCBFrame returns the inflated packet from the first HTTPS/SVCB answer
// carrying our frame param, or ok=false when none is present.
func extractSVCBFrame(parsed Packet) (VpnProto.Packet, bool, error) {
	for _, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_HTTPS && ans.Type != Enums.DNS_RECORD_TYPE_SVCB {
			continue
		}
		raw, ok := decodeSVCBFrame(ans.RData)
		if !ok {
			continue
		}
		pkt, err := VpnProto.ParseInflated(raw)
		if err != nil {
			return VpnProto.Packet{}, true, err
		}
		return pkt, true, nil
	}
	return VpnProto.Packet{}, false, nil
}
