// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_txtchunk.go — encoding of the tunnel frame into length-prefixed TXT
// answer chunks (raw or base64) and extraction of the raw bytes back out of TXT
// answer RDATA. Split out of transport.go.
// ==============================================================================

package dnsparser

import (
	baseCodec "cottendns-go/internal/basecodec"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func buildTXTAnswerChunks(rawFrame []byte, baseEncode bool) ([][]byte, error) {
	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}

	if len(rawFrame) == 0 {
		return [][]byte{appendLengthPrefixedTXT(nil)}, nil
	}

	if len(rawFrame) <= maxChunk {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	header, err := VpnProto.Parse(rawFrame)
	if err != nil {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	headerLen := header.HeaderLength
	chunk0PrefixLen := 2
	maxChunk0Data := max(maxChunk-chunk0PrefixLen-headerLen, 0)

	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxChunk - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunks := make([][]byte, 0, totalChunks)
	chunk0DataLen := min(maxChunk0Data, len(header.Payload))
	rawChunk0 := make([]byte, 2+headerLen+chunk0DataLen)
	rawChunk0[0] = 0x00
	rawChunk0[1] = byte(totalChunks)
	copy(rawChunk0[2:], rawFrame[:headerLen])
	copy(rawChunk0[2+headerLen:], header.Payload[:chunk0DataLen])

	if !baseEncode {
		chunks = append(chunks, appendLengthPrefixedTXT(rawChunk0))
		return appendRawTXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
	}

	chunks = append(chunks, appendLengthPrefixedBase64TXT(rawChunk0))
	return appendBase64TXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
}

func buildTXTAnswerChunk(data []byte, baseEncode bool) []byte {
	if !baseEncode {
		return appendLengthPrefixedTXT(data)
	}
	return appendLengthPrefixedBase64TXT(data)
}

func appendRawTXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		chunks = append(chunks, buildLengthPrefixedTXTChunk(byte(chunkID), payload[cursor:end]))
		cursor = end
	}
	return chunks
}

func appendBase64TXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	rawChunk := make([]byte, 1+maxChunkNData)
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		rawChunk[0] = byte(chunkID)
		size := copy(rawChunk[1:], payload[cursor:end])
		chunks = append(chunks, appendLengthPrefixedBase64TXT(rawChunk[:1+size]))
		cursor = end
	}
	return chunks
}

func buildLengthPrefixedTXTChunk(prefix byte, data []byte) []byte {
	out := make([]byte, 2+len(data))
	out[0] = byte(1 + len(data))
	out[1] = prefix
	copy(out[2:], data)
	return out
}

func appendLengthPrefixedTXT(data []byte) []byte {
	if len(data) <= 255 {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out
	}

	parts := 1 + (len(data)-1)/255
	out := make([]byte, len(data)+parts)
	writeOffset := 0
	for start := 0; start < len(data); start += 255 {
		end := min(start+255, len(data))
		out[writeOffset] = byte(end - start)
		writeOffset++
		writeOffset += copy(out[writeOffset:], data[start:end])
	}
	return out
}

func appendLengthPrefixedBase64TXT(data []byte) []byte {
	encodedLen := baseCodec.EncodedRawBase64Len(len(data))
	out := make([]byte, 1+encodedLen)
	out[0] = byte(encodedLen)
	baseCodec.EncodeRawBase64Into(out[1:], data)
	return out
}

func extractTXTAnswerPayloads(parsed Packet) [][]byte {
	if len(parsed.Answers) == 0 {
		return nil
	}

	payloads := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_TXT {
			continue
		}
		raw := extractTXTBytes(answer.RData)
		if len(raw) == 0 {
			continue
		}
		payloads = append(payloads, raw)
	}
	return payloads
}

func extractTXTBytes(rData []byte) []byte {
	if len(rData) == 0 {
		return nil
	}
	if int(rData[0])+1 == len(rData) {
		return rData[1:]
	}

	totalLen := 0
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			totalLen += len(rData) - offset
			break
		}
		totalLen += size
		offset += size
	}

	if totalLen == 0 {
		return nil
	}

	out := make([]byte, totalLen)
	writeOffset := 0
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			writeOffset += copy(out[writeOffset:], rData[offset:])
			break
		}
		writeOffset += copy(out[writeOffset:], rData[offset:offset+size])
		offset += size
	}
	return out
}
