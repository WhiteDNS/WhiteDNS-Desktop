package dnsparser

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	baseCodec "cottendns-go/internal/basecodec"
	"cottendns-go/internal/compression"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

// BuildEncryptedVPNResponsePacketMatchingQuery encrypts the complete compressed
// frame before placing it into the selected DNS carrier. Session identifiers,
// packet metadata and payload are all covered by the downstream codec.
func BuildEncryptedVPNResponsePacketMatchingQuery(questionPacket []byte, answerName, answerDomain string, packet VpnProto.Packet, baseEncode, allowARecord, allowAAAARecord bool, codec *security.Codec) ([]byte, error) {
	raw, err := VpnProto.BuildRawAuto(VpnProto.BuildOptions{
		SessionID: packet.SessionID, PacketType: packet.PacketType,
		SessionCookie: packet.SessionCookie, StreamID: packet.StreamID,
		SequenceNum: packet.SequenceNum, FragmentID: packet.FragmentID,
		TotalFragments: packet.TotalFragments, CompressionType: packet.CompressionType,
		Payload: packet.Payload, LegacySessionID: packet.LegacySessionID,
	}, compression.DefaultMinSize)
	if err != nil {
		return nil, err
	}
	question, err := ParsePacketLite(questionPacket)
	if err != nil || !question.HasQuestion {
		return nil, ErrInvalidQuestion
	}
	ciphertext, err := codec.EncryptDownstream(raw, downstreamQuestionContext(question.FirstQuestion))
	if err != nil {
		return nil, err
	}
	if response, matched, err := buildMatchingRawResponse(questionPacket, answerName, answerDomain, ciphertext, allowARecord, allowAAAARecord); matched || err != nil {
		return response, err
	}
	chunks, err := buildEncryptedTXTAnswerChunks(ciphertext, baseEncode)
	if err != nil {
		return nil, err
	}
	return BuildTXTResponsePacket(questionPacket, answerName, chunks)
}

// ExtractEncryptedVPNResponseMatching never falls back to plaintext. It
// decrypts the assembled ciphertext (authenticating with AEAD codecs) before
// parsing or decompressing VPN data, using the downstream key.
func ExtractEncryptedVPNResponseMatching(packet []byte, baseEncoded bool, domains []string, codec *security.Codec) (VpnProto.Packet, error) {
	parsed, err := parseTunnelResponse(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	ciphertext, matched, err := extractMatchingRawResponse(packet, parsed, domains)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	if !matched {
		answers := extractTXTAnswerPayloads(parsed)
		if len(answers) == 0 {
			return VpnProto.Packet{}, ErrTXTAnswerMissing
		}
		ciphertext, err = assembleEncryptedTXTAnswers(answers, baseEncoded)
		if err != nil {
			return VpnProto.Packet{}, err
		}
	}
	if len(parsed.Questions) == 0 {
		return VpnProto.Packet{}, ErrInvalidQuestion
	}
	raw, err := codec.DecryptDownstream(ciphertext, downstreamQuestionContext(parsed.Questions[0]))
	if err != nil {
		return VpnProto.Packet{}, err
	}
	decoded, err := VpnProto.ParseInflated(raw)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	decoded.DownstreamCiphertextHash = sha256.Sum256(ciphertext)
	decoded.HasDownstreamCiphertext = true
	return decoded, nil
}

// Bind authenticated responses to the query they answer. Name parsing already
// lowercases ASCII labels, so recursor ID changes and 0x20 case randomization
// do not affect authentication. A captured reply cannot be rewrapped under a
// different encrypted upstream query with the same long-lived tunnel key.
func downstreamQuestionContext(question Question) []byte {
	context := make([]byte, 0, len(question.Name)+5)
	context = append(context, question.Name...)
	context = append(context, 0)
	context = binary.BigEndian.AppendUint16(context, question.Type)
	return binary.BigEndian.AppendUint16(context, question.Class)
}

// Ciphertext has no readable VPN header. Each TXT chunk has its own index and
// total count so recursive resolver reordering and identical duplicates are
// harmless, while missing or conflicting chunks are rejected before decryption.
func buildEncryptedTXTAnswerChunks(ciphertext []byte, baseEncoded bool) ([][]byte, error) {
	chunkSize := maxTXTAnswerPayload - 2
	if baseEncoded {
		chunkSize = maxTXTEncodedChunk - 2
	}
	count := (len(ciphertext) + chunkSize - 1) / chunkSize
	if count == 0 || count > 255 {
		return nil, ErrTXTAnswerTooLarge
	}
	chunks := make([][]byte, 0, count)
	for i, start := 0, 0; start < len(ciphertext); i, start = i+1, start+chunkSize {
		end := min(start+chunkSize, len(ciphertext))
		chunk := make([]byte, 2+end-start)
		chunk[0], chunk[1] = byte(i), byte(count)
		copy(chunk[2:], ciphertext[start:end])
		chunks = append(chunks, buildTXTAnswerChunk(chunk, baseEncoded))
	}
	return chunks, nil
}

func assembleEncryptedTXTAnswers(answers [][]byte, baseEncoded bool) ([]byte, error) {
	var chunks [255][]byte
	count, seen, size := 0, 0, 0
	for _, chunk := range answers {
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(chunk)
			if err != nil {
				return nil, err
			}
			chunk = decoded
		}
		if len(chunk) < 3 || chunk[1] == 0 || chunk[0] >= chunk[1] {
			return nil, ErrTXTAnswerMalformed
		}
		if count == 0 {
			count = int(chunk[1])
		} else if count != int(chunk[1]) {
			return nil, ErrTXTAnswerMalformed
		}
		index := int(chunk[0])
		if chunks[index] != nil {
			if !bytes.Equal(chunks[index], chunk[2:]) {
				return nil, ErrTXTAnswerMalformed
			}
			continue
		}
		chunks[index] = chunk[2:]
		seen++
		size += len(chunk) - 2
	}
	if count == 0 || seen != count {
		return nil, ErrTXTAnswerMalformed
	}
	ciphertext := make([]byte, 0, size)
	for i := 0; i < count; i++ {
		ciphertext = append(ciphertext, chunks[i]...)
	}
	return ciphertext, nil
}
