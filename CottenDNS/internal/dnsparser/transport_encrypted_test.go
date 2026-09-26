package dnsparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"cottendns-go/internal/compression"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestEncryptedResponsesRoundTripAllCarriers(t *testing.T) {
	carriers := []struct{ qtype, answerType uint16 }{
		{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_TXT},
		{Enums.DNS_RECORD_TYPE_A, Enums.DNS_RECORD_TYPE_A},
		{Enums.DNS_RECORD_TYPE_AAAA, Enums.DNS_RECORD_TYPE_AAAA},
		{Enums.DNS_RECORD_TYPE_MX, Enums.DNS_RECORD_TYPE_CNAME},
		{Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_NULL},
		{Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_HTTPS},
		{Enums.DNS_RECORD_TYPE_SVCB, Enums.DNS_RECORD_TYPE_SVCB},
	}
	for _, method := range security.AllMethods {
		for _, carrier := range carriers {
			for _, baseEncoded := range []bool{false, true} {
				t.Run(fmt.Sprintf("method%d/%s/base64%v", method, Enums.DNSRecordTypeName(carrier.qtype), baseEncoded), func(t *testing.T) {
					codec, err := security.NewCodec(method, "response-secret")
					if err != nil {
						t.Fatal(err)
					}
					query := buildDNSQuery(4, "abc."+cnameTestDomain, carrier.qtype, true)
					in := VpnProto.Packet{SessionID: 300, SessionCookie: 17, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 12, SequenceNum: 23, TotalFragments: 1, Payload: []byte("private downstream payload")}
					response, err := BuildEncryptedVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, baseEncoded, true, true, codec)
					if err != nil {
						t.Fatal(err)
					}
					if got := answerTypeOf(t, response); got != carrier.answerType {
						t.Fatalf("carrier: got %d want %d", got, carrier.answerType)
					}
					out, err := ExtractEncryptedVPNResponseMatching(response, baseEncoded, []string{cnameTestDomain}, codec)
					if err != nil {
						t.Fatal(err)
					}
					if out.SessionID != in.SessionID || out.SessionCookie != in.SessionCookie || out.PacketType != in.PacketType || out.StreamID != in.StreamID || out.SequenceNum != in.SequenceNum || !bytes.Equal(out.Payload, in.Payload) {
						t.Fatalf("round trip mismatch: %+v", out)
					}
					if method != 0 && bytes.Contains(response, in.Payload) {
						t.Fatal("plaintext payload leaked into response")
					}
				})
			}
		}
	}
}

func TestEncryptedTXTReordersChunksAndRejectsDamage(t *testing.T) {
	codec, err := security.NewCodec(3, "response-secret")
	if err != nil {
		t.Fatal(err)
	}
	query := buildDNSQuery(4, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_TXT, true)
	in := VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 2, TotalFragments: 1, Payload: bytes.Repeat([]byte("private downstream data"), 80)}
	for _, baseEncoded := range []bool{false, true} {
		response, err := BuildEncryptedVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, baseEncoded, true, true, codec)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePacket(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Answers) < 2 {
			t.Fatal("test must produce several TXT chunks")
		}
		chunks := make([][]byte, len(parsed.Answers))
		for i, answer := range parsed.Answers {
			chunks[len(chunks)-1-i] = append([]byte(nil), answer.RData...)
		}
		chunks = append(chunks, chunks[0]) // identical duplicate is harmless
		reordered, err := BuildTXTResponsePacket(query, "abc."+cnameTestDomain, chunks)
		if err != nil {
			t.Fatal(err)
		}
		out, err := ExtractEncryptedVPNResponseMatching(reordered, baseEncoded, []string{cnameTestDomain}, codec)
		if err != nil || !bytes.Equal(out.Payload, in.Payload) {
			t.Fatalf("reordered response failed: %v", err)
		}
		missing, err := BuildTXTResponsePacket(query, "abc."+cnameTestDomain, chunks[1:len(chunks)-1])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractEncryptedVPNResponseMatching(missing, baseEncoded, []string{cnameTestDomain}, codec); err == nil {
			t.Fatal("missing chunk accepted")
		}
		chunks[len(chunks)-1] = append([]byte(nil), chunks[0]...)
		chunks[len(chunks)-1][len(chunks[0])-1] ^= 1
		conflicting, err := BuildTXTResponsePacket(query, "abc."+cnameTestDomain, chunks)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractEncryptedVPNResponseMatching(conflicting, baseEncoded, []string{cnameTestDomain}, codec); err == nil {
			t.Fatal("conflicting duplicate accepted")
		}
	}
}

func TestEncryptedResponseRejectsPlaintextWrongKeyAndTampering(t *testing.T) {
	codec, _ := security.NewCodec(3, "response-secret")
	wrongCodec, _ := security.NewCodec(3, "wrong-secret")
	query := buildDNSQuery(4, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_NULL, true)
	in := VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_PONG, Payload: bytes.Repeat([]byte("compress this private payload"), 20), CompressionType: compression.TypeZLIB}
	response, err := BuildEncryptedVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true, true, codec)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ExtractEncryptedVPNResponseMatching(response, false, []string{cnameTestDomain}, codec)
	if err != nil || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("compressed round trip: %v", err)
	}
	if _, err := ExtractEncryptedVPNResponseMatching(response, false, []string{cnameTestDomain}, wrongCodec); err == nil {
		t.Fatal("wrong key accepted")
	}
	parsed, _ := ParsePacket(response)
	response[parsed.Answers[0].rdataOffset] ^= 1
	if _, err := ExtractEncryptedVPNResponseMatching(response, false, []string{cnameTestDomain}, codec); err == nil {
		t.Fatal("tampered response accepted")
	}
	plaintext, err := BuildVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, in, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEncryptedVPNResponseMatching(plaintext, false, []string{cnameTestDomain}, codec); err == nil {
		t.Fatal("plaintext fallback accepted")
	}
}

func TestSmallCarrierCapacityIncludesCiphertextAndDNSWireBudget(t *testing.T) {
	codec, _ := security.NewCodec(3, "response-secret")
	for _, qType := range []uint16{Enums.DNS_RECORD_TYPE_A, Enums.DNS_RECORD_TYPE_AAAA, Enums.DNS_RECORD_TYPE_MX} {
		for _, edns := range []bool{false, true} {
			for _, encrypted := range []bool{false, true} {
				name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 45) + "." + cnameTestDomain
				query := buildDNSQuery(7, name, qType, edns)
				capacity := MatchingFrameCapacity(query, cnameTestDomain, true, true)
				in := VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_PONG}
				header, err := VpnProto.BuildRaw(VpnProto.BuildOptions{SessionID: in.SessionID, PacketType: in.PacketType})
				if err != nil {
					t.Fatal(err)
				}
				payloadSize := capacity - len(header)
				if encrypted {
					payloadSize -= codec.CiphertextOverhead()
				}
				if payloadSize <= 0 {
					t.Fatalf("unexpected capacity %d", capacity)
				}
				in.Payload = bytes.Repeat([]byte{0x5a}, payloadSize)
				var response []byte
				if encrypted {
					response, err = BuildEncryptedVPNResponsePacketMatchingQuery(query, name, cnameTestDomain, in, false, true, true, codec)
				} else {
					response, err = BuildVPNResponsePacketMatchingQuery(query, name, cnameTestDomain, in, false, true, true)
				}
				if err != nil {
					t.Fatal(err)
				}
				limit := 512
				if edns {
					limit = 4096
				}
				if len(response) > limit {
					t.Fatalf("qtype=%d encrypted=%v edns=%v: response %d exceeds %d", qType, encrypted, edns, len(response), limit)
				}
				if got := answerTypeOf(t, response); got == Enums.DNS_RECORD_TYPE_TXT {
					t.Fatalf("frame at matching capacity fell back to TXT: qtype=%d encrypted=%v edns=%v", qType, encrypted, edns)
				}
				var out VpnProto.Packet
				if encrypted {
					out, err = ExtractEncryptedVPNResponseMatching(response, false, []string{cnameTestDomain}, codec)
				} else {
					out, err = ExtractVPNResponseMatching(response, false, []string{cnameTestDomain})
				}
				if err != nil || !bytes.Equal(out.Payload, in.Payload) {
					t.Fatalf("at-capacity round trip failed: %v", err)
				}
			}
		}
	}
}

func TestEncryptedResponseBindsQuestionButAllowsResolverRewrites(t *testing.T) {
	codec, _ := security.NewCodec(3, "response-secret")
	query := buildDNSQuery(7, "abc."+cnameTestDomain, Enums.DNS_RECORD_TYPE_NULL, false)
	response, err := BuildEncryptedVPNResponsePacketMatchingQuery(query, "abc."+cnameTestDomain, cnameTestDomain, VpnProto.Packet{SessionID: 300, PacketType: Enums.PACKET_PONG}, false, true, true, codec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ExtractEncryptedVPNResponseMatching(response, false, []string{cnameTestDomain}, codec)
	if err != nil || !decoded.HasDownstreamCiphertext {
		t.Fatalf("missing ciphertext identity: %v", err)
	}
	rewritten := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(rewritten[:2], 0x9876)
	rewritten[dnsHeaderSize+1] = 'A'
	rewritten[dnsHeaderSize+2] = 'B'
	rewritten[dnsHeaderSize+3] = 'C'
	accepted, err := ExtractEncryptedVPNResponseMatching(rewritten, false, []string{cnameTestDomain}, codec)
	if err != nil || accepted.DownstreamCiphertextHash != decoded.DownstreamCiphertextHash {
		t.Fatalf("resolver ID/case rewrite changed authentication or identity: %v", err)
	}
	parsed, _ := ParsePacketLite(query)
	for _, offset := range []int{dnsHeaderSize + 1, parsed.QuestionEndOffset - 3, parsed.QuestionEndOffset - 1} {
		rewrapped := append([]byte(nil), response...)
		rewrapped[offset] ^= 1
		if _, err := ExtractEncryptedVPNResponseMatching(rewrapped, false, []string{cnameTestDomain}, codec); err == nil {
			t.Fatalf("rewrapped response accepted after question byte %d changed", offset)
		}
	}
}
