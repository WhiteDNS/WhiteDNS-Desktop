package client

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

type mtuCarrierExchange struct {
	exchangeFn func([]byte) ([]byte, error)
}

func (x mtuCarrierExchange) exchange(query []byte, _ time.Duration) ([]byte, error) {
	return x.exchangeFn(query)
}
func (mtuCarrierExchange) Close() error { return nil }

func TestMTUSearchPinsCarrierAndFallsBackWithoutScoring(t *testing.T) {
	for _, download := range []bool{false, true} {
		name := "upload"
		if download {
			name = "download"
		}
		t.Run(name, func(t *testing.T) {
			c := createTestClient(t)
			var err error
			c.codec, err = security.NewCodec(0, "")
			if err != nil {
				t.Fatal(err)
			}
			c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_HTTPS}
			c.carrier = newCarrierSelector(c.queryTypes, nil)
			c.cfg.MinUploadMTU, c.cfg.MaxUploadMTU = 16, 80
			c.cfg.MinDownloadMTU, c.cfg.MaxDownloadMTU = 16, 128
			c.cfg.MTUProbeSamples = 3
			c.cfg.MTUMaxLoss = 0
			c.mtuTestRetries = 1
			conn := &Connection{Domain: "example.com", ResolverLabel: "test"}
			var seen []uint16
			transport := mtuCarrierExchange{exchangeFn: func(query []byte) ([]byte, error) {
				dns, err := DnsParser.ParsePacket(query)
				if err != nil {
					return nil, err
				}
				question := dns.Questions[0]
				seen = append(seen, question.Type)
				if question.Type == Enums.DNS_RECORD_TYPE_TXT {
					return nil, errors.New("blocked carrier")
				}
				labels := strings.TrimSuffix(strings.TrimSuffix(question.Name, "."), "."+conn.Domain)
				request, err := VpnProto.ParseFromLabels(strings.ReplaceAll(labels, ".", ""), c.codec)
				if err != nil {
					return nil, err
				}
				size := len(request.Payload)
				responseType := uint8(Enums.PACKET_MTU_UP_RES)
				responseSize := 6
				if request.PacketType == Enums.PACKET_MTU_DOWN_REQ {
					size = int(binary.BigEndian.Uint16(request.Payload[1+mtuProbeCodeLength:]))
					responseType = Enums.PACKET_MTU_DOWN_RES
					responseSize = size
				}
				payload := make([]byte, responseSize)
				copy(payload, request.Payload[1:1+mtuProbeCodeLength])
				binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(size))
				return DnsParser.BuildVPNResponsePacketMatchingQuery(query, question.Name, conn.Domain, VpnProto.Packet{
					SessionID: 255, PacketType: responseType, Payload: payload,
				}, false, true, true)
			}}
			if download {
				ok, mtu, _, _, err := c.testDownloadMTU(context.Background(), conn, transport, 32)
				if err != nil || !ok || mtu != 128 {
					t.Fatalf("download: ok=%v mtu=%d err=%v", ok, mtu, err)
				}
			} else {
				ok, mtu, _, _, _, err := c.testUploadMTU(context.Background(), conn, transport, 80)
				if err != nil || !ok || mtu != 80 {
					t.Fatalf("upload: ok=%v mtu=%d err=%v", ok, mtu, err)
				}
			}
			switched := false
			for _, qType := range seen {
				if qType == Enums.DNS_RECORD_TYPE_HTTPS {
					switched = true
				}
				if switched && qType == Enums.DNS_RECORD_TYPE_TXT {
					t.Fatalf("search mixed carriers: %v", seen)
				}
			}
			if len(seen) < 3 || seen[0] != Enums.DNS_RECORD_TYPE_TXT || seen[1] != Enums.DNS_RECORD_TYPE_TXT || !switched {
				t.Fatalf("want one failed search followed by a successful alternate: %v", seen)
			}
			for i := range c.carrier.sent {
				if n := c.carrier.sent[i].Load(); n != 0 {
					t.Fatalf("MTU probes polluted carrier %d: sent=%d", i, n)
				}
			}
		})
	}
}

func TestDownloadMTURejectsOversizedSmallCarrierBeforeSending(t *testing.T) {
	for _, method := range []int{0, 2, 3} {
		c := createTestClient(t)
		var err error
		c.codec, err = security.NewCodec(method, "testkey")
		if err != nil {
			t.Fatal(err)
		}
		c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_CNAME}
		conn := &Connection{Domain: "example.com", ResolverLabel: "test"}
		query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		capacity := DnsParser.MatchingFrameCapacity(query, conn.Domain, true, true)
		candidate := capacity - VpnProto.MaxHeaderRawSize() - mtuCryptoOverhead(method) + 1
		transport := mtuCarrierExchange{exchangeFn: func([]byte) ([]byte, error) {
			t.Fatalf("method %d sent an MTU probe requiring an oversized TXT fallback", method)
			return nil, nil
		}}
		ok, _, err := c.sendDownloadMTUProbe(context.Background(), conn, transport, candidate, 32, mtuProbeOptions{Quiet: true})
		if err != nil || ok {
			t.Fatalf("method %d: ok=%v err=%v", method, ok, err)
		}
	}
}

func TestDownloadMTUFallsBackToWorkingSmallCarrier(t *testing.T) {
	c := createTestClient(t)
	var err error
	c.codec, err = security.NewCodec(0, "")
	if err != nil {
		t.Fatal(err)
	}
	c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_TXT}
	c.cfg.MinDownloadMTU, c.cfg.MaxDownloadMTU = 16, 512
	c.cfg.MTUProbeSamples = 1
	c.mtuTestRetries = 1
	conn := &Connection{Domain: "example.com", ResolverLabel: "test"}
	var seen []uint16
	var capacity int
	transport := mtuCarrierExchange{exchangeFn: func(query []byte) ([]byte, error) {
		dns, err := DnsParser.ParsePacket(query)
		if err != nil {
			return nil, err
		}
		question := dns.Questions[0]
		seen = append(seen, question.Type)
		if question.Type == Enums.DNS_RECORD_TYPE_TXT {
			return nil, errors.New("blocked carrier")
		}
		capacity = DnsParser.MatchingFrameCapacity(query, conn.Domain, true, true)
		labels := strings.TrimSuffix(strings.TrimSuffix(question.Name, "."), "."+conn.Domain)
		request, err := VpnProto.ParseFromLabels(strings.ReplaceAll(labels, ".", ""), c.codec)
		if err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(request.Payload[1+mtuProbeCodeLength:]))
		if size < VpnProto.MinMTUDownloadProbePayload {
			return nil, errors.New("server rejects undersized probe payload")
		}
		payload := make([]byte, size)
		copy(payload, request.Payload[1:1+mtuProbeCodeLength])
		binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(size))
		return DnsParser.BuildVPNResponsePacketMatchingQuery(query, question.Name, conn.Domain, VpnProto.Packet{
			SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_RES, Payload: payload,
		}, false, true, true)
	}}
	ok, mtu, _, _, err := c.testDownloadMTU(context.Background(), conn, transport, 32)
	if err != nil || !ok || mtu != capacity-VpnProto.MaxHeaderRawSize() {
		t.Fatalf("small-carrier fallback: ok=%v mtu=%d capacity=%d err=%v", ok, mtu, capacity, err)
	}
	if len(seen) < 3 || seen[0] != Enums.DNS_RECORD_TYPE_TXT || seen[1] != Enums.DNS_RECORD_TYPE_TXT || seen[2] != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("want bulk-first then small carrier fallback, got %v", seen)
	}
}

func TestResolverMTURecheckTriesAlternateCarrier(t *testing.T) {
	c := createTestClient(t)
	var err error
	c.codec, err = security.NewCodec(0, "")
	if err != nil {
		t.Fatal(err)
	}
	c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}
	c.syncedUploadMTU, c.syncedDownloadMTU = 32, 64
	c.mtuTestRetries = 1
	conn := &Connection{Domain: "example.com", ResolverLabel: "test"}
	var uploadSeen, downloadSeen bool
	transport := mtuCarrierExchange{exchangeFn: func(query []byte) ([]byte, error) {
		dns, err := DnsParser.ParsePacket(query)
		if err != nil {
			return nil, err
		}
		question := dns.Questions[0]
		if question.Type == Enums.DNS_RECORD_TYPE_TXT {
			return nil, errors.New("blocked carrier")
		}
		labels := strings.TrimSuffix(strings.TrimSuffix(question.Name, "."), "."+conn.Domain)
		request, err := VpnProto.ParseFromLabels(strings.ReplaceAll(labels, ".", ""), c.codec)
		if err != nil {
			return nil, err
		}
		size := len(request.Payload)
		responseSize, responseType := 6, uint8(Enums.PACKET_MTU_UP_RES)
		if request.PacketType == Enums.PACKET_MTU_DOWN_REQ {
			downloadSeen = true
			size = int(binary.BigEndian.Uint16(request.Payload[1+mtuProbeCodeLength:]))
			responseSize, responseType = size, Enums.PACKET_MTU_DOWN_RES
		} else {
			uploadSeen = true
		}
		payload := make([]byte, responseSize)
		copy(payload, request.Payload[1:1+mtuProbeCodeLength])
		binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(size))
		return DnsParser.BuildVPNResponsePacketMatchingQuery(query, question.Name, conn.Domain, VpnProto.Packet{
			SessionID: 255, PacketType: responseType, Payload: payload,
		}, false, true, true)
	}}
	if !c.recheckResolverMTU(context.Background(), conn, transport) || !uploadSeen || !downloadSeen {
		t.Fatalf("alternate carrier must restore resolver: upload=%v download=%v", uploadSeen, downloadSeen)
	}
}

func TestDownloadMTURejectsDisabledAAAATXTFallback(t *testing.T) {
	c := createTestClient(t)
	c.codec, _ = security.NewCodec(0, "")
	c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_AAAA}
	c.ednsUDPSize = 1232
	conn := &Connection{Domain: "example.com", ResolverLabel: "test"}
	seen := false
	transport := mtuCarrierExchange{exchangeFn: func(query []byte) ([]byte, error) {
		seen = true
		dns, err := DnsParser.ParsePacket(query)
		if err != nil {
			return nil, err
		}
		question := dns.Questions[0]
		labels := strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(question.Name, "."), "."+conn.Domain), ".", "")
		request, err := VpnProto.ParseFromLabels(labels, c.codec)
		if err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(request.Payload[5:7]))
		payload := make([]byte, size)
		copy(payload, request.Payload[1:5])
		binary.BigEndian.PutUint16(payload[4:6], uint16(size))
		response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(query, question.Name, conn.Domain, VpnProto.Packet{SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_RES, Payload: payload}, false, false, false)
		if err == nil {
			parsed, _ := DnsParser.ParsePacket(response)
			if len(parsed.Answers) == 0 || parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_TXT {
				t.Fatal("test did not exercise TXT fallback")
			}
		}
		return response, err
	}}
	ok, _, err := c.sendDownloadMTUProbe(context.Background(), conn, transport, 300, 32, mtuProbeOptions{Quiet: true})
	if err != nil || ok || !seen {
		t.Fatalf("TXT fallback counted as AAAA capacity: ok=%v seen=%v err=%v", ok, seen, err)
	}
}
