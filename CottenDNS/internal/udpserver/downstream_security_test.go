package udpserver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func secureTestQuery(t *testing.T, codec *security.Codec, qtype uint16, opts VpnProto.BuildOptions) []byte {
	t.Helper()
	encoded, err := VpnProto.BuildEncoded(opts, codec)
	if err != nil {
		t.Fatal(err)
	}
	name, err := DnsParser.BuildTunnelQuestionName("v.example.com", encoded)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTXTQuestionPacket(name, qtype, 1232)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func TestEncryptedDownstreamDynamicSessionAndProbes(t *testing.T) {
	for method := 1; method <= 5; method++ {
		for _, base64 := range []bool{false, true} {
			t.Run(fmt.Sprintf("method%d/base64%v", method, base64), func(t *testing.T) {
				s, _ := newDynamicTransportTestServer(t, 5, method)
				s.cfg.ARecordDataDelivery = true
				s.cfg.AAAARecordDataDelivery = true
				codec, _ := security.NewCodec(method, "transport-matrix-shared-key")
				mode := security.DownstreamEncryptedFlag
				if base64 {
					mode |= 1
				}
				extract := func(response []byte) VpnProto.Packet {
					t.Helper()
					p, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, base64, []string{"v.example.com"}, codec)
					if err != nil {
						t.Fatalf("encrypted response: %v", err)
					}
					return p
				}
				for _, qtype := range []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_A, Enums.DNS_RECORD_TYPE_AAAA, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_SVCB} {
					q := secureTestQuery(t, codec, qtype, VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{mode, 1, 2, 3, 4}})
					prepared, ok := s.prepareIngressPacket(q)
					if !ok {
						t.Fatal("secure probe rejected at admission")
					}
					p := extract(s.safeHandlePreparedIngress(q, prepared))
					if p.PacketType != Enums.PACKET_MTU_UP_RES {
						t.Fatal("wrong up response")
					}
				}
				down := []byte{mode, 1, 2, 3, 4, 1, 44}
				p := extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_REQ, Payload: down})))
				if p.PacketType != Enums.PACKET_MTU_DOWN_RES || len(p.Payload) != 300 {
					t.Fatal("down probe size changed")
				}
				init := []byte{mode, 0, 0, 100, 2, 0, 5, 6, 7, 8}
				p = extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: init})))
				if p.PacketType != Enums.PACKET_SESSION_ACCEPT {
					t.Fatal("wrong accept")
				}
				sid := binary.BigEndian.Uint16(p.Payload[:2])
				cookie := p.Payload[2]
				record, ok := s.sessions.Get(sid)
				if !ok || record.Codec.Method() != method {
					t.Fatal("session decoder not retained")
				}
				ping := VpnProto.BuildOptions{SessionID: sid, SessionCookie: cookie, PacketType: Enums.PACKET_PING}
				p = extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_AAAA, ping)))
				if p.PacketType != Enums.PACKET_PONG || p.SessionCookie != cookie {
					t.Fatal("wrong encrypted pong")
				}
				body := bytes.Repeat([]byte{0xa5}, 400)
				if !s.queueSessionPacket(sid, VpnProto.Packet{PacketType: Enums.PACKET_DNS_QUERY_RES, Payload: body}) {
					t.Fatal("queue data")
				}
				p = extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_CNAME, ping)))
				if p.PacketType != Enums.PACKET_PONG {
					t.Fatal("oversize encrypted frame escaped small carrier")
				}
				p = extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, ping)))
				if p.PacketType != Enums.PACKET_DNS_QUERY_RES || !bytes.Equal(p.Payload, body) {
					t.Fatal("small carrier lost queued bulk frame")
				}
				// A valid decoder for another method cannot use the live session.
				wrong, _ := security.NewCodec(1, "transport-matrix-shared-key")
				if method == 1 {
					wrong, _ = security.NewCodec(5, "transport-matrix-shared-key")
				}
				before := record.lastActivity()
				response := s.safeHandlePacket(secureTestQuery(t, wrong, Enums.DNS_RECORD_TYPE_TXT, ping))
				if _, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, base64, []string{"v.example.com"}, codec); err == nil {
					t.Fatal("cross-codec session accepted")
				}
				if record.lastActivity() != before {
					t.Fatal("cross-codec query touched session")
				}
				_, ok = s.sessions.Close(sid, time.Now(), time.Minute)
				if !ok {
					t.Fatal("close")
				}
				p = extract(s.safeHandlePacket(secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, ping)))
				if p.PacketType != Enums.PACKET_ERROR_DROP {
					t.Fatal("closed session did not encrypt error")
				}
			})
		}
	}
}
