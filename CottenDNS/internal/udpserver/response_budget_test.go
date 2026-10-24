package udpserver

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func budgetTestQuery(t *testing.T, codec *security.Codec, edns uint16, packet VpnProto.BuildOptions) []byte {
	t.Helper()
	encoded, err := VpnProto.BuildEncoded(packet, codec)
	if err != nil {
		t.Fatal(err)
	}
	name, err := DnsParser.BuildTunnelQuestionName("v.example.com", encoded)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, edns)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func budgetTestSession(t *testing.T) (*Server, *sessionRecord, *security.Codec) {
	t.Helper()
	s, _ := newDynamicTransportTestServer(t, 5, 5)
	codec := s.codecs[s.preferredCodec.Load()]
	payload := []byte{security.DownstreamEncryptedFlag, 0, 0, 100, 16, 0, 1, 2, 3, 4}
	record, _, err := s.sessions.findOrCreate(payload, 0, 0, 8, false, codec)
	if err != nil || record == nil {
		t.Fatal("create session", err)
	}
	t.Cleanup(func() {
		if closed, ok := s.sessions.Close(record.ID, time.Now(), 0); ok {
			s.cleanupClosedSession(record.ID, closed)
		}
	})
	return s, record, codec
}

func TestResponseBudgetRetainsQueuedPayloadAcrossMixedUDPAndTCP(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "larger_udp", true: "tcp"}[tcp], func(t *testing.T) {
			s, record, codec := budgetTestSession(t)
			payload := make([]byte, 2800)
			for i := range payload {
				payload[i] = byte(i*73 + i/251)
			}
			if !s.queueMainSessionPacket(record.ID, VpnProto.Packet{PacketType: Enums.PACKET_DNS_QUERY_RES, SequenceNum: 7, TotalFragments: 1, Payload: payload}) {
				t.Fatal("queue")
			}
			poll := func(edns uint16, tcp bool) VpnProto.Packet {
				t.Helper()
				query := budgetTestQuery(t, codec, edns, VpnProto.BuildOptions{SessionID: record.ID, SessionCookie: record.Cookie, PacketType: Enums.PACKET_PING})
				var response []byte
				if tcp {
					response = s.safeHandlePacketTCP(query)
				} else {
					response = s.safeHandlePacket(query)
					if len(response) > max(512, int(edns)) {
						t.Fatal("UDP budget exceeded", len(response))
					}
				}
				packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, codec)
				if err != nil {
					t.Fatal(err)
				}
				return packet
			}
			for _, size := range []uint16{512, 1232, 512} {
				if packet := poll(size, false); packet.PacketType != Enums.PACKET_PONG {
					t.Fatal("oversized payload was removed", packet.PacketType)
				}
			}
			if packet := poll(map[bool]uint16{false: 4096, true: 512}[tcp], tcp); packet.PacketType != Enums.PACKET_DNS_QUERY_RES || !bytes.Equal(packet.Payload, payload) {
				t.Fatal("retained payload lost or changed")
			}
			record.mu.RLock()
			stillBlocked := !record.udpBudgetBlockedSince.IsZero()
			record.mu.RUnlock()
			if stillBlocked {
				t.Fatal("healthy larger path did not clear stall recovery timer")
			}
		})
	}
}

func TestResponseBudgetSessionNegotiationPreservesTCP(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			s, _ := newDynamicTransportTestServer(t, 5, 5)
			codec, _ := security.NewCodec(5, "transport-matrix-shared-key")
			init := []byte{security.DownstreamEncryptedFlag, 0, 0, 100, 16, 0, 9, 8, 7, 6}
			query := budgetTestQuery(t, codec, 512, VpnProto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: init})
			var response []byte
			if tcp {
				response = s.safeHandlePacketTCP(query)
			} else {
				response = s.safeHandlePacket(query)
			}
			packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, codec)
			if err != nil || packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
				t.Fatal("handshake", err)
			}
			id := binary.BigEndian.Uint16(packet.Payload[:2])
			record, ok := s.sessions.Get(id)
			if !ok {
				t.Fatal("session absent")
			}
			t.Cleanup(func() {
				if closed, ok := s.sessions.Close(id, time.Now(), 0); ok {
					s.cleanupClosedSession(id, closed)
				}
			})
			if tcp && record.DownloadMTUBytes != 4096 {
				t.Fatal("TCP session incorrectly received UDP clamp", record.DownloadMTUBytes)
			}
			if !tcp && (record.DownloadMTUBytes <= 0 || record.DownloadMTUBytes >= 512) {
				t.Fatal("UDP session did not negotiate safe MTU", record.DownloadMTUBytes)
			}
			if s.clientPolicy.MaxDownloadMTU != 0 || s.cfg.MaxAllowedClientDownloadMTU != 0 {
				t.Fatal("negotiation changed server settings")
			}
		})
	}
}

func TestResponseBudgetPersistentShrinkExplicitlyResetsAndRenegotiates(t *testing.T) {
	s, record, codec := budgetTestSession(t)
	if !s.queueMainSessionPacket(record.ID, VpnProto.Packet{PacketType: Enums.PACKET_DNS_QUERY_RES, SequenceNum: 7, TotalFragments: 1, Payload: make([]byte, 2800)}) {
		t.Fatal("queue")
	}
	poll := func() VpnProto.Packet {
		query := budgetTestQuery(t, codec, 512, VpnProto.BuildOptions{SessionID: record.ID, SessionCookie: record.Cookie, PacketType: Enums.PACKET_PING})
		packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(s.safeHandlePacket(query), false, []string{"v.example.com"}, codec)
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}
	if poll().PacketType != Enums.PACKET_PONG {
		t.Fatal("first small poll must retain")
	}
	record.mu.Lock()
	record.udpBudgetBlockedSince = time.Now().Add(-udpBudgetStallTimeout - time.Second)
	record.mu.Unlock()
	if poll().PacketType != Enums.PACKET_ERROR_DROP {
		t.Fatal("persistent small path did not request explicit recovery")
	}
	if s.sessions.HasActive(record.ID) {
		t.Fatal("unusable session retained after reset")
	}
	init := []byte{security.DownstreamEncryptedFlag, 0, 0, 100, 16, 0, 9, 8, 7, 6}
	query := budgetTestQuery(t, codec, 512, VpnProto.BuildOptions{PacketType: Enums.PACKET_SESSION_INIT, Payload: init})
	accepted, err := DnsParser.ExtractEncryptedVPNResponseMatching(s.safeHandlePacket(query), false, []string{"v.example.com"}, codec)
	if err != nil || accepted.PacketType != Enums.PACKET_SESSION_ACCEPT {
		t.Fatal("recovery handshake", err)
	}
	policy, ok := VpnProto.DecodeSessionAcceptPolicy(accepted.Payload, false)
	if !ok || policy.MaxDownloadMTU <= 0 || policy.MaxDownloadMTU >= 512 {
		t.Fatal("recovery lacks usable MTU ceiling", policy.MaxDownloadMTU)
	}
	id := binary.BigEndian.Uint16(accepted.Payload[:2])
	next, ok := s.sessions.Get(id)
	if !ok || next.DownloadMTUBytes != policy.MaxDownloadMTU {
		t.Fatal("server and existing client policy disagree")
	}
	t.Cleanup(func() {
		if closed, ok := s.sessions.Close(id, time.Now(), 0); ok {
			s.cleanupClosedSession(id, closed)
		}
	})
}

func TestResponseBudgetMTUProbeUDPAndTCP(t *testing.T) {
	s, _ := newDynamicTransportTestServer(t, 5, 5)
	codec, _ := security.NewCodec(5, "transport-matrix-shared-key")
	payload := []byte{security.DownstreamEncryptedFlag, 1, 2, 3, 4, 5, 220} // 1500 bytes
	query := budgetTestQuery(t, codec, 512, VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_REQ, Payload: payload})
	response := s.safeHandlePacket(query)
	if len(response) > 512 || len(response) < 12 || response[2]&2 == 0 {
		t.Fatal("UDP MTU probe did not honor limit")
	}
	packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(s.safeHandlePacketTCP(query), false, []string{"v.example.com"}, codec)
	if err != nil || packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != 1500 {
		t.Fatal("TCP retry lost full probe", err, len(packet.Payload))
	}
}
