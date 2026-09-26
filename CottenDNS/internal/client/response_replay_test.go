package client

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestDownstreamReplayRequiresMatchingPendingQuestion(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{Domains: []string{"example.com"}}, "a", "b", "c", "d")
	c.codec, _ = security.NewCodec(5, "replay-test")
	c.sessionReady = true
	c.sessionID = 300
	c.sessionCookie = 77
	query, _ := DnsParser.BuildTXTQuestionPacket("first.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	response, e := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(query, "first.example.com", "example.com", VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_PONG}, false, true, true, c.codec)
	if e != nil {
		t.Fatal(e)
	}
	packet, e := c.extractVPNResponse(response, false)
	if e != nil {
		t.Fatal(e)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5300}
	key := resolverSampleKey{resolverAddr: addr.String(), dnsID: binary.BigEndian.Uint16(query[:2])}
	if accepted, _ := c.acceptDownstreamPacketReplay(response, addr, "", packet); accepted {
		t.Fatal("unsolicited response accepted")
	}
	wrong, _ := DnsParser.BuildTXTQuestionPacket("second.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	digest, _ := resolverQuestionDigest(wrong)
	c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now(), questionKnown: true, questionDigest: digest}
	if accepted, _ := c.acceptDownstreamPacketReplay(response, addr, "", packet); accepted {
		t.Fatal("DNS ID reuse bypassed question match")
	}
	digest, _ = resolverQuestionDigest(query)
	c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now(), questionKnown: true, questionDigest: digest}
	if accepted, _ := c.acceptDownstreamPacketReplay(response, addr, "", packet); !accepted {
		t.Fatal("fresh response rejected")
	}
	if accepted, _ := c.acceptDownstreamPacketReplay(response, addr, "", packet); accepted {
		t.Fatal("response repeated on same path")
	}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 5300}
	second := resolverSampleKey{resolverAddr: other.String(), dnsID: key.dnsID}
	c.resolverPending[second] = resolverSample{serverKey: "b", sentAt: time.Now(), questionKnown: true, questionDigest: digest}
	accepted, handled := c.acceptDownstreamPacketReplay(response, other, "", packet)
	if accepted {
		t.Fatal("duplicate repeated dispatch on another path")
	}
	if !handled {
		t.Fatal("duplicate path must still get success bookkeeping applied inline")
	}
	if _, exists := c.resolverPending[second]; exists {
		t.Fatal("duplicate path did not receive success credit")
	}
}

func TestDownstreamReplayConcurrentAndBounded(t *testing.T) {
	cache := downstreamReplayCache{limit: 2, ttl: time.Second}
	now := time.Now()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cache.accept([32]byte{1}, now) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent dispatches: %d", wins.Load())
	}
	if !cache.accept([32]byte{2}, now) || !cache.accept([32]byte{3}, now) {
		t.Fatal("fresh responses rejected")
	}
	if len(cache.seen) > 2 {
		t.Fatal("unbounded replay cache")
	}
	if !cache.accept([32]byte{3}, now.Add(2*time.Second)) {
		t.Fatal("TTL did not expire")
	}
}
