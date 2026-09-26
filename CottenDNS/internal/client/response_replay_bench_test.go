// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

// BenchmarkAcceptDownstreamPacketReplay measures the CPU cost of the
// authenticated-downstream accept path per response, isolated from network and
// OS scheduling noise. It builds one realistic ~4KB encrypted download response
// (matching the bench harness's MAX_DOWNLOAD_MTU) and re-seeds a fresh pending
// sample each iteration so the benchmark exercises the real digest+lock+claim
// path exactly as handleInboundPacket does, not a warmed/cached shortcut.
func BenchmarkAcceptDownstreamPacketReplay(b *testing.B) {
	c := buildTestClientWithResolvers(config.ClientConfig{Domains: []string{"example.com"}}, "a")
	c.codec, _ = security.NewCodec(5, "bench-key")
	c.sessionReady = true
	c.sessionID = 300
	c.sessionCookie = 77

	query, err := DnsParser.BuildTXTQuestionPacket("bulk.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 3800) // ~4KB response, matching bench.go's MAX_DOWNLOAD_MTU
	for i := range payload {
		payload[i] = byte(i)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5300}
	digest, ok := resolverQuestionDigest(query)
	if !ok {
		b.Fatal("digest failed")
	}
	// The response echoes the query's DNS transaction ID verbatim; key on that,
	// exactly as trackResolverSend/claimResolverSuccessSample do in production.
	key := resolverSampleKey{resolverAddr: addr.String(), dnsID: uint16(query[0])<<8 | uint16(query[1])}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// A fresh encrypted response each iteration, matching the real wire: the
		// server's AEAD nonce differs per send, so ciphertext differs even for an
		// identical plaintext, and the replay-dedup cache never sees a duplicate.
		response, err := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(
			query, "bulk.example.com", "example.com",
			VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload},
			false, true, true, c.codec,
		)
		if err != nil {
			b.Fatal(err)
		}
		packet, err := c.extractVPNResponse(response, false)
		if err != nil {
			b.Fatal(err)
		}
		c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now(), questionKnown: true, questionDigest: digest}
		accepted, _ := c.acceptDownstreamPacketReplay(response, addr, "", packet)
		if !accepted {
			b.Fatal("expected acceptance")
		}
	}
}

// BenchmarkAcceptDownstreamPacketReplayParallel is the same workload as
// BenchmarkAcceptDownstreamPacketReplay but run from many goroutines at once,
// to surface resolverStatsMu contention that a single-goroutine benchmark
// cannot show. The real client has ~20 asyncProcessorWorker goroutines all
// calling this on every inbound packet.
func BenchmarkAcceptDownstreamPacketReplayParallel(b *testing.B) {
	c := buildTestClientWithResolvers(config.ClientConfig{Domains: []string{"example.com"}}, "a")
	c.codec, _ = security.NewCodec(5, "bench-key")
	c.sessionReady = true
	c.sessionID = 300
	c.sessionCookie = 77

	query, err := DnsParser.BuildTXTQuestionPacket("bulk.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 3800)
	digest, ok := resolverQuestionDigest(query)
	if !ok {
		b.Fatal("digest failed")
	}
	baseKey := uint16(query[0])<<8 | uint16(query[1])
	var goroutineSeq atomic.Uint32

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine uses its own resolverAddr (a guaranteed-unique port, not
		// a collidable pseudo-random one) so pending-sample map writes land on
		// distinct keys, matching how in-flight queries never collide in
		// production; only the mutex itself is shared across goroutines.
		port := 20000 + int(goroutineSeq.Add(1))
		localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
		key := resolverSampleKey{resolverAddr: localAddr.String(), dnsID: baseKey}
		for pb.Next() {
			response, err := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(
				query, "bulk.example.com", "example.com",
				VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload},
				false, true, true, c.codec,
			)
			if err != nil {
				b.Fatal(err)
			}
			packet, err := c.extractVPNResponse(response, false)
			if err != nil {
				b.Fatal(err)
			}
			c.resolverStatsMu.Lock()
			c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now(), questionKnown: true, questionDigest: digest}
			c.resolverStatsMu.Unlock()
			if accepted, _ := c.acceptDownstreamPacketReplay(response, localAddr, "", packet); !accepted {
				b.Fatal("expected acceptance")
			}
		}
	})
}

// BenchmarkResolverQuestionDigest isolates the per-packet DNS-lite-parse +
// SHA256 hash that the accept path pays for.
func BenchmarkResolverQuestionDigest(b *testing.B) {
	query, err := DnsParser.BuildTXTQuestionPacket("bulk.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := resolverQuestionDigest(query); !ok {
			b.Fatal("digest failed")
		}
	}
}

// BenchmarkEncryptedDownstreamRoundTrip isolates the AEAD encrypt+decrypt cost
// for one ~4KB download response, independent of the replay/accept bookkeeping.
func BenchmarkEncryptedDownstreamRoundTrip(b *testing.B) {
	c := buildTestClientWithResolvers(config.ClientConfig{Domains: []string{"example.com"}}, "a")
	c.codec, _ = security.NewCodec(5, "bench-key")
	c.sessionReady = true

	query, err := DnsParser.BuildTXTQuestionPacket("bulk.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 3800)
	pkt := VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(query, "bulk.example.com", "example.com", pkt, false, true, true, c.codec)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.extractVPNResponse(response, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPlaintextDownstreamRoundTrip is the unencrypted equivalent of
// BenchmarkEncryptedDownstreamRoundTrip, for a direct allocation/cost
// comparison of what downstream encryption adds on top of the baseline
// TXT-chunking cost every download response already pays.
func BenchmarkPlaintextDownstreamRoundTrip(b *testing.B) {
	c := buildTestClientWithResolvers(config.ClientConfig{Domains: []string{"example.com"}}, "a")
	c.sessionReady = true

	query, err := DnsParser.BuildTXTQuestionPacket("bulk.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 3800)
	pkt := VpnProto.Packet{SessionID: 300, SessionCookie: 77, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := DnsParser.BuildVPNResponsePacketMatchingQuery(query, "bulk.example.com", "example.com", pkt, false, true, true)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.extractVPNResponse(response, false); err != nil {
			b.Fatal(err)
		}
	}
}
