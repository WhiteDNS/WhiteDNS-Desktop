package client

import (
	"encoding/binary"
	"testing"
	"time"

	"cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
	"golang.org/x/net/dns/dnsmessage"
)

func pendingDNSWireQuery(t *testing.T, c *Client, query []byte) []byte {
	t.Helper()
	parsed, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	key := dnscache.BuildQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, parsed.FirstQuestion.Type, parsed.FirstQuestion.Class))
	c.pendingDNS.mu.Lock()
	defer c.pendingDNS.mu.Unlock()
	g := c.pendingDNS.groups[key]
	if g == nil {
		t.Fatal("missing pending wire query")
	}
	return append([]byte(nil), g.query...)
}

func connectionDNSReply(t *testing.T, query []byte, ttl uint32) []byte {
	t.Helper()
	parsed, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query[:parsed.QuestionEndOffset]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 8, 8)
	binary.BigEndian.PutUint32(response[len(response)-10:len(response)-6], ttl)
	return response
}

func TestDNSNoncacheableRepliesReachEveryWaiterAndAllowRetry(t *testing.T) {
	for _, scenario := range []string{"zero-ttl", "truncated", "servfail", "refused"} {
		t.Run(scenario, func(t *testing.T) {
			query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
			if err != nil {
				t.Fatal(err)
			}
			parsed, _ := dnsParser.ParseDNSRequestLite(query)
			c := &Client{localDNSCache: dnscache.New(128, time.Hour, time.Second), sessionReady: true}
			defer c.clearPendingDNSQueries()
			var replies [][]byte
			for _, id := range []uint16{111, 222} {
				binary.BigEndian.PutUint16(query, id)
				if c.ProcessDNSQuery(query, nil, func(reply []byte) { replies = append(replies, reply) }) {
					t.Fatal("unexpected initial cache hit")
				}
			}
			response := connectionDNSReply(t, pendingDNSWireQuery(t, c, query), 60)
			switch scenario {
			case "zero-ttl":
				binary.BigEndian.PutUint32(response[len(response)-10:len(response)-6], 0)
			case "truncated":
				response[2] |= 2
			case "servfail":
				response[3] = response[3]&0xf0 | 2
			case "refused":
				response[3] = response[3]&0xf0 | 5
			}
			c.completePendingDNS(response, parsed.FirstQuestion)
			if len(replies) != 2 {
				t.Fatalf("delivered %d replies, want 2", len(replies))
			}
			for i, id := range []uint16{111, 222} {
				if binary.BigEndian.Uint16(replies[i]) != id || replies[i][2] != response[2] || replies[i][3] != response[3] {
					t.Fatal("response cache admission changed its delivery or transaction ID")
				}
			}
			replies[0][len(replies[0])-1] ^= 255
			if replies[1][len(replies[1])-1] != response[len(response)-1] {
				t.Fatal("waiters share a mutable response")
			}
			if c.pendingDNS.total != 0 || c.localDNSCache.HasPending() {
				t.Fatal("completion retained pending DNS capacity")
			}
			if c.ProcessDNSQuery(query, nil, func([]byte) { t.Fatal("uncacheable response was reused") }) {
				t.Fatal("retry was served from cache")
			}
			if c.pendingDNS.total != 1 {
				t.Fatal("a fresh request could not register after uncached completion")
			}
		})
	}
}

func TestDNSCacheHitKeepsTransactionFlagsAndPrivatePayload(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := dnsParser.ParseDNSRequestLite(query)
	c := &Client{localDNSCache: dnscache.New(128, time.Hour, time.Second), sessionReady: true}
	binary.BigEndian.PutUint16(query[2:4], 0x0110)
	key := dnscache.BuildQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, 1, 1))
	c.localDNSCache.SetReady(key, parsed.FirstQuestion.Name, 1, 1, connectionDNSReply(t, query, 120), time.Now().Add(-30*time.Second))
	binary.BigEndian.PutUint16(query, 0x7249)
	var first []byte
	if !c.ProcessDNSQuery(query, nil, func(reply []byte) { first = reply }) {
		t.Fatal("valid answer was not reusable")
	}
	var message dnsmessage.Message
	if err := message.Unpack(first); err != nil {
		t.Fatal(err)
	}
	if message.Header.ID != 0x7249 || !message.Header.RecursionDesired || !message.Header.CheckingDisabled || len(message.Answers) != 1 || message.Answers[0].Header.TTL > 90 || message.Answers[0].Header.TTL == 0 {
		t.Fatal("cache hit changed query identity/flags or failed to age its TTL")
	}
	first[len(first)-1] ^= 255
	var second []byte
	if !c.ProcessDNSQuery(query, nil, func(reply []byte) { second = reply }) || second[len(second)-1] != 8 {
		t.Fatal("caller mutation damaged a later cached response")
	}
}
