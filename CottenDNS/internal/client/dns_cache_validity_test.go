package client

import (
	"encoding/binary"
	"testing"
	"time"

	"cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
)

func TestCompletedDNSFailureIsDeliveredButNotCached(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := dnsParser.ParseDNSRequestLite(query)
	c := &Client{localDNSCache: dnscache.New(128, 4*time.Hour, time.Second), sessionReady: true}
	key := dnscache.BuildQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, 1, 1))
	c.localDNSCache.LookupOrCreatePending(key, parsed.FirstQuestion.Name, 1, 1, time.Now())
	var got []byte
	c.pendingDNS.mu.Lock()
	c.addPendingDNSLocked(key, query, func(reply []byte) { got = reply })
	c.pendingDNS.mu.Unlock()
	response, err := dnsParser.BuildServerFailureResponse(pendingDNSWireQuery(t, c, query))
	if err != nil {
		t.Fatal(err)
	}
	c.completePendingDNS(response, parsed.FirstQuestion)
	if len(got) < 4 || got[3]&15 != 2 {
		t.Fatal("waiter lost its actual upstream failure")
	}
	if c.localDNSCache.HasPending() {
		t.Fatal("failure left the cache pending")
	}
	if hit := c.ProcessDNSQuery(query, nil, func([]byte) { t.Fatal("transient failure reused from cache") }); hit {
		t.Fatal("transient failure was cached")
	}
}

func TestClientDNSHotAnswerExpires(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := dnsParser.ParseDNSRequestLite(query)
	response := append([]byte(nil), query[:parsed.QuestionEndOffset]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8)
	c := &Client{localDNSCache: dnscache.New(128, 4*time.Hour, time.Second), sessionReady: true}
	key := dnscache.BuildQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, 1, 1))
	start := time.Now().Add(-61 * time.Second)
	c.localDNSCache.SetReady(key, parsed.FirstQuestion.Name, 1, 1, response, start)
	for i := 0; i < 60; i++ {
		c.localDNSCache.GetReady(key, query, start.Add(time.Duration(i)*time.Second))
	}
	if c.ProcessDNSQuery(query, nil, func([]byte) { t.Fatal("expired DNS answer was served") }) {
		t.Fatal("client prolonged authoritative DNS TTL")
	}
}
