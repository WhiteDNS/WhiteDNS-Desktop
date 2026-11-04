package client

import (
	"encoding/binary"
	"testing"
	"time"

	dnsCache "cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
)

func TestFirstDNSRequestReceivesDelayedTunnelResponse(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Second), sessionReady: true}
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(query, 0x1234)
	result := make(chan []byte, 1)
	if c.ProcessDNSQuery(query, nil, func(reply []byte) { result <- reply }) {
		t.Fatal("first request unexpectedly hit cache")
	}
	wireQuery := pendingDNSWireQuery(t, c, query)
	query[0] = 0xff // the socket read buffer may already be reused
	c.completePendingDNS(connectionDNSReply(t, wireQuery, 60), dnsParser.Question{Name: "example.com", Type: 1, Class: 1})
	select {
	case reply := <-result:
		if binary.BigEndian.Uint16(reply) != 0x1234 || reply[len(reply)-1] != 8 {
			t.Fatal("reply lost original transaction ID", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("first request still requires a retransmission")
	}
}

func TestDNSReplyWaitersAreBounded(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Second)}
	c.pendingDNS.total = maxPendingDNSWaiters
	c.pendingDNS.mu.Lock()
	_, accepted := c.addPendingDNSLocked("pending", []byte{1, 2}, func([]byte) { t.Error("admitted excess waiter") })
	c.pendingDNS.mu.Unlock()
	if accepted || c.pendingDNS.total != maxPendingDNSWaiters {
		t.Fatal("waiter limit changed")
	}
}
