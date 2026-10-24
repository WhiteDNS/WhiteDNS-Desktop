package client

import (
	"bytes"
	"testing"
	"time"

	dnsCache "cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
)

func TestFirstDNSRequestReceivesDelayedTunnelResponse(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Second)}
	key := dnsCache.BuildKey("example.com", 1, 1)
	query := []byte{0x12, 0x34, 0, 0}
	result := make(chan []byte, 1)
	c.pendingDNS.mu.Lock()
	_, accepted := c.addPendingDNSLocked(key, query, func(reply []byte) { result <- reply })
	c.pendingDNS.mu.Unlock()
	if !accepted {
		t.Fatal("first waiter was rejected")
	}
	query[0] = 0xff // the socket read buffer may already be reused
	c.completePendingDNS([]byte{0, 0, 0x80, 0}, dnsParser.Question{Name: "example.com", Type: 1, Class: 1})
	select {
	case reply := <-result:
		if !bytes.Equal(reply, []byte{0x12, 0x34, 0x80, 0}) {
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
