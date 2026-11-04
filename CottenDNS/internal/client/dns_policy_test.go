package client

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
)

func TestDNSCachedAnswerDoesNotSatisfyAnotherPolicy(t *testing.T) {
	for _, policy := range []string{"cd", "do"} {
		t.Run(policy, func(t *testing.T) {
			query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{localDNSCache: dnscache.New(128, time.Hour, time.Second), sessionReady: true}
			defer c.clearPendingDNSQueries()
			c.ProcessDNSQuery(query, nil, func([]byte) {})
			var wireQuery []byte
			for _, group := range c.pendingDNS.groups {
				wireQuery = append([]byte(nil), group.query...)
			}
			parsed, _ := dnsParser.ParseDNSRequestLite(wireQuery)
			c.completePendingDNS(connectionDNSReply(t, wireQuery, 60), parsed.FirstQuestion)
			if policy == "cd" {
				query[3] |= 0x10
			} else {
				query[len(query)-4] |= 0x80
			}
			served := false
			if c.ProcessDNSQuery(query, nil, func([]byte) { served = true }) || served {
				t.Fatal("ordinary cached answer satisfied a different DNS policy")
			}
		})
	}
}

func TestDNSPoliciesKeepIndependentCacheAndWaiters(t *testing.T) {
	base, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	const policies = 6
	queries := make([][]byte, policies)
	for i := range queries {
		queries[i] = append([]byte(nil), base...)
		binary.BigEndian.PutUint16(queries[i], 0x4242) // collide across policies
	}
	queries[1][3] |= 0x10           // CD
	queries[2][len(base)-4] |= 0x80 // DO
	queries[3][3] |= 0x10
	queries[3][len(base)-4] |= 0x80 // CD + DO
	binary.BigEndian.PutUint16(queries[4][len(base)-8:len(base)-6], 1400)
	// EDNS Cookie option, intentionally absent from the upstream responses.
	binary.BigEndian.PutUint16(queries[5][len(base)-2:], 12)
	queries[5] = append(queries[5], 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	c := &Client{localDNSCache: dnscache.New(128, time.Hour, time.Second), sessionReady: true}
	defer c.clearPendingDNSQueries()
	got := make([][][]byte, policies)
	wireQueries := make([][]byte, policies)
	ids := make(map[uint16]bool)
	for i, query := range queries {
		if c.ProcessDNSQuery(query, nil, func(reply []byte) { got[i] = append(got[i], reply) }) {
			t.Fatal("a different DNS policy reused a cached answer")
		}
		wireQueries[i] = pendingDNSWireQuery(t, c, query)
		id := binary.BigEndian.Uint16(wireQueries[i])
		if ids[id] {
			t.Fatal("different policies share a wire transaction ID")
		}
		ids[id] = true
	}
	// Same policy with another caller ID and QNAME case must still coalesce.
	mixedCase := append([]byte(nil), queries[0]...)
	binary.BigEndian.PutUint16(mixedCase, 0x9192)
	mixedCase[13] = 'E'
	var mixedReply []byte
	c.ProcessDNSQuery(mixedCase, nil, func(reply []byte) { mixedReply = reply })
	if len(c.pendingDNS.groups) != policies || len(c.pendingDNS.byID) != policies || c.pendingDNS.total != policies+1 {
		t.Fatal("same-policy coalescing or registry bounds changed")
	}
	for i := len(queries) - 1; i >= 0; i-- {
		response := connectionDNSReply(t, wireQueries[i], 60)
		response[len(response)-1] = byte(i + 1)
		parsed, _ := dnsParser.ParsePacketLite(response)
		c.completePendingDNS(response, parsed.FirstQuestion)
		if len(got[i]) != 1 || binary.BigEndian.Uint16(got[i][0]) != 0x4242 || got[i][0][len(got[i][0])-1] != byte(i+1) {
			t.Fatalf("policy %d lost its response or original caller ID", i)
		}
		for pending := 0; pending < i; pending++ {
			if len(got[pending]) != 0 {
				t.Fatal("one policy completed another policy's waiters")
			}
		}
	}
	parsedCase, _ := dnsParser.ParseDNSRequestLite(mixedCase)
	if binary.BigEndian.Uint16(mixedReply) != 0x9192 || !bytes.Equal(mixedReply[12:parsedCase.QuestionEndOffset], mixedCase[12:parsedCase.QuestionEndOffset]) {
		t.Fatal("coalesced reply lost caller transaction ID or QNAME case")
	}
	if c.pendingDNS.total != 0 || len(c.pendingDNS.groups) != 0 || len(c.pendingDNS.byID) != 0 {
		t.Fatal("response completion retained pending capacity or IDs")
	}
	for i, query := range queries {
		binary.BigEndian.PutUint16(query, uint16(100+i))
		var cached []byte
		if !c.ProcessDNSQuery(query, nil, func(reply []byte) { cached = reply }) || cached[len(cached)-1] != byte(i+1) || binary.BigEndian.Uint16(cached) != uint16(100+i) {
			t.Fatalf("policy %d did not keep its own cached answer", i)
		}
	}
}

func TestDNSCompletionRejectsUnknownIDWrongQuestionAndOldMaxGroup(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{localDNSCache: dnscache.New(128, time.Hour, time.Second), sessionReady: true}
	defer c.clearPendingDNSQueries()
	replies := 0
	c.ProcessDNSQuery(query, nil, func([]byte) { replies++ })
	key := dnscache.BuildQueryKey(query, dnscache.BuildKey("example.com", 1, 1))
	oldGroup := c.pendingDNS.groups[key]
	response := connectionDNSReply(t, oldGroup.query, 60)
	parsed, _ := dnsParser.ParsePacketLite(response)
	unknown := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(unknown, oldGroup.transactionID+1)
	c.completePendingDNS(unknown, parsed.FirstQuestion)
	c.completePendingDNS(response, dnsParser.Question{Name: "wrong.example", Type: 1, Class: 1})
	if replies != 0 || c.pendingDNS.total != 1 {
		t.Fatal("unrelated response completed a pending request")
	}
	c.expirePendingDNS(key, oldGroup)
	if replies != 1 || len(c.pendingDNS.byID) != 0 {
		t.Fatal("timeout did not fail waiter and release transaction ID")
	}
	c.ProcessDNSQuery(query, nil, func([]byte) { replies++ })
	newGroup := c.pendingDNS.groups[key]
	newResponse := connectionDNSReply(t, newGroup.query, 60)
	// Max has an exchange goroutine and can additionally verify its group.
	c.completePendingDNSForGroup(newResponse, parsed.FirstQuestion, oldGroup)
	c.completePendingDNS(response, parsed.FirstQuestion) // late Normal response
	if replies != 1 || c.pendingDNS.total != 1 {
		t.Fatal("late reply completed the replacement request")
	}
	c.completePendingDNSForGroup(newResponse, parsed.FirstQuestion, newGroup)
	if replies != 2 || c.pendingDNS.total != 0 || len(c.pendingDNS.byID) != 0 {
		t.Fatal("replacement request could not complete")
	}
}
