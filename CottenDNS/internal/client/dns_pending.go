package client

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	dnsCache "cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
)

const (
	maxPendingDNSWaiters            = 4096
	maxPendingDNSWaitersPerQuestion = 64
)

type dnsPendingWaiter struct {
	query   []byte
	respond func([]byte)
}

type dnsPendingGroup struct {
	key           string
	question      dnsParser.Question
	query         []byte // private wire query with a reserved transaction ID
	transactionID uint16
	waiters       []dnsPendingWaiter
	timer         *time.Timer
}

// This lock also serializes cache lookup with response publication: a reply
// cannot populate the cache between a miss and registration of its callback.
type dnsPendingQueries struct {
	mu          sync.Mutex
	groups      map[string]*dnsPendingGroup
	byID        map[uint16]*dnsPendingGroup
	issuedIDs   [1024]uint64 // 8 KiB: retired IDs stay reserved for this cycle
	issuedCount uint32
	total       int
}

// IDs can reach the plaintext DNS upstream, so allocation must preserve their
// unpredictability. Retired IDs stay unavailable until the current 16-bit
// cycle is exhausted, reducing early reuse. IDs can recur after cycle reset;
// the finite DNS ID space cannot disambiguate every arbitrarily late reply.
func (p *dnsPendingQueries) reserveDNSIDLocked() (uint16, bool) {
	var entropy [2]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return 0, false
	}
	return p.reserveDNSIDFromStartLocked(binary.BigEndian.Uint16(entropy[:]))
}

// The deterministic scan is kept separate so collision, retirement and full
// pool behavior can be checked without replacing the cryptographic RNG.
func (p *dnsPendingQueries) reserveDNSIDFromStartLocked(start uint16) (uint16, bool) {
	if p.issuedCount == 1<<16 {
		p.issuedIDs = [1024]uint64{}
		p.issuedCount = uint32(len(p.byID))
		for id := range p.byID {
			p.issuedIDs[id>>6] |= uint64(1) << (id & 63)
		}
	}
	id := start
	for attempts := 0; attempts < 1<<16; attempts++ {
		bit := uint64(1) << (id & 63)
		if p.issuedIDs[id>>6]&bit == 0 && p.byID[id] == nil {
			p.issuedIDs[id>>6] |= bit
			p.issuedCount++
			return id, true
		}
		id++
	}
	return 0, false
}

// addLocked retains a private query copy because SOCKS UDP reuses its buffer.
func (c *Client) addPendingDNSLocked(key string, query []byte, respond func([]byte)) (first, accepted bool) {
	p := &c.pendingDNS
	g := p.groups[key]
	if p.total >= maxPendingDNSWaiters || (g != nil && len(g.waiters) >= maxPendingDNSWaitersPerQuestion) || (g == nil && len(p.groups) >= maxPendingDNSWaiters) {
		return false, false
	}
	if g == nil {
		parsed, err := dnsParser.ParseDNSRequestLite(query)
		if err != nil || !parsed.HasQuestion {
			return false, false
		}
		if p.groups == nil {
			p.groups = make(map[string]*dnsPendingGroup)
			p.byID = make(map[uint16]*dnsPendingGroup)
		}
		// Responses need not echo EDNS options, so their policy key cannot be
		// reconstructed from reply bytes. Reserve an existing DNS ID instead.
		id, available := p.reserveDNSIDLocked()
		if !available {
			return false, false
		}
		g = &dnsPendingGroup{key: key, question: parsed.FirstQuestion, query: append([]byte(nil), query...), transactionID: id}
		binary.BigEndian.PutUint16(g.query, g.transactionID)
		p.groups[key] = g
		p.byID[g.transactionID] = g
		first = true
		timeout := c.cfg.DNSResponseFragmentTimeout()
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		g.timer = time.AfterFunc(timeout, func() { c.expirePendingDNS(key, g) })
	}
	if respond != nil {
		g.waiters = append(g.waiters, dnsPendingWaiter{query: append([]byte(nil), query...), respond: respond})
		p.total++
	}
	return first, true
}

func (c *Client) takePendingDNSLocked(key string) []dnsPendingWaiter {
	p := &c.pendingDNS
	g := p.groups[key]
	if g == nil {
		return nil
	}
	delete(p.groups, key)
	delete(p.byID, g.transactionID)
	p.total -= len(g.waiters)
	if g.timer != nil {
		g.timer.Stop()
	}
	return g.waiters
}

func (c *Client) expirePendingDNS(key string, expected *dnsPendingGroup) {
	p := &c.pendingDNS
	p.mu.Lock()
	if p.groups[key] != expected {
		p.mu.Unlock()
		return
	}
	waiters := c.takePendingDNSLocked(key)
	p.mu.Unlock()
	for _, w := range waiters {
		failPendingDNS(w)
	}
}

func failPendingDNS(w dnsPendingWaiter) {
	if response, err := dnsParser.BuildServerFailureResponse(w.query); err == nil && w.respond != nil {
		w.respond(response)
	}
}

func (c *Client) clearPendingDNSQueries() {
	p := &c.pendingDNS
	p.mu.Lock()
	for key := range p.groups {
		c.takePendingDNSLocked(key)
	}
	p.mu.Unlock()
}

func (c *Client) completePendingDNS(response []byte, question dnsParser.Question) {
	c.completePendingDNSForGroup(response, question, nil)
}

func (c *Client) completePendingDNSForGroup(response []byte, question dnsParser.Question, expected *dnsPendingGroup) {
	if len(response) < 2 {
		return
	}
	p := &c.pendingDNS
	p.mu.Lock()
	g := p.byID[binary.BigEndian.Uint16(response)]
	if g == nil || g.question != question || (expected != nil && g != expected) {
		p.mu.Unlock()
		return
	}
	if c.localDNSCache != nil {
		c.localDNSCache.SetReady(g.key, question.Name, question.Type, question.Class, response, time.Now())
	}
	waiters := c.takePendingDNSLocked(g.key)
	p.mu.Unlock()
	// Network writes and callbacks must never hold the registry/cache lock.
	for _, w := range waiters {
		w.respond(dnsCache.PatchResponseForQuery(response, w.query))
	}
}
