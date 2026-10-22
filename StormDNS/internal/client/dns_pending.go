package client

import (
	"sync"
	"time"

	dnsCache "stormdns-go/internal/dnscache"
	dnsParser "stormdns-go/internal/dnsparser"
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
	waiters []dnsPendingWaiter
	timer   *time.Timer
}

// This lock also serializes cache lookup with response publication: a reply
// cannot populate the cache between a miss and registration of its callback.
type dnsPendingQueries struct {
	mu     sync.Mutex
	groups map[string]*dnsPendingGroup
	total  int
}

// addLocked retains a private query copy because SOCKS UDP reuses its buffer.
func (c *Client) addPendingDNSLocked(key string, query []byte, respond func([]byte)) (first, accepted bool) {
	p := &c.pendingDNS
	g := p.groups[key]
	if p.total >= maxPendingDNSWaiters || (g != nil && len(g.waiters) >= maxPendingDNSWaitersPerQuestion) {
		return false, false
	}
	if g == nil {
		if p.groups == nil {
			p.groups = make(map[string]*dnsPendingGroup)
		}
		g = &dnsPendingGroup{}
		p.groups[key] = g
		first = true
		timeout := c.cfg.DNSResponseFragmentTimeout()
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		g.timer = time.AfterFunc(timeout, func() { c.expirePendingDNS(key, g) })
	}
	g.waiters = append(g.waiters, dnsPendingWaiter{query: append([]byte(nil), query...), respond: respond})
	p.total++
	return first, true
}

func (c *Client) takePendingDNSLocked(key string) []dnsPendingWaiter {
	p := &c.pendingDNS
	g := p.groups[key]
	if g == nil {
		return nil
	}
	delete(p.groups, key)
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
	key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
	p := &c.pendingDNS
	p.mu.Lock()
	if c.localDNSCache != nil {
		c.localDNSCache.SetReady(key, question.Name, question.Type, question.Class, response, time.Now())
	}
	waiters := c.takePendingDNSLocked(key)
	p.mu.Unlock()
	// Network writes and callbacks must never hold the registry/cache lock.
	for _, w := range waiters {
		w.respond(dnsCache.PatchResponseForQuery(response, w.query))
	}
}
