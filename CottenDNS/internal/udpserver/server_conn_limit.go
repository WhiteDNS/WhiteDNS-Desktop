// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_conn_limit.go — a net.Listener wrapper that bounds concurrent
// connections globally and per source IP. The TCP/DoT accept loop already
// enforces these caps inline (reserveTCPIPSlot); the DoH listener is driven by
// net/http, which manages its own accept loop, so it gets the same flood
// protection by wrapping its listener with this. Over-limit connections are
// accepted then immediately closed, so an attacker cannot exhaust memory with
// idle connections but the listener itself keeps serving legitimate clients.
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
)

type limitedListener struct {
	net.Listener
	maxConns int
	perIP    int
	budget   *connectionBudget

	mu         sync.Mutex
	active     int
	activeByIP map[string]int
	onReject   func()
}

func newLimitedListener(inner net.Listener, maxConns, perIP int) *limitedListener {
	return newLimitedListenerWithBudget(inner, newConnectionBudget(maxConns), maxConns, perIP)
}

func newLimitedListenerWithBudget(inner net.Listener, budget *connectionBudget, maxConns, perIP int) *limitedListener {
	if maxConns < 1 {
		maxConns = 2048
	}
	return &limitedListener{
		Listener:   inner,
		maxConns:   maxConns,
		perIP:      perIP,
		budget:     budget,
		activeByIP: make(map[string]int),
	}
}

func (l *limitedListener) withRejectCallback(fn func()) *limitedListener {
	l.onReject = fn
	return l
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := tcpRemoteIPKey(conn.RemoteAddr())
		if !l.reserve(ip) {
			if l.onReject != nil {
				l.onReject()
			}
			_ = conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, listener: l, ip: ip}, nil
	}
}

func (l *limitedListener) reserve(ip string) bool {
	if !l.budget.reserve() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.maxConns {
		l.budget.release()
		return false
	}
	if l.perIP > 0 && ip != "" && l.activeByIP[ip] >= l.perIP {
		l.budget.release()
		return false
	}
	l.active++
	if ip != "" {
		l.activeByIP[ip]++
	}
	return true
}

func (l *limitedListener) release(ip string) {
	l.budget.release()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active > 0 {
		l.active--
	}
	if ip == "" {
		return
	}
	if n := l.activeByIP[ip]; n <= 1 {
		delete(l.activeByIP, ip)
	} else {
		l.activeByIP[ip] = n - 1
	}
}

// limitedConn releases its slot exactly once on Close, whether closed by the
// HTTP server, the SNI passthrough splicer, or the TLS layer.
type limitedConn struct {
	net.Conn
	listener *limitedListener
	ip       string
	once     sync.Once
}

// connectionBudget bounds concurrent stream connections. A budget may have a
// parent: reserving takes a slot from the parent first, so a child budget is
// always a *sub-share* of the parent's ceiling.
//
// This is what keeps the optional encrypted listeners from starving the survival
// path. DoT/DoH reserve from a child budget capped below the global one, so
// however hard they are flooded, the difference (global - encrypted cap) always
// stays available for plain DNS-over-TCP/53. UDP/53 is a separate path entirely
// and is unaffected by any of these budgets.
type connectionBudget struct {
	parent *connectionBudget
	mu     sync.Mutex
	active int
	max    int
}

func newConnectionBudget(maxConns int) *connectionBudget {
	if maxConns < 1 {
		maxConns = 2048
	}
	return &connectionBudget{max: maxConns}
}

// newChildConnectionBudget returns a budget that can never exceed maxConns and
// whose reservations also consume parent capacity.
func newChildConnectionBudget(parent *connectionBudget, maxConns int) *connectionBudget {
	b := newConnectionBudget(maxConns)
	b.parent = parent
	return b
}

// encryptedConnCeiling decides how much of the global stream-connection budget
// the DoT/DoH listeners may take. configured > 0 wins (clamped below the global
// ceiling so headroom always remains); otherwise DoT/DoH get three quarters,
// leaving a quarter permanently reserved for plain DNS-over-TCP/53.
func encryptedConnCeiling(totalMaxConns, configured int) int {
	if totalMaxConns < 1 {
		totalMaxConns = 2048
	}
	if configured > 0 {
		if configured >= totalMaxConns {
			configured = totalMaxConns - 1
		}
		if configured < 1 {
			configured = 1
		}
		return configured
	}
	if ceiling := totalMaxConns * 3 / 4; ceiling >= 1 {
		return ceiling
	}
	return 1
}

func (b *connectionBudget) reserve() bool {
	if b == nil {
		return true
	}
	if !b.parent.reserve() {
		return false
	}
	b.mu.Lock()
	if b.active >= b.max {
		b.mu.Unlock()
		b.parent.release()
		return false
	}
	b.active++
	b.mu.Unlock()
	return true
}

func (b *connectionBudget) release() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.active > 0 {
		b.active--
	}
	b.mu.Unlock()
	b.parent.release()
}

func (b *connectionBudget) snapshot() (active int, limit int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	active, limit = b.active, b.max
	b.mu.Unlock()
	return active, limit
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.listener.release(c.ip) })
	return err
}
