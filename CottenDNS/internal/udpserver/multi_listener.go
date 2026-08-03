// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// multi_listener.go — several SO_REUSEPORT listeners presented as one.
//
// Opening N listeners on the same address gives each its own kernel accept
// queue, so N accept loops stop contending for a single queue. Doing that
// naively would break the connection accounting: limitedListener and the
// DNS-over-stream accept loop each track active connections and per-IP counts
// per listener instance, so N independent listeners would silently permit N *
// TCPMaxConns and N * TCPMaxConnsPerIP.
//
// multiListener keeps the kernel-side benefit without that hazard. It runs one
// accept goroutine per underlying listener and funnels the results through a
// single Accept(), so everything upstream still sees exactly one listener and
// one set of counters.
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
)

type acceptResult struct {
	conn net.Conn
	err  error
}

type multiListener struct {
	listeners []net.Listener
	results   chan acceptResult
	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// newMultiListener takes ownership of listeners: closing the returned listener
// closes every one of them. It requires at least one listener.
func newMultiListener(listeners []net.Listener) *multiListener {
	m := &multiListener{
		listeners: listeners,
		results:   make(chan acceptResult),
		done:      make(chan struct{}),
	}

	for _, ln := range listeners {
		m.wg.Add(1)
		go m.acceptLoop(ln)
	}
	return m
}

func (m *multiListener) acceptLoop(ln net.Listener) {
	defer m.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed sibling must not tear the whole set down on a transient
			// error, but once we are shutting down there is nobody to hand the
			// error to, so just stop.
			select {
			case m.results <- acceptResult{err: err}:
			case <-m.done:
				if conn != nil {
					_ = conn.Close()
				}
			}
			return
		}
		select {
		case m.results <- acceptResult{conn: conn}:
		case <-m.done:
			_ = conn.Close()
			return
		}
	}
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case res := <-m.results:
		return res.conn, res.err
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.done)
		for _, ln := range m.listeners {
			if cerr := ln.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		m.wg.Wait()
	})
	return err
}

// Addr reports the shared listening address. Every underlying listener is bound
// to the same one, so the first is representative.
func (m *multiListener) Addr() net.Addr {
	return m.listeners[0].Addr()
}

// listenTCPShared opens address as a set of SO_REUSEPORT listeners presented as
// one, falling back to a single ordinary listener when the platform lacks
// SO_REUSEPORT or the full set cannot be opened. A partial set is torn down
// rather than used, so the accept queues stay evenly served.
func (s *Server) listenTCPShared(address string, sockets int) (net.Listener, error) {
	if reusePortSupported && sockets > 1 {
		listeners := make([]net.Listener, 0, sockets)
		for range sockets {
			ln, err := listenTCPReusePort(address)
			if err != nil {
				for _, opened := range listeners {
					_ = opened.Close()
				}
				listeners = nil
				break
			}
			listeners = append(listeners, ln)
		}
		if len(listeners) == sockets {
			return newMultiListener(listeners), nil
		}
		if s.log != nil {
			s.log.Warnf("\U0001F4E1 <yellow>SO_REUSEPORT Unavailable For TCP, Falling Back To A Single Listener</yellow>")
		}
	}

	return net.Listen("tcp", address)
}
