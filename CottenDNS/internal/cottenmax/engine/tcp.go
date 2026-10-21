// Modified for CottenDNS, 2026-10-17. See NOTICE.cottendns.txt and LICENSE.
package soar

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tcpLink carries one path's queries to a resolver over TCP, pipelined on one connection
// (RFC 7766). Some networks intercept or block UDP/53 but leave TCP/53 alone (Russia since
// 2026-08). The link redials with backoff for as long as the client runs.
type tcpLink struct {
	addr     string
	out      chan []byte
	up       atomic.Bool
	done     chan struct{}
	stopOnce sync.Once
	connMu   sync.Mutex
	conn     net.Conn // guarded by connMu; Close runs outside the client scheduler
}

func (c *Client) startTCP(addr string) *tcpLink {
	l := &tcpLink{addr: addr, out: make(chan []byte, 256), done: make(chan struct{})}
	go l.run(c)
	return l
}

// stop ends the link, as when discovery prunes its path.
func (l *tcpLink) stop() { l.stopOnce.Do(func() { close(l.done) }) }

// send queues msg; a full queue drops it, which the query's timeout treats as loss.
func (l *tcpLink) send(msg []byte) {
	select {
	case l.out <- msg:
	default:
	}
}

// reconnect closes only the captured socket. A slow TLS/custom Close cannot
// block answer processing or healthy paths under the client's lock.
func (l *tcpLink) reconnect() {
	l.connMu.Lock()
	conn := l.conn
	if conn == nil || !l.up.Swap(false) {
		l.connMu.Unlock()
		return
	}
	l.connMu.Unlock()
	go func() {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}()
}

func (l *tcpLink) run(c *Client) {
	backoff := time.Second
	for {
		select {
		case <-c.done:
			return
		case <-l.done:
			return
		default:
		}
		// Do not let a large resolver list open an unbounded number of sockets
		// or TLS handshakes at once. UDP startup never waits for these slots.
		select {
		case c.tcpDialSlots <- struct{}{}:
		case <-c.done:
			return
		case <-l.done:
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// A blocked TCP/TLS handshake must release its socket when the app
		// closes or discovery removes this path, rather than wait ten seconds.
		go func() {
			select {
			case <-c.done:
				cancel()
			case <-l.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		conn, err := c.cfg.DialTCP(ctx, "tcp", l.addr)
		cancel()
		<-c.tcpDialSlots
		dbg("tcp link %s dial err=%v", l.addr, err)
		if err != nil {
			select {
			case <-c.done:
				return
			case <-l.done:
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		l.connMu.Lock()
		l.conn = conn
		l.up.Store(true)
		l.connMu.Unlock()
		c.wake()
		n := l.serve(c, conn)
		dbg("tcp link %s down after %d queries", l.addr, n)
		l.connMu.Lock()
		l.conn = nil
		l.up.Store(false)
		l.connMu.Unlock()
		// Answers to anything still in flight on that connection are gone: fail those queries
		// now so their data goes out on other paths, rather than waiting out their timeouts.
		c.linkDown(l)
	}
}

// serve relays until the connection fails or the client closes.
func (l *tcpLink) serve(c *Client, conn net.Conn) (sent int) {
	errc := make(chan struct{})
	go func() {
		defer close(errc)
		var hdr [2]byte
		buf := make([]byte, 65535)
		for {
			// A black-holed connection accepts writes for a long time; an idle read deadline
			// closes it so the link redials (resolvers drop idle TCP/53 anyway, RFC 7766).
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				dbg("tcp link %s read err=%v", l.addr, err)
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(conn, buf[:n]); err != nil {
				return
			}
			c.onAnswer(buf[:n])
		}
	}()
	defer conn.Close()
	for {
		select {
		case <-c.done:
			return
		case <-l.done:
			return
		case <-errc:
			return
		case msg := <-l.out:
			framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg)))
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(append(framed, msg...)); err != nil {
				return
			}
			sent++
		}
	}
}
