package udpserver

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
)

// tlsMetricListener performs the TLS handshake on first read and records
// failures without serializing handshakes in the accept loop.
type tlsMetricListener struct {
	net.Listener
	config   *tls.Config
	failures *atomic.Uint64
}

func newTLSMetricListener(inner net.Listener, config *tls.Config, failures *atomic.Uint64) net.Listener {
	return &tlsMetricListener{Listener: inner, config: config, failures: failures}
}

func (l *tlsMetricListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsMetricConn{Conn: tls.Server(conn, l.config), failures: l.failures}, nil
}

type tlsMetricConn struct {
	net.Conn
	once         sync.Once
	handshakeErr error
	failures     *atomic.Uint64
}

func (c *tlsMetricConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		if tlsConn, ok := c.Conn.(*tls.Conn); ok {
			c.handshakeErr = tlsConn.Handshake()
			if c.handshakeErr != nil && c.failures != nil {
				c.failures.Add(1)
			}
		}
	})
	if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}
	return c.Conn.Read(p)
}
