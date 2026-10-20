package cottenmax

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	soar "cottendns-go/internal/cottenmax/engine"
	"cottendns-go/internal/dnsparser"
)

type datagram struct {
	data []byte
	addr net.Addr
}
type replyAddr struct {
	net.Addr
	send func([]byte) error
}

func (a *replyAddr) UDPAddr() *net.UDPAddr {
	addr, _ := a.Addr.(*net.UDPAddr)
	return addr
}

// queueConn owns only its bounded queue, never the shared legacy listener.
type queueConn struct {
	queue chan datagram
	done  chan struct{}
	once  sync.Once
}

func (p *queueConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.done:
		return 0, nil, net.ErrClosed
	case d := <-p.queue:
		return copy(b, d.data), d.addr, nil
	}
}
func (p *queueConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(*replyAddr)
	if !ok {
		return 0, errors.New("cottenmax: invalid reply address")
	}
	if err := a.send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *queueConn) Close() error                     { p.once.Do(func() { close(p.done) }); return nil }
func (p *queueConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (p *queueConn) SetDeadline(time.Time) error      { return nil }
func (p *queueConn) SetReadDeadline(time.Time) error  { return nil }
func (p *queueConn) SetWriteDeadline(time.Time) error { return nil }

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	zones  map[string]*queueConn
	wg     sync.WaitGroup
	once   sync.Once
	errMu  sync.Mutex
	err    error
}

type ServerConfig struct {
	Domains                 []string
	Key                     ed25519.PrivateKey
	Secret                  string
	Dial                    func(context.Context, string) (net.Conn, error)
	MaxSessions, MaxStreams int
}

// ValidateServerDomain checks the Max reserved zone and handshake capacity
// without starting workers or touching keys. A legacy server may use it to
// offer Max only on compatible domains while retaining its complete domain set.
func ValidateServerDomain(domain string) error {
	zone := Zone(domain)
	if strings.Trim(domain, ". ") == "" || len(zone)+56 > 253 {
		return fmt.Errorf("cottenmax: domain leaves insufficient handshake capacity")
	}
	for _, label := range strings.Split(zone, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("cottenmax: invalid domain label")
		}
		for _, c := range label {
			if c < '!' || c > '~' {
				return fmt.Errorf("cottenmax: invalid domain character")
			}
		}
	}
	return nil
}

func NewServer(ctx context.Context, cfg ServerConfig) (*Server, error) {
	if len(cfg.Domains) == 0 || len(cfg.Key) != ed25519.PrivateKeySize || cfg.Secret == "" || cfg.Dial == nil {
		return nil, fmt.Errorf("cottenmax: incomplete server configuration")
	}
	for _, domain := range cfg.Domains {
		if err := ValidateServerDomain(domain); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &Server{ctx: ctx, cancel: cancel, zones: make(map[string]*queueConn)}
	for _, domain := range cfg.Domains {
		zone := Zone(domain)
		if _, exists := s.zones[zone]; exists {
			continue
		}
		p := &queueConn{queue: make(chan datagram, 256), done: make(chan struct{})}
		s.zones[zone] = p
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := soar.Serve(ctx, p, soar.ServerConfig{
				Zone: zone, PrivateKey: cfg.Key,
				MaxSessions: max(1, cfg.MaxSessions/len(cfg.Domains)), MaxStreams: cfg.MaxStreams,
				Dial: func(ctx context.Context, _, signed string) (net.Conn, error) {
					target, err := verifyTarget(cfg.Secret, signed)
					if err != nil {
						return nil, err
					}
					return cfg.Dial(ctx, target)
				},
			})
			if err != nil && ctx.Err() == nil {
				s.errMu.Lock()
				if s.err == nil {
					s.err = err
				}
				s.errMu.Unlock()
				s.cancel()
			}
		}()
	}
	return s, nil
}

func (s *Server) Done() <-chan struct{} { return s.ctx.Done() }
func (s *Server) Err() error            { s.errMu.Lock(); defer s.errMu.Unlock(); return s.err }

func (s *Server) match(data []byte) *queueConn {
	parsed, err := dnsparser.ParseDNSRequestLite(data)
	if err != nil || !parsed.HasQuestion {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(parsed.FirstQuestion.Name, "."))
	// A hyphenated reserved label cannot be a legacy base32 payload label.
	for zone, p := range s.zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return p
		}
	}
	return nil
}

func enqueue(p *queueConn, data []byte, addr *replyAddr) {
	if len(data) > 4096 {
		return
	}
	select {
	case <-p.done:
	case p.queue <- datagram{data: append([]byte(nil), data...), addr: addr}:
	default: // bounded queue: loss is repaired by the transport
	}
}

// DispatchUDP routes only the reserved subtree; legacy packets stay untouched.
func (s *Server) DispatchUDP(data []byte, conn *net.UDPConn, addr *net.UDPAddr) bool {
	p := s.match(data)
	if p == nil {
		return false
	}
	enqueue(p, data, &replyAddr{Addr: addr, send: func(b []byte) error { _, err := conn.WriteToUDP(b, addr); return err }})
	return true
}

// Exchange serves existing TCP/DoT/DoH request handlers on the same server.
func (s *Server) Exchange(data []byte) ([]byte, bool) {
	p := s.match(data)
	if p == nil {
		return nil, false
	}
	reply := make(chan []byte, 1)
	enqueue(p, data, &replyAddr{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, send: func(b []byte) error {
		select {
		case reply <- append([]byte(nil), b...):
		default:
		}
		return nil
	}})
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case b := <-reply:
		return b, true
	case <-s.ctx.Done():
		return nil, true
	case <-timer.C:
		return nil, true
	}
}

func (s *Server) Close() error {
	s.once.Do(func() {
		s.cancel()
		for _, p := range s.zones {
			_ = p.Close()
		}
		s.wg.Wait()
	})
	return nil
}
