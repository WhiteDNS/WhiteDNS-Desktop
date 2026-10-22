// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// doh_transport.go â€” DNS-over-HTTPS resolver transport (RFC 8484), used when
// RESOLVER_TRANSPORT=doh. Unlike UDP/TCP/DoT there is no persistent framed
// stream: each query is an HTTP POST whose body is the raw DNS wire-format
// message, and the response body is the wire-format answer. HTTP/2 multiplexes
// them over a small number of connections, and Go's Transport pools one
// connection set per resolver host automatically.
//
// Two users of this file:
//   - dohQueryTransport â€” the synchronous exchanger used by MTU probing,
//     session init and health rechecks (implements queryExchanger).
//   - dohDataManager    â€” the data-plane sender, which mirrors tcpDataManager:
//     it posts asynchronously and pushes answers into the SAME rxChannel the UDP
//     reader feeds, so handleInboundPacket treats every transport identically.
// ==============================================================================

package client

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/resolvertransport"
)

const (
	dohContentType       = "application/dns-message"
	dohDialTimeout       = 6 * time.Second
	dohIdleConnTimeout   = 90 * time.Second
	dohMaxResponse       = 65535
	dohWorkerCount       = 16
	dohDataQueueCapacity = 256
	dohControlQueueCap   = 64
)

// newDoHHTTPClient builds the shared HTTP/2 client used by both DoH users. The
// resolver is addressed by IP in the URL, while SNI/verification come from the
// TLS config, so one client serves every resolver with per-host pooling.
func (c *Client) newDoHHTTPClient() *http.Client {
	tlsCfg := c.resolverTLSConfig()
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       dohIdleConnTimeout,
		TLSHandshakeTimeout:   dohDialTimeout,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   dohDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Transport: transport}
}

func (c *Client) sharedDoHHTTPClient() *http.Client {
	c.dohHTTPMu.Lock()
	defer c.dohHTTPMu.Unlock()
	if c.dohHTTP == nil {
		c.dohHTTP = c.newDoHHTTPClient()
	}
	return c.dohHTTP
}

func (c *Client) closeSharedDoHHTTPClient() {
	c.closeSharedEncryptedDNSClient()
	c.dohHTTPMu.Lock()
	defer c.dohHTTPMu.Unlock()
	if c.dohHTTP == nil {
		return
	}
	if tr, ok := c.dohHTTP.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	c.dohHTTP = nil
}

// dohEndpoint builds the request URL for a resolver. Resolver entries carry the
// DNS port (53); DoH lives on its own port and path.
func (c *Client) dohEndpoint(resolverLabel string) string {
	return "https://" + resolverHostWithPort(resolverLabel, c.cfg.ResolverDoHPort) + c.cfg.ResolverDoHPath
}

// dohExchange performs one DoH round trip and returns the wire-format answer.
func dohExchange(ctx context.Context, httpClient *http.Client, endpoint string, packet []byte) ([]byte, error) {
	return resolvertransport.ExchangeHTTP(ctx, httpClient, endpoint, packet)
}

// ---------------------------------------------------------------------------
// Synchronous exchanger (queryExchanger)
// ---------------------------------------------------------------------------

type dohQueryTransport struct {
	httpClient *http.Client
	endpoint   string
}

func (c *Client) newDoHQueryTransport(resolverLabel string) (queryExchanger, error) {
	return c.newEncryptedQueryTransport(resolverLabel)
}

func (t *dohQueryTransport) exchange(packet []byte, timeout time.Duration) ([]byte, error) {
	if t == nil || t.httpClient == nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dohExchange(ctx, t.httpClient, t.endpoint, packet)
}

func (t *dohQueryTransport) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// Data-plane manager (streamDataTransport)
// ---------------------------------------------------------------------------

type dohDataManager struct {
	client   *Client
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	dead     bool
	controlQ chan dohDataJob
	dataQ    chan dohDataJob
	wg       sync.WaitGroup
}

type dohDataJob struct {
	serverKey string
	addr      *net.UDPAddr
	body      []byte
	now       time.Time
}

func newDoHDataManager(c *Client) *dohDataManager {
	return &dohDataManager{
		client:   c,
		controlQ: make(chan dohDataJob, dohControlQueueCap),
		dataQ:    make(chan dohDataJob, dohDataQueueCapacity),
	}
}

func (m *dohDataManager) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.ctx = workerCtx
	m.cancel = cancel
	m.dead = false
	m.mu.Unlock()
	for i := 0; i < dohWorkerCount; i++ {
		m.wg.Add(1)
		go m.worker(workerCtx)
	}
}

func (m *dohDataManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.dead = true
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// Send queues one already-built DNS query. A bounded worker pool performs the
// POST and feeds the answer back into rxChannel; control packets have reserved
// capacity so a bulk burst cannot strand ACKs or session traffic.
func (m *dohDataManager) Send(serverKey string, addr *net.UDPAddr, packet []byte, priority int, now time.Time) {
	if m == nil || addr == nil || len(packet) == 0 {
		return
	}
	m.mu.Lock()
	ctx, dead := m.ctx, m.dead
	m.mu.Unlock()
	if dead || ctx == nil || ctx.Err() != nil {
		return
	}

	job := dohDataJob{serverKey: serverKey, addr: addr, body: append([]byte(nil), packet...), now: now}
	queue := m.dataQ
	if priority <= Enums.PacketPriorityHigh {
		queue = m.controlQ
	}
	select {
	case queue <- job:
	default:
		m.client.txAdmissionDrops.Add(1)
	}
}

func (m *dohDataManager) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		// Give control traffic a reserved queue and strict first look without
		// starving bulk data when the control queue is empty.
		select {
		case <-ctx.Done():
			return
		case job := <-m.controlQ:
			m.exchangeJob(ctx, job)
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return
		case job := <-m.controlQ:
			m.exchangeJob(ctx, job)
		case job := <-m.dataQ:
			m.exchangeJob(ctx, job)
		}
	}
}

func (m *dohDataManager) exchangeJob(ctx context.Context, job dohDataJob) {
	m.client.trackResolverSend(job.body, job.addr.String(), "", job.serverKey, job.now)
	m.client.txTotalBytes.Add(uint64(len(job.body)))
	reqCtx, cancel := context.WithTimeout(ctx, m.client.resolverRequestTimeout())
	defer cancel()
	response, err := m.client.exchangeEncryptedDNS(reqCtx, job.addr.String(), job.body)
	if err != nil || len(response) < 12 || (response[2]&0x80) == 0 {
		return
	}
	buf := m.client.getRuntimeUDPBuffer()
	if len(response) > len(buf) {
		m.client.putRuntimeUDPBuffer(buf)
		return
	}
	n := copy(buf, response)
	m.client.rxTotalBytes.Add(uint64(n))
	select {
	case m.client.rxChannel <- asyncReadPacket{data: buf[:n], addr: job.addr, localAddr: ""}:
	default:
		m.client.putRuntimeUDPBuffer(buf)
		m.client.onRXDrop(job.addr)
	}
}
