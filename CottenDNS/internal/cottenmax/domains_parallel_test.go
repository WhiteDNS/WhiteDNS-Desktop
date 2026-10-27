package cottenmax

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/dnsparser"
)

type parallelDNSServer struct {
	addr    string
	blocked [2]atomic.Bool
	queries [2]atomic.Int64
}

func startParallelDNSServer(t *testing.T) *parallelDNSServer {
	t.Helper()
	key, err := SharedIdentity("parallel-domain-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(context.Background(), ServerConfig{
		Domains: []string{"a.example", "b.example"}, Key: key,
		Secret: "parallel-domain-test-secret", MaxSessions: 32, MaxStreams: 32,
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = io.Copy(server, server)
			}()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	f := &parallelDNSServer{addr: pc.LocalAddr().String()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			parsed, err := dnsparser.ParseDNSRequestLite(buf[:n])
			if err != nil || !parsed.HasQuestion {
				continue
			}
			index := 0
			if strings.HasSuffix(strings.TrimSuffix(parsed.FirstQuestion.Name, "."), Zone("b.example")) {
				index = 1
			}
			f.queries[index].Add(1)
			if !f.blocked[index].Load() {
				s.DispatchUDP(buf[:n], pc, addr)
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); s.Close(); <-done })
	return f
}

func parallelTestConfig(f *parallelDNSServer) ClientConfig {
	return ClientConfig{Domain: "a.example", Domains: []string{"b.example"},
		DomainStrategy: "parallel", Secret: "parallel-domain-test-secret",
		Resolvers: []string{f.addr}, TCP: "off", MaxInflight: 8, MaxPathWindow: 8,
		SafeQName: 253, MaxQName: 253, FailoverAfter: 2 * time.Second}
}

func echoParallelConn(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(data)
		writeDone <- err
	}()
	reply := make([]byte, len(data))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, data) {
		t.Fatal("concurrent-domain echo corrupted application bytes")
	}
}

func TestParallelDomainsUseTwoAuthenticatedSessions(t *testing.T) {
	f := startParallelDNSServer(t)
	c, err := NewClient(parallelTestConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conns := make([]net.Conn, 2)
	for i := range conns {
		conns[i], err = c.Dial(ctx, "echo:123")
		if err != nil {
			t.Fatal(err)
		}
		defer conns[i].Close()
	}
	stats := c.DomainStats()
	for i, stat := range stats {
		if !stat.Established || stat.ActiveStreams != 1 || stat.AssignedStreams != 1 || stat.MaxInflight != 4 {
			t.Fatalf("domain %d not independently active with a fair budget: %+v", i, stat)
		}
		if f.queries[i].Load() == 0 {
			t.Fatalf("domain %d carried no DNS queries", i)
		}
	}
	stopSampling := make(chan struct{})
	sampled := make(chan struct{})
	var excess atomic.Int64
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stopSampling:
				return
			default:
			}
			total := 0
			for _, domain := range c.DomainStats() {
				perDomain := 0
				for _, path := range domain.Paths {
					perDomain += path.Inflight
				}
				if perDomain > domain.MaxInflight {
					excess.Add(1)
				}
				total += perDomain
			}
			if total > 8 {
				excess.Add(1)
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()
	var wg sync.WaitGroup
	for i, conn := range conns {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			echoParallelConn(t, conn, bytes.Repeat([]byte{byte(i + 1)}, 32<<10))
		}(i, conn)
	}
	wg.Wait()
	close(stopSampling)
	<-sampled
	if excess.Load() != 0 {
		t.Fatal("parallel domains multiplied the configured aggregate query budget")
	}
	for _, conn := range conns {
		conn.Close()
		conn.Close()
	}
	for _, domain := range c.DomainStats() {
		if domain.ActiveStreams != 0 {
			t.Fatalf("closing twice did not release exactly one assignment: %+v", domain)
		}
	}
}

func TestParallelDomainsFailureFallbackAndRecovery(t *testing.T) {
	f := startParallelDNSServer(t)
	f.blocked[0].Store(true)
	cfg := parallelTestConfig(f)
	cfg.FailoverAfter = 150 * time.Millisecond
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	survivor, err := c.Dial(ctx, "echo:123")
	if err != nil {
		t.Fatal(err)
	}
	defer survivor.Close()
	stats := c.DomainStats()
	if stats[0].AssignedStreams != 0 || stats[1].AssignedStreams != 1 {
		t.Fatalf("blocked-domain stream was not assigned to the survivor: %+v", stats)
	}
	echoParallelConn(t, survivor, []byte("survives first domain failure"))
	f.blocked[0].Store(false)
	// HELLO retries are rate-limited to one second independently of domain
	// selection cooldown; let the previously dropped HELLO become eligible.
	time.Sleep(1100 * time.Millisecond)
	recovered, err := c.Dial(ctx, "echo:123")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	stats = c.DomainStats()
	if stats[0].AssignedStreams != 1 || stats[0].ActiveStreams != 1 || stats[1].ActiveStreams != 1 {
		t.Fatalf("recovered domain did not rejoin without moving the survivor: %+v", stats)
	}
	echoParallelConn(t, recovered, []byte("recovered first domain"))
	echoParallelConn(t, survivor, []byte("original stream is still intact"))
}

func TestParallelDomainsExistingStreamDoesNotMigrate(t *testing.T) {
	f := startParallelDNSServer(t)
	c, err := NewClient(parallelTestConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original, err := c.Dial(ctx, "echo:123")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	echoParallelConn(t, original, []byte("original stream on domain A"))
	if stats := c.DomainStats(); stats[0].AssignedStreams != 1 || stats[1].AssignedStreams != 0 {
		t.Fatalf("initial stream was not bound to A: %+v", stats)
	}

	// Blocking A after its successful application transfer cannot move its
	// stream sequence space to B: B has a different authenticated session.
	f.blocked[0].Store(true)
	newConn, err := c.Dial(ctx, "echo:123")
	if err != nil {
		t.Fatal(err)
	}
	defer newConn.Close()
	echoParallelConn(t, newConn, []byte("new independent connection on domain B"))
	if err := original.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	pending := []byte("existing A bytes must not be replayed through B")
	if _, err := original.Write(pending); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(pending))
	if _, err := io.ReadFull(original, reply); err == nil {
		t.Fatal("existing stream unexpectedly migrated to another domain")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("existing stream did not stop at its bounded read deadline: %v", err)
		}
	}
	stats := c.DomainStats()
	if stats[0].ActiveStreams != 1 || stats[0].AssignedStreams != 1 || stats[1].ActiveStreams != 1 || stats[1].AssignedStreams != 1 {
		t.Fatalf("existing stream was reassigned or replayed while A was blocked: %+v", stats)
	}
	echoParallelConn(t, newConn, []byte("B remains usable while the original A stream is stalled"))
}

func TestDefaultDomainsStayLazyAndKeepOriginalBudget(t *testing.T) {
	f := startParallelDNSServer(t)
	cfg := parallelTestConfig(f)
	cfg.DomainStrategy = ""
	cfg.MaxInflight = 9
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if f.queries[0].Load() != 0 || f.queries[1].Load() != 0 {
		t.Fatal("default constructor sent unsolicited DNS flights")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "echo:123")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stats := c.DomainStats()
	if !stats[0].Established || stats[1].Started || f.queries[1].Load() != 0 {
		t.Fatalf("default failover eagerly activated a standby: %+v", stats)
	}
	if stats[0].MaxInflight != 9 || stats[1].MaxInflight != 9 || c.parallel != nil {
		t.Fatalf("default failover changed its original query budget: %+v", stats)
	}
}

func TestParallelDomainsCancellationAndClose(t *testing.T) {
	f := startParallelDNSServer(t)
	f.blocked[0].Store(true)
	f.blocked[1].Store(true)
	c, err := NewClient(parallelTestConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = c.Dial(ctx, "echo:123"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial did not honor caller cancellation: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Dial(context.Background(), "echo:123"); done <- err }()
	time.Sleep(10 * time.Millisecond)
	c.Close()
	select {
	case err = <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("dial did not observe client close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing a parallel client left a blocked dial")
	}
	for _, domain := range c.DomainStats() {
		if domain.ActiveStreams != 0 {
			t.Fatalf("cancelled opening leaked a reservation: %+v", domain)
		}
	}
}

func TestSplitDomainBudget(t *testing.T) {
	for _, tc := range []struct{ total, count int }{{8, 2}, {17, 3}, {4096, 8}, {2, 2}} {
		budgets, err := splitDomainBudget(tc.total, tc.count)
		if err != nil {
			t.Fatal(err)
		}
		sum, low, high := 0, budgets[0], budgets[0]
		for _, budget := range budgets {
			sum += budget
			low, high = min(low, budget), max(high, budget)
		}
		if sum != tc.total || low < 1 || high-low > 1 {
			t.Fatalf("budget %d across %d domains was not conserved fairly: %v", tc.total, tc.count, budgets)
		}
	}
	if _, err := splitDomainBudget(1, 2); err == nil {
		t.Fatal("accepted fewer query slots than active domains")
	}
}

func TestParallelDomainsReserveConcurrentOpeningsFairly(t *testing.T) {
	f := startParallelDNSServer(t)
	c, err := NewClient(parallelTestConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const count = 12
	conns := make(chan net.Conn, count)
	failures := make(chan error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := c.Dial(ctx, "echo:123")
			if err != nil {
				failures <- err
				return
			}
			conns <- conn
		}()
	}
	close(start)
	wg.Wait()
	close(conns)
	close(failures)
	for conn := range conns {
		defer conn.Close()
	}
	for err := range failures {
		t.Error(err)
	}
	for _, domain := range c.DomainStats() {
		if domain.ActiveStreams != count/2 || domain.AssignedStreams != count/2 {
			t.Errorf("simultaneous opening reservations were not balanced: %+v", domain)
		}
	}
}

func TestParallelDomainsValidateBeforeOpeningSockets(t *testing.T) {
	for _, tc := range []struct {
		name, strategy string
		budget         int
	}{{"unknown strategy", "unknown", 8}, {"insufficient total budget", "parallel", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			opened := false
			_, err := NewClient(ClientConfig{Domain: "a.example", Domains: []string{"b.example"},
				Secret: "parallel-domain-test-secret", DomainStrategy: tc.strategy, MaxInflight: tc.budget,
				Resolvers: []string{"127.0.0.1:53"}, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
					opened = true
					return nil, errors.New("socket should not be opened")
				}})
			if err == nil || opened {
				t.Fatalf("invalid configuration was not rejected before socket creation: opened=%v, error=%v", opened, err)
			}
		})
	}
}
