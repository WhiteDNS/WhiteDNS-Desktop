package cottenmax

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/dnsparser"
)

func TestTrafficProfileDefaultPreservesConfiguration(t *testing.T) {
	for _, profile := range []string{"", "full", " FULL "} {
		cfg := ClientConfig{TrafficProfile: profile, LowReductionPercent: 35, MaxInflight: 377, MaxPathWindow: 99,
			MaxStreams: 93, Hold: 7 * time.Millisecond,
			Discovery: Discovery{Enabled: true, Want: 30, Concurrency: 17, Pace: time.Millisecond, SampleRanges: 47}}
		before := cfg
		name, limiter, err := applyTrafficProfile(&cfg)
		if err != nil || name != TrafficProfileFull || limiter != nil || !reflect.DeepEqual(before, cfg) {
			t.Fatalf("default/full changed its behavior: name=%q limiter=%p err=%v cfg=%+v", name, limiter, err, cfg)
		}
	}
}

func TestTrafficProfileLowCeilingsAndDiscovery(t *testing.T) {
	cfg := ClientConfig{TrafficProfile: " LOW ", DiscoveryForDomain: func(domain string) Discovery {
		return Discovery{Enabled: true, Candidates: []string{domain}, Want: 50, Concurrency: 20, SampleRanges: 100}
	}}
	name, limiter, err := applyTrafficProfile(&cfg)
	if err != nil || name != TrafficProfileLow || limiter == nil {
		t.Fatalf("low profile was not selected: name=%q limiter=%p err=%v", name, limiter, err)
	}
	if cfg.MaxInflight != 0 || cfg.MaxPathWindow != 0 || cfg.MaxStreams != 0 || cfg.Hold != 0 || cfg.LowReductionPercent != 35 {
		t.Fatalf("Low changed Full reference limits, streams or hold: %+v", cfg)
	}
	for _, discovery := range []Discovery{cfg.Discovery, cfg.DiscoveryForDomain("a.example")} {
		if discovery.Want != 4 || discovery.Concurrency != 2 || discovery.Pace != 250*time.Millisecond || discovery.SampleRanges != 0 {
			t.Fatalf("discovery can exceed low profile bounds: %+v", discovery)
		}
	}
	// Choosing low must never increase already stricter user settings.
	cfg = ClientConfig{TrafficProfile: TrafficProfileLow, MaxInflight: 3, MaxPathWindow: 2,
		MaxStreams: 5, Hold: 2 * time.Second, Discovery: Discovery{Want: 1, Concurrency: 1, Pace: time.Second}}
	_, _, err = applyTrafficProfile(&cfg)
	if err != nil || cfg.MaxInflight != 3 || cfg.MaxPathWindow != 2 || cfg.MaxStreams != 5 || cfg.Hold != 2*time.Second || cfg.Discovery.Want != 1 || cfg.Discovery.Concurrency != 1 || cfg.Discovery.Pace != time.Second {
		t.Fatalf("low profile raised stricter limits: %+v, err=%v", cfg, err)
	}
}

func TestTrafficProfileUnknownRejectedBeforeSockets(t *testing.T) {
	var sockets atomic.Int32
	_, err := NewClient(ClientConfig{TrafficProfile: "fast-ish", Domain: "a.example", Secret: "test",
		ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
			sockets.Add(1)
			return nil, net.ErrClosed
		}})
	if err == nil || !strings.Contains(err.Error(), "traffic profile") || sockets.Load() != 0 {
		t.Fatalf("invalid profile opened sockets or lacked clear error: err=%v sockets=%d", err, sockets.Load())
	}
}

func TestTrafficProfileFullKeepsPacingDisabled(t *testing.T) {
	f := startParallelDNSServer(t)
	cfg := parallelTestConfig(f)
	cfg.TrafficProfile = TrafficProfileFull
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.TrafficProfile() != TrafficProfileFull || c.LowReductionPercent() != 35 || c.admission != nil || c.transportAdmission != nil || c.failover.admission != nil || c.failover.cfg.QueryRateLimiter != nil || c.failover.cfg.PercentagePacer != nil || c.failover.cfg.LowReductionPercent != 0 || c.failover.cfg.DisableTailDuplication || c.failover.cfg.InitialResolverLimit != 0 {
		t.Fatal("full profile acquired a rate ceiling or changed discovery/duplication")
	}
}

func TestTrafficProfileLowStreamAdmissionPacesAndCancels(t *testing.T) {
	a := newLowDialAdmission()
	defer a.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start := time.Now()
	results := make(chan time.Time, 6)
	errs := make(chan error, 6)
	for range 6 {
		go func() {
			if err := a.wait(ctx); err != nil {
				errs <- err
				return
			}
			results <- time.Now()
		}()
	}
	times := make([]time.Time, 0, 6)
	for range 6 {
		select {
		case at := <-results:
			times = append(times, at)
		case err := <-errs:
			t.Fatal(err)
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	if times[5].Sub(start) < 950*time.Millisecond {
		t.Fatalf("six attempts bypassed the 2/sec burst4 stream budget: %s", times[5].Sub(start))
	}
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := a.wait(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- a.wait(context.Background()) }()
	a.cancel()
	select {
	case err := <-waiting:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed admission wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release a waiting stream")
	}
}

func TestTrafficProfileLowTransportAdmissionPacesAndCancels(t *testing.T) {
	a := newDialAdmission(LowTrafficStreamsPerSecond, LowTrafficTransportBurst)
	defer a.cancel()
	var calls atomic.Int32
	dial := a.wrapDial(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, io.EOF
	})
	start := time.Now()
	for range 4 {
		if _, err := dial(context.Background(), "tcp", "127.0.0.1:53"); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 950*time.Millisecond || calls.Load() != 4 {
		t.Fatalf("transport dials bypassed 2/sec burst2: calls=%d duration=%s", calls.Load(), time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dial(ctx, "tcp", "127.0.0.1:53"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatal("canceled dial reached the real transport")
	}
	waiting := make(chan error, 1)
	go func() { _, err := dial(context.Background(), "tcp", "127.0.0.1:53"); waiting <- err }()
	a.cancel()
	select {
	case err := <-waiting:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release a waiting transport")
	}
	if calls.Load() != 4 {
		t.Fatal("closed dial reached the real transport")
	}
}

type trafficQuery struct {
	at     time.Time
	domain int
}

type trafficRecorder struct {
	mu      sync.Mutex
	queries []trafficQuery
}

type trafficPacketConn struct {
	net.PacketConn
	recorder *trafficRecorder
}

func (c *trafficPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	at := time.Now()
	n, err := c.PacketConn.WriteTo(b, addr)
	if err == nil {
		query, parseErr := dnsparser.ParseDNSRequestLite(b)
		if parseErr == nil && query.HasQuestion {
			domain := 0
			if strings.HasSuffix(strings.TrimSuffix(query.FirstQuestion.Name, "."), Zone("b.example")) {
				domain = 1
			}
			c.recorder.mu.Lock()
			c.recorder.queries = append(c.recorder.queries, trafficQuery{at: at, domain: domain})
			c.recorder.mu.Unlock()
		}
	}
	return n, err
}

// This sends real UDP DNS and application data through independent domain
// sessions. Rate assertions observe writes at the socket boundary, so network
// scheduler batching cannot manufacture a burst at the receiving socket.
func TestTrafficProfileLowSharesPercentagePacerAcrossDomains(t *testing.T) {
	f := startParallelDNSServer(t)
	recorder := &trafficRecorder{}
	cfg := parallelTestConfig(f)
	cfg.TrafficProfile = TrafficProfileLow
	cfg.MaxInflight, cfg.MaxPathWindow = 256, 256
	cfg.MaxAnswer = 512
	cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		var lc net.ListenConfig
		pc, err := lc.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &trafficPacketConn{PacketConn: pc, recorder: recorder}, nil
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.TrafficProfile() != TrafficProfileLow || c.LowReductionPercent() != 35 || c.failover.cfg.PercentagePacer == nil || c.failover.cfg.QueryRateLimiter != nil || c.failover.cfg.LowReductionPercent != 35 || !c.failover.cfg.DisableTailDuplication {
		t.Fatal("low profile did not configure every domain engine through shared config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conns := make([]net.Conn, 2)
	for i := range conns {
		conns[i], err = c.Dial(ctx, "echo:123")
		if err != nil {
			t.Fatal(err)
		}
		defer conns[i].Close()
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(conns))
	for i, conn := range conns {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			if err := conn.SetDeadline(time.Now().Add(18 * time.Second)); err != nil {
				errs <- err
				return
			}
			data := bytes.Repeat([]byte{byte(i + 17)}, 24<<10)
			written := make(chan error, 1)
			go func() { _, err := io.Copy(conn, bytes.NewReader(data)); written <- err }()
			got := make([]byte, len(data))
			_, readErr := io.ReadFull(conn, got)
			writeErr := <-written
			if readErr != nil {
				errs <- readErr
				return
			}
			if writeErr != nil {
				errs <- writeErr
				return
			}
			if !bytes.Equal(data, got) {
				errs <- io.ErrUnexpectedEOF
			}
		}(i, conn)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	recorder.mu.Lock()
	queries := append([]trafficQuery(nil), recorder.queries...)
	recorder.mu.Unlock()
	sort.Slice(queries, func(i, j int) bool { return queries[i].at.Before(queries[j].at) })
	if len(queries) < 200 {
		t.Fatalf("workload did not exercise sustained pacing: %d queries", len(queries))
	}
	counts := [2]int{}
	for _, query := range queries {
		counts[query.domain]++
	}
	if counts[0] < 50 || counts[1] < 50 {
		t.Fatalf("both domains must carry verified traffic: %v", counts)
	}
	duration := queries[len(queries)-1].at.Sub(queries[0].at)
	for _, stat := range c.DomainStats() {
		if stat.ActiveStreams > 1 || stat.MaxInflight != 128 {
			t.Fatalf("unexpected domain budget: %+v", stat)
		}
	}
	t.Logf("verified %d bytes across two domains using %d queries in %s (%v per domain)", 48<<10, len(queries), duration, counts)
}

func TestTrafficProfileReductionTargetsValidatedBeforeSockets(t *testing.T) {
	for _, profile := range []string{TrafficProfileFull, TrafficProfileLow} {
		for _, percent := range []int{10, 35, 90} {
			cfg := ClientConfig{TrafficProfile: profile, LowReductionPercent: percent, MaxStreams: 200, Hold: 500 * time.Millisecond}
			_, pacer, err := applyTrafficProfile(&cfg)
			if err != nil || cfg.LowReductionPercent != percent || cfg.MaxStreams != 200 || cfg.Hold != 500*time.Millisecond || (pacer != nil) != (profile == TrafficProfileLow) {
				t.Fatalf("profile=%s percent=%d cfg=%+v pacer=%p err=%v", profile, percent, cfg, pacer, err)
			}
		}
		for _, percent := range []int{-1, 9, 91, 100} {
			var sockets atomic.Int32
			_, err := NewClient(ClientConfig{TrafficProfile: profile, LowReductionPercent: percent, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
				sockets.Add(1)
				return nil, net.ErrClosed
			}})
			if err == nil || sockets.Load() != 0 {
				t.Fatalf("invalid target %d opened socket or accepted", percent)
			}
		}
	}
}
