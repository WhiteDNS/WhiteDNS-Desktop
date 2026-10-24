package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/dnscache"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

func embeddedTestDNSQuery(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	query, err := DnsParser.BuildTXTQuestionPacket(name, 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(query[:2], id)
	return query
}

func embeddedTestDNSResponse(t *testing.T, query []byte, ttl uint32) []byte {
	t.Helper()
	parsed, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query[:parsed.QuestionEndOffset]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 8, 8}
	binary.BigEndian.PutUint32(rr[6:10], ttl)
	return append(response, rr...)
}

func newEmbeddedDNSFixture(t *testing.T, exchange func(context.Context, []byte) ([]byte, error), allowed func() bool) *Embedded {
	t.Helper()
	in := embeddedSessionLimitConfig(0)
	in.ExchangeDNS = exchange
	if allowed != nil {
		in.Allowed = allowed
	}
	e, err := NewEmbedded(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestEmbeddedDNSCacheTTLAndPolicy(t *testing.T) {
	var calls atomic.Int32
	var allowed atomic.Bool
	allowed.Store(true)
	e := newEmbeddedDNSFixture(t, func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return embeddedTestDNSResponse(t, query, 3), nil
	}, allowed.Load)
	query := embeddedTestDNSQuery(t, "Example.COM", 11)
	if response := e.s.buildDNSQueryResponsePayload(query, 1, 1); len(response) == 0 {
		t.Fatal("missing first response")
	}
	parsed, _ := DnsParser.ParseDNSRequestLite(query)
	key := embeddedDNSQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, 1, 1))
	e.s.embeddedDNSCacheMu.Lock()
	entry := e.s.embeddedDNSCache[key]
	e.s.embeddedDNSCacheMu.Unlock()
	lower := embeddedTestDNSQuery(t, "example.com", 22)
	response, ok := e.s.cachedDNSResponse(key, lower, entry.storedAt.Add(2*time.Second))
	if !ok || binary.BigEndian.Uint16(response[:2]) != 22 {
		t.Fatal("cached response did not keep follower query ID")
	}
	r, err := DnsParser.ParsePacket(response)
	if err != nil || len(r.Answers) != 1 || r.Answers[0].TTL != 1 {
		t.Fatalf("cached response TTL did not age: %+v, %v", r.Answers, err)
	}
	if string(response[12:parsed.QuestionEndOffset]) != string(lower[12:parsed.QuestionEndOffset]) {
		t.Fatal("cached question did not preserve caller case")
	}
	if _, ok := e.s.cachedDNSResponse(key, lower, entry.expiresAt); ok {
		t.Fatal("repeated hits prolonged the authoritative TTL")
	}
	if response := e.s.buildDNSQueryResponsePayload(lower, 1, 2); len(response) == 0 || calls.Load() != 2 {
		t.Fatal("expired entry was not resolved again")
	}
	allowed.Store(false)
	if response := e.s.buildDNSQueryResponsePayload(lower, 1, 3); response != nil || calls.Load() != 2 {
		t.Fatal("cached DNS bypassed account policy")
	}
}

func TestEmbeddedDNSZeroTTLAndRequestPolicyIsolation(t *testing.T) {
	var calls atomic.Int32
	e := newEmbeddedDNSFixture(t, func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return embeddedTestDNSResponse(t, query, 0), nil
	}, nil)
	q := embeddedTestDNSQuery(t, "example.com", 1)
	e.s.buildDNSQueryResponsePayload(q, 1, 1)
	e.s.buildDNSQueryResponsePayload(q, 1, 2)
	if calls.Load() != 2 {
		t.Fatal("zero TTL response was cached")
	}
	e.s.embeddedDNSExchange = func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return embeddedTestDNSResponse(t, query, 60), nil
	}
	e.s.buildDNSQueryResponsePayload(q, 1, 3)
	cd := append([]byte(nil), q...)
	cd[3] |= 0x10
	e.s.buildDNSQueryResponsePayload(cd, 1, 4)
	smallEDNS := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(smallEDNS[len(smallEDNS)-8:len(smallEDNS)-6], 512)
	e.s.buildDNSQueryResponsePayload(smallEDNS, 1, 5)
	do := append([]byte(nil), q...)
	do[len(do)-4] |= 0x80
	e.s.buildDNSQueryResponsePayload(do, 1, 6)
	if calls.Load() != 6 {
		t.Fatalf("different CD/EDNS policies shared a cache result: calls=%d", calls.Load())
	}
	dnskey := append([]byte(nil), q...)
	parsed, _ := DnsParser.ParseDNSRequestLite(q)
	binary.BigEndian.PutUint16(dnskey[parsed.QuestionEndOffset-4:parsed.QuestionEndOffset-2], 48)
	e.s.buildDNSQueryResponsePayload(dnskey, 1, 7)
	if calls.Load() != 7 {
		t.Fatal("embedded resolver hook lost support for DNSKEY queries")
	}
}

func TestEmbeddedDNSNegativeTTLAndOPTFlags(t *testing.T) {
	e := newEmbeddedDNSFixture(t, func(context.Context, []byte) ([]byte, error) { return nil, net.ErrClosed }, nil)
	query := embeddedTestDNSQuery(t, "absent.example", 1)
	parsed, _ := DnsParser.ParseDNSRequestLite(query)
	response := append([]byte(nil), query[:parsed.QuestionEndOffset]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[8:10], 1)
	binary.BigEndian.PutUint16(response[10:12], 1)
	soa := []byte{0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 100, 0, 22}
	soa = append(soa, make([]byte, 22)...)
	binary.BigEndian.PutUint32(soa[len(soa)-4:], 3)
	response = append(response, soa...)
	opt := []byte{0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0}
	response = append(response, opt...)
	now := time.Now()
	key := embeddedDNSQueryKey(query, dnscache.BuildKey(parsed.FirstQuestion.Name, 1, 1))
	e.s.cacheEmbeddedDNSResponse(key, query, response, parsed.FirstQuestion, now)
	cached, ok := e.s.cachedDNSResponse(key, query, now.Add(2*time.Second))
	if !ok {
		t.Fatal("valid negative response was not cached")
	}
	r, err := DnsParser.ParsePacket(cached)
	if err != nil || len(r.Authorities) != 1 || r.Authorities[0].TTL != 1 || len(r.Additional) != 1 || r.Additional[0].TTL != 0x8000 {
		t.Fatalf("negative TTL or OPT flags changed incorrectly: %+v, %v", r, err)
	}
	if _, ok := e.s.cachedDNSResponse(key, query, now.Add(3*time.Second)); ok {
		t.Fatal("negative SOA minimum did not expire the response")
	}
}

func TestEmbeddedDNSCancellationAndPolicyDuringLookup(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller_cancel", true: "policy_revoked"}[revoke], func(t *testing.T) {
			var allowed atomic.Bool
			allowed.Store(true)
			started, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			e := newEmbeddedDNSFixture(t, func(ctx context.Context, query []byte) ([]byte, error) {
				close(started)
				defer close(exited)
				select {
				case <-release:
					return embeddedTestDNSResponse(t, query, 60), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}, allowed.Load)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan []byte, 1)
			query := embeddedTestDNSQuery(t, "example.com", 1)
			go func() { done <- e.s.buildDNSQueryResponsePayloadContext(ctx, query, 1, 1) }()
			<-started
			if revoke {
				allowed.Store(false)
				close(release)
			} else {
				cancel()
			}
			select {
			case response := <-done:
				if response != nil {
					t.Fatal("cancelled or revoked lookup was delivered")
				}
			case <-time.After(time.Second):
				t.Fatal("actual DNS lookup ignored caller cancellation")
			}
			<-exited
			if len(e.s.embeddedDNSCache) != 0 {
				t.Fatal("cancelled or revoked lookup populated cache")
			}
		})
	}
}

func TestEmbeddedDNSWorkerBounds(t *testing.T) {
	for _, workers := range []int{0, 1, 2, 8, 64} {
		dnsWorkers, _, dnsQueue, _ := splitDeferredSessionPools(workers, 64)
		if dnsWorkers != min(max(workers, 2), 8) || dnsQueue != 64 {
			t.Fatalf("workers=%d: DNS workers=%d, queue=%d", workers, dnsWorkers, dnsQueue)
		}
	}
}

func TestEmbeddedDNSQueueAgeConsumesLookupBudget(t *testing.T) {
	s := &Server{
		cfg:                config.ServerConfig{DNSUpstreamTimeoutSecs: 0.06},
		deferredDNSSession: newDeferredSessionProcessor(2, 64, nil),
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.deferredDNSSession.Start(ctx)
	t.Cleanup(func() {
		cancel()
		s.deferredDNSSession.wait()
	})
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var queuedRan atomic.Bool
	for sequence := uint16(1); sequence <= 2; sequence++ {
		if !s.dispatchDeferredSessionPacket(VpnProto.Packet{SessionID: 1, SequenceNum: sequence, PacketType: Enums.PACKET_DNS_QUERY_REQ}, func(ctx context.Context) {
			started <- struct{}{}
			<-release
		}) {
			t.Fatal("blocking worker task was not admitted")
		}
	}
	<-started
	<-started
	if !s.dispatchDeferredSessionPacket(VpnProto.Packet{SessionID: 1, SequenceNum: 3, PacketType: Enums.PACKET_DNS_QUERY_REQ}, func(context.Context) {
		queuedRan.Store(true)
	}) {
		t.Fatal("queued task was not admitted")
	}
	time.Sleep(90 * time.Millisecond)
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pending, _ := s.deferredDNSSession.snapshot()
		if pending == 0 {
			if queuedRan.Load() {
				t.Fatal("stale queued DNS request began a fresh lookup budget")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expired DNS queue did not drain")
}

func TestEmbeddedDNSInflightCoalescesIDsAndCancelsFollower(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	e := newEmbeddedDNSFixture(t, func(ctx context.Context, query []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return embeddedTestDNSResponse(t, query, 60), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil)
	leaderDone := make(chan []byte, 1)
	go func() {
		leaderDone <- e.s.buildDNSQueryResponsePayload(embeddedTestDNSQuery(t, "example.com", 1), 1, 1)
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	followerDone := make(chan []byte, 1)
	go func() {
		followerDone <- e.s.buildDNSQueryResponsePayloadContext(ctx, embeddedTestDNSQuery(t, "example.com", 2), 1, 2)
	}()
	cancel()
	select {
	case response := <-followerDone:
		if response != nil {
			t.Fatal("cancelled follower received a response")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled follower kept a DNS worker busy")
	}
	var wg sync.WaitGroup
	for id := uint16(3); id < 19; id++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			query := embeddedTestDNSQuery(t, "EXAMPLE.com", id)
			response := e.s.buildDNSQueryResponsePayload(query, 1, id)
			if len(response) < 2 || binary.BigEndian.Uint16(response[:2]) != id {
				t.Errorf("follower query %d received wrong transaction ID", id)
			}
			parsed, _ := DnsParser.ParseDNSRequestLite(query)
			if len(response) < parsed.QuestionEndOffset || string(response[12:parsed.QuestionEndOffset]) != string(query[12:parsed.QuestionEndOffset]) {
				t.Errorf("follower query %d did not echo caller's question case", id)
			}
		}(id)
	}
	time.Sleep(25 * time.Millisecond)
	close(release)
	wg.Wait()
	if response := <-leaderDone; len(response) == 0 || calls.Load() != 1 {
		t.Fatalf("identical inflight queries made %d upstream requests", calls.Load())
	}
}

func TestEmbeddedDNSBlockedLookupDoesNotSerializeSession(t *testing.T) {
	blocked, release := make(chan struct{}), make(chan struct{})
	e := newEmbeddedDNSFixture(t, func(ctx context.Context, query []byte) ([]byte, error) {
		parsed, _ := DnsParser.ParseDNSRequestLite(query)
		if parsed.FirstQuestion.Name == "blocked.example" {
			close(blocked)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return embeddedTestDNSResponse(t, query, 60), nil
	}, nil)
	if workers := len(e.s.deferredDNSSession.workers); workers < 2 || workers > 8 {
		t.Fatalf("DNS concurrency is not bounded at 2..8: %d", workers)
	}
	dispatch := func(sequence uint16, name string, done chan<- struct{}) {
		t.Helper()
		query := embeddedTestDNSQuery(t, name, sequence)
		if !e.s.dispatchDeferredSessionPacket(VpnProto.Packet{SessionID: 7, SequenceNum: sequence, PacketType: Enums.PACKET_DNS_QUERY_REQ}, func(ctx context.Context) {
			if response := e.s.buildDNSQueryResponsePayloadContext(ctx, query, 7, sequence); len(response) != 0 {
				close(done)
			}
		}) {
			t.Fatal("DNS work was not admitted")
		}
	}
	first, second := make(chan struct{}), make(chan struct{})
	dispatch(1, "blocked.example", first)
	<-blocked
	dispatch(2, "healthy.example", second)
	select {
	case <-second:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("one failed lookup serialized unrelated DNS in the same session")
	}
	close(release)
	<-first
}

func TestEmbeddedDialPropagatesCancellationAndRequestedTimeout(t *testing.T) {
	for _, mode := range []string{"caller_cancel", "caller_deadline", "requested_timeout", "account_close"} {
		t.Run(mode, func(t *testing.T) {
			started, released := make(chan struct{}), make(chan struct{})
			in := embeddedSessionLimitConfig(0)
			in.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				close(released)
				return nil, ctx.Err()
			}
			e, err := NewEmbedded(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { e.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "caller_deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 25*time.Millisecond)
				defer stop()
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if mode == "requested_timeout" {
					_, err = e.s.dialStreamUpstreamFn("tcp", "8.8.8.8:443", 25*time.Millisecond)
				} else {
					_, err = e.s.dialTCPTargetContext(ctx, "8.8.8.8:443")
				}
				done <- err
			}()
			<-started
			if mode == "caller_cancel" {
				cancel()
			}
			if mode == "account_close" {
				e.Close()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("dial returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled dial did not return")
			}
			select {
			case <-released:
			default:
				t.Fatal("caller returned but actual outbound dial was still running")
			}
		})
	}
}
