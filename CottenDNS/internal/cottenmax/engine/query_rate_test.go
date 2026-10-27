package soar

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueryRateLimiterRefillBurstAndStaleClock(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewQueryRateLimiter(100, 4)
	for i := 0; i < 4; i++ {
		if ok, _ := r.TryTake(now); !ok {
			t.Fatal("initial burst unavailable")
		}
	}
	for _, at := range []time.Time{now, now.Add(9 * time.Millisecond), now.Add(-time.Second)} {
		ok, next := r.TryTake(at)
		if delta := next.Sub(now.Add(10 * time.Millisecond)); ok || delta < 0 || delta > time.Nanosecond {
			t.Fatalf("unexpected refill: ok=%v next=%v", ok, next)
		}
	}
	// Floating-point token accounting can conservatively round by one nanosecond.
	if ok, _ := r.TryTake(now.Add(10*time.Millisecond + time.Nanosecond)); !ok {
		t.Fatal("next paced token unavailable")
	}
	// Idle time can refill only the configured burst, never a backlog of tokens.
	for i := 0; i < 5; i++ {
		ok, _ := r.TryTake(now.Add(time.Hour))
		if ok != (i < 4) {
			t.Fatal("idle time changed the burst limit")
		}
	}
}

func TestQueryRateLimiterConcurrentOwnersShareBurst(t *testing.T) {
	r := NewQueryRateLimiter(100, 4)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := r.TryTake(time.Unix(1000, 0)); ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 4 {
		t.Fatalf("shared budget admitted %d owners, want 4", got)
	}
}

func TestQueryPacingDoesNotBuildUnsentDataOrProbes(t *testing.T) {
	c, good, st, pc := schedulerFixture(t, 0, 32)
	c.cfg.QueryRateLimiter = NewQueryRateLimiter(100, 1)
	c.cfg.MaxQName = 253
	good.successes = 3
	now := time.Now()
	c.cfg.QueryRateLimiter.TryTake(now)
	controls := append([]ctrl(nil), c.sess.ctrlQ...)
	pending := append(rangeSet(nil), st.spending...)
	if sent := c.sendDataWithSlotsLocked(c.sess, good, now, true, 32); sent != 0 {
		t.Fatal("throttled query was sent")
	}
	if len(pc.writes) != 0 || len(c.pending) != 0 || len(c.sess.sent) != 0 || good.probing || good.alt != 0 || good.inflight != 0 {
		t.Fatal("denied token mutated packet/probe/loss state")
	}
	if !reflect.DeepEqual(controls, c.sess.ctrlQ) || !reflect.DeepEqual(pending, st.spending) {
		t.Fatal("denied token stranded queued stream or control bytes")
	}
	if d := c.nextDeadlineLocked(now); d != 10*time.Millisecond {
		t.Fatalf("scheduler did not wake for pacing: %v", d)
	}
	if sent := c.sendDataWithSlotsLocked(c.sess, good, now.Add(10*time.Millisecond), true, 32); sent != 1 || !good.probing {
		t.Fatal("paced size probe did not resume")
	}
	if sent := c.sendDataWithSlotsLocked(c.sess, good, now.Add(20*time.Millisecond), true, 31); sent != 1 || len(c.sess.sent) == 0 {
		t.Fatal("paced stream did not resume after size probe")
	}
}

func TestQueryPacingDoesNotStartUnsentHelloClock(t *testing.T) {
	c, _, _, pc := schedulerFixture(t, 4, 32)
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.sess.eph, c.sess.established = eph, false
	c.cfg.QueryRateLimiter = NewQueryRateLimiter(100, 1)
	now := time.Now()
	c.cfg.QueryRateLimiter.TryTake(now)
	c.sendHellosLocked(c.sess, now)
	if len(pc.writes) != 0 || !c.sess.firstHello.IsZero() {
		t.Fatal("denied HELLO started handshake/loss clock")
	}
	for _, p := range c.paths {
		if !p.lastHello.IsZero() || p.inflight != 0 {
			t.Fatal("denied HELLO changed resolver state")
		}
	}
	c.sendHellosLocked(c.sess, now.Add(10*time.Millisecond))
	if len(pc.writes) != 1 || c.sess.firstHello.IsZero() {
		t.Fatal("HELLO did not resume with the shared one-query allowance")
	}
}

func TestQueryPacedScoutsProgressUnderContinuousData(t *testing.T) {
	c, good, _, _ := schedulerFixture(t, 4, 32)
	c.cfg.QueryRateLimiter = NewQueryRateLimiter(100, 1)
	c.cfg.DisableTailDuplication = true
	seen := make(map[*path]bool)
	dataQueries := 0
	now := time.Now()
	for i := 0; i < 110; i++ {
		c.fillLocked(now.Add(time.Duration(i) * 11 * time.Millisecond))
		for txn, q := range c.pending {
			if q.scout {
				seen[q.p] = true
			} else {
				if q.p != good {
					t.Fatal("unverified path took application bytes")
				}
				dataQueries++
				if packet := c.sess.sent[q.pn]; packet != nil {
					c.sess.acked(packet)
				}
			}
			q.p.inflight--
			delete(c.pending, txn)
		}
	}
	if len(seen) < 3 || dataQueries < 50 {
		t.Fatalf("paced traffic starved scouts or data: scouts=%d data=%d", len(seen), dataQueries)
	}
}

func TestLowTrafficResolverStartupDefersWholePool(t *testing.T) {
	for _, discover := range []bool{false, true} {
		t.Run(fmt.Sprint(discover), func(t *testing.T) {
			resolvers := make([]string, 4000)
			for i := range resolvers {
				resolvers[i] = fmt.Sprintf("192.0.%d.%d:53", i/256, i%256)
			}
			c, err := NewClient(Config{
				Zone: "cottenmax-v1.v.example.com", ServerKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
				TCP: "off", Resolvers: resolvers, InitialResolverLimit: 2,
				Discovery:    Discovery{Enabled: discover, Candidates: []string{"203.0.113.250:53"}, Want: 4, Concurrency: 2, Pace: 250 * time.Millisecond},
				ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return &schedulerPacketConn{}, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.mu.Lock()
			defer c.mu.Unlock()
			// The scheduler may already have admitted one paced candidate.
			if len(c.paths) > 3 || len(c.cands) < 3998 {
				t.Fatalf("pool was dropped or eagerly started: paths=%d candidates=%d", len(c.paths), len(c.cands))
			}
			if c.cfg.Discovery.noBundled == discover {
				t.Fatal("deferring configured resolvers changed bundled-discovery policy")
			}
			seen := make(map[string]bool, len(c.cands))
			for _, r := range c.cands {
				seen[r] = true
			}
			for _, r := range resolvers[2:] {
				if !seen[r] {
					t.Fatalf("deferred configured resolver lost: %s", r)
				}
			}
			if !discover && (seen["203.0.113.250:53"] || len(c.cands) != 3998) {
				t.Fatal("deferring explicit resolvers enabled previously disabled candidate sources")
			}
		})
	}
}
