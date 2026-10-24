package soar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// Capture the real encrypted DNS queries without opening any network sockets.
type schedulerPacketConn struct {
	writes []schedulerWrite
}

type schedulerWrite struct {
	data []byte
	addr net.Addr
}

func (p *schedulerPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.writes = append(p.writes, schedulerWrite{append([]byte(nil), b...), addr})
	return len(b), nil
}
func (*schedulerPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*schedulerPacketConn) Close() error                           { return nil }
func (*schedulerPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (*schedulerPacketConn) SetDeadline(time.Time) error            { return nil }
func (*schedulerPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (*schedulerPacketConn) SetWriteDeadline(time.Time) error       { return nil }

func schedulerFixture(t *testing.T, unknown, maxInflight int) (*Client, *path, *stream, *schedulerPacketConn) {
	t.Helper()
	cfg := Config{SafeQName: 101, MaxQName: 101, MaxInflight: maxInflight, TCP: "off"}
	cfg.setDefaults()
	z, err := parseZone("cottenmax-v1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pc := &schedulerPacketConn{}
	cs := &clientSession{
		session:     newSession(true, streamConfig{StreamWindow: 256 << 10, SendBuffer: 256 << 10, MaxStreams: 4}, &packetCipher{}, &packetCipher{}),
		established: true,
	}
	c := &Client{cfg: cfg, z: z, pc: pc, sess: cs, pending: make(map[uint16]*pendingQuery), wakeCh: make(chan struct{}, 1)}
	for i := 0; i <= unknown; i++ {
		p := &path{addr: &net.UDPAddr{IP: net.IPv4(192, 0, byte(i/256), byte(i)), Port: 53}, cwnd: float64(maxInflight), ssthresh: float64(maxInflight), nameLen: 101, qtype: typeTXT}
		c.paths = append(c.paths, p)
	}
	good := c.paths[len(c.paths)-1]
	good.verified, good.hasRTT, good.srtt = true, true, 2*time.Second
	st, err := cs.openStream()
	if err != nil {
		t.Fatal(err)
	}
	st.sbuf = bytes.Repeat([]byte{42}, 256<<10)
	st.spending.add(0, uint64(len(st.sbuf)))
	return c, good, st, pc
}

func TestCottenMaxLargeResolverListKeepsVerifiedTrafficMoving(t *testing.T) {
	for _, maxInflight := range []int{1, 2, 4, 256} {
		t.Run(fmt.Sprint(maxInflight), func(t *testing.T) {
			c, good, _, pc := schedulerFixture(t, 4000, maxInflight)
			// Authentication just consumed one HELLO. Other unanswered HELLOs
			// can already occupy every remaining slot in a small global window.
			for i := 0; i < maxInflight-1; i++ {
				p := c.paths[i]
				p.inflight++
				c.pending[uint16(i)] = &pendingQuery{p: p, sess: c.sess, hello: true, scout: true}
			}
			c.fillLocked(time.Now())
			if len(pc.writes) == 0 || pc.writes[0].addr != good.addr {
				t.Fatal("discovery prevented the authenticated path's first stream query")
			}
			if len(c.sess.sent) == 0 {
				t.Fatal("the available authenticated slot carried no stream/control data")
			}
			if got := c.liveQueriesLocked(); got > maxInflight {
				t.Fatalf("global flight exceeded: %d > %d", got, maxInflight)
			}
		})
	}
}

func TestCottenMaxLargeResolverListScoutsEveryCandidate(t *testing.T) {
	c, good, _, pc := schedulerFixture(t, 4000, 256)
	good.cwnd = 4
	seen := make(map[*path]bool)
	for round := 0; round < 260 && len(seen) < 4000; round++ {
		c.fillLocked(time.Now())
		if good.inflight == 0 {
			t.Fatalf("verified traffic was starved in exploration round %d", round)
		}
		scouts := 0
		for txn, q := range c.pending {
			if q.scout {
				scouts++
				seen[q.p] = true
				if sp := c.sess.sent[q.pn]; sp != nil {
					t.Fatal("an unverified path took ownership of retransmittable traffic")
				}
			} else if sp := c.sess.sent[q.pn]; sp != nil {
				c.sess.acked(sp)
			}
			// Complete this artificial round. There is deliberately no response
			// from a candidate, so it must not monopolize the next scout batch.
			q.p.inflight--
			delete(c.pending, txn)
		}
		if scouts > maxHelloPaths {
			t.Fatalf("unbounded exploration flight: %d", scouts)
		}
		pc.writes = pc.writes[:0]
	}
	if len(seen) != 4000 {
		t.Fatalf("exploration never reached all configured candidates: %d/4000", len(seen))
	}
}

func TestCottenMaxHealthyPathsKeepTheirFullWindow(t *testing.T) {
	c, _, _, _ := schedulerFixture(t, 3, 32)
	for _, p := range c.paths {
		p.verified, p.cwnd = true, 8
	}
	c.fillLocked(time.Now())
	if got := c.liveQueriesLocked(); got != 32 {
		t.Fatalf("healthy paths lost their global flight capacity: %d/32", got)
	}
	for _, p := range c.paths {
		if p.inflight != 8 {
			t.Fatalf("healthy path lost its congestion window: %d/8", p.inflight)
		}
	}
}

func TestCottenMaxUnverifiedPathsCannotTakeApplicationTraffic(t *testing.T) {
	c, good, _, _ := schedulerFixture(t, 4000, 256)
	if got := c.pickPathLocked(time.Now(), nil); got != good {
		t.Fatal("a quicker unverified candidate displaced the authenticated path")
	}
	good.inflight = int(good.cwnd)
	if got := c.pickPathLocked(time.Now(), nil); got != nil {
		t.Fatal("a full authenticated flight spilled application traffic onto unverified paths")
	}
}

func TestCottenMaxQNameTrialDoesNotStrandStreamOrControlBytes(t *testing.T) {
	c, good, st, pc := schedulerFixture(t, 0, 256)
	c.cfg.MaxQName = 253
	good.successes = 3
	controls := append([]ctrl(nil), c.sess.ctrlQ...)
	pending := append(rangeSet(nil), st.spending...)
	c.sendDataLocked(c.sess, good, time.Now(), false)
	if len(pc.writes) != 1 {
		t.Fatalf("size trial sent %d queries", len(pc.writes))
	}
	q, err := parseQuery(pc.writes[0].data, c.z)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(q.question) - 6; got < c.cfg.MaxQName-2 {
		t.Fatalf("trial did not test the full requested QNAME: %d", got)
	}
	_, plain, err := (&packetCipher{}).openUp(q.payload, func(pn uint16) uint64 { return uint64(pn) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain[1:], make([]byte, len(plain)-1)) {
		t.Fatal("size trial carried application/control frames instead of padding")
	}
	if plain[0]>>4 != 0 {
		t.Fatal("explicit size trial requested an idle-poll hold")
	}
	for _, pendingQuery := range c.pending {
		if pendingQuery.deadline.Sub(pendingQuery.sent) != good.rto() {
			t.Fatal("size trial deadline included an idle-poll hold")
		}
	}
	if len(c.sess.sent) != 0 || !reflect.DeepEqual(c.sess.ctrlQ, controls) || !reflect.DeepEqual(st.spending, pending) {
		t.Fatal("size trial took ownership of queued traffic")
	}
	// The size trial is still outstanding, yet an ordinary safe-size query
	// must be able to send the data immediately, without waiting for its RTO.
	c.sendDataLocked(c.sess, good, time.Now(), false)
	if len(c.sess.sent) == 0 || reflect.DeepEqual(st.spending, pending) {
		t.Fatal("application traffic waited for the outstanding size trial")
	}
	q, err = parseQuery(pc.writes[1].data, c.z)
	if err != nil || len(q.question)-6 > c.cfg.SafeQName {
		t.Fatal("ordinary traffic did not retain the usable QNAME size")
	}
}

func TestCottenMaxScoutsRequestImmediatePaddingOnlyAnswers(t *testing.T) {
	c, good, st, pc := schedulerFixture(t, 1, 16)
	good.verified = false
	controls := append([]ctrl(nil), c.sess.ctrlQ...)
	pending := append(rangeSet(nil), st.spending...)
	c.fillLocked(time.Now())
	if len(pc.writes) == 0 {
		t.Fatal("no unverified resolver was vetted")
	}
	for _, write := range pc.writes {
		q, err := parseQuery(write.data, c.z)
		if err != nil {
			t.Fatal(err)
		}
		_, plain, err := (&packetCipher{}).openUp(q.payload, func(pn uint16) uint64 { return uint64(pn) })
		if err != nil {
			t.Fatal(err)
		}
		if plain[0]>>4 != 0 || !bytes.Equal(plain[1:], make([]byte, len(plain)-1)) {
			t.Fatal("scout held its reply or carried retransmittable data")
		}
	}
	for _, q := range c.pending {
		if !q.scout || q.deadline.Sub(q.sent) != q.p.rto() {
			t.Fatal("scout flight/deadline was not independent of idle polling")
		}
	}
	if !reflect.DeepEqual(c.sess.ctrlQ, controls) || !reflect.DeepEqual(st.spending, pending) {
		t.Fatal("scouts took ownership of application/control bytes")
	}
}

func TestCottenMaxConfiguredPoolDeduplicatesWithoutChangingTransports(t *testing.T) {
	for _, mode := range []string{"auto", "on", "only", "off"} {
		t.Run(mode, func(t *testing.T) {
			c, err := NewClient(Config{
				Zone: "cottenmax-v1.v.example.com", ServerKey: make(ed25519.PublicKey, ed25519.PublicKeySize), TCP: mode,
				Resolvers:    []string{"127.0.0.1:53", "127.0.0.1:53", "[::ffff:127.0.0.1]:53", "127.0.0.2:53"},
				ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return &schedulerPacketConn{}, nil },
				DialTCP:      func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			want := 2
			if mode == "auto" || mode == "on" {
				want = 4
			}
			if len(c.paths) != want {
				t.Fatalf("deduplication changed %s transport paths: %d, want %d", mode, len(c.paths), want)
			}
		})
	}
}

func BenchmarkCottenMaxLargeResolverPoolConstructor(b *testing.B) {
	resolvers := make([]string, 4000)
	for i := range resolvers {
		resolvers[i] = fmt.Sprintf("192.0.%d.%d:53", i/256, i%256)
	}
	cfg := Config{
		Zone: "cottenmax-v1.v.example.com", ServerKey: make(ed25519.PublicKey, ed25519.PublicKeySize), TCP: "off", Resolvers: resolvers,
		ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return &schedulerPacketConn{}, nil },
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := NewClient(cfg)
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}
