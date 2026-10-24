package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func embeddedConnectSession(t *testing.T, e *Embedded, codec *security.Codec, nonce byte) (uint16, uint8) {
	t.Helper()
	query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    []byte{security.DownstreamEncryptedFlag, 0, 0, 100, 2, 0, 1, 2, 3, nonce},
	})
	packet, err := DnsParser.ExtractEncryptedVPNResponseMatching(e.HandleDNSTCP(query), false, []string{"v.example.com"}, codec)
	if err != nil || packet.PacketType != Enums.PACKET_SESSION_ACCEPT || len(packet.Payload) < 3 {
		t.Fatalf("session initialization: packet=%d err=%v", packet.PacketType, err)
	}
	return binary.BigEndian.Uint16(packet.Payload[:2]), packet.Payload[2]
}

func embeddedConnectQuery(t *testing.T, e *Embedded, codec *security.Codec, sessionID uint16, cookie uint8, streamID uint16, host string) {
	t.Helper()
	payload := append([]byte{3, byte(len(host))}, host...)
	payload = append(payload, 1, 187) // TCP/443
	query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{
		SessionID: sessionID, SessionCookie: cookie, StreamID: streamID,
		PacketType: Enums.PACKET_SOCKS5_SYN, TotalFragments: 1, Payload: payload,
	})
	if response := e.HandleDNSTCP(query); len(response) < 12 {
		t.Fatal("authenticated TCP SYN did not get a DNS response")
	}
}

func TestEmbeddedSlowConnectsDoNotSerializeHealthySessions(t *testing.T) {
	blocked := make(chan struct{}, 2)
	healthy := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	in := embeddedSessionLimitConfig(0)
	in.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "healthy.example:443" {
			healthy <- struct{}{}
			return nil, errors.New("test destination unavailable")
		}
		blocked <- struct{}{}
		select {
		case <-ctx.Done():
		case <-release:
		}
		return nil, errors.New("test blocked destination")
	}
	e, err := NewEmbedded(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	codec, _ := security.NewCodec(5, in.Key)
	slowID, slowCookie := embeddedConnectSession(t, e, codec, 1)
	for stream := uint16(1); stream <= 2; stream++ {
		embeddedConnectQuery(t, e, codec, slowID, slowCookie, stream, "slow.example")
		select {
		case <-blocked:
		case <-time.After(time.Second):
			t.Fatal("slow dial did not start")
		}
	}
	healthyID, healthyCookie := embeddedConnectSession(t, e, codec, 2)
	embeddedConnectQuery(t, e, codec, healthyID, healthyCookie, 1, "healthy.example")
	select {
	case <-healthy:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("healthy session waited behind unrelated slow connection attempts")
	}
	_, capacity := e.s.deferredConnectSession.snapshot()
	if queuedCapacity := capacity - len(e.s.deferredConnectSession.workers); queuedCapacity > 128 {
		t.Fatalf("embedded connection queue grew beyond its previous 128-slot budget: %d", queuedCapacity)
	}
}

func TestDeferredQueuedConnectExpiresWithoutStartingFreshDial(t *testing.T) {
	for _, packetType := range []uint8{Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN} {
		t.Run(Enums.PacketTypeName(packetType), func(t *testing.T) {
			s := newTestServerForStreamSyn("TCP")
			var dials atomic.Int32
			s.embeddedDialContext = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("expired work dialed")
			}
			s.socksConnectTimeout = 40 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			s.deferredConnectSession.Start(ctx)
			defer func() { cancel(); s.deferredConnectSession.wait() }()
			release := make(chan struct{})
			started := make(chan struct{}, len(s.deferredConnectSession.workers))
			for i := range s.deferredConnectSession.workers {
				if !s.deferredConnectSession.Enqueue(deferredSessionLane{sessionID: 600, streamID: uint16(i + 1)}, func(ctx context.Context) {
					started <- struct{}{}
					select {
					case <-ctx.Done():
					case <-release:
					}
				}) {
					t.Fatal("cannot occupy connection worker")
				}
			}
			for range s.deferredConnectSession.workers {
				<-started
			}
			record := newTestSessionRecord(800)
			putTestSession(s.sessions, record)
			defer record.closeAllStreams("test cleanup")
			packet := packetWithSession(packetType, record.ID, record.Cookie, 1)
			packet.TotalFragments = 1
			packet.Payload = append([]byte{3, 15}, []byte("healthy.example")...)
			packet.Payload = append(packet.Payload, 1, 187)
			if !s.queueImmediateControlAck(record, packet) {
				t.Fatal("SYN admission ACK was not queued")
			}
			if result := s.dispatchDeferredSessionPacketTracked(packet, "test", func(ctx context.Context) {
				if packetType == Enums.PACKET_STREAM_SYN {
					s.processDeferredStreamSyn(ctx, packet)
				} else {
					s.processDeferredSOCKS5Syn(ctx, packet)
				}
			}); result != deferredDispatchEnqueued {
				t.Fatal("connect was not queued")
			}
			time.Sleep(70 * time.Millisecond)
			close(release)
			want := uint8(Enums.PACKET_STREAM_CONNECT_FAIL)
			if packetType == Enums.PACKET_SOCKS5_SYN {
				want = Enums.PACKET_SOCKS5_TTL_EXPIRED
			}
			deadline := time.Now().Add(time.Second)
			for {
				response, ok := s.dequeueSessionResponse(record.ID, time.Now(), dnsResponseUnlimited)
				if ok && response.PacketType == want {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("expired ACKed connect did not return explicit %s", Enums.PacketTypeName(want))
				}
				time.Sleep(time.Millisecond)
			}
			if dials.Load() != 0 {
				t.Fatal("expired queued work received a new connection attempt")
			}
			for s.isDeferredPacketStillTracked(packet) {
				if time.Now().After(deadline) {
					t.Fatal("expired connect leaked its duplicate guard")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestDeferredConnectDialReceivesRemainingQueueBudget(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	s.socksConnectTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	s.deferredConnectSession.Start(ctx)
	defer func() { cancel(); s.deferredConnectSession.wait() }()
	release := make(chan struct{})
	started := make(chan struct{})
	s.deferredConnectSession.Enqueue(deferredSessionLane{sessionID: 900, streamID: 1}, func(ctx context.Context) {
		close(started)
		select {
		case <-ctx.Done():
		case <-release:
		}
	})
	<-started
	remaining := make(chan time.Duration, 1)
	s.embeddedDialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			remaining <- -1
		} else {
			remaining <- time.Until(deadline)
		}
		return nil, errors.New("test dial failure")
	}
	record := newTestSessionRecord(800)
	putTestSession(s.sessions, record)
	defer record.closeAllStreams("test cleanup")
	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 1)
	if result := s.dispatchDeferredSessionPacketTracked(packet, "test", func(ctx context.Context) {
		s.processDeferredStreamSyn(ctx, packet)
	}); result != deferredDispatchEnqueued {
		t.Fatal("connect was not queued")
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	select {
	case got := <-remaining:
		if got <= 0 || got > 250*time.Millisecond {
			t.Fatalf("dial received %s instead of the remaining enqueue budget", got)
		}
	case <-time.After(time.Second):
		t.Fatal("queued dial did not run")
	}
}

func TestDeferredConnectParentCancellationStaysQuiet(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	s.socksConnectTimeout = time.Nanosecond
	record := newTestSessionRecord(800)
	putTestSession(s.sessions, record)
	defer record.closeAllStreams("test cleanup")
	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	s.deferredConnectRun(packet, func(context.Context) { called = true })(ctx)
	if called {
		t.Fatal("canceled parent started connection work")
	}
	if response, ok := s.dequeueSessionResponse(record.ID, time.Now(), dnsResponseUnlimited); ok {
		t.Fatalf("canceled parent emitted an extra response: %s", Enums.PacketTypeName(response.PacketType))
	}
}

func TestEmbeddedFragmentedConnectRetriesKeepSingleUpstream(t *testing.T) {
	var dials atomic.Int32
	addresses := make(chan string, 2)
	local, remote := net.Pipe()
	defer remote.Close()
	in := embeddedSessionLimitConfig(0)
	in.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		dials.Add(1)
		addresses <- address
		return local, nil
	}
	e, err := NewEmbedded(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	codec, _ := security.NewCodec(5, in.Key)
	sid, cookie := embeddedConnectSession(t, e, codec, 1)
	payload := append([]byte{3, 15}, []byte("healthy.example")...)
	payload = append(payload, 1, 187)
	fragments := [][]byte{payload[:8], payload[8:]}
	send := func(fragment int) {
		t.Helper()
		query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{
			SessionID: sid, SessionCookie: cookie, StreamID: 1, PacketType: Enums.PACKET_SOCKS5_SYN,
			FragmentID: uint8(fragment), TotalFragments: 2, Payload: fragments[fragment],
		})
		if len(e.HandleDNSTCP(query)) < 12 {
			t.Fatal("fragment did not get a DNS reply")
		}
	}
	send(0)
	send(0) // Fresh encryption, as with an ARQ retry.
	send(1)
	select {
	case address := <-addresses:
		if address != "healthy.example:443" {
			t.Fatalf("fragmented target changed: %s", address)
		}
	case <-time.After(time.Second):
		t.Fatal("fragmented connect never started")
	}
	waitEmpty := func() {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			pending, _ := e.s.deferredConnectSession.snapshot()
			if pending == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("fragmented connect work did not finish")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitEmpty()
	send(0)
	send(1)
	waitEmpty()
	if dials.Load() != 1 {
		t.Fatalf("fragment retry duplicated the upstream connection: %d dials", dials.Load())
	}
}
