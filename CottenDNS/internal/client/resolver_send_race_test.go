package client

import (
	"context"
	"cottendns-go/internal/config"
	"cottendns-go/internal/security"
	"io"
	"net"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

type replyDuringWriteConn struct {
	onWrite func([]byte) (int, error)
}

func (c *replyDuringWriteConn) Write(p []byte) (int, error) { return c.onWrite(p) }
func (*replyDuringWriteConn) Read([]byte) (int, error)      { return 0, io.EOF }
func (*replyDuringWriteConn) Close() error                  { return nil }
func (*replyDuringWriteConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*replyDuringWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (*replyDuringWriteConn) SetDeadline(time.Time) error      { return nil }
func (*replyDuringWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*replyDuringWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPReplyCanClaimPendingBeforeWriteReturns(t *testing.T) {
	c := createTestClient(t)
	q, err := DnsParser.BuildTXTQuestionPacket("reply.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	m := newTCPDataManager(c)
	accepted := false
	conn := &replyDuringWriteConn{onWrite: func(p []byte) (int, error) {
		if len(p) > 2 {
			_, accepted = c.claimResolverSuccessSample(q, addr, "local")
		}
		return len(p), nil
	}}
	key := addr.String() + "#0"
	m.conns[key] = &tcpDataConn{manager: m, key: key, resolverAddr: addr, localAddr: "local", conn: conn}
	m.sendJob(tcpDataJob{serverKey: "a", addr: addr, packet: q, now: time.Now()})
	if !accepted {
		t.Fatal("fast reply arrived before its pending question was registered")
	}
	if len(c.resolverPending) != 0 {
		t.Fatal("send resurrected a pending sample after its reply was consumed")
	}
}

func TestFailedTCPWriteDiscardsOnlyItsPendingSample(t *testing.T) {
	c := createTestClient(t)
	q, err := DnsParser.BuildTXTQuestionPacket("reply.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	m := newTCPDataManager(c)
	key := addr.String() + "#0"
	m.conns[key] = &tcpDataConn{manager: m, key: key, resolverAddr: addr, localAddr: "local", conn: &replyDuringWriteConn{onWrite: func([]byte) (int, error) { return 0, io.ErrClosedPipe }}}
	m.sendJob(tcpDataJob{serverKey: "a", addr: addr, packet: q, now: time.Now()})
	if len(c.resolverPending) != 0 {
		t.Fatal("failed write left a phantom timeout sample")
	}
	old := time.Now()
	c.trackResolverSend(q, addr.String(), "local", "a", old.Add(time.Second))
	c.discardResolverSend(q, addr.String(), "local", old)
	if len(c.resolverPending) != 1 {
		t.Fatal("failed write erased a newer query that reused its ID")
	}
}

func TestTCPQueueBackpressureUnblocksOnCancellation(t *testing.T) {
	c := createTestClient(t)
	m := newTCPDataManager(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.ctx = ctx
	for i := 0; i < cap(m.dataQ); i++ {
		m.dataQ <- tcpDataJob{}
	}
	done := make(chan struct{})
	go func() {
		m.Send("a", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}, []byte{1}, Enums.PacketPriorityHigh+1, time.Now())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("full TCP queue silently discarded the frame")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not release blocked sender")
	}
	if c.txAdmissionDrops.Load() != 0 {
		t.Fatal("backpressure counted as packet loss")
	}
}

func TestSessionInitCancellationClosesPendingUDPExchange(t *testing.T) {
	for _, racers := range []int{1, 2} {
		t.Run(itoaInt(racers), func(t *testing.T) {
			sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sock.Close()
			keys := []string{"a"}
			if racers == 2 {
				keys = append(keys, "b")
			}
			c := buildTestClientWithResolvers(config.ClientConfig{SessionInitRacingCount: racers}, keys...)
			c.codec, _ = security.NewCodec(0, "")
			c.mtuTestTimeout = 10 * time.Second
			c.syncedUploadMTU, c.syncedDownloadMTU = 100, 200
			for i := range c.connections {
				c.connections[i].ResolverLabel = sock.LocalAddr().String()
				c.connections[i].ResolverPort = sock.LocalAddr().(*net.UDPAddr).Port
				c.connections[i].UploadMTUBytes = 100
				c.connections[i].DownloadMTUBytes = 200
			}
			ptrs := make([]*Connection, len(c.connections))
			for i := range ptrs {
				ptrs[i] = &c.connections[i]
			}
			c.balancer.SetConnections(ptrs)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.InitializeSessionContext(ctx, 1) }()
			sock.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := sock.ReadFromUDP(make([]byte, 4096)); err != nil {
				select {
				case initErr := <-done:
					t.Fatalf("initialization failed before exchange: %v", initErr)
				default:
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != context.Canceled {
					t.Fatalf("got %v, want cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("session startup ignored cancellation")
			}
		})
	}
}
