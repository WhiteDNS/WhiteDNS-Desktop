package cottenmax

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestReceiveBufferCoversConfiguredFlightWithinBounds(t *testing.T) {
	for _, size := range []struct{ flight, answer int }{{1, 512}, {32, 512}, {256, 1232}, {4096, 1232}, {1 << 30, 1 << 30}, {-1, -1}} {
		got := receiveBufferForFlight(size.flight, size.answer)
		if got < 256<<10 || got > 16<<20 {
			t.Fatalf("out-of-bounds socket request %d for %+v", got, size)
		}
	}
	if receiveBufferForFlight(256, 1232) < 2*256*1232 || receiveBufferForFlight(4096, 1232) <= receiveBufferForFlight(256, 1232) {
		t.Fatal("receive request does not cover the configured flight")
	}
}

type bufferForwardingConn struct {
	net.PacketConn
	read, write int
}

func (c *bufferForwardingConn) SetReadBuffer(n int) error  { c.read = n; return nil }
func (c *bufferForwardingConn) SetWriteBuffer(n int) error { c.write = n; return nil }

func TestSizedPacketListenerSupportsForwardedUDPAndErrors(t *testing.T) {
	pc := &bufferForwardingConn{}
	listen := sizedPacketListener(func(context.Context, string, string) (net.PacketConn, error) { return pc, nil }, 256, 1232)
	got, err := listen(context.Background(), "udp", ":0")
	if err != nil || got != pc || pc.read != receiveBufferForFlight(256, 1232) || pc.write != 256<<10 {
		t.Fatalf("forwarded socket sizing failed: %v %+v", err, pc)
	}
	want := errors.New("socket unavailable")
	listen = sizedPacketListener(func(context.Context, string, string) (net.PacketConn, error) { return nil, want }, 256, 1232)
	if got, err := listen(context.Background(), "udp", ":0"); got != nil || !errors.Is(err, want) {
		t.Fatal("socket creation error was not preserved")
	}
}

func TestClientDoesNotResizeInjectedSocket(t *testing.T) {
	underlying, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer underlying.Close()
	pc := &bufferForwardingConn{PacketConn: underlying}
	c, err := NewClient(ClientConfig{Domain: "a.test", Secret: "test", TCP: "off", Resolvers: []string{"127.0.0.1:53"},
		ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return pc, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pc.read != 0 || pc.write != 0 {
		t.Fatalf("injected socket contract changed: read=%d write=%d", pc.read, pc.write)
	}
}
