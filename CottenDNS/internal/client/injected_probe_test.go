package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// fakeInjectingResolver answers every query with a forged NXDOMAIN at once and
// the genuine NOERROR reply 50ms later, like an on-path censor racing a resolver.
func fakeInjectingResolver(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			id := binary.BigEndian.Uint16(buf[:2])
			reply := func(flags uint16) []byte {
				r := make([]byte, 12)
				binary.BigEndian.PutUint16(r[0:2], id)
				binary.BigEndian.PutUint16(r[2:4], flags)
				return r
			}
			_, _ = pc.WriteToUDP(reply(0x8183), from) // QR RD RA, NXDOMAIN
			time.Sleep(50 * time.Millisecond)
			_, _ = pc.WriteToUDP(reply(0x8180), from) // QR RD RA, NOERROR
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestProbeExchangeSkipsForgedNXDOMAIN(t *testing.T) {
	addr := fakeInjectingResolver(t)
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0xBEEF)

	// Probe skipping is opt-in: the tunnel-wide flag alone must not enable it.
	for _, tc := range []struct {
		ignore, inProbes bool
		wantRCode        byte
	}{{true, true, 0}, {true, false, 3}, {false, true, 3}} {
		c := New(config.ClientConfig{Domains: []string{"a.io"}, ResolverIgnoreInjectedNXDOMAIN: tc.ignore, ResolverIgnoreInjectedNXDOMAINInProbes: tc.inProbes}, nil, nil)
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.exchangeUDPQueryWithConn(conn, query, 2*time.Second)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("ignore=%v: %v", tc.ignore, err)
		}
		if got := resp[3] & 0x0F; got != tc.wantRCode {
			t.Fatalf("ignore=%v: rcode %d, want %d", tc.ignore, got, tc.wantRCode)
		}
	}
}
