package client

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDNSListenerBindsIPv6Loopback(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = probe.Close()

	c := createTestClient(t)
	listener := NewDNSListener(c)
	if err := listener.Start(context.Background(), "::1", 0); err != nil {
		t.Fatalf("start IPv6 DNS listener: %v", err)
	}
	defer listener.Stop()
	hasV6 := false
	for _, conn := range listener.conns {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() == nil {
			hasV6 = true
		}
	}
	if !hasV6 {
		t.Fatal("DNS listener did not open an IPv6 socket")
	}
}

type dnsTempError struct {
	timeout   bool
	temporary bool
}

func (e dnsTempError) Error() string   { return "dns temp error" }
func (e dnsTempError) Timeout() bool   { return e.timeout }
func (e dnsTempError) Temporary() bool { return e.temporary }

func TestDNSListenerShouldRetryRead(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "closed", err: net.ErrClosed, want: false},
		{name: "timeout", err: dnsTempError{timeout: true}, want: true},
		{name: "temporary", err: dnsTempError{temporary: true}, want: true},
		{name: "permanent", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		if got := dnsListenerShouldRetryRead(tt.err); got != tt.want {
			t.Fatalf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}
