package udpserver

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"cottendns-go/internal/udpframe"
)

func TestReadSOCKS5BoundUDPAddress(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		payload := append([]byte{4, 3, 2, 1}, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[4:], 5300)
		_, _ = server.Write(payload)
	}()
	addr, err := readSOCKS5BoundUDPAddress(client, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if !addr.IP.Equal(net.IPv4(4, 3, 2, 1)) || addr.Port != 5300 {
		t.Fatalf("unexpected relay address: %v", addr)
	}
}

func TestResolvePublicUDPAddrRejectsLocalAndPrivateTargets(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "::1", "fd00::1", "169.254.1.1"} {
		if _, err := resolvePublicUDPAddr(host, 443); err == nil {
			t.Fatalf("expected %s to be rejected", host)
		}
	}
}

func TestResolvePublicUDPAddrAcceptsPublicIPv4AndIPv6(t *testing.T) {
	for _, host := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		addr, err := resolvePublicUDPAddr(host, 443)
		if err != nil {
			t.Fatalf("resolve %s: %v", host, err)
		}
		if addr.Port != 443 || !addr.IP.Equal(net.ParseIP(host)) {
			t.Fatalf("unexpected address for %s: %v", host, addr)
		}
	}
}

func TestUDPAssociationReadDeadlineIsTransient(t *testing.T) {
	association := newUDPAssociationConn()
	defer association.Close()
	if err := association.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	_, err := association.Read(buffer)
	if err == nil {
		t.Fatal("expected read timeout")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || !netErr.Temporary() {
		t.Fatalf("expected transient network timeout, got %T %v", err, err)
	}
}

func TestUDPAssociationMonitoringLifecycleAndErrors(t *testing.T) {
	s := &Server{}
	association := newUDPAssociationConn(s)
	if s.genericUDPActive.Load() != 1 || s.genericUDPTotal.Load() != 1 {
		t.Fatalf("association counters active=%d total=%d", s.genericUDPActive.Load(), s.genericUDPTotal.Load())
	}

	frame, err := udpframe.Encode(udpframe.AddressTypeIPv4, "127.0.0.1", 443, []byte("blocked"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := association.Write(frame); err != nil {
		t.Fatal(err)
	}
	if s.genericUDPErrors.Load() != 1 {
		t.Fatalf("generic UDP errors=%d want=1", s.genericUDPErrors.Load())
	}
	if err := association.Close(); err != nil {
		t.Fatal(err)
	}
	if s.genericUDPActive.Load() != 0 {
		t.Fatalf("generic UDP active=%d want=0", s.genericUDPActive.Load())
	}
}
