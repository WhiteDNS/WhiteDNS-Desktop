// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_coexist_test.go — locks the two properties that keep the optional
// encrypted listeners from harming the core tunnel:
//
//  1. DoT/DoH draw from a capped sub-budget, so flooding them can never consume
//     the connection headroom plain DNS-over-TCP/53 depends on.
//  2. Automatic coexistence never seizes a TLS port a panel already holds.
// ==============================================================================

package udpserver

import (
	"net"
	"testing"

	"cottendns-go/internal/config"
	"cottendns-go/internal/logger"
)

func TestEncryptedConnCeilingAlwaysLeavesTCPHeadroom(t *testing.T) {
	cases := []struct{ total, configured int }{
		{2048, 0},    // derived share
		{2048, 4096}, // configured above the global ceiling
		{2048, 2048}, // configured exactly at the ceiling
		{4, 0},       // tiny budget
		{1, 0},       // degenerate budget
	}
	for _, tc := range cases {
		got := encryptedConnCeiling(tc.total, tc.configured)
		if got < 1 {
			t.Fatalf("total=%d configured=%d: ceiling %d must be at least 1", tc.total, tc.configured, got)
		}
		if tc.total > 1 && got >= tc.total {
			t.Fatalf("total=%d configured=%d: ceiling %d leaves no headroom for TCP/53", tc.total, tc.configured, got)
		}
	}
}

// A saturated encrypted sub-budget must still leave the parent budget usable,
// which is what guarantees the TCP/53 survival path keeps accepting.
func TestEncryptedBudgetCannotStarvePlainTCP(t *testing.T) {
	const total = 8
	parent := newConnectionBudget(total)
	encrypted := newChildConnectionBudget(parent, encryptedConnCeiling(total, 0)) // 6

	granted := 0
	for encrypted.reserve() {
		granted++
		if granted > total {
			t.Fatal("encrypted budget exceeded the global ceiling")
		}
	}
	if granted >= total {
		t.Fatalf("encrypted budget consumed the whole global budget (%d/%d)", granted, total)
	}

	// TCP/53 reserves straight from the parent and must still succeed.
	if !parent.reserve() {
		t.Fatal("plain TCP/53 was starved by a saturated encrypted budget")
	}

	// Releasing an encrypted slot must give capacity back to the parent too.
	encrypted.release()
	freed := 0
	for parent.reserve() {
		freed++
	}
	if freed == 0 {
		t.Fatal("releasing an encrypted slot did not return parent capacity")
	}
}

func testCoexistServer(t *testing.T, cfg config.ServerConfig) *Server {
	t.Helper()
	return &Server{cfg: cfg, log: logger.New("coexist-test", "error")}
}

// auto must resolve to model A even when the TLS port is completely free: owning
// :443 is an explicit decision, never something that happens by default, so a
// panel installed later can always still bind it.
func TestResolveDoHPlanAutoNeverClaimsFreeTLSPort(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPortForTest(t, probe.Addr().String())
	_ = probe.Close() // the port is now free

	s := testCoexistServer(t, config.ServerConfig{
		DoHCoexistMode: "auto",
		DoHTLSEnabled:  true,
		DoHListenHost:  host,
		DoHListenPort:  port,
		DoHBehindPort:  8453,
	})

	ln, tlsMode := s.resolveDoHPlan()
	if tlsMode || ln != nil {
		t.Fatal("auto mode must resolve to model A and never claim the TLS port")
	}

	// A panel starting afterwards must still be able to take the port.
	panel, err := net.Listen("tcp", net.JoinHostPort(host, itoaPort(port)))
	if err != nil {
		t.Fatalf("auto mode left the TLS port unavailable to a panel: %v", err)
	}
	_ = panel.Close()
}

func TestResolveDoHPlanHonoursExplicitModes(t *testing.T) {
	base := config.ServerConfig{
		DoHListenerEnabled: true,
		DoHTLSEnabled:      true,
		DoHListenHost:      "127.0.0.1",
		DoHListenPort:      443,
		DoHBehindPort:      8453,
	}

	behind := base
	behind.DoHCoexistMode = "behind"
	s := testCoexistServer(t, behind)
	if ln, tlsMode := s.resolveDoHPlan(); tlsMode || ln != nil {
		t.Fatal("explicit behind mode must never bind the TLS port")
	}
	if s.dohWillTerminateTLS() {
		t.Fatal("model A must not require TLS material")
	}

	front := base
	front.DoHCoexistMode = "front"
	s = testCoexistServer(t, front)
	if _, tlsMode := s.resolveDoHPlan(); !tlsMode {
		t.Fatal("explicit front mode must terminate TLS itself")
	}
	if !s.dohWillTerminateTLS() {
		t.Fatal("model B must require TLS material")
	}
}

func splitHostPortForTest(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}
