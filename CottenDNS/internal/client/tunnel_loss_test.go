// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import "testing"

func TestTunnelLossMeter_UploadRetransmitRate(t *testing.T) {
	var m tunnelLossMeter

	// Before any full window, no estimate yet.
	if got := m.perMille(); got != 0 {
		t.Fatalf("expected 0 before first window, got %d", got)
	}

	// One window: 50 retransmits against 200 originals -> 50/250 = 20% loss.
	for i := 0; i < 50; i++ {
		m.recordResend()
	}
	for i := 0; i < tunnelLossWindow; i++ {
		m.recordData()
	}
	if got := m.perMille(); got != 200 {
		t.Fatalf("expected 200 per-mille (20%%), got %d", got)
	}

	// A clean window with no retransmits -> 0% loss.
	for i := 0; i < tunnelLossWindow; i++ {
		m.recordData()
	}
	if got := m.perMille(); got != 0 {
		t.Fatalf("expected 0%% loss on a clean window, got %d", got)
	}
}
