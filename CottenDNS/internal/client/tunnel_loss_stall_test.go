package client

import "testing"

// A tunnel that is losing badly sends little new data and many retransmits, so
// a purely data-driven window never closes and the estimate freezes. Adaptive
// duplication reads that estimate and is meant to raise the copy count exactly
// then, so the meter has to keep moving in this regime.
func TestTunnelLossMeterUpdatesWhenDataStalls(t *testing.T) {
	var m tunnelLossMeter

	// A healthy stretch first, so a stale reading would be a low one.
	for i := 0; i < tunnelLossWindow; i++ {
		m.recordData()
	}
	if got := m.perMille(); got != 0 {
		t.Fatalf("clean window should measure no loss, got %d", got)
	}

	// The stall: a trickle of new data against a window's worth of resends.
	for i := 0; i < tunnelLossWindow; i++ {
		m.recordResend()
		if i%20 == 0 {
			m.recordData()
		}
	}
	got := m.perMille()
	if got == 0 {
		t.Fatal("loss estimate stayed frozen while the tunnel was retransmitting")
	}
	if got < 800 {
		t.Fatalf("expected a heavy resend ratio, got %d per mille", got)
	}

	// And that estimate has to move duplication off its floor.
	if copies := duplicationForLoss(1, float64(got)/1000.0, 0.95); copies <= 1 {
		t.Fatalf("duplication stayed at the floor under %d per mille loss", got)
	}
}
