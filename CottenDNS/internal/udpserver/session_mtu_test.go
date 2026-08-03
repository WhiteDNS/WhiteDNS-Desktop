// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// session_mtu_test.go — validates the server side of the client's dynamic /
// adaptive MTU: whatever upload/download MTU the client negotiates in
// SESSION_INIT (including a lowered value re-derived on a restart after primary
// resolver loss) must be honored and clamped per session. This is the server's
// half of the per-group / re-clustering MTU behavior.
// ==============================================================================

package udpserver

import "testing"

func TestApplyMTUFromSessionInit_HonorsClientMTU(t *testing.T) {
	cases := []struct {
		name         string
		upload       uint16
		download     uint16
		wantDownload int
	}{
		{"typical", 200, 4000, 4000},
		{"lowered after restart", 120, 1000, 1000},
		{"below floor clamps up", 1, 1, minSessionMTU},
		{"above ceiling clamps down", 9000, 9000, maxSessionMTU},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &sessionRecord{}
			r.applyMTUFromSessionInit(tc.upload, tc.download, 5, 0, 0)

			if got := int(r.DownloadMTU); got != tc.wantDownload {
				t.Errorf("DownloadMTU = %d, want %d", got, tc.wantDownload)
			}
			if r.DownloadMTUBytes != tc.wantDownload {
				t.Errorf("DownloadMTUBytes = %d, want %d", r.DownloadMTUBytes, tc.wantDownload)
			}
			if r.DownloadMTUBytes <= 0 {
				t.Errorf("DownloadMTUBytes must be positive, got %d", r.DownloadMTUBytes)
			}
		})
	}
}

// TestApplyMTUFromSessionInit_ReinitLowersMTU mimics a client that first
// negotiates a high MTU, then (after its fast resolver pool died and it
// re-derived a lower operating point) reconnects with a lower MTU. A fresh
// session record must reflect the new, lower value.
func TestApplyMTUFromSessionInit_ReinitLowersMTU(t *testing.T) {
	first := &sessionRecord{}
	first.applyMTUFromSessionInit(200, 4000, 5, 0, 0)
	if first.DownloadMTUBytes != 4000 {
		t.Fatalf("first session download = %d, want 4000", first.DownloadMTUBytes)
	}

	// New session after restart at the re-derived (lower) operating point.
	second := &sessionRecord{}
	second.applyMTUFromSessionInit(120, 1000, 5, 0, 0)
	if second.DownloadMTUBytes != 1000 {
		t.Fatalf("re-init session download = %d, want 1000 (server honors lowered MTU)", second.DownloadMTUBytes)
	}
}
