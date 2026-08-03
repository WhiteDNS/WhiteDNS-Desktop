// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import "testing"

func TestParseResolverCacheLine_WithLossTokens(t *testing.T) {
	line := "2026-04-20T15:04:05Z 8.8.8.8:53 v.domain.com UP=64 DOWN=120 UPLOSS=0 DOWNLOSS=50"
	e, ok := parseResolverCacheLine(line)
	if !ok {
		t.Fatal("expected line to parse")
	}
	if e.UploadMTU != 64 || e.DownloadMTU != 120 {
		t.Errorf("MTU mismatch: up=%d down=%d", e.UploadMTU, e.DownloadMTU)
	}
	if e.UploadLossPerMille != 0 || e.DownloadLossPerMille != 50 {
		t.Errorf("loss mismatch: up=%d down=%d, want 0/50", e.UploadLossPerMille, e.DownloadLossPerMille)
	}
}

func TestParseResolverCacheLine_BackwardCompatNoLoss(t *testing.T) {
	// Older log lines without the UPLOSS/DOWNLOSS tokens must still parse.
	line := "2026-04-20T15:04:05Z 8.8.8.8:53 v.domain.com UP=64 DOWN=120"
	e, ok := parseResolverCacheLine(line)
	if !ok {
		t.Fatal("expected legacy line to parse")
	}
	if e.UploadMTU != 64 || e.DownloadMTU != 120 {
		t.Errorf("MTU mismatch: up=%d down=%d", e.UploadMTU, e.DownloadMTU)
	}
	if e.UploadLossPerMille != 0 || e.DownloadLossPerMille != 0 {
		t.Errorf("expected zero loss for legacy line, got up=%d down=%d", e.UploadLossPerMille, e.DownloadLossPerMille)
	}
}
