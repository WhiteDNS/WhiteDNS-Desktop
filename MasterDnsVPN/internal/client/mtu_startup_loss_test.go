package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

func TestInitialMTUStageDoesNotRunStartupLossCalibration(t *testing.T) {
	c := buildStartupLossTestClient(t, "a", "b", "c")
	c.mtuProbeFunc = fixedMTUProbe(100, 300)
	calls := 0
	c.mtuStartupLossProbeFunc = func(context.Context, Connection, mtuProbeAxis, int, int, int, time.Duration) mtuLossProbeStats {
		calls++
		return mtuLossProbeStats{Sent: 1, Lost: 1}
	}

	if err := c.runInitialMTUStage(context.Background()); err != nil {
		t.Fatal(err)
	}

	state := c.mtuStateSnapshot()
	if state.UploadMTU != 100 || state.DownloadMTU != 300 {
		t.Fatalf("expected initial MTU stage to preserve binary MTU 100/300, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
	if calls != 0 {
		t.Fatalf("startup loss probe must not run in blocking initial MTU stage, calls=%d", calls)
	}
}

func TestPostConnectStartupLossCalibrationLowersUnreliableMTU(t *testing.T) {
	c := buildStartupLossTestClient(t, "a", "b", "c")
	c.mtuProbeFunc = fixedMTUProbe(100, 300)
	c.mtuStartupLossProbeFunc = func(_ context.Context, _ Connection, axis mtuProbeAxis, candidate int, _ int, samples int, _ time.Duration) mtuLossProbeStats {
		stats := mtuLossProbeStats{Sent: samples}
		if axis == mtuProbeAxisUpload && candidate > 70 {
			stats.Lost = samples
		}
		if axis == mtuProbeAxisDownload && candidate > 200 {
			stats.Lost = samples
		}
		return stats
	}

	if err := c.runInitialMTUStage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.balancer.SetConnectionValidity("c", false) {
		t.Fatal("expected test connection c to be marked inactive")
	}
	if !c.runStartupMTULossVerificationWithOptions(context.Background(), startupMTULossOptions{
		ActiveLimit:   postConnectStartupLossResolverCap,
		MaxSamples:    postConnectStartupLossSampleCap,
		MaxCandidates: postConnectStartupLossCandidateCap,
		LowerOnly:     true,
	}) {
		t.Fatal("expected post-connect startup loss calibration to finish")
	}

	state := c.mtuStateSnapshot()
	if state.UploadMTU != 70 || state.DownloadMTU != 200 {
		t.Fatalf("expected startup loss calibration to lower MTU to 70/200, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
	for _, conn := range c.balancer.AllConnections() {
		if conn.UploadMTUBytes > 70 || conn.DownloadMTUBytes > 200 {
			t.Fatalf("expected balancer connection MTU to be capped after lowering, got %#v", conn)
		}
	}
}

func TestStartupLossCalibrationKeepsReliableMTU(t *testing.T) {
	c := buildStartupLossTestClient(t, "a", "b", "c")
	c.mtuProbeFunc = fixedMTUProbe(100, 300)
	c.mtuStartupLossProbeFunc = func(_ context.Context, _ Connection, _ mtuProbeAxis, _ int, _ int, samples int, _ time.Duration) mtuLossProbeStats {
		return mtuLossProbeStats{Sent: samples}
	}

	if err := c.runInitialMTUStage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.runStartupMTULossVerification(context.Background()) {
		t.Fatal("expected startup loss calibration to finish")
	}

	state := c.mtuStateSnapshot()
	if state.UploadMTU != 100 || state.DownloadMTU != 300 {
		t.Fatalf("expected reliable MTU to stay at 100/300, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
}

func TestStartupLossCalibrationFallsBackWhenInconclusive(t *testing.T) {
	c := buildStartupLossTestClient(t, "a", "b", "c")
	c.mtuProbeFunc = fixedMTUProbe(100, 300)
	c.mtuStartupLossProbeFunc = func(context.Context, Connection, mtuProbeAxis, int, int, int, time.Duration) mtuLossProbeStats {
		return mtuLossProbeStats{}
	}

	if err := c.runInitialMTUStage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.runStartupMTULossVerification(context.Background()) {
		t.Fatal("expected startup loss calibration to finish")
	}

	state := c.mtuStateSnapshot()
	if state.UploadMTU != 100 || state.DownloadMTU != 300 {
		t.Fatalf("expected inconclusive calibration to preserve binary MTU 100/300, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
}

func TestStartupLossCalibrationSeedsLeastLossStatsWithoutDisabling(t *testing.T) {
	c := buildStartupLossTestClient(t, "a", "b")
	c.cfg.MTUStartupLossVerifyMaxLossPercent = 100
	c.mtuProbeFunc = fixedMTUProbe(100, 300)
	c.mtuStartupLossProbeFunc = func(_ context.Context, conn Connection, _ mtuProbeAxis, _ int, _ int, samples int, _ time.Duration) mtuLossProbeStats {
		stats := mtuLossProbeStats{Sent: samples, RTTSum: time.Duration(samples) * time.Millisecond}
		if conn.Key == "b" {
			stats.Lost = samples - 1
		}
		return stats
	}

	if err := c.runInitialMTUStage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.runStartupMTULossVerification(context.Background()) {
		t.Fatal("expected startup loss calibration to finish")
	}

	if active := c.balancer.ActiveCount(); active != 2 {
		t.Fatalf("startup loss calibration must not disable resolvers, active=%d", active)
	}
	selected, err := c.balancer.SelectTargets(Enums.PACKET_PING, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Key != "a" {
		t.Fatalf("expected least-loss stats to prefer resolver a, got %#v", selected)
	}
}

func fixedMTUProbe(upload int, download int) func(context.Context, Connection, int) (mtuConnectionProbeResult, mtuRejectReason) {
	return func(context.Context, Connection, int) (mtuConnectionProbeResult, mtuRejectReason) {
		return mtuConnectionProbeResult{
			UploadBytes:   upload,
			UploadChars:   upload,
			DownloadBytes: download,
		}, mtuRejectNone
	}
}

func buildStartupLossTestClient(t *testing.T, keys ...string) *Client {
	t.Helper()
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		PacketDuplicationCount:             3,
		SetupPacketDuplicationCount:        3,
		ResolverBalancingStrategy:          BalancingLeastLoss,
		MTUTestParallelism:                 1,
		MinUploadMTU:                       40,
		MinDownloadMTU:                     100,
		MaxUploadMTU:                       100,
		MaxDownloadMTU:                     300,
		MTUStartupLossVerifyEnabled:        true,
		MTUStartupLossVerifySamples:        3,
		MTUStartupLossVerifyMaxLossPercent: 0,
		MTUStartupLossVerifyCandidates:     3,
		MTURecheckEnabled:                  false,
		MaxPacketsPerBatch:                 8,
	}, keys...)
	return c
}
