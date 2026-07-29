package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestMTURecheckUpdatesChangedConnectionAndHotAppliesGlobalMinimum(t *testing.T) {
	c := buildMTURecheckTestClient(t, map[string]mtuConnectionProbeResult{
		"a": {UploadBytes: 90, UploadChars: 90, DownloadBytes: 250},
		"b": {UploadBytes: 120, UploadChars: 120, DownloadBytes: 350},
	})

	if !c.runMTURecheckPass(context.Background()) {
		t.Fatal("expected recheck pass to update MTU state")
	}
	state := c.mtuStateSnapshot()
	if state.UploadMTU != 90 || state.DownloadMTU != 250 {
		t.Fatalf("expected synced MTU to shrink to 90/250, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
	if active := c.balancer.ActiveCount(); active != 2 {
		t.Fatalf("recheck must not disable active resolvers, active=%d", active)
	}
}

func TestMTURecheckIgnoresOneByteDifferences(t *testing.T) {
	c := buildMTURecheckTestClient(t, map[string]mtuConnectionProbeResult{
		"a": {UploadBytes: 99, UploadChars: 99, DownloadBytes: 299},
		"b": {UploadBytes: 100, UploadChars: 100, DownloadBytes: 300},
	})

	if c.runMTURecheckPass(context.Background()) {
		t.Fatal("expected one-byte differences to be ignored")
	}
	state := c.mtuStateSnapshot()
	if state.UploadMTU != 100 || state.DownloadMTU != 300 {
		t.Fatalf("expected synced MTU to stay at 100/300, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
}

func TestMTURecheckTransientFailureDoesNotInvalidateOrShrink(t *testing.T) {
	c := buildMTURecheckTestClient(t, nil)
	c.mtuProbeFunc = func(context.Context, Connection, int) (mtuConnectionProbeResult, mtuRejectReason) {
		return mtuConnectionProbeResult{}, mtuRejectUpload
	}

	if c.runMTURecheckPass(context.Background()) {
		t.Fatal("expected failed recheck to leave MTU unchanged")
	}
	state := c.mtuStateSnapshot()
	if state.UploadMTU != 100 || state.DownloadMTU != 300 {
		t.Fatalf("expected synced MTU to stay at 100/300, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
	if active := c.balancer.ActiveCount(); active != 2 {
		t.Fatalf("transient recheck failure must not invalidate resolvers, active=%d", active)
	}
}

func TestMTURecheckCanIncreaseSyncedMTUWhenAllActiveResolversImprove(t *testing.T) {
	c := buildMTURecheckTestClient(t, map[string]mtuConnectionProbeResult{
		"a": {UploadBytes: 110, UploadChars: 110, DownloadBytes: 330},
		"b": {UploadBytes: 120, UploadChars: 120, DownloadBytes: 350},
	})
	_ = c.balancer.SetConnectionMTU("a", 90, 90, 260)
	_ = c.balancer.SetConnectionMTU("b", 100, 100, 300)
	c.applySyncedMTUState(90, 260, 90)

	if !c.runMTURecheckPass(context.Background()) {
		t.Fatal("expected recheck pass to widen MTU state")
	}
	state := c.mtuStateSnapshot()
	if state.UploadMTU != 110 || state.DownloadMTU != 330 {
		t.Fatalf("expected synced MTU to widen to 110/330, got %d/%d", state.UploadMTU, state.DownloadMTU)
	}
}

func TestMTURecheckLoopExitsOnCancellation(t *testing.T) {
	c := buildMTURecheckTestClient(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.runMTURecheckLoop(ctx, time.Hour)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected recheck loop to exit after cancellation")
	}
}

func buildMTURecheckTestClient(t *testing.T, results map[string]mtuConnectionProbeResult) *Client {
	t.Helper()
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		ResolverBalancingStrategy: BalancingLeastLoss,
		MTURecheckEnabled:         true,
		MTURecheckIntervalMinutes: 5,
		MaxPacketsPerBatch:        8,
	}, "a", "b")
	for _, key := range []string{"a", "b"} {
		_ = c.balancer.ApplyMTUProbeResult(key, 100, 100, 300, 0, true)
	}
	c.applySyncedMTUState(100, 300, 100)
	c.mtuProbeFunc = func(_ context.Context, conn Connection, _ int) (mtuConnectionProbeResult, mtuRejectReason) {
		if results == nil {
			return mtuConnectionProbeResult{UploadBytes: conn.UploadMTUBytes, UploadChars: conn.UploadMTUChars, DownloadBytes: conn.DownloadMTUBytes}, mtuRejectNone
		}
		result, ok := results[conn.Key]
		if !ok {
			return mtuConnectionProbeResult{}, mtuRejectUpload
		}
		return result, mtuRejectNone
	}
	return c
}
