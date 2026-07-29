package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/security"
)

func TestRunInitialMTUTestsStartsEarlyAndBackgroundActivatesEligibleResolvers(t *testing.T) {
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 3,
		MTUTestParallelism:          1,
		MaxPacketsPerBatch:          8,
	}, "a", "b", "c", "d", "e")

	dStarted := make(chan struct{})
	releaseD := make(chan struct{})
	c.mtuProbeFunc = func(ctx context.Context, conn Connection, _ int) (mtuConnectionProbeResult, mtuRejectReason) {
		switch conn.Key {
		case "d":
			close(dStarted)
			select {
			case <-releaseD:
			case <-ctx.Done():
				return mtuConnectionProbeResult{}, mtuRejectUpload
			}
			return mtuConnectionProbeResult{UploadBytes: 90, UploadChars: 90, DownloadBytes: 250}, mtuRejectNone
		case "e":
			return mtuConnectionProbeResult{UploadBytes: 120, UploadChars: 120, DownloadBytes: 240}, mtuRejectNone
		default:
			return mtuConnectionProbeResult{UploadBytes: 100, UploadChars: 100, DownloadBytes: 200}, mtuRejectNone
		}
	}

	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.syncedUploadMTU != 100 || c.syncedDownloadMTU != 200 {
		t.Fatalf("unexpected synced MTU after early start: up=%d down=%d", c.syncedUploadMTU, c.syncedDownloadMTU)
	}
	if active := c.balancer.ActiveCount(); active != 3 {
		t.Fatalf("expected early start with 3 active resolvers, got %d", active)
	}

	select {
	case <-dStarted:
	case <-time.After(time.Second):
		t.Fatal("expected background MTU scan to continue after early start")
	}
	close(releaseD)

	waitForResolverHealthCondition(t, time.Second, func() bool {
		connD, okD := c.balancer.GetConnectionByKey("d")
		connE, okE := c.balancer.GetConnectionByKey("e")
		return okD && okE && !connD.IsValid && connE.IsValid && c.balancer.ActiveCount() == 4
	}, "expected background scan to reject low-MTU resolver and activate eligible resolver")

	active, _, valid, counts := c.resolverRuntimeSnapshot()
	if active.Count != 4 || valid.Count != 5 || counts.Valid != 5 {
		t.Fatalf("expected runtime state to distinguish active and MTU-valid resolvers, active=%#v valid=%#v counts=%#v", active, valid, counts)
	}
}

func TestRunInitialMTUTestsFullScanWaitsForAllResolvers(t *testing.T) {
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 3,
		MTUTestParallelism:          1,
		MaxPacketsPerBatch:          8,
	}, "a", "b", "c", "d")
	c.fullInitialMTUScan = true

	called := make(map[string]struct{})
	c.mtuProbeFunc = func(_ context.Context, conn Connection, _ int) (mtuConnectionProbeResult, mtuRejectReason) {
		called[conn.Key] = struct{}{}
		return mtuConnectionProbeResult{UploadBytes: 100, UploadChars: 100, DownloadBytes: 200}, mtuRejectNone
	}

	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(called) != 4 {
		t.Fatalf("expected full scan to probe all resolvers, got %#v", called)
	}
	if active := c.balancer.ActiveCount(); active != 4 {
		t.Fatalf("expected all resolvers active after full scan, got %d", active)
	}
}

func TestRunInitialMTUTestsSkipUsesTrustedMTUWithoutProbing(t *testing.T) {
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		MinUploadMTU:       100,
		MaxUploadMTU:       140,
		MinDownloadMTU:     300,
		MaxDownloadMTU:     420,
		MaxPacketsPerBatch: 8,
	}, "a", "b")
	c.skipInitialMTUScan = true
	probed := false
	c.mtuProbeFunc = func(context.Context, Connection, int) (mtuConnectionProbeResult, mtuRejectReason) {
		probed = true
		return mtuConnectionProbeResult{}, mtuRejectUpload
	}

	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probed {
		t.Fatal("expected trusted MTU path to skip resolver probes")
	}
	if c.syncedUploadMTU != 140 || c.syncedDownloadMTU != 420 {
		t.Fatalf("unexpected trusted synced MTU: up=%d down=%d", c.syncedUploadMTU, c.syncedDownloadMTU)
	}
	if active := c.balancer.ActiveCount(); active != 2 {
		t.Fatalf("expected all trusted resolvers active, got %d", active)
	}
	for _, key := range []string{"a", "b"} {
		conn, ok := c.balancer.GetConnectionByKey(key)
		if !ok {
			t.Fatalf("missing resolver %s", key)
		}
		if !conn.IsValid || conn.UploadMTUBytes != 140 || conn.DownloadMTUBytes != 420 {
			t.Fatalf("unexpected trusted resolver state for %s: %#v", key, conn)
		}
	}
	active, _, valid, counts := c.resolverRuntimeSnapshot()
	if active.Count != 2 || valid.Count != 2 || counts.Valid != 2 || counts.Pending != 0 || counts.Rejected != 0 {
		t.Fatalf("unexpected trusted resolver runtime state: active=%#v valid=%#v counts=%#v", active, valid, counts)
	}
}

func TestRunInitialMTUTestsCancellationStopsPendingScan(t *testing.T) {
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 3,
		MTUTestParallelism:          1,
		MaxPacketsPerBatch:          8,
	}, "a", "b", "c")

	ctx, cancel := context.WithCancel(context.Background())
	c.mtuProbeFunc = func(context.Context, Connection, int) (mtuConnectionProbeResult, mtuRejectReason) {
		cancel()
		return mtuConnectionProbeResult{}, mtuRejectUpload
	}

	if err := c.RunInitialMTUTests(ctx); err != ErrNoValidConnections {
		t.Fatalf("expected no valid connections after cancellation, got %v", err)
	}
	if active := c.balancer.ActiveCount(); active != 0 {
		t.Fatalf("expected no active resolvers after cancelled scan, got %d", active)
	}
}

func TestRunInitialMTUTestsCancellationStopsBackgroundScan(t *testing.T) {
	c := buildEarlyStartTestClient(t, config.ClientConfig{
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 3,
		MTUTestParallelism:          1,
		MaxPacketsPerBatch:          8,
	}, "a", "b", "c", "d", "e")

	ctx, cancel := context.WithCancel(context.Background())
	dStarted := make(chan struct{})
	dReleased := make(chan struct{})
	eStarted := make(chan struct{})
	c.mtuProbeFunc = func(ctx context.Context, conn Connection, _ int) (mtuConnectionProbeResult, mtuRejectReason) {
		switch conn.Key {
		case "d":
			close(dStarted)
			<-ctx.Done()
			close(dReleased)
			return mtuConnectionProbeResult{}, mtuRejectUpload
		case "e":
			close(eStarted)
			return mtuConnectionProbeResult{UploadBytes: 120, UploadChars: 120, DownloadBytes: 240}, mtuRejectNone
		default:
			return mtuConnectionProbeResult{UploadBytes: 100, UploadChars: 100, DownloadBytes: 200}, mtuRejectNone
		}
	}

	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatal(err)
	}
	if active := c.balancer.ActiveCount(); active != 3 {
		t.Fatalf("expected early start with 3 active resolvers, got %d", active)
	}
	select {
	case <-dStarted:
	case <-time.After(time.Second):
		t.Fatal("expected background scan to start next resolver")
	}
	cancel()
	select {
	case <-dReleased:
	case <-time.After(time.Second):
		t.Fatal("expected background probe to unblock after cancellation")
	}
	select {
	case <-eStarted:
		t.Fatal("expected cancellation to stop remaining background probes")
	case <-time.After(100 * time.Millisecond):
	}
	if active := c.balancer.ActiveCount(); active != 3 {
		t.Fatalf("expected cancellation to leave only early-start resolvers active, got %d", active)
	}
	active, _, valid, counts := c.resolverRuntimeSnapshot()
	if active.Count != 3 || valid.Count != 3 || counts.Rejected != 1 || counts.Pending != 1 {
		t.Fatalf("expected cancellation to preserve resolver classifications, active=%#v valid=%#v counts=%#v", active, valid, counts)
	}
}

func buildEarlyStartTestClient(t *testing.T, cfg config.ClientConfig, keys ...string) *Client {
	t.Helper()
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Domains = []string{"example.com"}
	c := New(cfg, nil, codec)
	c.active_streams = make(map[uint16]*Stream_client)

	connections := make([]Connection, 0, len(keys))
	ptrs := make([]*Connection, 0, len(keys))
	for i, key := range keys {
		conn := Connection{
			Key:           key,
			Domain:        "example.com",
			Resolver:      "127.0.0.1",
			ResolverPort:  5300 + i,
			ResolverLabel: "127.0.0.1:5300",
		}
		connections = append(connections, conn)
	}
	for i := range connections {
		ptrs = append(ptrs, &connections[i])
	}
	c.balancer.SetConnections(ptrs)
	return c
}
