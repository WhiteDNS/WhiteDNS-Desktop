package client

import (
	"testing"
	"time"
)

func TestBalancerLeastLossFallsBackToRoundRobinWithoutStats(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
	}
	b.SetConnections(connections)

	first, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected first connection")
	}
	second, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected second connection")
	}
	third, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected third connection")
	}

	if first.Key != "a" || second.Key != "b" || third.Key != "c" {
		t.Fatalf("expected round-robin a,b,c before stats, got %q,%q,%q", first.Key, second.Key, third.Key)
	}
}

func TestMTUGoodputWeightDiscountsLossyResolvers(t *testing.T) {
	// Unknown MTU -> floor weight, still reachable.
	if w := mtuGoodputWeight(&Connection{DownloadMTUBytes: 0}); w != 1 {
		t.Fatalf("unknown MTU should get unit weight, got %d", w)
	}
	// Lossless resolver keeps its full MTU as weight.
	if w := mtuGoodputWeight(&Connection{DownloadMTUBytes: 1000, DownloadMTULoss: 0}); w != 1000 {
		t.Fatalf("lossless resolver should weight to full MTU, got %d", w)
	}
	// A high-MTU-but-lossy resolver is weighted down to its real goodput, so a
	// smaller-but-clean resolver can out-weigh it. 1000 MTU at 80% loss -> ~200
	// goodput, below a 500 MTU lossless resolver.
	lossy := mtuGoodputWeight(&Connection{DownloadMTUBytes: 1000, DownloadMTULoss: 0.8})
	clean := mtuGoodputWeight(&Connection{DownloadMTUBytes: 500, DownloadMTULoss: 0})
	if lossy != 200 {
		t.Fatalf("expected 1000*0.2=200 goodput weight, got %d", lossy)
	}
	if lossy >= clean {
		t.Fatalf("lossy high-MTU resolver (%d) should weigh less than clean lower-MTU one (%d)", lossy, clean)
	}
	// Fully-lossy resolver still keeps a floor weight of 1.
	if w := mtuGoodputWeight(&Connection{DownloadMTUBytes: 1000, DownloadMTULoss: 1}); w != 1 {
		t.Fatalf("fully-lossy resolver should keep floor weight 1, got %d", w)
	}
}

func TestBalancerLowestLatencyUsesRuntimeStats(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)

	for i := 0; i < 6; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 8*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 2*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected lower-latency resolver b, got %q", best.Key)
	}
}

func TestBalancerHighestMTUSelectsLargestDownloadUploadThenLatency(t *testing.T) {
	b := NewBalancer(BalancingHighestMTU)
	connections := []*Connection{
		{Key: "slow", IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 1200},
		{Key: "fast-low-up", IsValid: true, UploadMTUBytes: 100, DownloadMTUBytes: 3000, MTUResolveTime: time.Millisecond},
		{Key: "fast-high-up-slow", IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 3000, MTUResolveTime: 20 * time.Millisecond},
		{Key: "fast-high-up-fast", IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 3000, MTUResolveTime: 2 * time.Millisecond},
	}
	b.SetConnections(connections)

	selected := b.GetUniqueConnections(3)
	if len(selected) != 3 ||
		selected[0].Key != "fast-high-up-fast" ||
		selected[1].Key != "fast-high-up-slow" ||
		selected[2].Key != "fast-low-up" {
		t.Fatalf("unexpected highest-MTU order: %+v", selected)
	}
	best, ok := b.GetBestConnectionExcluding("fast-high-up-fast")
	if !ok || best.Key != "fast-high-up-slow" {
		t.Fatalf("unexpected highest-MTU fallback: %+v, ok=%v", best, ok)
	}
}

func TestBalancerStatsHalfLifeAlsoAppliesOnSend(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	connections := []*Connection{
		{Key: "a", IsValid: true},
	}
	b.SetConnections(connections)

	for i := 0; i < connectionStatsHalfLifeThreshold+1; i++ {
		b.ReportSend("a")
	}

	stats := b.statsForKey("a")
	if stats == nil {
		t.Fatal("expected stats for resolver a")
	}

	sent, acked, sum, count := stats.snapshot()
	if sent != (connectionStatsHalfLifeThreshold+1)/2 {
		t.Fatalf("expected send-triggered half-life to bound sent, got sent=%d acked=%d sum=%d count=%d", sent, acked, sum, count)
	}
	if acked != 0 || sum != 0 || count != 0 {
		t.Fatalf("expected send-triggered half-life to preserve zero success stats, got acked=%d sum=%d count=%d", acked, sum, count)
	}
}

func TestBalancerStatsHalfLifePreservesRelativeSuccessSignal(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	connections := []*Connection{
		{Key: "a", IsValid: true},
	}
	b.SetConnections(connections)

	for i := 0; i < 800; i++ {
		b.ReportSend("a")
	}
	for i := 0; i < 400; i++ {
		b.ReportSuccess("a", 5*time.Millisecond)
	}
	for i := 0; i < 401; i++ {
		b.ReportSend("a")
	}

	stats := b.statsForKey("a")
	if stats == nil {
		t.Fatal("expected stats for resolver a")
	}

	sent, acked, sum, count := stats.snapshot()
	if sent != 700 || acked != 200 || count != 200 {
		t.Fatalf("expected balanced half-life after crossing threshold, got sent=%d acked=%d count=%d", sent, acked, count)
	}
	if sum != uint64(time.Millisecond/time.Microsecond)*5*200 {
		t.Fatalf("expected RTT signal to decay proportionally, got sum=%d", sum)
	}
}

func TestBalancerSnapshotIgnoresSourceMutationUntilRefresh(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault)
	connections := []*Connection{
		{Key: "a", IsValid: true, UploadMTUBytes: 120},
	}
	b.SetConnections(connections)

	connections[0].UploadMTUBytes = 64

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in balancer snapshot")
	}
	if got.UploadMTUBytes != 120 {
		t.Fatalf("expected immutable snapshot value before refresh, got %d", got.UploadMTUBytes)
	}

	b.RefreshValidConnections()

	got, ok = b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a after refresh")
	}
	if got.UploadMTUBytes != 64 {
		t.Fatalf("expected refreshed snapshot to pick new MTU, got %d", got.UploadMTUBytes)
	}
}

func TestBalancerSetConnectionValidityRefreshesSnapshotFromSource(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault)
	connections := []*Connection{
		{Key: "a", IsValid: false, UploadMTUBytes: 140, DownloadMTUBytes: 220},
	}
	b.SetConnections(connections)

	connections[0].UploadMTUBytes = 90
	connections[0].DownloadMTUBytes = 180

	if !b.SetConnectionValidity("a", true) {
		t.Fatal("expected SetConnectionValidity to succeed")
	}

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in snapshot")
	}
	if !got.IsValid {
		t.Fatal("expected resolver a to become valid")
	}
	if got.UploadMTUBytes != 90 || got.DownloadMTUBytes != 180 {
		t.Fatalf("expected snapshot to pick latest source MTUs, got up=%d down=%d", got.UploadMTUBytes, got.DownloadMTUBytes)
	}
}

func TestBalancerSetConnectionMTURefreshesSourceAndSnapshot(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault)
	connections := []*Connection{
		{Key: "a", IsValid: true, UploadMTUBytes: 120, UploadMTUChars: 180, DownloadMTUBytes: 220},
	}
	b.SetConnections(connections)

	if !b.SetConnectionMTU("a", 90, 135, 180) {
		t.Fatal("expected SetConnectionMTU to succeed")
	}

	if connections[0].UploadMTUBytes != 90 || connections[0].UploadMTUChars != 135 || connections[0].DownloadMTUBytes != 180 {
		t.Fatalf("expected source MTUs to update, got up=%d chars=%d down=%d", connections[0].UploadMTUBytes, connections[0].UploadMTUChars, connections[0].DownloadMTUBytes)
	}

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in snapshot")
	}
	if got.UploadMTUBytes != 90 || got.UploadMTUChars != 135 || got.DownloadMTUBytes != 180 {
		t.Fatalf("expected snapshot MTUs to update, got up=%d chars=%d down=%d", got.UploadMTUBytes, got.UploadMTUChars, got.DownloadMTUBytes)
	}
}
