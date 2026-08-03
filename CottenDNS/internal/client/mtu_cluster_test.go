// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

func TestClusterConnectionsByMTU_GapBanding(t *testing.T) {
	conns := []Connection{
		{ResolverLabel: "a", IsValid: true, DownloadMTUBytes: 4000, UploadMTUBytes: 200},
		{ResolverLabel: "b", IsValid: true, DownloadMTUBytes: 3900, UploadMTUBytes: 180},
		{ResolverLabel: "c", IsValid: true, DownloadMTUBytes: 1000, UploadMTUBytes: 120},
		{ResolverLabel: "d", IsValid: true, DownloadMTUBytes: 950, UploadMTUBytes: 110},
		{ResolverLabel: "invalid", IsValid: false, DownloadMTUBytes: 4000},
		{ResolverLabel: "zero", IsValid: true, DownloadMTUBytes: 0},
	}

	groups := clusterConnectionsByMTU(conns, 0.25)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(groups), groups)
	}

	// Largest-capacity group first.
	if groups[0].DownloadMTU != 3900 {
		t.Errorf("group[0] download MTU = %d, want 3900 (min of the high band)", groups[0].DownloadMTU)
	}
	if groups[0].UploadMTU != 180 {
		t.Errorf("group[0] upload MTU = %d, want 180 (min of the high band)", groups[0].UploadMTU)
	}
	if len(groups[0].Members) != 2 {
		t.Errorf("group[0] members = %d, want 2", len(groups[0].Members))
	}
	if groups[1].DownloadMTU != 950 {
		t.Errorf("group[1] download MTU = %d, want 950", groups[1].DownloadMTU)
	}
	if len(groups[1].Members) != 2 {
		t.Errorf("group[1] members = %d, want 2", len(groups[1].Members))
	}
}

func TestClusterConnectionsByMTU_SingleGroupWhenClose(t *testing.T) {
	conns := []Connection{
		{IsValid: true, DownloadMTUBytes: 4000, UploadMTUBytes: 200},
		{IsValid: true, DownloadMTUBytes: 3950, UploadMTUBytes: 190},
		{IsValid: true, DownloadMTUBytes: 3800, UploadMTUBytes: 195},
	}
	groups := clusterConnectionsByMTU(conns, 0.25)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for closely-spaced MTUs, got %d", len(groups))
	}
	if groups[0].DownloadMTU != 3800 {
		t.Errorf("group download MTU = %d, want 3800 (group min)", groups[0].DownloadMTU)
	}
}

func TestClusterConnectionsByMTU_Empty(t *testing.T) {
	if g := clusterConnectionsByMTU(nil, 0.25); g != nil {
		t.Fatalf("expected nil for no connections, got %+v", g)
	}
	conns := []Connection{{IsValid: false, DownloadMTUBytes: 4000}}
	if g := clusterConnectionsByMTU(conns, 0.25); g != nil {
		t.Fatalf("expected nil when no valid connections, got %+v", g)
	}
}

func TestSelectMTUOperatingPoint_DropsSlowOutliers(t *testing.T) {
	// 40 fast resolvers (4000) + 10 slow (1000). score(4000)=160000 beats
	// score(1000)=50000, so the optimizer runs at 4000 and the 10 slow ones are
	// excluded from the pool.
	conns := make([]Connection, 0, 50)
	for i := 0; i < 40; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 4000})
	}
	for i := 0; i < 10; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000})
	}

	u, d, pool := selectMTUOperatingPoint(conns)
	if d != 4000 {
		t.Errorf("download operating MTU = %d, want 4000", d)
	}
	if u != 200 {
		t.Errorf("upload operating MTU = %d, want 200 (min of the fast pool)", u)
	}
	if pool != 40 {
		t.Errorf("pool size = %d, want 40", pool)
	}
}

func TestSelectMTUOperatingPoint_UploadLaggardBecomesBackup(t *testing.T) {
	// 40 resolvers good on both axes, plus one with a fine download but a very
	// low upload. The joint optimizer must not let that one upload-laggard cap
	// the session upload: it should be excluded from the winning pool.
	conns := make([]Connection, 0, 41)
	for i := 0; i < 40; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 4000})
	}
	conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 40, DownloadMTUBytes: 4000})

	u, d, pool := selectMTUOperatingPoint(conns)
	if u != 200 {
		t.Errorf("upload operating MTU = %d, want 200 (laggard excluded)", u)
	}
	if d != 4000 || pool != 40 {
		t.Errorf("got d=%d pool=%d, want d=4000 pool=40", d, pool)
	}
}

func TestSelectMTUOperatingPoint_KeepsCrowdOverOutlier(t *testing.T) {
	// 1 very-fast resolver (8000) + 50 at 1000. score(8000)=8000 loses to
	// score(1000)=51000, so the crowd wins and nobody is dropped.
	conns := make([]Connection, 0, 51)
	conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 8000})
	for i := 0; i < 50; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000})
	}

	_, d, pool := selectMTUOperatingPoint(conns)
	if d != 1000 {
		t.Errorf("download operating MTU = %d, want 1000 (crowd)", d)
	}
	if pool != 51 {
		t.Errorf("pool size = %d, want 51 (everyone)", pool)
	}
}

func TestSelectMTUOperatingPointPreferHigh_RunsAtHighestSustainableMTU(t *testing.T) {
	// 2 fast resolvers (8000) + 50 at 1000. The throughput-optimal point keeps the
	// crowd at 1000; prefer-high (minPool=2) instead runs at 8000 because two
	// resolvers sustain it — so the high-MTU resolvers actually use their MTU.
	conns := make([]Connection, 0, 52)
	conns = append(conns,
		Connection{IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 8000},
		Connection{IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 8000},
	)
	for i := 0; i < 50; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000})
	}

	// Baseline: throughput-optimal keeps the crowd at 1000.
	if _, d, _ := selectMTUOperatingPoint(conns); d != 1000 {
		t.Fatalf("baseline optimal download = %d, want 1000", d)
	}
	// Prefer-high with minPool=2 raises to 8000.
	u, d, pool := selectMTUOperatingPointPreferHigh(conns, 2)
	if d != 8000 || u != 300 || pool != 2 {
		t.Fatalf("prefer-high got u=%d d=%d pool=%d, want u=300 d=8000 pool=2", u, d, pool)
	}
}

func TestSelectMTUOperatingPointPreferHigh_FallsBackWhenPoolTooSmall(t *testing.T) {
	// Only one resolver sustains the top MTU; with minPool=2 the session must not
	// strand on it — it falls back to the throughput-optimal point.
	conns := []Connection{
		{IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 8000},
		{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
		{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
	}
	u, d, pool := selectMTUOperatingPointPreferHigh(conns, 2)
	// Optimal point over this set is 1000 across all three.
	if d != 1000 || u != 120 || pool != 3 {
		t.Fatalf("prefer-high fallback got u=%d d=%d pool=%d, want u=120 d=1000 pool=3", u, d, pool)
	}
}

func TestSelectMTUOperatingPoint_IgnoresInvalidAndZero(t *testing.T) {
	conns := []Connection{
		{IsValid: false, UploadMTUBytes: 200, DownloadMTUBytes: 9000},
		{IsValid: true, UploadMTUBytes: 0, DownloadMTUBytes: 4000},
		{IsValid: true, UploadMTUBytes: 150, DownloadMTUBytes: 2000},
	}
	u, d, pool := selectMTUOperatingPoint(conns)
	if d != 2000 || u != 150 || pool != 1 {
		t.Errorf("got u=%d d=%d pool=%d, want u=150 d=2000 pool=1", u, d, pool)
	}
}

func TestRebuildValidIndices_PrefersPrimaryKeepsBackup(t *testing.T) {
	// Primaries present -> only primaries are selectable.
	conns := []Connection{
		{Key: "p1", IsValid: true},
		{Key: "b1", IsValid: true, Backup: true},
		{Key: "p2", IsValid: true},
		{Key: "dead", IsValid: false},
	}
	idx := rebuildValidIndices(conns)
	if len(idx) != 2 {
		t.Fatalf("expected 2 primary indices, got %d (%v)", len(idx), idx)
	}
	for _, i := range idx {
		if conns[i].Backup || !conns[i].IsValid {
			t.Errorf("selected non-primary connection %q", conns[i].Key)
		}
	}

	// No primaries -> backups become selectable (failover).
	conns2 := []Connection{
		{Key: "b1", IsValid: true, Backup: true},
		{Key: "b2", IsValid: true, Backup: true},
		{Key: "dead", IsValid: false},
	}
	idx2 := rebuildValidIndices(conns2)
	if len(idx2) != 2 {
		t.Fatalf("expected 2 backup indices on failover, got %d", len(idx2))
	}
}

func TestReclassifyBackups_PromotesSurvivorsAtLowerMTU(t *testing.T) {
	// One fast resolver (4000) + two slow (1000). Initially the fast one is the
	// sole primary and the slow ones are backups.
	conns := []*Connection{
		{Key: "fast", IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 4000},
		{Key: "slow1", IsValid: true, Backup: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
		{Key: "slow2", IsValid: true, Backup: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
	}
	b := NewBalancer(BalancingRoundRobin)
	b.SetConnections(conns)
	if got := b.ValidCount(); got != 1 {
		t.Fatalf("initial active pool = %d, want 1 (only the fast primary)", got)
	}

	// The fast resolver dies; re-derive over survivors (the two slow ones).
	b.SetConnectionValidity("fast", false)
	all := b.AllValidConnectionsIncludingBackup()
	u, d, n := selectMTUOperatingPoint(all)
	if d != 1000 || n != 2 {
		t.Fatalf("operating point over survivors = (u=%d d=%d n=%d), want d=1000 n=2", u, d, n)
	}
	b.ReclassifyBackups(func(cc Connection) bool {
		return cc.DownloadMTUBytes < d || cc.UploadMTUBytes < u
	})

	if got := b.ValidCount(); got != 2 {
		t.Fatalf("after promotion active pool = %d, want 2 (both slow resolvers)", got)
	}
}

func TestBalancingMTUWeighted_BiasesTowardLargerMTU(t *testing.T) {
	conns := []*Connection{
		{Key: "big", IsValid: true, DownloadMTUBytes: 4000},
		{Key: "small", IsValid: true, DownloadMTUBytes: 1000},
	}
	b := NewBalancer(BalancingMTUWeighted)
	b.SetConnections(conns)

	counts := map[string]int{}
	const n = 4000
	for i := 0; i < n; i++ {
		c, ok := b.GetBestConnection()
		if !ok {
			t.Fatal("expected a connection")
		}
		counts[c.Key]++
	}
	// Expected ~80% big / ~20% small (4000:1000). Allow a wide tolerance band.
	if counts["big"] <= counts["small"]*2 {
		t.Fatalf("expected 'big' to dominate ~4:1, got big=%d small=%d", counts["big"], counts["small"])
	}
}

func TestResolverTierCounts_ThreeStates(t *testing.T) {
	c := &Client{}
	c.connections = []Connection{
		{IsValid: true},               // active
		{IsValid: true},               // active
		{IsValid: true, Backup: true}, // reserve
		{IsValid: false},              // invalid
		{IsValid: false},              // invalid
		{IsValid: false},              // invalid
	}
	active, reserve, invalid := c.resolverTierCounts()
	if active != 2 || reserve != 1 || invalid != 3 {
		t.Fatalf("got active=%d reserve=%d invalid=%d, want 2/1/3", active, reserve, invalid)
	}
	if active+reserve+invalid != len(c.connections) {
		t.Fatalf("tier counts (%d) do not sum to total (%d)", active+reserve+invalid, len(c.connections))
	}
}

func TestConnectionsWithoutPreknownMTU(t *testing.T) {
	conns := []Connection{
		{IsValid: true, DownloadMTUBytes: 4000}, // preknown -> skip
		{IsValid: false},                        // new resolver -> scan
		{IsValid: true, DownloadMTUBytes: 0},    // valid but no MTU -> scan
		{IsValid: true, DownloadMTUBytes: 1000}, // preknown -> skip
	}
	idx := connectionsWithoutPreknownMTU(conns)
	if len(idx) != 2 || idx[0] != 1 || idx[1] != 2 {
		t.Fatalf("got indices %v, want [1 2] (only un-cached resolvers scanned)", idx)
	}
}

func TestMTUShouldAdoptOperatingPoint_Hysteresis(t *testing.T) {
	// No current point yet -> adopt.
	if !mtuShouldAdoptOperatingPoint(0, 0, 4000, 0, 2, 2) {
		t.Error("should adopt when no current point exists")
	}
	// Current point stranded (curPool == 0) -> adopt even if smaller.
	if !mtuShouldAdoptOperatingPoint(200, 4000, 1000, 0, 2, 2) {
		t.Error("should adopt when current MTU is stranded")
	}
	// Current sustainable, new only marginally larger (< 12.5%) -> keep stable.
	if mtuShouldAdoptOperatingPoint(200, 4000, 4200, 5, 2, 5) {
		t.Error("should NOT adopt a marginal (<12.5%) improvement (hysteresis)")
	}
	// Current sustainable, new materially larger (> 12.5%) -> adopt.
	if !mtuShouldAdoptOperatingPoint(200, 4000, 4600, 5, 2, 5) {
		t.Error("should adopt a material (>12.5%) improvement")
	}
	// Current sustainable, new smaller but pool fine -> keep stable (no churn).
	if mtuShouldAdoptOperatingPoint(200, 4000, 1000, 5, 2, 8) {
		t.Error("should NOT lower the MTU while the current pool is healthy")
	}
	// Strategy 5 primary tier below its configured minimum -> widen the pool,
	// even if that requires lowering the MTU.
	if !mtuShouldAdoptOperatingPoint(200, 4000, 1000, 1, 2, 8) {
		t.Error("should lower MTU when the strategy-5 primary pool is below target")
	}
}

func TestEvaluateMTUCandidate_LossAware(t *testing.T) {
	// 4 samples, accept threshold 25% loss => at most 1 of 4 may fail.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 4, MTUMaxLoss: 0.25}}

	// Fail exactly 1 of 4 -> loss 25% -> accepted.
	calls := 0
	ok, _, loss := c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return calls != 2, time.Millisecond, nil // 2nd probe fails
	})
	if !ok {
		t.Errorf("expected accept at 25%% loss with threshold 25%%, got reject (loss=%.2f)", loss)
	}
	if loss != 0.25 {
		t.Errorf("loss = %.2f, want 0.25", loss)
	}

	// Fail the first 2 of 4 -> exceeds the 1-failure budget -> rejected. With
	// coarse-then-refine the sampler stops as soon as the 2nd failure locks the
	// reject, but loss is still normalized against the configured sample budget.
	calls = 0
	ok, _, loss = c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return calls > 2, time.Millisecond, nil // first 2 fail
	})
	if ok {
		t.Errorf("expected reject when failures exceed budget, got accept")
	}
	if calls != 2 {
		t.Errorf("expected early-exit after 2 probes, got %d", calls)
	}
	if loss != 0.5 {
		t.Errorf("loss = %.2f, want 0.50 on early reject", loss)
	}
}

func TestEvaluateMTUCandidate_EarlyRejectReportsBudgetedLoss(t *testing.T) {
	// With a zero-loss budget, the first failure rejects the candidate. This used
	// to report 100% because only one probe had been sampled; it should report
	// one failure over the configured sample budget instead.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 6, MTUMaxLoss: 0.0}}
	calls := 0
	ok, _, loss := c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return false, 0, errors.New("timeout")
	})
	if ok {
		t.Fatal("expected reject after first failure with zero-loss budget")
	}
	if calls != 1 {
		t.Fatalf("expected early reject after 1 probe, got %d", calls)
	}
	want := 1.0 / 6.0
	if loss < want-0.0001 || loss > want+0.0001 {
		t.Fatalf("loss = %.4f, want %.4f", loss, want)
	}
}

func TestEvaluateMTUCandidate_EarlyAcceptStopsProbing(t *testing.T) {
	// 6 samples, 0 loss budget -> needs all 6 to pass, but reject locks on the
	// first failure. Here every probe passes; with a 50% budget only
	// neededSuccess = 3 probes are required before accept is locked.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 6, MTUMaxLoss: 0.5}}
	calls := 0
	ok, _, _ := c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return true, time.Millisecond, nil
	})
	if !ok {
		t.Fatal("expected accept when all probes pass")
	}
	// allowedFail = floor(6*0.5)=3, neededSuccess = 6-3 = 3.
	if calls != 3 {
		t.Errorf("expected early-accept after 3 probes, got %d", calls)
	}
}

func TestEvaluateMTUCandidate_LegacyRetry(t *testing.T) {
	// Samples<=1 keeps legacy behavior: accept if any of mtuTestRetries succeed.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 1}, mtuTestRetries: 3}

	calls := 0
	ok, _, loss := c.evaluateMTUCandidate(context.Background(), 200, func(_ int, isRetry bool) (bool, time.Duration, error) {
		calls++
		if calls < 3 {
			return false, 0, errors.New("transient")
		}
		return true, time.Millisecond, nil // 3rd attempt succeeds
	})
	if !ok {
		t.Errorf("expected legacy accept after retries, got reject")
	}
	if loss != 0 {
		t.Errorf("legacy loss = %.2f, want 0 on success", loss)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}
