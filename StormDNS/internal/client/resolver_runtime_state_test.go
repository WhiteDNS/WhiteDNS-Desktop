package client

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"stormdns-go/internal/config"
)

func TestFinalizeValidResolversKeepsAllValidResolversActive(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "fast", "wide", "slow")
	for idx := range c.connections {
		c.connections[idx].IsValid = true
		c.connections[idx].UploadMTUBytes = 100 + idx
		c.connections[idx].UploadMTUChars = 120 + idx
		c.connections[idx].DownloadMTUBytes = 180 + idx
	}
	c.balancer.RefreshValidConnections()

	valid, _, _, _ := summarizeValidMTUConnections(c.connections)
	selected, minUpload, minDownload, _ := c.finalizeValidResolvers(valid)

	if len(selected) != 3 {
		t.Fatalf("expected all valid resolvers to remain active, got %d", len(selected))
	}
	if minUpload != 100 || minDownload != 180 {
		t.Fatalf("expected MTU minima from all valid resolvers, got up=%d down=%d", minUpload, minDownload)
	}
	if c.balancer.ValidCount() != 3 {
		t.Fatalf("expected all resolvers active in balancer, got %d", c.balancer.ValidCount())
	}
}

func TestSummarizeValidMTUConnectionsRejectsZeroMTUConnections(t *testing.T) {
	connections := []Connection{
		{Key: "missing-mtu", IsValid: true},
		{Key: "valid", IsValid: true, UploadMTUBytes: 100, UploadMTUChars: 120, DownloadMTUBytes: 180},
	}

	valid, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(connections)

	if len(valid) != 1 || valid[0].Key != "valid" {
		t.Fatalf("expected only positive-MTU connections to be valid, got %+v", valid)
	}
	if minUpload != 100 || minDownload != 180 || minUploadChars != 120 {
		t.Fatalf("unexpected MTU minima: up=%d down=%d chars=%d", minUpload, minDownload, minUploadChars)
	}
}

func TestResolverClassificationTransitions(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")
	for idx := range c.connections {
		c.connections[idx].IsValid = false
		c.connections[idx].UploadMTUBytes = 0
		c.connections[idx].DownloadMTUBytes = 0
	}
	c.resetResolverClassificationsPending()

	_, _, _, counts := c.resolverRuntimeSnapshot()
	if counts.Total != 2 || counts.Pending != 2 || counts.Valid != 0 || counts.Rejected != 0 {
		t.Fatalf("expected all resolvers pending initially, got %#v", counts)
	}

	c.markResolverRejected("a")
	c.markResolverRejected("a")
	_, _, _, counts = c.resolverRuntimeSnapshot()
	if counts.Rejected != 1 || counts.Valid != 0 || counts.Pending != 1 {
		t.Fatalf("expected one rejected resolver after duplicate rejects, got %#v", counts)
	}

	c.markResolverValid("b")
	_, _, _, counts = c.resolverRuntimeSnapshot()
	if counts.Valid != 1 || counts.Rejected != 1 || counts.Pending != 0 {
		t.Fatalf("expected pending-to-valid to leave rejected unchanged, got %#v", counts)
	}

	c.markResolverValid("a")
	c.markResolverValid("a")
	_, _, _, counts = c.resolverRuntimeSnapshot()
	if counts.Valid != 2 || counts.Rejected != 0 || counts.Pending != 0 {
		t.Fatalf("expected rejected-to-valid to reduce rejected count once, got %#v", counts)
	}
}

func TestResolverRuntimeStateFinalCountsAfterAllResolversTested(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b", "c")
	for idx := range c.connections {
		c.connections[idx].IsValid = false
		c.connections[idx].UploadMTUBytes = 0
		c.connections[idx].DownloadMTUBytes = 0
	}
	c.resetResolverClassificationsPending()
	c.markResolverValid("a")
	c.markResolverRejected("b")
	c.markResolverRejected("c")

	_, _, valid, counts := c.resolverRuntimeSnapshot()
	if counts.Total != 3 || counts.Valid != 1 || counts.Rejected != 2 || counts.Pending != 0 {
		t.Fatalf("unexpected final resolver counts: %#v", counts)
	}
	if valid.Count != 1 || !valid.Complete {
		t.Fatalf("unexpected final valid snapshot: %#v", valid)
	}
	line := c.resolverRuntimeStateLogLine(resolverRuntimeListSnapshot{}, resolverRuntimeListSnapshot{}, valid, counts)
	for _, want := range []string{"total_count=3", "valid_count=1", "rejected_count=2", "pending_count=0"} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected resolver state line to include %q, got %s", want, line)
		}
	}
}

func TestResolverRuntimeStateLogSuppressesDuplicateSnapshotsUntilHeartbeat(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "active", "standby")
	now := time.Date(2026, 5, 7, 15, 0, 0, 0, time.UTC)

	line := "WD_RESOLVERS active=active standby=- valid=active,standby"
	if !c.shouldEmitResolverRuntimeState(line, now) {
		t.Fatal("expected first resolver state snapshot to be emitted")
	}
	if c.shouldEmitResolverRuntimeState(line, now.Add(time.Second)) {
		t.Fatal("expected duplicate resolver state snapshot to be suppressed")
	}
	if !c.shouldEmitResolverRuntimeState(line, now.Add(resolverRuntimeStateHeartbeatInterval)) {
		t.Fatal("expected duplicate resolver state snapshot to be emitted on heartbeat")
	}
	if !c.shouldEmitResolverRuntimeState(line+",new", now.Add(resolverRuntimeStateHeartbeatInterval+time.Second)) {
		t.Fatal("expected changed resolver state snapshot to be emitted immediately")
	}
}

func TestResolverRuntimeStateLogLineCapsResolverSamples(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "domain")
	c.connections = nil
	for i := 0; i < resolverRuntimeStateSampleLimit+5; i++ {
		label := fmt.Sprintf("resolver-%04d", i)
		c.connections = append(c.connections, Connection{
			Key:              label,
			ResolverLabel:    label,
			IsValid:          true,
			UploadMTUBytes:   100,
			DownloadMTUBytes: 200,
		})
	}

	active, _, valid, counts := c.resolverRuntimeSnapshot()
	if active.Count != resolverRuntimeStateSampleLimit+5 || valid.Count != resolverRuntimeStateSampleLimit+5 {
		t.Fatalf("expected full resolver counts, got active=%d valid=%d", active.Count, valid.Count)
	}
	if len(active.Sample) != resolverRuntimeStateSampleLimit || active.Complete {
		t.Fatalf("expected capped incomplete active sample, got %#v", active)
	}
	line := c.resolverRuntimeStateLogLine(active, resolverRuntimeListSnapshot{}, valid, counts)
	expectedCount := fmt.Sprintf("active_count=%d", resolverRuntimeStateSampleLimit+5)
	if !strings.Contains(line, expectedCount) || !strings.Contains(line, "active_complete=false") || !strings.Contains(line, "rejected_count=0") {
		t.Fatalf("expected count/sample resolver log line, got %s", line)
	}
}
