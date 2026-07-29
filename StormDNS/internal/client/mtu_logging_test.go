package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stormdns-go/internal/logger"
)

func TestAcceptedResolverLogBypassesWarnThreshold(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "stormdns.log")
	c := &Client{log: logger.NewWithFile("test", "WARN", logPath)}
	counters := &mtuScanCounters{}
	conn := &Connection{
		Domain:        "v10.whitedns.shop",
		ResolverLabel: "1.1.1.1:53",
	}

	c.acceptConnectionMTUProbe(
		conn,
		mtuConnectionProbeResult{
			UploadBytes:   120,
			UploadChars:   180,
			DownloadBytes: 1400,
			ResolveTime:   10 * time.Millisecond,
		},
		counters,
		3,
	)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(raw)
	if !strings.Contains(logText, "[INFO] ") ||
		!strings.Contains(logText, "Accepted (1/3): v10.whitedns.shop via 1.1.1.1:53") {
		t.Fatalf("accepted resolver line missing from WARN-level log: %s", logText)
	}
	if !strings.Contains(logText, "upload=120 | download=1400 | totals: valid=1, rejected=0") {
		t.Fatalf("accepted resolver MTU details missing from log: %s", logText)
	}
}

func TestMTUJobBufferSizeIsBoundedByWorkers(t *testing.T) {
	if got := mtuJobBufferSize(100, 100000); got != 200 {
		t.Fatalf("expected worker-sized job buffer, got %d", got)
	}
	if got := mtuJobBufferSize(100, 12); got != 12 {
		t.Fatalf("expected small totals to cap job buffer, got %d", got)
	}
}

func TestMTUProgressThrottleKeepsInitialFinalAndPercentChanges(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	c := &Client{nowFn: func() time.Time { return now }}
	c.resetMTUProgressThrottle()

	if !c.shouldLogMTUProgress(0, 1000, 10) {
		t.Fatal("expected initial progress to be logged")
	}
	if c.shouldLogMTUProgress(1, 1000, 10) {
		t.Fatal("expected same-percent progress inside throttle window to be suppressed")
	}
	if !c.shouldLogMTUProgress(20, 1000, 11) {
		t.Fatal("expected percent change to be logged")
	}
	if c.shouldLogMTUProgress(21, 1000, 11) {
		t.Fatal("expected duplicate percent to be suppressed")
	}
	now = now.Add(mtuProgressInterval)
	if !c.shouldLogMTUProgress(22, 1000, 11) {
		t.Fatal("expected heartbeat progress after throttle interval")
	}
	if !c.shouldLogMTUProgress(1000, 1000, 80) {
		t.Fatal("expected final progress to be logged")
	}
}
