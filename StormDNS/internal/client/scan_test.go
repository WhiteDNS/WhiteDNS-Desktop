package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stormdns-go/internal/logger"
)

func TestRunResolverScanAllowsZeroValidResolvers(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "scan.log")
	c := &Client{log: logger.NewWithFile("test", "INFO", logPath)}

	summary, err := c.RunResolverScan(context.Background())
	if err != nil {
		t.Fatalf("RunResolverScan returned error: %v", err)
	}
	if summary.Total != 0 || summary.Valid != 0 || summary.Rejected != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "WD_SCAN event=complete total=0 valid=0 rejected=0") {
		t.Fatalf("completion line missing from log: %s", raw)
	}
}

func TestResolverScanMachineLines(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "scan.log")
	c := &Client{log: logger.NewWithFile("test", "INFO", logPath)}

	c.logResolverScanValid(Connection{ResolverLabel: "1.1.1.1:53"})
	c.logResolverScanRejected(Connection{ResolverLabel: "8.8.8.8:53"})
	c.logResolverScanComplete(ResolverScanSummary{Total: 3, Valid: 1, Rejected: 2})

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(raw)
	if !strings.Contains(logText, "WD_SCAN event=valid resolver=1.1.1.1:53") {
		t.Fatalf("valid line missing from log: %s", logText)
	}
	if !strings.Contains(logText, "WD_SCAN event=rejected resolver=8.8.8.8:53") {
		t.Fatalf("rejected line missing from log: %s", logText)
	}
	if !strings.Contains(logText, "WD_SCAN event=complete total=3 valid=1 rejected=2") {
		t.Fatalf("completion line missing from log: %s", logText)
	}
}

func TestResolverScanWorkersHonorPauseControl(t *testing.T) {
	controlFile := filepath.Join(t.TempDir(), "mtu-control")
	if err := os.WriteFile(controlFile, []byte("pause\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		mtuScanControlFile: controlFile,
		connections: []Connection{
			{Domain: "example.com", ResolverLabel: "127.0.0.1:53"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	counters := &mtuScanCounters{}
	c.runAllResolverScanWorkers(ctx, nil, 1, counters, nil, nil)
	if counters.completed.Load() != 0 {
		t.Fatalf("expected paused scan-only worker not to start probes, completed=%d", counters.completed.Load())
	}
}
