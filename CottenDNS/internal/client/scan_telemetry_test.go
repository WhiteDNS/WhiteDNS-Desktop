package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cottendns-go/internal/logger"
)

// emitScanResult must stay silent during a normal tunnel run (the shared MTU
// probe path) and only emit once RunResolverScan arms it, so WD_SCAN telemetry
// never leaks into non-scan runs.
func TestEmitScanResultGatedByScanTelemetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.txt")
	log := logger.NewWithFile("test", "INFO", path)
	t.Cleanup(func() { _ = log.Close() })
	c := &Client{log: log}

	// Disarmed: nothing should be written.
	c.emitScanResult("1.1.1.1:53", true)

	c.scanTelemetryActive.Store(true)
	c.emitScanResult("8.8.8.8:53", true)
	c.emitScanResult("9.9.9.9:53", false)
	c.scanTelemetryActive.Store(false)
	c.emitScanResult("2.2.2.2:53", true)

	out := readFile(t, path)
	if strings.Contains(out, "1.1.1.1:53") {
		t.Fatalf("emitted before scan telemetry was armed:\n%s", out)
	}
	if strings.Contains(out, "2.2.2.2:53") {
		t.Fatalf("emitted after scan telemetry was disarmed:\n%s", out)
	}
	if !strings.Contains(out, "WD_SCAN event=valid resolver=8.8.8.8:53") {
		t.Fatalf("missing real-time valid line:\n%s", out)
	}
	if !strings.Contains(out, "WD_SCAN event=rejected resolver=9.9.9.9:53") {
		t.Fatalf("missing real-time rejected line:\n%s", out)
	}
}

// The selected-resolver summary must survive LOG_LEVEL=WARN (where the per-
// resolver "Accepted" lines are suppressed), listing active resolvers and
// excluding invalid ones, so the user always sees which resolvers were chosen.
func TestLogSelectedResolversVisibleAtWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.txt")
	log := logger.NewWithFile("test", "WARN", path)
	t.Cleanup(func() { _ = log.Close() })
	c := &Client{log: log}
	c.connections = []Connection{
		{ResolverLabel: "1.1.1.1:53", IsValid: true},
		{ResolverLabel: "8.8.8.8:53", IsValid: true, Backup: true},
		{ResolverLabel: "9.9.9.9:53", IsValid: false},
	}

	c.logSelectedResolvers()

	out := readFile(t, path)
	if !strings.Contains(out, "1.1.1.1:53") {
		t.Fatalf("active resolver not shown at WARN:\n%s", out)
	}
	if !strings.Contains(out, "Connected via") {
		t.Fatalf("expected a visible selection summary at WARN:\n%s", out)
	}
	if strings.Contains(out, "9.9.9.9:53") {
		t.Fatalf("invalid resolver must not be listed as selected:\n%s", out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(data)
}
