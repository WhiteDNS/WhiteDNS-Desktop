package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerReportValidWritesEachResolverOnce(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "valid.resolvers")
	c := &Client{
		scannerReportPath: reportPath,
		scannerReportSeen: make(map[string]struct{}),
	}
	c.scannerReportActive.Store(true)

	c.recordScannerReportValid(Connection{ResolverLabel: "1.1.1.1:53"})
	c.recordScannerReportValid(Connection{ResolverLabel: "1.1.1.1:53"})
	c.recordScannerReportValid(Connection{ResolverLabel: "8.8.8.8:53"})

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(raw)), "1.1.1.1:53\n8.8.8.8:53"; got != want {
		t.Fatalf("unexpected scanner report:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestScannerReportIgnoredUntilConnectedScanStarts(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "valid.resolvers")
	c := &Client{
		scannerReportPath: reportPath,
		scannerReportSeen: make(map[string]struct{}),
	}

	c.recordScannerReportValid(Connection{ResolverLabel: "1.1.1.1:53"})

	if _, err := os.Stat(reportPath); !os.IsNotExist(err) {
		t.Fatalf("expected scanner report to be absent before connected scan starts, stat err=%v", err)
	}
}
