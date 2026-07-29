package client

import (
	"os"
	"path/filepath"
	"strings"
)

const scannerReportEnv = "WHITEDNS_SCANNER_REPORT_FILE"
const scannerInputEnv = "WHITEDNS_SCANNER_INPUT_FILE"

func (c *Client) recordScannerReportValid(conn Connection) {
	if c == nil || !c.scannerReportActive.Load() || strings.TrimSpace(c.scannerReportPath) == "" {
		return
	}
	resolver := strings.TrimSpace(conn.ResolverLabel)
	if resolver == "" {
		return
	}

	c.scannerReportMu.Lock()
	defer c.scannerReportMu.Unlock()
	if c.scannerReportSeen == nil {
		c.scannerReportSeen = make(map[string]struct{})
	}
	if _, exists := c.scannerReportSeen[resolver]; exists {
		return
	}
	c.scannerReportSeen[resolver] = struct{}{}

	if err := os.MkdirAll(filepath.Dir(c.scannerReportPath), 0o755); err != nil {
		if c.log != nil {
			c.log.Errorf("scanner report setup failed: %v", err)
		}
		return
	}
	file, err := os.OpenFile(c.scannerReportPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		if c.log != nil {
			c.log.Errorf("scanner report open failed: %v", err)
		}
		return
	}
	_, writeErr := file.WriteString(resolver + "\n")
	closeErr := file.Close()
	if writeErr != nil && c.log != nil {
		c.log.Errorf("scanner report write failed: %v", writeErr)
	}
	if closeErr != nil && c.log != nil {
		c.log.Errorf("scanner report close failed: %v", closeErr)
	}
}

func (c *Client) resetScannerReportSeen() {
	if c == nil {
		return
	}
	c.scannerReportMu.Lock()
	c.scannerReportSeen = make(map[string]struct{})
	c.scannerReportMu.Unlock()
}
