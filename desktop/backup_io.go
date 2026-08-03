package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const maxBackupFileBytes int64 = 128 << 20

func (a *App) SaveBackup() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("file picker is unavailable")
	}
	rawText, err := a.ExportBackup()
	if err != nil {
		return "", err
	}
	path, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Save WhiteDNS full backup",
		DefaultFilename: defaultBackupFilename(time.Now()),
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "WhiteDNS backup (*.json)", Pattern: "*.json"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(rawText)+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("save backup: %w", err)
	}
	return path, nil
}

func (a *App) SelectBackupFile() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("file picker is unavailable")
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Open WhiteDNS full backup",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "WhiteDNS backup (*.json)", Pattern: "*.json"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("open backup: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("backup path must be a file")
	}
	if info.Size() > maxBackupFileBytes {
		return "", fmt.Errorf("backup file is too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read backup: %w", err)
	}
	return string(raw), nil
}

func defaultBackupFilename(now time.Time) string {
	return "whitedns-full-backup-" + now.Format("20060102-150405") + ".json"
}
