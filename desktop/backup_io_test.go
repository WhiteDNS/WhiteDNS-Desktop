package main

import (
	"testing"
	"time"
)

func TestDefaultBackupFilenameIsTimestampedJSON(t *testing.T) {
	now := time.Date(2026, time.August, 3, 14, 5, 6, 0, time.UTC)
	if got, want := defaultBackupFilename(now), "whitedns-full-backup-20260803-140506.json"; got != want {
		t.Fatalf("default backup filename = %q, want %q", got, want)
	}
}

func TestBackupFileDialogsRequireAppContext(t *testing.T) {
	app := &App{}
	if _, err := app.SaveBackup(); err == nil {
		t.Fatal("expected save backup to reject a missing app context")
	}
	if _, err := app.SelectBackupFile(); err == nil {
		t.Fatal("expected backup picker to reject a missing app context")
	}
}
