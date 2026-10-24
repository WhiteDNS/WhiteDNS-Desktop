package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"whitedns-desktop/internal/model"
	runtimemgr "whitedns-desktop/internal/runtime"
	"whitedns-desktop/internal/storm"
)

func (a *App) startSoarDNSScanner(connection model.ConnectionProfile, inputPath, inputName string, total, invalid, duplicates, parallel int) (model.ScannerState, error) {
	parallel = min(normalizeDNSScannerParallel(parallel), storm.MaxSoarScannerParallel)
	data, err := storm.RenderSoarScannerConfig(connection, parallel)
	if err != nil {
		return a.GetScannerState(), err
	}
	runtimeDir, err := a.newDNSScannerRuntimeDir()
	if err != nil {
		return a.GetScannerState(), err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(runtimeDir)
		}
	}()
	manager := runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), runtimemgr.Callbacks{})
	bin, err := manager.ResolveClientBinaryForEngine(context.Background(), model.ImportTypeSoar)
	if err != nil {
		return a.GetScannerState(), err
	}
	configFile := filepath.Join(runtimeDir, "soar-scan.json")
	if err := os.WriteFile(configFile, []byte(data), 0o600); err != nil {
		return a.GetScannerState(), err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.scannerMu.Lock()
	if a.scannerState.Status == model.ScannerRunning {
		a.scannerMu.Unlock()
		cancel()
		return a.GetScannerState(), fmt.Errorf("DNS scanner is already running")
	}
	a.scannerRunID++
	runID := a.scannerRunID
	a.scannerCancel = cancel
	a.scannerControlFile = ""
	a.scannerRuntimeDir = runtimeDir
	a.scannerInputStarted = true
	a.scannerAutoApplyStarted = false
	a.scannerState = model.ScannerState{
		Status: model.ScannerRunning, Mode: dnsScannerModeManual, Phase: "probing",
		Message:                     "Testing Soar resolver authentication and HTTPS transfer",
		SelectedConnectionProfileID: connection.ID, InputFileName: inputName,
		ScanParallel: parallel, Total: total, Invalid: invalid, Duplicates: duplicates,
		ValidResolvers: []string{}, StartedAt: time.Now().UnixMilli(),
	}
	a.resetScannerResultsFileLocked()
	a.persistScannerSnapshotLocked()
	state := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	cleanup = false
	a.emit("scanner:state", state)
	go func() {
		defer cancel()
		a.runNativeDNSScanner(ctx, runID, bin, configFile, inputPath, runtimeDir, model.ImportTypeSoar)
	}()
	return state, nil
}
