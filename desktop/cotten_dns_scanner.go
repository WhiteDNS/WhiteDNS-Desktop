package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"whitedns-desktop/internal/cottendns"
	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	runtimemgr "whitedns-desktop/internal/runtime"
)

func (a *App) startCottenDNSScanner(connection model.ConnectionProfile, inputPath, inputName string, total, invalid, duplicates, parallel int) (model.ScannerState, error) {
	a.mu.Lock()
	state := profiles.NormalizeStatePreservingRuntime(a.state)
	a.mu.Unlock()
	settings := model.DefaultCottenDNSSettingsProfile()
	for _, candidate := range state.SettingsProfiles {
		if candidate.ID == state.SelectedSettingsProfileID && model.NormalizeImportType(candidate.ImportType) == model.ImportTypeCottenDNS {
			settings = candidate
			break
		}
	}
	runtimeDir, err := a.newDNSScannerRuntimeDir()
	if err != nil {
		return a.GetScannerState(), err
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(runtimeDir)
		}
	}()
	manager := runtimemgr.NewManager(runtimeManagerOptions(runtimeDir), runtimemgr.Callbacks{})
	bin, err := manager.ResolveClientBinaryForEngine(context.Background(), model.ImportTypeCottenDNS)
	if err != nil {
		return a.GetScannerState(), err
	}
	configFile := filepath.Join(runtimeDir, "cottendns-scan.toml")
	data := cottendns.RenderScannerClientTOML(connection, cottendns.OptionValues(settings.CottenDNSOptions), parallel)
	if err = os.WriteFile(configFile, []byte(data), 0600); err != nil {
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
	a.scannerState = model.ScannerState{Status: model.ScannerRunning, Mode: dnsScannerModeManual, Phase: "mtu", Message: "Testing CottenDNS resolver paths with the selected Normal/Max mode and DNS transport", SelectedConnectionProfileID: connection.ID, InputFileName: inputName, ScanParallel: parallel, Total: total, Invalid: invalid, Duplicates: duplicates, ValidResolvers: []string{}, StartedAt: time.Now().UnixMilli()}
	a.resetScannerResultsFileLocked()
	a.persistScannerSnapshotLocked()
	snapshot := cloneScannerState(a.scannerState)
	a.scannerMu.Unlock()
	cleanup = false
	a.emit("scanner:state", snapshot)
	go func() {
		defer cancel()
		a.runNativeDNSScanner(ctx, runID, bin, configFile, inputPath, runtimeDir, model.ImportTypeCottenDNS)
	}()
	return snapshot, nil
}

func (a *App) runNativeDNSScanner(ctx context.Context, runID int64, bin, configFile, inputPath, runtimeDir, engine string) {
	defer os.RemoveAll(runtimeDir)
	cmd := exec.CommandContext(ctx, bin, "-config", configFile, "-resolvers", inputPath, "-scan-only")
	hideConsoleWindow(cmd)
	cmd.Dir = runtimeDir
	out, err := cmd.StdoutPipe()
	if err != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
		return
	}
	// Drain telemetry before Wait closes the pipe, including the final results
	// of short scan-only processes.
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		a.handleDNSScannerLogLine(runID, scanner.Text())
	}
	if scanner.Err() != nil {
		_ = cmd.Process.Kill()
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		a.finishDNSScannerRun(runID, model.ScannerCancelled, "DNS scanner cancelled")
	} else if scanner.Err() != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, "DNS scanner output could not be read")
	} else if err != nil {
		a.finishDNSScannerRun(runID, model.ScannerFailed, err.Error())
	} else {
		a.finishDNSScannerRun(runID, model.ScannerCompleted, dnsEngineDisplayName(engine)+" resolver scan completed")
	}
}
