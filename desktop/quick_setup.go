package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	"whitedns-desktop/internal/resolver"
	runtimemgr "whitedns-desktop/internal/runtime"
)

const quickResolverProfileID = "quick-setup-resolvers"

func (a *App) GetTunModeSupported() bool { return runtimemgr.TunModeSupported() }

func (a *App) SetTunnelMode(mode string) (model.AppState, error) {
	if a.parallelTestRunning() {
		return a.GetAppState(), fmt.Errorf("wait for the parallel test to finish before changing tunnel mode")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectionSelectionLockedLocked() {
		return a.state, fmt.Errorf("disconnect before changing tunnel mode")
	}
	switch mode {
	case "proxy", "vpn", "tun":
	default:
		return a.state, fmt.Errorf("unknown tunnel mode")
	}
	if mode == "tun" && !runtimemgr.TunModeSupported() {
		return a.state, fmt.Errorf("automatic TUN mode is currently supported on Windows")
	}
	next := a.state
	next.TunnelMode = mode
	return a.saveQuickSetupLocked(next)
}

// An override keeps per-connection resolver assignments intact, including those
// arriving in future imports and subscription refreshes. Clearing it restores them.
func (a *App) SetGlobalResolverProfile(id string) (model.AppState, error) {
	if a.parallelTestRunning() {
		return a.GetAppState(), fmt.Errorf("wait for the parallel test to finish before changing resolvers")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolverSelectionLockedLocked() {
		return a.state, fmt.Errorf("disconnect before changing the shared resolver")
	}
	id = strings.TrimSpace(id)
	if id != "" {
		idx := slices.IndexFunc(a.state.ResolverProfiles, func(p model.ResolverProfile) bool { return p.ID == id })
		if idx < 0 {
			return a.state, fmt.Errorf("resolver profile not found")
		}
		profile := a.state.ResolverProfiles[idx]
		if strings.EqualFold(profile.ResolverSource, "file") {
			if info, err := os.Stat(profile.ResolverFile); err != nil || info.IsDir() || profile.ResolverCount <= 0 {
				return a.state, fmt.Errorf("resolver file is empty or unavailable")
			}
		} else if !resolver.ValidateText(profile.ResolverText).IsValid {
			return a.state, fmt.Errorf("add at least one valid resolver first")
		}
	}
	next := a.state
	next.GlobalResolverProfileID = id
	if id == "" {
		for _, connection := range next.ConnectionProfiles {
			if connection.ID == next.SelectedConnectionProfileID && connection.ResolverProfileID != "" {
				next.SelectedResolverProfileID = connection.ResolverProfileID
			}
		}
	}
	return a.saveQuickSetupLocked(next)
}

func (a *App) SaveGlobalResolvers(rawText string) (model.AppState, error) {
	if a.parallelTestRunning() {
		return a.GetAppState(), fmt.Errorf("wait for the parallel test to finish before changing resolvers")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolverSelectionLockedLocked() {
		return a.state, fmt.Errorf("disconnect before changing the shared resolver")
	}
	validation := resolver.ValidateText(rawText)
	if !validation.IsValid {
		return a.state, fmt.Errorf("enter at least one valid resolver with no invalid entries (for example 1.1.1.1 or 8.8.8.8:53)")
	}
	next := a.state
	next.ResolverProfiles = slices.Clone(next.ResolverProfiles)
	profile := model.ResolverProfile{ID: quickResolverProfileID, Name: "Shared resolvers", ResolverSource: "inline", ResolverText: validation.NormalizedText}
	idx := slices.IndexFunc(next.ResolverProfiles, func(p model.ResolverProfile) bool { return p.ID == profile.ID })
	if idx >= 0 {
		next.ResolverProfiles[idx] = profile
	} else {
		next.ResolverProfiles = append(next.ResolverProfiles, profile)
	}
	next.GlobalResolverProfileID = profile.ID
	return a.saveQuickSetupLocked(next)
}

func (a *App) saveQuickSetupLocked(next model.AppState) (model.AppState, error) {
	next = profiles.NormalizeStatePreservingRuntime(next)
	saved, err := a.store.SaveState(next)
	if err != nil {
		return a.state, err
	}
	a.state = saved
	return saved, nil
}

func (a *App) ImportGlobalResolverFile() (model.ResolverImportResult, error) {
	if a.parallelTestRunning() {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("wait for the parallel test to finish before importing resolvers")
	}
	a.mu.Lock()
	locked := a.resolverSelectionLockedLocked()
	a.mu.Unlock()
	if locked {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("disconnect before importing shared resolvers")
	}
	if a.ctx == nil {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("file picker is unavailable")
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Import shared resolvers",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Resolver lists (*.txt, *.csv, *.lst)", Pattern: "*.txt;*.csv;*.lst;*.resolvers"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return model.ResolverImportResult{State: a.GetAppState()}, err
	}
	return a.importGlobalResolverFilePath(path)
}

func (a *App) importGlobalResolverFilePath(path string) (model.ResolverImportResult, error) {
	if a.parallelTestRunning() {
		return model.ResolverImportResult{State: a.GetAppState()}, fmt.Errorf("wait for the parallel test to finish before importing resolvers")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// The connection may have changed while the native picker was open.
	if a.resolverSelectionLockedLocked() {
		return model.ResolverImportResult{State: a.state}, fmt.Errorf("disconnect before importing shared resolvers")
	}
	profile, err := a.store.ImportResolverFile(path)
	if err != nil {
		return model.ResolverImportResult{State: a.state}, err
	}
	next := a.state
	next.ResolverProfiles = append(slices.Clone(next.ResolverProfiles), profile)
	next.GlobalResolverProfileID = profile.ID
	saved, err := a.saveQuickSetupLocked(next)
	if err != nil {
		_ = os.Remove(profile.ResolverFile)
		return model.ResolverImportResult{State: a.state}, err
	}
	return model.ResolverImportResult{State: saved, Profile: profile, Imported: profile.ResolverCount, Skipped: profile.ResolverInvalidCount}, nil
}
