package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	runtimemgr "whitedns-desktop/internal/runtime"
)

func elevationTestApp(t *testing.T) *App {
	t.Helper()
	a := quickSetupApp(t)
	a.configDir = filepath.Join(t.TempDir(), "WhiteDNS Desktop")
	if err := os.MkdirAll(a.configDir, 0700); err != nil {
		t.Fatal(err)
	}
	a.store = profiles.NewStore(filepath.Join(a.configDir, "state.json"))
	a.state.TunnelMode = "tun"
	return a
}

func TestTunConnectRequestsElevationAndPreservesResumeSelections(t *testing.T) {
	a := elevationTestApp(t)
	selected := a.state.SelectedConnectionProfileID
	settings := a.state.SettingsProfiles[0]
	settings.ListenPort = 12345
	var requestPath string
	quit := false
	a.tunElevation = &tunElevationHooks{
		needed: func() bool { return true },
		launch: func(_ context.Context, file string) error {
			requestPath = file
			req, err := readTunResume(file, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if req.ParentPID != os.Getpid() || req.OverrideSettings == nil || req.OverrideSettings.ListenPort != 12345 || req.PresetID != "winner" || len(req.Resolvers) != 2 {
				t.Fatal("connection intent lost during elevation")
			}
			saved, err := a.store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if saved.TunnelMode != "tun" || saved.SelectedConnectionProfileID != selected {
				t.Fatal("selected mode/profile not saved before UAC")
			}
			return nil
		},
		quit: func() { quit = true },
	}
	// A nil manager also proves no unprivileged engine was started first.
	_, err := a.startConnectionWithSettingsOptions(context.Background(), &settings, "winner", "Winning preset", []string{"1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if !quit {
		t.Fatal("accepted handoff did not close the old window")
	}
	if _, err := os.Stat(requestPath); !os.IsNotExist(err) {
		t.Fatal("one-shot request was retained")
	}
}

func TestTunElevationCancellationAndLaunchFailureKeepCurrentWindow(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		a := elevationTestApp(t)
		quit := false
		failure := errors.New("launch failed")
		if cancelled {
			failure = errTunElevationCancelled
		}
		a.tunElevation = &tunElevationHooks{needed: func() bool { return true }, launch: func(context.Context, string) error { return failure }, quit: func() { quit = true }}
		next, err := a.StartConnection()
		if quit {
			t.Fatal("unsuccessful elevation closed the current window")
		}
		if cancelled {
			if err != nil || next.Runtime.Status != model.RuntimeDisconnected || next.TunnelMode != "tun" {
				t.Fatal("UAC cancellation was treated as a connection or lost the selection")
			}
		} else if err == nil || next.Runtime.Status != model.RuntimeFailed {
			t.Fatal("launch failure did not reach the UI")
		}
		files, _ := filepath.Glob(filepath.Join(a.configDir, "tun-resume-*"))
		if len(files) != 0 {
			t.Fatal("failed elevation left resume files")
		}
	}
}

func TestTunResumeRejectsStaleMalformedAndUnexpectedLocations(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "WhiteDNS Desktop")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "tun-resume-"+strings.Repeat("a", 32)+".json")
	for _, created := range []time.Time{time.Now().Add(-3 * time.Minute), time.Now().Add(time.Minute)} {
		raw, _ := json.Marshal(tunResumeRequest{ParentPID: os.Getpid(), CreatedAt: created})
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTunResume(file, time.Now()); err == nil {
			t.Fatal("stale/future request was accepted")
		}
	}
	if err := os.WriteFile(file, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTunResume(file, time.Now()); err == nil {
		t.Fatal("malformed request was accepted")
	}
	for _, path := range []string{"relative.json", filepath.Join(t.TempDir(), filepath.Base(file)), filepath.Join(dir, "tun-resume-short.json")} {
		if _, err := readTunResume(path, time.Now()); err == nil {
			t.Fatal("unexpected request location was accepted")
		}
	}
	if req, _, err := prepareTunResume(nil); req != nil || err != nil {
		t.Fatal("normal startup became an automatic connection")
	}
}

func TestTunResumeConnectsOnlyOnceAfterUIReady(t *testing.T) {
	a := elevationTestApp(t)
	a.manager = runtimemgr.NewManager(runtimemgr.Options{}, runtimemgr.Callbacks{})
	a.tunElevation = &tunElevationHooks{needed: func() bool { return false }}
	a.tunResume = &tunResumeRequest{ParentPID: os.Getpid(), CreatedAt: time.Now()}
	done := make(chan struct{}, 1)
	a.emitHook = func(name string, payload any) {
		if name == "runtime:state" {
			if state, ok := payload.(model.RuntimeStatus); ok && state.Status == model.RuntimeDisconnected {
				select {
				case done <- struct{}{}:
				default:
				}
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.domReady(ctx)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("elevated startup did not resume the requested connection")
	}
	a.domReady(ctx)
	a.tunResumeOnce.Do(func() { t.Fatal("auto-connect was not marked one-shot") })
}
