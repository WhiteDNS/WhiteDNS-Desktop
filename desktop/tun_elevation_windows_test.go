//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
)

// Opt-in native UAC test. The child uses the same executable and production
// handoff, waits for this parent to exit, loads its saved configuration, and
// verifies auto-resume without creating network routes or starting a tunnel.
func TestNativeTunElevationHandoffParent(t *testing.T) {
	dir := os.Getenv("WHITEDNS_NATIVE_ELEVATION_TEST_DIR")
	if dir == "" {
		t.Skip("native UAC test not requested")
	}
	if !tunElevationRequired() && os.Getenv("WHITEDNS_TEST_ALREADY_ELEVATED_HANDOFF") != "1" {
		t.Skip("test parent must start without administrator rights")
	}
	if filepath.Base(dir) != "WhiteDNS Desktop" {
		t.Fatal("invalid test data folder")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := model.DefaultAppState()
	state.TunnelMode = "tun"
	state.ConnectionProfiles[0].Domain = "dns.example.org"
	state.ConnectionProfiles[0].Domains = []string{"dns.example.org"}
	state.ConnectionProfiles[0].EncryptionKey = "test-key"
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8"
	a := &App{state: state, configDir: dir, store: profiles.NewStore(filepath.Join(dir, "state.json"))}
	quit := false
	a.tunElevation = &tunElevationHooks{
		needed: func() bool { return true }, // Exercise handoff on elevated CI runners too.
		launch: func(ctx context.Context, file string) error {
			return launchTunElevatedArgs(ctx, file, []string{"-test.run=^TestNativeTunElevationHandoffChild$", "--"})
		},
		quit: func() { quit = true },
	}
	if _, err := a.StartConnection(); err != nil {
		t.Fatal(err)
	}
	if !quit {
		t.Fatal("native handoff did not release the original window")
	}
	t.Log("Native Windows elevated child acknowledged the connection resume request")
}

func TestNativeTunElevationHandoffChild(t *testing.T) {
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		t.Skip("native UAC child not requested")
	}
	req, dir, err := prepareTunResume(args)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAppInConfigDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	a.tunResume = req
	if tunElevationRequired() || a.state.TunnelMode != "tun" || a.state.ConnectionProfiles[0].Domain != "dns.example.org" || a.state.ResolverProfiles[0].ResolverText != "1.1.1.1\n8.8.8.8" {
		t.Fatal("elevated startup did not preserve identity and selections")
	}
	done := make(chan struct{}, 1)
	a.emitHook = func(name string, payload any) {
		if name == "runtime:state" {
			if s, ok := payload.(model.RuntimeStatus); ok && s.Status == model.RuntimeDisconnected {
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
	case <-time.After(3 * time.Second):
		t.Fatal("elevated instance did not auto-resume")
	}
	raw, _ := json.Marshal(map[string]any{"elevated": !tunElevationRequired(), "savedSelectionsPreserved": true, "autoResumeReached": true, "parentExitedBeforeResume": true})
	if err := os.WriteFile(filepath.Join(dir, "native-elevation-result.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
