package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	"whitedns-desktop/internal/storm"
)

func quickSetupApp(t *testing.T) *App {
	t.Helper()
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "dns.example.org"
	state.ConnectionProfiles[0].EncryptionKey = "test-key"
	state.ConnectionProfiles[0].ResolverProfileID = model.DefaultResolverProfileID
	state.ResolverProfiles[0].ResolverText = "9.9.9.9"
	return &App{state: state, store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))}
}

func TestSharedResolversSurviveImportsSelectionAndReload(t *testing.T) {
	app := quickSetupApp(t)
	state, err := app.SaveGlobalResolvers("1.1.1.1\n8.8.8.8:53\n1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if state.GlobalResolverProfileID != quickResolverProfileID {
		t.Fatal("shared resolver was not enabled")
	}
	if _, err := app.SaveGlobalResolvers("1.1.1.1\n8.8.8.8:5353"); err != nil {
		t.Fatal(err)
	}
	if len(app.state.ResolverProfiles) != len(state.ResolverProfiles) {
		t.Fatal("saving again created a duplicate")
	}
	imported, err := app.ImportConnectionProfiles(testStormDNSImportLink(t, "Imported", "two.example.org", "key-two"), "")
	if err != nil {
		t.Fatal(err)
	}
	if imported.State.GlobalResolverProfileID != quickResolverProfileID {
		t.Fatal("import disabled shared resolver")
	}
	if _, err := app.SelectConnectionProfile(model.DefaultConnectionProfileID); err != nil {
		t.Fatal(err)
	}
	loaded, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := storm.BuildLaunchConfig(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Resolvers != "1.1.1.1\n8.8.8.8:5353" {
		t.Fatalf("wrong effective resolvers: %q", cfg.Resolvers)
	}
	if loaded.ConnectionProfiles[0].ResolverProfileID != model.DefaultResolverProfileID {
		t.Fatal("original per-connection resolver was overwritten")
	}
	if _, err := app.DeleteResolverProfile(quickResolverProfileID); err == nil {
		t.Fatal("pinned resolver should not be deleted")
	}
	state, err = app.SetGlobalResolverProfile("")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = storm.BuildLaunchConfig(state)
	if err != nil || cfg.Resolvers != "9.9.9.9" {
		t.Fatalf("per-connection resolver not restored: %v, %q", err, cfg.Resolvers)
	}
}

func TestQuickSetupRejectsInvalidLockedAndUnpersistableChanges(t *testing.T) {
	app := quickSetupApp(t)
	before := app.state
	if _, err := app.SaveGlobalResolvers("1.1.1.1\nnot-an-ip"); err == nil {
		t.Fatal("invalid resolver accepted")
	}
	if _, err := app.SetTunnelMode("unknown"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, err := app.SetGlobalResolverProfile("missing"); err == nil {
		t.Fatal("missing resolver accepted")
	}
	if !reflect.DeepEqual(app.state, before) {
		t.Fatal("rejected input changed state")
	}
	for _, status := range []string{model.RuntimeConnecting, model.RuntimeConnected} {
		app.state.Runtime.Status = status
		if _, err := app.SaveGlobalResolvers("1.1.1.1"); err == nil {
			t.Fatal("resolver changed during connection")
		}
		if _, err := app.SetTunnelMode("vpn"); err == nil {
			t.Fatal("mode changed during connection")
		}
	}
	app.state.Runtime.Status = model.RuntimeDisconnected
	app.parallelState.Status = model.ParallelTestRunning
	if _, err := app.SetGlobalResolverProfile(model.DefaultResolverProfileID); err == nil {
		t.Fatal("resolver changed during test")
	}
	if _, err := app.SetTunnelMode("vpn"); err == nil {
		t.Fatal("mode changed during test")
	}
	app.parallelState.Status = model.ParallelTestIdle
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	app.store = profiles.NewStore(filepath.Join(blocker, "state.json"))
	before = app.state
	if _, err := app.SaveGlobalResolvers("1.1.1.1"); err == nil {
		t.Fatal("expected save failure")
	}
	if !reflect.DeepEqual(before, app.state) {
		t.Fatal("failed save changed live state")
	}
}

func TestTunnelModesOverridePresetsAndPersist(t *testing.T) {
	app := quickSetupApp(t)
	for _, mode := range []string{"proxy", "vpn", "tun"} {
		if mode == "tun" && !app.GetTunModeSupported() {
			continue
		}
		state, err := app.SetTunnelMode(mode)
		if err != nil {
			t.Fatal(err)
		}
		// A saved or auto-selected preset must not override the dashboard choice.
		settings := model.DefaultSettingsProfile()
		settings.SingBoxSetSystemProxy = mode != "vpn"
		cfg, err := storm.BuildLaunchConfigWithSettings(state, settings)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SetSystemProxy != (mode == "vpn") || cfg.TunEnabled != (mode == "tun") {
			t.Fatalf("wrong mode: %#v", cfg)
		}
		if strings.Contains(cfg.CoreConfig, `"protocol": "tun"`) != (mode == "tun") {
			t.Fatal("wrong core TUN config")
		}
		loaded, err := app.store.Load()
		if err != nil || loaded.TunnelMode != mode {
			t.Fatalf("mode not persisted: %v", err)
		}
	}
}

func TestSharedResolverSelectionLeavesConnectionAssignmentsIntact(t *testing.T) {
	app := quickSetupApp(t)
	if _, err := app.SaveGlobalResolvers("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SelectResolverProfile(model.DefaultResolverProfileID); err != nil {
		t.Fatal(err)
	}
	if app.state.GlobalResolverProfileID != model.DefaultResolverProfileID {
		t.Fatal("selector did not update shared resolver")
	}
	if app.state.ConnectionProfiles[0].ResolverProfileID != model.DefaultResolverProfileID {
		t.Fatal("connection assignment changed")
	}
	if _, err := app.SetGlobalResolverProfile(quickResolverProfileID); err != nil {
		t.Fatal(err)
	}
	backup, err := app.store.ExportBackup(app.state)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := app.store.ImportBackup(backup)
	if err != nil || restored.GlobalResolverProfileID != quickResolverProfileID {
		t.Fatalf("backup lost shared resolver: %v", err)
	}
}

func TestSharedResolversOverrideSoarBootstrapImport(t *testing.T) {
	app := quickSetupApp(t)
	if _, err := app.SaveGlobalResolvers("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	options := model.DefaultSoarSettings()
	profile := model.ConnectionProfile{Name: "Soar import", ImportType: model.ImportTypeSoar, Domain: "user.soar.example.org", EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), BootstrapResolvers: []string{"8.8.8.8"}, SoarSettings: &options}
	link, err := profiles.ExportConnectionProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportConnectionProfiles(link, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := storm.BuildLaunchConfig(imported.State)
	if err != nil || cfg.Resolvers != "1.1.1.1" {
		t.Fatalf("bootstrap resolver replaced shared selection: %v, %q", err, cfg.Resolvers)
	}
	next, err := app.SetGlobalResolverProfile("")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = storm.BuildLaunchConfig(next)
	if err != nil || cfg.Resolvers != "8.8.8.8" {
		t.Fatalf("bootstrap resolver not restored: %v, %q", err, cfg.Resolvers)
	}
}

func TestGlobalResolverFileImportCopiesAndPinsWithoutChangingConnections(t *testing.T) {
	app := quickSetupApp(t)
	input := filepath.Join(t.TempDir(), "resolvers.csv")
	if err := os.WriteFile(input, []byte("1.1.1.1\n8.8.8.8:53\n1.1.1.1\ninvalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := app.importGlobalResolverFilePath(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 || result.Skipped != 1 || result.Profile.SourceFileName != "resolvers.csv" {
		t.Fatalf("unexpected file summary: %#v", result.Profile)
	}
	if result.State.GlobalResolverProfileID != result.Profile.ID || result.State.ConnectionProfiles[0].ResolverProfileID != model.DefaultResolverProfileID {
		t.Fatal("import did not preserve per-connection assignments")
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	loaded, err := app.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := storm.BuildLaunchConfig(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResolversPath != result.Profile.ResolverFile {
		t.Fatal("file not used for the runtime")
	}
	data, err := os.ReadFile(cfg.ResolversPath)
	if err != nil || string(data) != "1.1.1.1\n8.8.8.8\n" {
		t.Fatalf("managed copy unavailable: %v %q", err, data)
	}
	if _, err := app.SetGlobalResolverProfile(""); err != nil {
		t.Fatal(err)
	}
	cfg, err = storm.BuildLaunchConfig(app.state)
	if err != nil || cfg.Resolvers != "9.9.9.9" {
		t.Fatal("turning off file override did not restore the previous resolver")
	}
}

func TestGlobalResolverFileImportRejectsLockedInvalidAndFailedSaves(t *testing.T) {
	app := quickSetupApp(t)
	input := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(input, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	before := app.state
	if _, err := app.importGlobalResolverFilePath(input); err == nil {
		t.Fatal("empty valid resolver set was imported")
	}
	if !reflect.DeepEqual(app.state, before) {
		t.Fatal("invalid import changed state")
	}
	if err := os.WriteFile(input, []byte("1.1.1.1"), 0600); err != nil {
		t.Fatal(err)
	}
	app.state.Runtime.Status = model.RuntimeConnected
	if _, err := app.importGlobalResolverFilePath(input); err == nil {
		t.Fatal("import was allowed after connection started while picker was open")
	}
	app.state.Runtime.Status = model.RuntimeDisconnected
	app.parallelState.Status = model.ParallelTestRunning
	if _, err := app.importGlobalResolverFilePath(input); err == nil {
		t.Fatal("parallel test did not lock file import")
	}
	app.parallelState.Status = model.ParallelTestIdle
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(statePath, 0700); err != nil {
		t.Fatal(err)
	}
	app.store = profiles.NewStore(statePath)
	before = app.state
	if _, err := app.importGlobalResolverFilePath(input); err == nil {
		t.Fatal("expected state persistence failure")
	}
	if !reflect.DeepEqual(app.state, before) {
		t.Fatal("failed persistence changed the active state")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(statePath), "resolvers", "*.txt"))
	if err != nil || len(files) != 0 {
		t.Fatal("failed import leaked a managed resolver file")
	}
}
