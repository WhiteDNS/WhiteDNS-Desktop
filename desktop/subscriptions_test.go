package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
)

func TestSubscriptionAPIsImportRefreshAndFailures(t *testing.T) {
	var requests atomic.Int32
	var broken atomic.Bool
	var key atomic.Int32
	key.Store(7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if broken.Load() {
			http.Error(w, "revoked", 404)
			return
		}
		p := model.ConnectionProfile{Name: "Provider account", ImportType: model.ImportTypeSoar, Domain: "user.soar.example.org", RemoteID: "one", EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(key.Load())}, 32)), BootstrapResolvers: []string{"1.1.1.1"}}
		opts := model.DefaultSoarSettings()
		p.SoarSettings = &opts
		link, err := profiles.ExportConnectionProfile(p)
		if err != nil {
			t.Error(err)
			http.Error(w, "fixture", 500)
			return
		}
		w.Header().Set("Subscription-Userinfo", "upload=12; download=34; total=10737418240")
		w.Header().Set("Profile-Update-Interval", "12")
		_, _ = w.Write([]byte(link))
	}))
	defer srv.Close()
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	app := &App{store: store, state: model.DefaultAppState()}
	initial := app.state.ConnectionProfiles[0]
	if _, err := app.ImportSubscription(srv.URL, false); err == nil || requests.Load() != 0 {
		t.Fatal("HTTP was fetched without consent")
	}
	state, err := app.ImportSubscription(srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	id := state.SelectedConnectionProfileID
	if len(state.ConnectionProfiles) != 2 || id == initial.ID || state.SelectedSettingsProfileID != model.DefaultSoarSettingsID {
		t.Fatal("import failed to select the proper engine")
	}
	before := requests.Load()
	if _, err = app.RefreshSubscriptions(true); err != nil || requests.Load() != before {
		t.Fatal("not-due source refreshed")
	}
	key.Store(8)
	state, err = app.RefreshSubscriptions(false)
	if err != nil {
		t.Fatal(err)
	}
	if state.SelectedConnectionProfileID != id || state.ConnectionProfiles[0].ID != initial.ID || state.ConnectionProfiles[1].EncryptionKey != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)) {
		t.Fatal("refresh lost identity, manual profile, or new key")
	}
	saved, err := store.Load()
	if err != nil || saved.SelectedConnectionProfileID != id || saved.ConnectionProfiles[1].Subscription.Total != 10737418240 {
		t.Fatal("subscription not persisted")
	}
	beforeState := app.GetAppState()
	broken.Store(true)
	if _, err = app.RefreshSubscriptions(false); err == nil || strings.Contains(err.Error(), srv.URL) {
		t.Fatal("failed source must report a generic error")
	}
	if !reflect.DeepEqual(beforeState, app.GetAppState()) {
		t.Fatal("failed fetch changed cached state")
	}
	app.state.Runtime.Status = model.RuntimeConnected
	before = requests.Load()
	if _, err = app.ImportSubscription(srv.URL, true); err == nil {
		t.Fatal("active import accepted")
	}
	if _, err = app.RefreshSubscriptions(false); err == nil || requests.Load() != before {
		t.Fatal("active refresh fetched or mutated profiles")
	}
}

func TestSubscriptionImportRollsBackOnSaveFailure(t *testing.T) {
	p := model.ConnectionProfile{Name: "Provider", ImportType: model.ImportTypeSoar, Domain: "user.soar.example.org", EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), BootstrapResolvers: []string{"1.1.1.1"}}
	link, err := profiles.ExportConnectionProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(link)) }))
	defer srv.Close()
	block := filepath.Join(t.TempDir(), "not-a-directory")
	if err = os.WriteFile(block, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	app := &App{store: profiles.NewStore(filepath.Join(block, "state.json")), state: model.DefaultAppState()}
	before := app.GetAppState()
	if _, err = app.ImportSubscription(srv.URL, true); err == nil {
		t.Fatal("expected write failure")
	}
	if !reflect.DeepEqual(before, app.GetAppState()) {
		t.Fatal("failed save left partial subscription")
	}
}

func TestSoarDoesNotUseMasterTOMLOrDeleteBuiltInProxy(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	if _, err := app.ExportSettingsProfileToml(model.DefaultSoarSettingsProfile()); err == nil {
		t.Fatal("exported Soar as MasterDNS TOML")
	}
	if _, err := app.ImportSettingsProfileToml("LISTEN_PORT = 10887", "Soar", model.ImportTypeSoar); err == nil {
		t.Fatal("imported MasterDNS TOML as Soar")
	}
	if _, err := app.DeleteSettingsProfile(model.DefaultSoarSettingsID); err == nil {
		t.Fatal("deleted built-in Soar proxy")
	}
}
