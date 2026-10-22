package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"whitedns-desktop/internal/cottendns"
	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	runtimemgr "whitedns-desktop/internal/runtime"
	"whitedns-desktop/internal/storm"
)

func TestWriteSoarUIFixture(t *testing.T) {
	file := os.Getenv("DESKTOP_UI_FIXTURE")
	if file == "" {
		t.Skip("UI fixture generation not requested")
	}
	state := profiles.NormalizeState(model.DefaultAppState())
	p := model.ConnectionProfile{ID: "soar-ui", Name: "Soar Test", ImportType: model.ImportTypeSoar, Domain: "user.soar.example.org", Domains: []string{"user.soar.example.org"}, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ResolverProfileID: model.DefaultResolverProfileID}
	options := model.DefaultSoarSettings()
	p.SoarSettings = &options
	p.Subscription = &model.SubscriptionSource{URL: "https://panel.example.org/sub/test-only", RemoteID: "fake-account", UpdatedAt: time.Now().UnixMilli(), IntervalHours: 12, Total: 10 * 1024 * 1024 * 1024, Download: 1024 * 1024}
	state.ConnectionProfiles = append(state.ConnectionProfiles, p)
	state.SelectedConnectionProfileID = p.ID
	state.SettingsProfiles = append(state.SettingsProfiles, model.DefaultSoarSettingsProfile())
	state.SelectedSettingsProfileID = model.DefaultSoarSettingsID
	state.ConnectionProfiles = append(state.ConnectionProfiles, model.ConnectionProfile{ID: "cotten-ui", Name: "Cotten Test", ImportType: model.ImportTypeCottenDNS, Domain: "a.example", Domains: []string{"a.example"}, EncryptionKey: "shared-test-key", EncryptionMethod: 5, ResolverProfileID: model.DefaultResolverProfileID})
	cotten := model.DefaultCottenDNSSettingsProfile()
	cotten.ID, cotten.Name = "cotten-ui-settings", "CottenMax Settings"
	cottenOptions := map[string]any{"TUNNEL_MODE": "cottenmax", "RESOLVER_TRANSPORT": "auto"}
	cotten.CottenDNSOptions = &cottenOptions
	state.SettingsProfiles = append(state.SettingsProfiles, cotten)

	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture["_cottenSchema"] = cottendns.Schema()
	raw, err = json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// Opt-in: use only a private test profile. Never embeds credentials in the repo
// or changes the machine's system proxy. The normal test suite skips this case.
func TestLiveSoarDesktopProxyPath(t *testing.T) {
	file := os.Getenv("WHITEDNS_LIVE_PROFILE_FILE")
	if file == "" {
		t.Skip("live test profile not supplied")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal("invalid private profile input")
	}
	values, err := profiles.ParseConnectionProfileImports(input.Link, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ImportType != model.ImportTypeSoar {
		t.Fatal("live fixture must contain one Soar profile")
	}
	state := model.DefaultAppState()
	p := values[0]
	p.ID = "live-soar"
	state.ConnectionProfiles = []model.ConnectionProfile{p}
	state.SelectedConnectionProfileID = p.ID
	attachImportedResolvers(&state, &state.ConnectionProfiles[0])
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	settings := model.DefaultSoarSettingsProfile()
	settings.ListenPort = port()
	settings.StormDNSListenPort = port()
	settings.SingBoxSetSystemProxy = false
	state.SettingsProfiles = append(state.SettingsProfiles, settings)
	state.SelectedSettingsProfileID = settings.ID
	cfg, err := storm.BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	manager := runtimemgr.NewManager(runtimemgr.Options{RuntimeDir: filepath.Join(t.TempDir(), "runtime"), SoarBinaryPath: os.Getenv("WHITEDNS_LIVE_SOAR_BINARY"), XrayBinaryPath: os.Getenv("WHITEDNS_LIVE_XRAY_BINARY")}, runtimemgr.Callbacks{})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	defer manager.Stop()
	if err := manager.Start(ctx, cfg); err != nil {
		t.Fatal("desktop proxy startup:", err)
	}
	for _, protocol := range []string{"http", "socks5"} {
		endpoint, _ := url.Parse(protocol + "://" + net.JoinHostPort(cfg.PublicListenIP, fmtPort(cfg.PublicListenPort)))
		transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSHandshakeTimeout: 40 * time.Second}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s proxy HTTPS request failed: %v", protocol, err)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 256))
		response.Body.Close()
		if e != nil || response.StatusCode != 200 {
			t.Fatal("exit IP response failed")
		}
		if expected := os.Getenv("WHITEDNS_LIVE_EXPECTED_IP"); expected != "" && strings.TrimSpace(string(body)) != expected {
			t.Fatal("exit IP differs from the expected test server")
		}
	}
	t.Log("Live desktop Soar -> Xray HTTP and SOCKS5 -> verified HTTPS exit IP passed")
}

func fmtPort(port int) string { return strconv.Itoa(port) }
