package storm

import (
	"strings"
	"testing"

	"whitedns-desktop/internal/model"
)

func TestBuildLaunchConfigSelectsCottenDNSAndItsInternalListener(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].ImportType = model.ImportTypeCottenDNS
	state.ConnectionProfiles[0].EncryptionKey = "key"
	overrides := map[string]any{
		"CONFIG_PRESET":      "speed",
		"LISTEN_IP":          "127.0.0.1",
		"LISTEN_PORT":        19087,
		"RESOLVER_TRANSPORT": "tcp",
	}
	settings := model.DefaultSettingsProfile()
	settings.ID = "settings-cottendns"
	settings.Name = "CottenDNS"
	settings.ImportType = model.ImportTypeCottenDNS
	settings.CottenDNSOptions = &overrides
	state.SettingsProfiles = append(state.SettingsProfiles, settings)
	state.SelectedSettingsProfileID = settings.ID

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine != model.ImportTypeCottenDNS {
		t.Fatalf("expected CottenDNS engine, got %q", cfg.Engine)
	}
	if cfg.MasterDNSSettings.ListenPort != 19087 {
		t.Fatalf("expected Xray upstream to use CottenDNS port 19087, got %d", cfg.MasterDNSSettings.ListenPort)
	}
	for _, expected := range []string{
		`# WHITEDNS_IMPORT_TYPE = "cottendns"`,
		`CONFIG_PRESET = "speed"`,
		`LISTEN_PORT = 19087`,
		`RESOLVER_TRANSPORT = "tcp"`,
	} {
		if !strings.Contains(cfg.ClientTOML, expected) {
			t.Fatalf("CottenDNS TOML missing %q:\n%s", expected, cfg.ClientTOML)
		}
	}
	if !strings.Contains(cfg.CoreConfig, `"port": 19087`) {
		t.Fatalf("Xray config does not target CottenDNS:\n%s", cfg.CoreConfig)
	}
}

func TestSelectedConnectionControlsEngineAndMultipleDomains(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].ImportType = model.ImportTypeCottenDNS
	state.ConnectionProfiles[0].Domain = "one.example.com"
	state.ConnectionProfiles[0].Domains = []string{"one.example.com", "two.example.com"}
	state.ConnectionProfiles[0].EncryptionKey = "key"
	state.SelectedSettingsProfileID = model.MasterDNSSettingsProfileID

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine != model.ImportTypeCottenDNS || cfg.Settings.ImportType != model.ImportTypeCottenDNS {
		t.Fatalf("selected connection did not control engine: %#v", cfg)
	}
	if !strings.Contains(cfg.ClientTOML, `DOMAINS = ["one.example.com", "two.example.com"]`) {
		t.Fatalf("multi-domain CottenDNS config was not rendered:\n%s", cfg.ClientTOML)
	}
}

func TestParseCottenDNSSettingsProfileUsesMarkerAndPreservesOptions(t *testing.T) {
	profile, err := ParseSettingsProfileTOML(`# WHITEDNS_IMPORT_TYPE = "cottendns"
CONFIG_PRESET = "tcp-survival"
RESOLVER_TRANSPORT = "dot"
QUERY_TYPES = ["TXT", "HTTPS"]
FAST_CONNECT = true`, "Cotten import", model.ImportTypeMasterDNS)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ImportType != model.ImportTypeCottenDNS || profile.CottenDNSOptions == nil {
		t.Fatalf("expected CottenDNS settings import, got %#v", profile)
	}
	options := *profile.CottenDNSOptions
	if options["CONFIG_PRESET"] != "tcp-survival" || options["RESOLVER_TRANSPORT"] != "dot" || options["FAST_CONNECT"] != true {
		t.Fatalf("CottenDNS options were not preserved: %#v", options)
	}
}

// Every CottenDNS option the settings editor can change has to survive the trip
// into the launched engine config, including the ones the app also mirrors into
// its own settings fields and into the Xray hop. A value that is silently
// dropped here looks to the user like a setting that does nothing.
func TestCottenDNSUserOverridesReachTheLaunchedConfig(t *testing.T) {
	state := model.DefaultAppState()
	state.ConnectionProfiles[0].Domain = "v.example.com"
	state.ConnectionProfiles[0].ImportType = model.ImportTypeCottenDNS
	state.ConnectionProfiles[0].EncryptionKey = "key"
	overrides := map[string]any{
		"LISTEN_IP":                         "127.0.0.1",
		"LISTEN_PORT":                       19099,
		"UPLOAD_PACKET_DUPLICATION_COUNT":   4,
		"DOWNLOAD_PACKET_DUPLICATION_COUNT": 5,
		"MIN_DOWNLOAD_MTU":                  512,
		"MTU_MAX_LOSS":                      0.1,
		"RX_TX_WORKERS":                     8,
		"QUERY_TYPES":                       []string{"TXT", "HTTPS"},
		"CONFIG_PRESET":                     "survival",
	}
	settings := model.DefaultSettingsProfile()
	settings.ID = "settings-cottendns-overrides"
	settings.ImportType = model.ImportTypeCottenDNS
	settings.CottenDNSOptions = &overrides
	state.SettingsProfiles = append(state.SettingsProfiles, settings)
	state.SelectedSettingsProfileID = settings.ID

	cfg, err := BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`CONFIG_PRESET = "survival"`,
		"LISTEN_PORT = 19099",
		"UPLOAD_PACKET_DUPLICATION_COUNT = 4",
		"DOWNLOAD_PACKET_DUPLICATION_COUNT = 5",
		"MIN_DOWNLOAD_MTU = 512",
		"MTU_MAX_LOSS = 0.1",
		"RX_TX_WORKERS = 8",
		`QUERY_TYPES = ["TXT", "HTTPS"]`,
	} {
		if !strings.Contains(cfg.ClientTOML, expected) {
			t.Fatalf("user override %q never reached the engine config:\n%s", expected, cfg.ClientTOML)
		}
	}
	// The app defaults must not be re-imposed on top of an explicit choice.
	if strings.Contains(cfg.ClientTOML, `CONFIG_PRESET = "speed"`) ||
		strings.Contains(cfg.ClientTOML, "MIN_DOWNLOAD_MTU = 300") {
		t.Fatalf("app fallbacks overrode the user's own values:\n%s", cfg.ClientTOML)
	}
	// The Xray hop has to follow the engine's listener, or traffic goes nowhere.
	if cfg.MasterDNSSettings.ListenPort != 19099 {
		t.Fatalf("Xray upstream did not follow the CottenDNS port: %d", cfg.MasterDNSSettings.ListenPort)
	}
}
