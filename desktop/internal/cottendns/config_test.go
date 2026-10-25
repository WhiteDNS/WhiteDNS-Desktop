package cottendns

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"whitedns-desktop/internal/model"
)

func TestMaxRuntimeFitsPanelDomainsWithoutChangingSavedOptions(t *testing.T) {
	connection := model.ConnectionProfile{Domain: "cot.abcdefghijklmnopqrstuvwxyz.soar.example.org", EncryptionKey: "panel-test-key", EncryptionMethod: 5}
	standby := "cot.abcdefghijklmnopqrstuvwxyz.backup.example.org"
	options := map[string]any{"TUNNEL_MODE": "cottenmax", "QNAME_LABEL_LENGTH": 32, "QNAME_LABEL_COUNT_JITTER": true, "STANDBY_DOMAINS": []string{standby}, "COTTENMAX_MAX_QNAME": 101}
	for _, raw := range []string{RenderClientTOML(connection, options), RenderScannerClientTOML(connection, options, 4)} {
		got, err := ParseOptions(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := len("cottenmax-v1."+standby) + 1 + 55 + 1 + 3
		if got["COTTENMAX_SAFE_QNAME"] != want || got["COTTENMAX_MAX_QNAME"] != want {
			t.Fatalf("Max HELLO does not fit panel/standby domain: %#v", got)
		}
	}
	if _, ok := options["COTTENMAX_SAFE_QNAME"]; ok {
		t.Fatal("render mutated stored settings")
	}
	if strings.Contains(RenderSettingsTOML(options), "COTTENMAX_SAFE_QNAME") {
		t.Fatal("domain sizing leaked into settings export")
	}
	options["TUNNEL_MODE"] = "legacy"
	if strings.Contains(RenderClientTOML(connection, options), "COTTENMAX_SAFE_QNAME") {
		t.Fatal("normal mode changed")
	}
}

func TestSchemaCoversEveryShippedClientOption(t *testing.T) {
	parsed, err := parseTemplate(defaultTemplate)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"CONFIG_PRESET": true}
	for _, option := range parsed {
		if _, managed := connectionManagedKeys[option.key]; !managed {
			want[option.key] = true
		}
	}
	got := make(map[string]bool)
	for _, definition := range Schema() {
		got[definition.Key] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema keys do not match shipped template\nwant=%v\ngot=%v", want, got)
	}
	if len(got) < 90 {
		t.Fatalf("expected the complete CottenDNS option surface, got only %d options", len(got))
	}
}

func TestSparseOverridesPreservePresetSemantics(t *testing.T) {
	overrides := map[string]any{
		"CONFIG_PRESET":                     "survival",
		"RESOLVER_TRANSPORT":                "doh",
		"DOWNLOAD_PACKET_DUPLICATION_COUNT": 7,
	}
	values := EffectiveOptions(overrides)
	if values["QNAME_LABEL_LENGTH"] != 42 || values["EDNS_UDP_SIZE"] != 1232 {
		t.Fatalf("survival preset was not reflected in effective values: %#v", values)
	}
	if values["RESOLVER_TRANSPORT"] != "doh" || values["DOWNLOAD_PACKET_DUPLICATION_COUNT"] != 7 {
		t.Fatalf("explicit values must override the preset: %#v", values)
	}

	raw := RenderSettingsTOML(overrides)
	for _, expected := range []string{
		`# WHITEDNS_IMPORT_TYPE = "cottendns"`,
		`CONFIG_PRESET = "survival"`,
		`RESOLVER_TRANSPORT = "doh"`,
		`DOWNLOAD_PACKET_DUPLICATION_COUNT = 7`,
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("rendered settings missing %q:\n%s", expected, raw)
		}
	}
	if strings.Contains(raw, "QNAME_LABEL_LENGTH") {
		t.Fatalf("preset-derived values must remain sparse so CottenDNS applies its native preset:\n%s", raw)
	}

	roundTrip, err := ParseOptions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip, NormalizeOverrides(overrides)) {
		t.Fatalf("settings did not round trip: want %#v, got %#v", overrides, roundTrip)
	}
}

func TestRenderClientTOMLIncludesManagedConnectionFields(t *testing.T) {
	raw := RenderClientTOML(model.ConnectionProfile{
		Domain:           "v.example.com.",
		EncryptionKey:    `secret"key`,
		EncryptionMethod: 2,
	}, map[string]any{"LISTEN_PORT": 19000})
	for _, expected := range []string{
		`DOMAINS = ["v.example.com"]`,
		`DATA_ENCRYPTION_METHOD = 2`,
		`ENCRYPTION_KEY = "secret\"key"`,
		`LISTEN_PORT = 19000`,
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("rendered client config missing %q:\n%s", expected, raw)
		}
	}
}

func TestApplyRuntimeSettingsUsesEffectiveCottenDNSListener(t *testing.T) {
	overrides := map[string]any{
		"LISTEN_IP":   "127.0.0.2",
		"LISTEN_PORT": 19001,
		"SOCKS5_AUTH": true,
		"SOCKS5_USER": "alice",
		"SOCKS5_PASS": "secret",
	}
	settings := model.DefaultSettingsProfile()
	settings.CottenDNSOptions = &overrides
	settings = ApplyRuntimeSettings(settings)
	if settings.StormDNSListenIP != "127.0.0.2" || settings.StormDNSListenPort != 19001 {
		t.Fatalf("runtime listener was not applied: %#v", settings)
	}
	if !settings.SOCKS5Authentication || settings.SOCKSUsername != "alice" || settings.SOCKSPassword != "secret" {
		t.Fatalf("runtime authentication was not applied: %#v", settings)
	}
}

func TestNormalizeOverridesRejectsInvalidCottenDNSPorts(t *testing.T) {
	normalized := NormalizeOverrides(map[string]any{
		"LISTEN_PORT":    70000,
		"LOCAL_DNS_PORT": 0,
	})
	if _, ok := normalized["LISTEN_PORT"]; ok {
		t.Fatalf("out-of-range CottenDNS listen port was retained: %#v", normalized)
	}
	if _, ok := normalized["LOCAL_DNS_PORT"]; ok {
		t.Fatalf("out-of-range CottenDNS local DNS port was retained: %#v", normalized)
	}
}

// A profile the user never customised must still run under the speed preset.
// The engine's own "default" probes each MTU candidate once and rejects it on
// any loss, which pins resolvers to small MTUs and caps throughput for the
// whole session. TXT-only is kept because speed otherwise rotates in HTTPS
// queries that filtered networks drop.
func TestUncustomisedProfileRunsUnderTheSpeedPreset(t *testing.T) {
	values := EffectiveOptions(map[string]any{})
	if values["MTU_PROBE_SAMPLES"] != 4 || values["MTU_MAX_LOSS"] != 0.25 {
		t.Fatalf("expected the speed MTU probe budget, got samples=%v max_loss=%v",
			values["MTU_PROBE_SAMPLES"], values["MTU_MAX_LOSS"])
	}
	if values["ADAPTIVE_DUPLICATION"] != true {
		t.Fatalf("duplication must be free to decay on a clean link: %v", values["ADAPTIVE_DUPLICATION"])
	}

	raw := RenderClientTOML(model.ConnectionProfile{}, map[string]any{})
	if !strings.Contains(raw, `CONFIG_PRESET = "speed"`) {
		t.Fatalf("runtime config did not fall back to the speed preset:\n%s", raw)
	}
	for _, want := range []string{
		`QUERY_TYPES = ["TXT"]`,
		"MIN_UPLOAD_MTU = 40",
		"MIN_DOWNLOAD_MTU = 300",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("runtime config missing %q:\n%s", want, raw)
		}
	}

	// An explicit choice still wins, including going back to the engine default.
	raw = RenderClientTOML(model.ConnectionProfile{}, map[string]any{"CONFIG_PRESET": "survival"})
	if !strings.Contains(raw, `CONFIG_PRESET = "survival"`) {
		t.Fatalf("explicit preset must win over the fallback:\n%s", raw)
	}

	// A settings export stays sparse so unset keys keep round tripping as unset.
	if settingsTOML := RenderSettingsTOML(map[string]any{}); strings.Contains(settingsTOML, "CONFIG_PRESET") ||
		strings.Contains(settingsTOML, "QUERY_TYPES") {
		t.Fatalf("settings export must not harden the fallback into an override:\n%s", settingsTOML)
	}
}

// The settings editor renders from Schema(), so anything the app supplies on
// top of the engine defaults has to be visible there too. Otherwise the editor
// shows one value while the launched engine runs another, which reads as a
// change that did not take.
func TestSchemaReportsWhatTheEngineWillActuallyRun(t *testing.T) {
	shown := map[string]any{}
	for _, option := range Schema() {
		shown[option.Key] = option.DefaultValue
	}
	if shown["CONFIG_PRESET"] != DefaultConfigPreset {
		t.Fatalf("editor would offer preset %v while the engine runs %q", shown["CONFIG_PRESET"], DefaultConfigPreset)
	}
	if fmt.Sprint(shown["MIN_UPLOAD_MTU"]) != "40" || fmt.Sprint(shown["MIN_DOWNLOAD_MTU"]) != "300" {
		t.Fatalf("editor would show engine MTU bounds, not the app's: up=%v down=%v",
			shown["MIN_UPLOAD_MTU"], shown["MIN_DOWNLOAD_MTU"])
	}

	// Effective values must agree with the rendered config for an untouched profile.
	values := EffectiveOptions(map[string]any{})
	raw := RenderClientTOML(model.ConnectionProfile{}, map[string]any{})
	for key, want := range map[string]string{
		"MIN_UPLOAD_MTU":   "40",
		"MIN_DOWNLOAD_MTU": "300",
	} {
		if fmt.Sprint(values[key]) != want {
			t.Fatalf("effective %s = %v, want %s", key, values[key], want)
		}
		if !strings.Contains(raw, key+" = "+want) {
			t.Fatalf("rendered config disagrees with effective %s:\n%s", key, raw)
		}
	}
}

func TestIPv6DesktopIntegrationContract(t *testing.T) {
	definitions := map[string]OptionDefinition{}
	for _, definition := range Schema() {
		definitions[definition.Key] = definition
	}
	familyDefinition, ok := definitions["RESOLVER_IP_MODE"]
	if !ok {
		t.Fatal("RESOLVER_IP_MODE is missing from the desktop settings schema")
	}
	wantFamilyModes := []any{"auto", "dual", "ipv4", "ipv6"}
	gotFamilyModes := make([]any, 0, len(familyDefinition.Choices))
	for _, choice := range familyDefinition.Choices {
		gotFamilyModes = append(gotFamilyModes, choice.Value)
	}
	if !reflect.DeepEqual(gotFamilyModes, wantFamilyModes) {
		t.Fatalf("resolver family choices = %#v, want %#v", gotFamilyModes, wantFamilyModes)
	}

	shown := map[string]any{}
	for _, definition := range Schema() {
		shown[definition.Key] = definition.DefaultValue
	}
	if shown["RESOLVER_IP_MODE"] != "auto" {
		t.Fatalf("desktop must default to automatic IPv6 fallback, got %v", shown["RESOLVER_IP_MODE"])
	}
	if shown["TERMINAL_UI"] != "plain" || shown["STARTUP_MODE"] != "resolvers" {
		t.Fatalf("GUI-safe engine modes are not reflected by the schema: terminal=%v startup=%v", shown["TERMINAL_UI"], shown["STARTUP_MODE"])
	}

	raw := RenderClientTOML(model.ConnectionProfile{}, map[string]any{})
	for _, want := range []string{
		`RESOLVER_IP_MODE = "auto"`,
		`TERMINAL_UI = "plain"`,
		`STARTUP_MODE = "resolvers"`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("runtime config missing GUI-safe IPv6 setting %q:\n%s", want, raw)
		}
	}
}

func TestCottenMaxScanRetainsTransportAndOptionalFeatures(t *testing.T) {
	options := map[string]any{"TUNNEL_MODE": "cottenmax", "RESOLVER_TRANSPORT": "auto",
		"COTTENMAX_MAX_INFLIGHT": 128, "RESOLVER_DISCOVERY_ENABLED": true,
		"RESOLVER_DISCOVERY_CANDIDATES": []string{"1.1.1.1:5353"}}
	connection := model.ConnectionProfile{Domain: "a.example", EncryptionKey: "shared-test-key", EncryptionMethod: 5}
	live := RenderClientTOML(connection, options)
	scan := RenderScannerClientTOML(connection, options, 4)
	for _, key := range []string{`TUNNEL_MODE = "cottenmax"`, `RESOLVER_TRANSPORT = "auto"`,
		`COTTENMAX_MAX_INFLIGHT = 128`, `RESOLVER_DISCOVERY_ENABLED = true`, `ENCRYPTION_KEY = "shared-test-key"`} {
		if !strings.Contains(live, key) || !strings.Contains(scan, key) {
			t.Fatalf("live/scan lost %s", key)
		}
	}
	if !strings.Contains(scan, "MTU_TEST_PARALLELISM_RESOLVERS = 4") || !strings.Contains(scan, "LOCAL_DNS_ENABLED = false") {
		t.Fatal("scan-specific controls missing")
	}
	if options["LOCAL_DNS_ENABLED"] != nil {
		t.Fatal("scan mutated the saved profile")
	}
}

func TestCottenMaxFECAndResolverDefaultsStayOptIn(t *testing.T) {
	want := map[string]any{
		"COTTENMAX_FEC_DOWNLOAD_ENABLED": false,
		"COTTENMAX_FEC_DATA_SHARDS":      4,
		"COTTENMAX_FEC_PARITY_SHARDS":    1,
		"COTTENMAX_MAX_INFLIGHT":         256,
		"RESOLVER_DISCOVERY_WANT":        16,
	}
	for _, preset := range []string{"default", "speed", "survival", "tcp-survival"} {
		values := EffectiveOptions(map[string]any{"CONFIG_PRESET": preset})
		for key, expected := range want {
			if values[key] != expected {
				t.Errorf("%s: %s = %v, want %v", preset, key, values[key], expected)
			}
		}
	}
	for _, definition := range Schema() {
		if strings.HasPrefix(definition.Key, "COTTENMAX_FEC_") && definition.Group != "Delivery and failover" {
			t.Errorf("FEC control %s is in %q", definition.Key, definition.Group)
		}
	}
}

func TestCottenMaxFECAndResolverOptionsSurviveProfileAndTOMLRoundTrip(t *testing.T) {
	options := map[string]any{
		"TUNNEL_MODE":                    "cottenmax",
		"COTTENMAX_FEC_DOWNLOAD_ENABLED": true,
		"COTTENMAX_FEC_DATA_SHARDS":      8,
		"COTTENMAX_FEC_PARITY_SHARDS":    2,
		"COTTENMAX_MAX_INFLIGHT":         4096,
		"RESOLVER_DISCOVERY_WANT":        4096,
		"RESOLVER_DISCOVERY_CONCURRENCY": 64,
	}
	profile := model.DefaultCottenDNSSettingsProfile()
	profile.CottenDNSOptions = &options
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var restored model.SettingsProfile
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	settingsExport := RenderSettingsTOML(OptionValues(restored.CottenDNSOptions))
	imported, err := ParseOptions(settingsExport)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imported, options) {
		t.Fatalf("CottenMax settings changed during JSON/TOML round trip: want %#v, got %#v", options, imported)
	}
	connection := model.ConnectionProfile{Domain: "max.example", EncryptionKey: "shared-test-key"}
	for name, raw := range map[string]string{
		"runtime": RenderClientTOML(connection, imported),
		"scanner": RenderScannerClientTOML(connection, imported, 4),
	} {
		got, err := ParseOptions(raw)
		if err != nil {
			t.Fatalf("%s config: %v", name, err)
		}
		for key, want := range options {
			if got[key] != want {
				t.Errorf("%s lost %s: got %v, want %v", name, key, got[key], want)
			}
		}
	}
}

func TestCottenMaxFECAndResolverOptionBounds(t *testing.T) {
	for _, tc := range []struct {
		key      string
		min, max int
	}{
		{"COTTENMAX_FEC_DATA_SHARDS", 2, 16},
		{"COTTENMAX_FEC_PARITY_SHARDS", 1, 4},
		{"COTTENMAX_MAX_INFLIGHT", 1, 4096},
		{"RESOLVER_DISCOVERY_WANT", 1, 4096},
		{"RESOLVER_DISCOVERY_CONCURRENCY", 1, 64},
		{"COTTENMAX_MAX_PATH_WINDOW", 1, 1024},
	} {
		t.Run(tc.key, func(t *testing.T) {
			for _, value := range []int{tc.min - 1, tc.min, tc.max, tc.max + 1} {
				_, retained := NormalizeOverrides(map[string]any{tc.key: value})[tc.key]
				want := value >= tc.min && value <= tc.max
				if retained != want {
					t.Errorf("value %d retained = %v, want %v", value, retained, want)
				}
			}
		})
	}
}
