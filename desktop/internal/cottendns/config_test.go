package cottendns

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"whitedns-desktop/internal/model"
)

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
