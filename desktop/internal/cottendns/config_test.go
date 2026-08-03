package cottendns

import (
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
