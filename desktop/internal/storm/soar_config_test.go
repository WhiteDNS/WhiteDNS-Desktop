package storm

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"whitedns-desktop/internal/model"
)

func TestSoarLaunchUsesJSONAndMatchedSOCKSAuthentication(t *testing.T) {
	for _, auth := range []bool{false, true} {
		state := model.DefaultAppState()
		p := &state.ConnectionProfiles[0]
		p.ImportType = model.ImportTypeSoar
		p.Domain = "user.soar.example.org"
		p.Domains = []string{p.Domain}
		p.EncryptionKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
		opts := model.DefaultSoarSettings()
		opts.Country = ""
		opts.MaxInflight = 32
		p.SoarSettings = &opts
		s := model.DefaultSoarSettingsProfile()
		s.SOCKS5Authentication = auth
		s.SOCKSUsername = "local-user"
		s.SOCKSPassword = "local-password"
		state.SettingsProfiles = append(state.SettingsProfiles, s)
		state.SelectedSettingsProfileID = s.ID
		cfg, err := BuildLaunchConfig(state)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Engine != model.ImportTypeSoar {
			t.Fatal("Soar was converted into another engine")
		}
		var raw struct {
			Zone, Listen, Username, Password string
			Key                              string `json:"server_public_key"`
			Soar                             model.SoarSettings
		}
		if err := json.Unmarshal([]byte(cfg.ClientTOML), &raw); err != nil {
			t.Fatal("Soar received TOML instead of JSON", err)
		}
		if raw.Listen != "127.0.0.1:10887" || raw.Key != p.EncryptionKey || raw.Soar.Country != "" || raw.Soar.MaxInflight != 32 {
			t.Fatal("Soar launch lost imported settings")
		}
		if (raw.Username != "") != auth || (raw.Password != "") != auth {
			t.Fatal("internal SOCKS authentication disagrees with Xray")
		}
		if strings.Contains(cfg.ClientTOML, "ENCRYPTION_METHOD") || strings.Contains(cfg.ClientTOML, "MTU") {
			t.Fatal("MasterDNS knobs leaked into Soar")
		}
		if !strings.Contains(cfg.CoreConfig, `"protocol": "socks"`) {
			t.Fatal("local Xray proxy path missing")
		}
	}
}

func TestSoarRejectsInvalidKeysMultipleDomainsAndWrongWindowBounds(t *testing.T) {
	state := model.DefaultAppState()
	p := &state.ConnectionProfiles[0]
	p.ImportType = model.ImportTypeSoar
	p.Domain = "user.soar.example.org"
	p.Domains = []string{p.Domain}
	p.EncryptionKey = "old-master-key"
	if _, err := BuildLaunchConfig(state); err == nil {
		t.Fatal("MasterDNS key accepted by Soar")
	}
	p.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	p.Domains = append(p.Domains, "other.example.org")
	if _, err := BuildLaunchConfig(state); err == nil {
		t.Fatal("multiple Soar domains accepted")
	}
	p.Domains = []string{p.Domain}
	opts := model.DefaultSoarSettings()
	opts.SafeQName = 200
	opts.MaxQName = 101
	p.SoarSettings = &opts
	if _, err := BuildLaunchConfig(state); err == nil {
		t.Fatal("unsafe query bounds accepted")
	}
}
