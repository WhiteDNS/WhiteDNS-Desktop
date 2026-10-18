package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type SoarSettings struct {
	Transport            string `json:"transport"`
	Discovery            bool   `json:"discovery"`
	Country              string `json:"country"`
	DiscoveryWant        int    `json:"discoveryWant"`
	DiscoveryConcurrency int    `json:"discoveryConcurrency"`
	DiscoveryPaceMs      int    `json:"discoveryPaceMs"`
	SafeQName            int    `json:"safeQName"`
	MaxQName             int    `json:"maxQName"`
	MaxAnswer            int    `json:"maxAnswer"`
	HoldMs               int    `json:"holdMs"`
	MaxInflight          int    `json:"maxInflight"`
	MaxPathWindow        int    `json:"maxPathWindow"`
	MaxStreams           int    `json:"maxStreams"`
	StreamWindowKiB      int    `json:"streamWindowKiB"`
	SendBufferKiB        int    `json:"sendBufferKiB"`
	SessionIdleSeconds   int    `json:"sessionIdleSeconds"`
	DialTimeoutSeconds   int    `json:"dialTimeoutSeconds"`
}

func DefaultSoarSettings() SoarSettings {
	return SoarSettings{Transport: "auto", Discovery: true, Country: "IR", DiscoveryWant: 2,
		DiscoveryConcurrency: 2, DiscoveryPaceMs: 1000, SafeQName: 101, MaxQName: 253,
		MaxAnswer: 1232, HoldMs: 500, MaxInflight: 128, MaxPathWindow: 32, MaxStreams: 128,
		StreamWindowKiB: 256, SendBufferKiB: 64, SessionIdleSeconds: 90, DialTimeoutSeconds: 90}
}

func (s *SoarSettings) UnmarshalJSON(raw []byte) error {
	type plain SoarSettings
	value := plain(DefaultSoarSettings())
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*s = SoarSettings(value)
	return nil
}
func (s SoarSettings) Validate() error {
	o := s
	if o.Transport != "auto" && o.Transport != "on" && o.Transport != "only" && o.Transport != "off" {
		return errors.New("resolver transport must be auto, on, only or off")
	}
	if len(o.Country) != 0 && (len(o.Country) != 2 || o.Country[0] < 'A' || o.Country[0] > 'Z' || o.Country[1] < 'A' || o.Country[1] > 'Z') {
		return errors.New("country must be a two-letter code or blank")
	}
	for _, bound := range []struct{ value, low, high int }{
		{o.SafeQName, 101, 253}, {o.MaxQName, o.SafeQName, 253}, {o.MaxAnswer, 512, 1232},
		{o.HoldMs, 100, 1500}, {o.MaxInflight, 8, 1024}, {o.MaxPathWindow, 2, 128}, {o.MaxStreams, 8, 256},
		{o.StreamWindowKiB, 64, 1024}, {o.SendBufferKiB, 32, 1024}, {o.SessionIdleSeconds, 15, 110},
		{o.DialTimeoutSeconds, 5, 120}, {o.DiscoveryWant, 1, 32}, {o.DiscoveryConcurrency, 1, 16}, {o.DiscoveryPaceMs, 100, 5000},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return errors.New("a Soar advanced setting is outside its supported range; reset to the Automatic preset")
		}
	}
	return nil
}
func ValidateSoarProfile(p ConnectionProfile) error {
	domains := ConnectionDomains(p)
	if len(domains) != 1 || len(domains[0]) > 45 || !strings.Contains(domains[0], ".") {
		return errors.New("Soar needs one ASCII tunnel domain of at most 45 characters")
	}
	for _, label := range strings.Split(domains[0], ".") {
		if len(label) == 0 || len(label) > 63 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`).MatchString(label) {
			return errors.New("invalid Soar tunnel domain")
		}
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.EncryptionKey))
	if err != nil || len(key) != 32 {
		return errors.New("Soar requires a base64-encoded 32-byte Ed25519 public key")
	}
	if p.SoarSettings != nil {
		if err := p.SoarSettings.Validate(); err != nil {
			return fmt.Errorf("Soar settings: %w", err)
		}
	}
	return nil
}
func DefaultSoarSettingsProfile() SettingsProfile {
	p := DefaultSettingsProfile()
	p.ID = DefaultSoarSettingsID
	p.Name = "Soar proxy"
	p.ImportType = ImportTypeSoar
	return p
}

type SubscriptionSource struct {
	URL           string `json:"url"`
	RemoteID      string `json:"remoteId"`
	AllowHTTP     bool   `json:"allowHttp"`
	UpdatedAt     int64  `json:"updatedAt"`
	IntervalHours int    `json:"intervalHours"`
	Upload        int64  `json:"upload"`
	Download      int64  `json:"download"`
	Total         int64  `json:"total"`
	ExpiresAt     int64  `json:"expiresAt"`
}
