package profiles

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"whitedns-desktop/internal/model"
)

const stormDNSProfileSchema = "whitedns.profile"

var stormDNSProfileURLPattern = regexp.MustCompile(`(?i)(soar|cottendns|stormdns|masterdns)://([A-Za-z0-9+/_=-]+)`)

type stormDNSProfilePayload struct {
	Schema     string `json:"schema"`
	Version    int    `json:"version"`
	ImportType string `json:"import_type,omitempty"`
	Profile    struct {
		Name         string                `json:"name"`
		ID           string                `json:"id,omitempty"`
		SoarSettings *model.SoarSettings   `json:"soarSettings,omitempty"`
		Resolvers    []string              `json:"resolvers,omitempty"`
		Server       stormDNSProfileServer `json:"server"`
	} `json:"profile"`
}

type stormDNSProfileServer struct {
	Domain                string   `json:"domain"`
	PublicKey             string   `json:"public_key,omitempty"`
	Domains               []string `json:"domains,omitempty"`
	EncryptionKey         string   `json:"encryption_key"`
	EncryptionKeyCamel    string   `json:"encryptionKey,omitempty"`
	EncryptionMethod      *int     `json:"encryption_method"`
	EncryptionMethodCamel *int     `json:"encryptionMethod,omitempty"`
}

func ParseConnectionProfileImports(rawText, resolverProfileID string, importType string) ([]model.ConnectionProfile, error) {
	matches := stormDNSProfileURLPattern.FindAllStringSubmatch(rawText, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no supported Soar, MasterDNS, StormDNS, or CottenDNS profiles found")
	}

	profiles := make([]model.ConnectionProfile, 0, len(matches))
	for idx, match := range matches {
		profile, err := parseStormDNSProfile(match[2], resolverProfileID, match[1], importType)
		if err != nil {
			return nil, fmt.Errorf("profile %d: %w", idx+1, err)
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func ExportConnectionProfile(profile model.ConnectionProfile) (string, error) {
	name := strings.TrimSpace(profile.Name)
	domains := model.ConnectionDomains(profile)
	key := strings.TrimSpace(profile.EncryptionKey)
	if len(domains) == 0 {
		return "", fmt.Errorf("at least one DNS tunnel domain is required")
	}
	if key == "" {
		return "", fmt.Errorf("MasterDNS/StormDNS encryption key is required")
	}
	method := profile.EncryptionMethod
	if method < 0 || method > 5 {
		return "", fmt.Errorf("unsupported encryption method")
	}
	if name == "" {
		name = domains[0]
	}

	payload := stormDNSProfilePayload{
		Schema:     stormDNSProfileSchema,
		Version:    1,
		ImportType: model.NormalizeImportType(profile.ImportType),
	}
	payload.Profile.Name = name
	payload.Profile.Server.Domain = domains[0]
	payload.Profile.Server.Domains = domains
	payload.Profile.Server.EncryptionKey = key
	payload.Profile.Server.EncryptionMethod = &method
	if model.NormalizeImportType(profile.ImportType) == model.ImportTypeSoar {
		if err := model.ValidateSoarProfile(profile); err != nil {
			return "", err
		}
		payload.Profile.ID = profile.RemoteID
		payload.Profile.SoarSettings = profile.SoarSettings
		payload.Profile.Resolvers = profile.BootstrapResolvers
		payload.Profile.Server.PublicKey = key
		payload.Profile.Server.EncryptionKey = ""
		payload.Profile.Server.EncryptionMethod = nil
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return model.NormalizeImportType(profile.ImportType) + "://" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func ExportConnectionProfiles(connectionProfiles []model.ConnectionProfile) (string, error) {
	links := make([]string, 0, len(connectionProfiles))
	for _, profile := range connectionProfiles {
		if !IsExportableConnectionProfile(profile) {
			continue
		}
		link, err := ExportConnectionProfile(profile)
		if err != nil {
			return "", err
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return "", fmt.Errorf("no complete connection profiles to export")
	}
	return strings.Join(links, "\n"), nil
}

func IsExportableConnectionProfile(profile model.ConnectionProfile) bool {
	return len(model.ConnectionDomains(profile)) > 0 && strings.TrimSpace(profile.EncryptionKey) != ""
}

func parseStormDNSProfile(encoded, resolverProfileID, scheme, legacyType string) (model.ConnectionProfile, error) {
	raw, err := decodeStormDNSProfile(encoded)
	if err != nil {
		return model.ConnectionProfile{}, err
	}

	var payload stormDNSProfilePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return model.ConnectionProfile{}, fmt.Errorf("invalid profile JSON")
	}
	if payload.Schema != stormDNSProfileSchema {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported profile schema")
	}
	if payload.Version != 1 {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported profile version")
	}
	importType, err := connectionImportType(scheme, payload.ImportType, legacyType)
	if err != nil {
		return model.ConnectionProfile{}, err
	}

	domains := model.NormalizeConnectionDomains(payload.Profile.Server.Domain, payload.Profile.Server.Domains)
	if len(domains) == 0 {
		return model.ConnectionProfile{}, fmt.Errorf("at least one DNS tunnel domain is required")
	}

	key := strings.TrimSpace(payload.Profile.Server.EncryptionKey)
	if model.NormalizeImportType(importType) == model.ImportTypeSoar {
		key = strings.TrimSpace(payload.Profile.Server.PublicKey)
	}
	if key == "" {
		key = strings.TrimSpace(payload.Profile.Server.EncryptionKeyCamel)
	}
	if key == "" {
		return model.ConnectionProfile{}, fmt.Errorf("MasterDNS/StormDNS encryption key is required")
	}

	method := 1
	if payload.Profile.Server.EncryptionMethod != nil {
		method = *payload.Profile.Server.EncryptionMethod
	} else if payload.Profile.Server.EncryptionMethodCamel != nil {
		method = *payload.Profile.Server.EncryptionMethodCamel
	}
	if method < 0 || method > 5 {
		return model.ConnectionProfile{}, fmt.Errorf("unsupported encryption method")
	}

	name := strings.TrimSpace(payload.Profile.Name)
	if name == "" {
		name = domains[0]
	}

	profile := model.ConnectionProfile{
		Name:              name,
		ImportType:        model.NormalizeImportType(importType),
		Domain:            domains[0],
		Domains:           domains,
		EncryptionKey:     key,
		EncryptionMethod:  method,
		ResolverProfileID: strings.TrimSpace(resolverProfileID),
		RemoteID:          payload.Profile.ID, SoarSettings: payload.Profile.SoarSettings, BootstrapResolvers: payload.Profile.Resolvers,
	}
	if profile.ImportType == model.ImportTypeSoar {
		profile.EncryptionMethod = 0
		if profile.SoarSettings == nil {
			value := model.DefaultSoarSettings()
			profile.SoarSettings = &value
		}
		if err := model.ValidateSoarProfile(profile); err != nil {
			return model.ConnectionProfile{}, err
		}
		if len(profile.BootstrapResolvers) == 0 {
			profile.BootstrapResolvers = []string{"1.1.1.1"}
		}
		if len(profile.BootstrapResolvers) > 8192 {
			return model.ConnectionProfile{}, fmt.Errorf("too many Soar resolvers")
		}
		for _, address := range profile.BootstrapResolvers {
			if _, err := netip.ParseAddr(address); err != nil {
				if ap, err := netip.ParseAddrPort(address); err != nil || ap.Port() == 0 {
					return model.ConnectionProfile{}, fmt.Errorf("Soar resolvers must be IP or IP:port addresses")
				}
			}
		}
	}
	return profile, nil
}

func connectionImportType(scheme, declared, legacyType string) (string, error) {
	// Old clients used stormdns:// for several engines. A payload marker takes
	// precedence there; the advanced choice is only a fallback for unmarked links.
	if !strings.EqualFold(scheme, model.ImportTypeStormDNS) {
		return model.NormalizeImportType(scheme), nil
	}
	value := strings.ToLower(strings.TrimSpace(declared))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(legacyType))
	}
	if value == "" {
		return model.ImportTypeMasterDNS, nil
	}
	switch value {
	case model.ImportTypeSoar, model.ImportTypeCottenDNS, model.ImportTypeMasterDNS, model.ImportTypeStormDNS:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported profile import type")
	}
}

func decodeStormDNSProfile(encoded string) ([]byte, error) {
	value := strings.TrimSpace(encoded)
	if value == "" {
		return nil, fmt.Errorf("empty profile payload")
	}

	padded := value
	if remainder := len(padded) % 4; remainder != 0 {
		padded += strings.Repeat("=", 4-remainder)
	}

	attempts := []struct {
		encoding *base64.Encoding
		value    string
	}{
		{base64.StdEncoding, padded},
		{base64.URLEncoding, padded},
		{base64.RawStdEncoding, strings.TrimRight(value, "=")},
		{base64.RawURLEncoding, strings.TrimRight(value, "=")},
	}
	for _, attempt := range attempts {
		raw, err := attempt.encoding.DecodeString(attempt.value)
		if err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 profile payload")
}
