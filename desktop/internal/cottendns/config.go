package cottendns

import (
	"bufio"
	_ "embed"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"whitedns-desktop/internal/model"
)

// The UI schema and defaults come from the exact configuration templates that
// are shipped with the pinned CottenDNS source. This keeps new engine options
// visible instead of silently dropping them in a hand-maintained adapter.
//
//go:embed client_config.toml
var defaultTemplate string

//go:embed client_config.speed.toml
var speedTemplate string

//go:embed client_config.survival.toml
var survivalTemplate string

//go:embed client_config.tcp-survival.toml
var tcpSurvivalTemplate string

// DefaultConfigPreset is the preset a CottenDNS profile runs under when the
// user has not picked one. The engine's own "default" preset probes each MTU
// candidate once and rejects it on any loss at all (MTU_PROBE_SAMPLES = 1,
// MTU_MAX_LOSS = 0), so a single dropped probe pins a resolver to a small MTU
// for the whole session and every query then carries less payload for the same
// overhead. "speed" samples four times against a 25% budget and lets
// duplication adapt to measured loss instead of staying pinned high.
const DefaultConfigPreset = "speed"

// runtimeFallbacks are written into a runnable client config when the user has
// not set them. They are engine defaults the Android client already overrides,
// kept here so both clients accept the same resolvers and shape queries the
// same way. A settings export never emits them, so an untouched key stays
// untouched.
var runtimeFallbacks = []struct {
	key   string
	value any
}{
	// The speed preset rotates in HTTPS queries. Filtered networks drop non-TXT
	// records, which surfaces as loss and retransmits, so TXT-only stays the
	// default until the user asks for the rotation.
	{"QUERY_TYPES", []string{"TXT"}},
	// MIN_*_MTU is a rejection threshold, not a floor: a resolver that cannot
	// sustain it is dropped from the pool outright. The engine defaults of
	// 100/1000 discard resolvers the Android client keeps at 40/300, which costs
	// desktop the parallel capacity those resolvers carry. The maxima stay at
	// the engine's higher ceilings.
	{"MIN_UPLOAD_MTU", 40},
	{"MIN_DOWNLOAD_MTU", 300},
	// A full RX channel drops inbound packets outright and logs "RX queue
	// overloaded", which then costs a retransmit for every drop. The engine's
	// 2048 is sized for a phone; a desktop pulling 1080p video fills it in about
	// a minute, and 480p in several.
	//
	// 4096 is what the MasterDNS engine ships and streams 1080p on, so it is a
	// measured value rather than one derived from a bitrate estimate.
	//
	// Only the receive side is widened. 1.1.2 also raised TX_CHANNEL_SIZE to
	// 8192 and both worker counts to 8, and was reported not as lossy but as
	// collapsing to a standstill. Deep queues in front of the ARQ are how that
	// happens: a packet can sit queued longer than the retransmit timeout, so
	// the ARQ resends it, which lengthens the same queue and expires more
	// timers. Nothing reports a full queue because it is draining, just
	// uselessly. The worker counts were their own problem, since every
	// processor serialises on fragmentstore's single global mutex and
	// RX_TX_WORKERS opens one UDP socket each.
	{"RX_CHANNEL_SIZE", 4096},
}

type OptionChoice struct {
	Value any    `json:"value"`
	Label string `json:"label"`
}

type OptionDefinition struct {
	Key            string         `json:"key"`
	Label          string         `json:"label"`
	Group          string         `json:"group"`
	Description    string         `json:"description"`
	Kind           string         `json:"kind"`
	DefaultValue   any            `json:"defaultValue"`
	PresetDefaults map[string]any `json:"presetDefaults"`
	Choices        []OptionChoice `json:"choices"`
}

type parsedOption struct {
	key         string
	value       any
	description string
}

var (
	schemaOnce sync.Once
	schema     []OptionDefinition
	byKey      map[string]OptionDefinition
	defaults   map[string]any
	presets    map[string]map[string]any
)

var connectionManagedKeys = map[string]struct{}{
	"DOMAINS":                {},
	"DATA_ENCRYPTION_METHOD": {},
	"ENCRYPTION_KEY":         {},
}

// Schema reports the options with the app's own defaults already applied, so
// the settings editor shows the value a profile will actually run with instead
// of the engine's bare default.
func Schema() []OptionDefinition {
	loadSchema()
	out := make([]OptionDefinition, len(schema))
	copy(out, schema)
	for idx := range out {
		if out[idx].Key == "CONFIG_PRESET" {
			out[idx].DefaultValue = DefaultConfigPreset
			continue
		}
		if value, ok := runtimeFallbackValue(out[idx].Key); ok {
			out[idx].DefaultValue = value
		}
	}
	return out
}

func runtimeFallbackValue(key string) (any, bool) {
	for _, fallback := range runtimeFallbacks {
		if fallback.key == key {
			return fallback.value, true
		}
	}
	return nil, false
}

func DefaultOptions() map[string]any {
	loadSchema()
	return cloneMap(defaults)
}

// NormalizeOverrides keeps only known, type-correct CottenDNS options. The map
// intentionally stores overrides rather than a full default snapshot so that
// CONFIG_PRESET retains its native CottenDNS semantics.
func NormalizeOverrides(input map[string]any) map[string]any {
	loadSchema()
	out := make(map[string]any)
	for key, raw := range input {
		key = strings.ToUpper(strings.TrimSpace(key))
		definition, ok := byKey[key]
		if !ok {
			continue
		}
		kind := definition.Kind
		if kind == "select" {
			kind = baseOptionKind(definition.DefaultValue)
		}
		value, ok := coerceValue(raw, kind)
		if !ok {
			continue
		}
		if !validChoice(value, definition.Choices) {
			continue
		}
		if !validOptionRange(key, value) {
			continue
		}
		out[key] = value
	}
	return out
}

func ParseOptions(rawText string) (map[string]any, error) {
	loadSchema()
	parsed, err := parseTemplate(rawText)
	if err != nil {
		return nil, err
	}
	values := make(map[string]any)
	for _, option := range parsed {
		if _, managed := connectionManagedKeys[option.key]; managed {
			continue
		}
		definition, ok := byKey[option.key]
		if !ok {
			continue
		}
		kind := definition.Kind
		if kind == "select" {
			kind = baseOptionKind(definition.DefaultValue)
		}
		value, ok := coerceValue(option.value, kind)
		if !ok {
			return nil, fmt.Errorf("invalid %s value", option.key)
		}
		values[option.key] = value
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("TOML does not contain CottenDNS settings")
	}
	return NormalizeOverrides(values), nil
}

func EffectiveOptions(overrides map[string]any) map[string]any {
	loadSchema()
	normalized := NormalizeOverrides(overrides)
	out := cloneMap(defaults)
	presetName := stringValue(normalized["CONFIG_PRESET"], DefaultConfigPreset)
	if preset, ok := presets[presetName]; ok {
		for key, value := range preset {
			out[key] = value
		}
	}
	// Applied over the preset and under the user, matching the order a runnable
	// client config is written in.
	for _, fallback := range runtimeFallbacks {
		out[fallback.key] = fallback.value
	}
	for key, value := range normalized {
		out[key] = value
	}
	return out
}

func ApplyRuntimeSettings(settings model.SettingsProfile) model.SettingsProfile {
	values := EffectiveOptions(OptionValues(settings.CottenDNSOptions))
	settings.StormDNSListenIP = stringValue(values["LISTEN_IP"], settings.StormDNSListenIP)
	settings.StormDNSListenPort = intValue(values["LISTEN_PORT"], settings.StormDNSListenPort)
	settings.SOCKS5Authentication = boolValue(values["SOCKS5_AUTH"], settings.SOCKS5Authentication)
	settings.SOCKSUsername = stringValue(values["SOCKS5_USER"], settings.SOCKSUsername)
	settings.SOCKSPassword = stringValue(values["SOCKS5_PASS"], settings.SOCKSPassword)
	settings.LocalDNSEnabled = boolValue(values["LOCAL_DNS_ENABLED"], settings.LocalDNSEnabled)
	settings.LocalDNSPort = intValue(values["LOCAL_DNS_PORT"], settings.LocalDNSPort)
	settings.BalancingStrategy = intValue(values["RESOLVER_BALANCING_STRATEGY"], settings.BalancingStrategy)
	settings.UploadDuplication = intValue(values["UPLOAD_PACKET_DUPLICATION_COUNT"], settings.UploadDuplication)
	settings.DownloadDuplication = intValue(values["DOWNLOAD_PACKET_DUPLICATION_COUNT"], settings.DownloadDuplication)
	settings.UploadCompression = intValue(values["UPLOAD_COMPRESSION_TYPE"], settings.UploadCompression)
	settings.DownloadCompression = intValue(values["DOWNLOAD_COMPRESSION_TYPE"], settings.DownloadCompression)
	settings.BaseEncodeData = boolValue(values["BASE_ENCODE_DATA"], settings.BaseEncodeData)
	settings.MinUploadMTU = intValue(values["MIN_UPLOAD_MTU"], settings.MinUploadMTU)
	settings.MinDownloadMTU = intValue(values["MIN_DOWNLOAD_MTU"], settings.MinDownloadMTU)
	settings.MaxUploadMTU = intValue(values["MAX_UPLOAD_MTU"], settings.MaxUploadMTU)
	settings.MaxDownloadMTU = intValue(values["MAX_DOWNLOAD_MTU"], settings.MaxDownloadMTU)
	settings.RXTXWorkers = intValue(values["RX_TX_WORKERS"], settings.RXTXWorkers)
	settings.TunnelProcessWorkers = intValue(values["TUNNEL_PROCESS_WORKERS"], settings.TunnelProcessWorkers)
	settings.LogLevel = strings.ToUpper(stringValue(values["LOG_LEVEL"], settings.LogLevel))
	return settings
}

func OptionValues(options *map[string]any) map[string]any {
	if options == nil {
		return map[string]any{}
	}
	return *options
}

func RenderClientTOML(connection model.ConnectionProfile, overrides map[string]any) string {
	return renderTOML(connection, overrides, true)
}

func RenderSettingsTOML(overrides map[string]any) string {
	return renderTOML(model.ConnectionProfile{}, overrides, false)
}

func renderTOML(connection model.ConnectionProfile, overrides map[string]any, includeConnection bool) string {
	loadSchema()
	normalized := NormalizeOverrides(overrides)
	var b strings.Builder
	line := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	line("# WHITEDNS_IMPORT_TYPE = \"cottendns\"")
	if value, ok := normalized["CONFIG_PRESET"]; ok {
		line("CONFIG_PRESET = %s", formatTOMLValue(value))
	} else if includeConnection {
		// Only a runnable client config states the fallback preset. A settings
		// export stays sparse so the unset keys keep round tripping as unset
		// rather than hardening into user overrides.
		line("CONFIG_PRESET = %s", formatTOMLValue(DefaultConfigPreset))
	}
	if includeConnection {
		for _, fallback := range runtimeFallbacks {
			if _, ok := normalized[fallback.key]; !ok {
				line("%s = %s", fallback.key, formatTOMLValue(fallback.value))
			}
		}
	}
	if includeConnection {
		domains := model.ConnectionDomains(connection)
		line("DOMAINS = %s", formatTOMLValue(domains))
		line("DATA_ENCRYPTION_METHOD = %d", connection.EncryptionMethod)
		line("ENCRYPTION_KEY = %s", formatTOMLValue(strings.TrimSpace(connection.EncryptionKey)))
	}
	for _, definition := range schema {
		if definition.Key == "CONFIG_PRESET" {
			continue
		}
		value, ok := normalized[definition.Key]
		if !ok {
			continue
		}
		line("%s = %s", definition.Key, formatTOMLValue(value))
	}
	return strings.TrimRight(b.String(), "\n")
}

func loadSchema() {
	schemaOnce.Do(func() {
		parsed, err := parseTemplate(defaultTemplate)
		if err != nil {
			panic(fmt.Sprintf("parse embedded CottenDNS defaults: %v", err))
		}
		presetTemplates := map[string]string{
			"speed":        speedTemplate,
			"survival":     survivalTemplate,
			"tcp-survival": tcpSurvivalTemplate,
		}
		presets = clientPresetOverrides()
		for name, raw := range presetTemplates {
			entries, parseErr := parseTemplate(raw)
			if parseErr != nil {
				panic(fmt.Sprintf("parse embedded CottenDNS %s preset: %v", name, parseErr))
			}
			_ = entries
			if _, ok := presets[name]; !ok {
				panic("missing CottenDNS preset metadata for " + name)
			}
		}

		definitions := make([]OptionDefinition, 0, len(parsed)+1)
		definitions = append(definitions, OptionDefinition{
			Key:          "CONFIG_PRESET",
			Label:        "Configuration preset",
			Group:        "General",
			Description:  "Apply a CottenDNS preset first; explicitly changed fields below override the preset.",
			Kind:         "select",
			DefaultValue: "default",
			Choices: []OptionChoice{
				{Value: "default", Label: "Default"},
				{Value: "speed", Label: "Speed"},
				{Value: "survival", Label: "Survival"},
				{Value: "tcp-survival", Label: "TCP survival"},
			},
		})
		for _, option := range parsed {
			if _, managed := connectionManagedKeys[option.key]; managed || option.key == "CONFIG_PRESET" {
				continue
			}
			definitions = append(definitions, OptionDefinition{
				Key:          option.key,
				Label:        optionLabel(option.key),
				Group:        optionGroup(option.key),
				Description:  option.description,
				Kind:         optionKind(option.key, option.value),
				DefaultValue: option.value,
				Choices:      optionChoices(option.key),
			})
		}

		byKey = make(map[string]OptionDefinition, len(definitions))
		defaults = make(map[string]any, len(definitions))
		for index := range definitions {
			definition := &definitions[index]
			definition.PresetDefaults = make(map[string]any)
			for name, values := range presets {
				if value, ok := values[definition.Key]; ok {
					definition.PresetDefaults[name] = value
				}
			}
			byKey[definition.Key] = *definition
			defaults[definition.Key] = definition.DefaultValue
		}
		schema = definitions
	})
}

// clientPresetOverrides mirrors the reviewed preset functions in the pinned
// CottenDNS commit recorded in vendor/cottendns.json. Keeping these values in
// the desktop schema lets the UI show the effective preset value while the
// runtime still delegates actual preset application to CottenDNS itself.
func clientPresetOverrides() map[string]map[string]any {
	return map[string]map[string]any{
		"default": {},
		"speed": {
			"RESOLVER_BALANCING_STRATEGY": 5, "RESOLVER_TRANSPORT": "auto",
			"UPLOAD_PACKET_DUPLICATION_COUNT": 1, "DOWNLOAD_PACKET_DUPLICATION_COUNT": 1,
			"UPLOAD_SETUP_PACKET_DUPLICATION_COUNT": 2, "DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT": 4,
			"DUPLICATION_PREFER_DISTINCT_DOMAINS": true, "ADAPTIVE_DUPLICATION": true,
			"ADAPTIVE_DUPLICATION_TARGET_DELIVERY": 0.95, "MTU_PROBE_SAMPLES": 4,
			"MTU_MAX_LOSS": 0.25, "MTU_ADAPTIVE_GROUPING": true,
			"MTU_TEST_RETRIES_RESOLVERS": 2, "MTU_TEST_TIMEOUT_RESOLVERS": 1.5,
			"MTU_TEST_PARALLELISM_RESOLVERS": 100, "MTU_TEST_RETRIES_LOGS": 3,
			"MTU_TEST_TIMEOUT_LOGS": 1.5, "SESSION_INIT_RACING_COUNT": 5,
			"PING_WATCHDOG_TIMEOUT_SECONDS": 20.0, "MAX_PACKETS_PER_BATCH": 12,
			"ARQ_WINDOW_SIZE": 1500, "ARQ_INITIAL_RTO_SECONDS": 0.45, "ARQ_MAX_RTO_SECONDS": 2.5,
			"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS": 0.25, "ARQ_DATA_NACK_REPEAT_SECONDS": 0.5,
			"UPLOAD_COMPRESSION_TYPE": 2, "DOWNLOAD_COMPRESSION_TYPE": 2, "COMPRESSION_MIN_SIZE": 180,
			"QNAME_LABEL_LENGTH": 63, "EDNS_UDP_SIZE": 4096, "QUERY_TYPES": []string{"TXT", "HTTPS"},
		},
		"survival": {
			"RESOLVER_BALANCING_STRATEGY": 3, "RESOLVER_TRANSPORT": "auto",
			"UPLOAD_PACKET_DUPLICATION_COUNT": 2, "DOWNLOAD_PACKET_DUPLICATION_COUNT": 6,
			"UPLOAD_SETUP_PACKET_DUPLICATION_COUNT": 4, "DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT": 8,
			"DUPLICATION_PREFER_DISTINCT_DOMAINS": true, "ADAPTIVE_DUPLICATION": true,
			"PING_WATCHDOG_TIMEOUT_SECONDS": 15.0, "ADAPTIVE_DUPLICATION_TARGET_DELIVERY": 0.97,
			"MIN_UPLOAD_MTU": 80, "MAX_UPLOAD_MTU": 180, "MIN_DOWNLOAD_MTU": 700, "MAX_DOWNLOAD_MTU": 2500,
			"MTU_PROBE_SAMPLES": 5, "MTU_MAX_LOSS": 0.2, "MTU_ADAPTIVE_GROUPING": true,
			"MTU_TEST_TIMEOUT_RESOLVERS": 2.5, "MTU_TEST_PARALLELISM_RESOLVERS": 64,
			"MAX_PACKETS_PER_BATCH": 8, "ARQ_INITIAL_RTO_SECONDS": 0.7, "ARQ_MAX_RTO_SECONDS": 4.0,
			"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS": 0.35, "ARQ_DATA_NACK_REPEAT_SECONDS": 0.8,
			"UPLOAD_COMPRESSION_TYPE": 2, "DOWNLOAD_COMPRESSION_TYPE": 2, "COMPRESSION_MIN_SIZE": 120,
			"QNAME_LABEL_LENGTH": 42, "EDNS_UDP_SIZE": 1232, "QUERY_TYPES": []string{"TXT", "CNAME", "HTTPS", "A"},
		},
		"tcp-survival": {
			"RESOLVER_BALANCING_STRATEGY": 5, "RESOLVER_TRANSPORT": "tcp",
			"UPLOAD_PACKET_DUPLICATION_COUNT": 1, "DOWNLOAD_PACKET_DUPLICATION_COUNT": 2,
			"UPLOAD_SETUP_PACKET_DUPLICATION_COUNT": 3, "DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT": 4,
			"DUPLICATION_PREFER_DISTINCT_DOMAINS": true, "ADAPTIVE_DUPLICATION": true,
			"ADAPTIVE_DUPLICATION_TARGET_DELIVERY": 0.95, "MTU_PROBE_SAMPLES": 4, "MTU_MAX_LOSS": 0.25,
			"MTU_TEST_PARALLELISM_RESOLVERS": 32, "MTU_TEST_TIMEOUT_RESOLVERS": 3.0,
			"MAX_PACKETS_PER_BATCH": 12, "ARQ_WINDOW_SIZE": 1500,
			"ARQ_INITIAL_RTO_SECONDS": 0.5, "ARQ_MAX_RTO_SECONDS": 3.0,
			"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS": 0.3, "ARQ_DATA_NACK_REPEAT_SECONDS": 0.6,
			"UPLOAD_COMPRESSION_TYPE": 2, "DOWNLOAD_COMPRESSION_TYPE": 2, "COMPRESSION_MIN_SIZE": 180,
			"QNAME_LABEL_LENGTH": 63, "EDNS_UDP_SIZE": 4096, "QUERY_TYPES": []string{"TXT", "HTTPS"},
		},
	}
}

func parseTemplate(raw string) ([]parsedOption, error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	comments := make([]string, 0)
	options := make([]parsedOption, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			comments = nil
			continue
		}
		if strings.HasPrefix(line, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if comment != "" && !isCommentDivider(comment) {
				comments = append(comments, comment)
			}
			continue
		}
		assignment := stripComment(line)
		key, rawValue, ok := strings.Cut(assignment, "=")
		if !ok {
			return nil, fmt.Errorf("invalid assignment on line %d", lineNumber)
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value, err := parseTOMLValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("invalid %s on line %d: %w", key, lineNumber, err)
		}
		options = append(options, parsedOption{key: key, value: value, description: compactDescription(comments)})
		comments = nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return options, nil
}

func parseTOMLValue(raw string) (any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "true" || raw == "false" {
		return raw == "true", nil
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		inside := strings.TrimSpace(raw[1 : len(raw)-1])
		if inside == "" {
			return []string{}, nil
		}
		parts := splitTOMLList(inside)
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			value, err := parseTOMLString(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	}
	if strings.HasPrefix(raw, "\"") || strings.HasPrefix(raw, "'") {
		return parseTOMLString(raw)
	}
	clean := strings.ReplaceAll(raw, "_", "")
	if strings.ContainsAny(clean, ".eE") {
		return strconv.ParseFloat(clean, 64)
	}
	value, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		return nil, err
	}
	return int(value), nil
}

func parseTOMLString(raw string) (string, error) {
	if len(raw) < 2 {
		return "", fmt.Errorf("expected quoted string")
	}
	if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], nil
	}
	return strconv.Unquote(raw)
}

func splitTOMLList(raw string) []string {
	parts := make([]string, 0)
	start := 0
	inString := false
	escaped := false
	for index, char := range raw {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == ',' && !inString {
			parts = append(parts, raw[start:index])
			start = index + 1
		}
	}
	return append(parts, raw[start:])
}

func stripComment(line string) string {
	inString := false
	escaped := false
	for index, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == '#' && !inString {
			return strings.TrimSpace(line[:index])
		}
	}
	return line
}

func formatTOMLValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strconv.Quote(typed)
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case []string:
		parts := make([]string, len(typed))
		for index, item := range typed {
			parts[index] = strconv.Quote(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return strconv.Quote(fmt.Sprint(value))
	}
}

func coerceValue(raw any, kind string) (any, bool) {
	switch kind {
	case "boolean":
		switch value := raw.(type) {
		case bool:
			return value, true
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			return parsed, err == nil
		}
	case "integer":
		switch value := raw.(type) {
		case int:
			return value, true
		case int64:
			return int(value), true
		case float64:
			if math.Trunc(value) == value {
				return int(value), true
			}
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			return parsed, err == nil
		}
	case "number":
		switch value := raw.(type) {
		case float64:
			return value, true
		case int:
			return float64(value), true
		case int64:
			return float64(value), true
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			return parsed, err == nil
		}
	case "string-list":
		switch value := raw.(type) {
		case []string:
			return value, true
		case []any:
			out := make([]string, 0, len(value))
			for _, item := range value {
				text, ok := item.(string)
				if !ok {
					return nil, false
				}
				out = append(out, text)
			}
			return out, true
		case string:
			parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				if text := strings.TrimSpace(part); text != "" {
					out = append(out, text)
				}
			}
			return out, true
		}
	default:
		if value, ok := raw.(string); ok {
			return value, true
		}
	}
	return nil, false
}

func validChoice(value any, choices []OptionChoice) bool {
	if len(choices) == 0 {
		return true
	}
	wanted := fmt.Sprint(value)
	for _, choice := range choices {
		if fmt.Sprint(choice.Value) == wanted {
			return true
		}
	}
	return false
}

func validOptionRange(key string, value any) bool {
	switch key {
	case "LISTEN_PORT", "LOCAL_DNS_PORT":
		port, ok := value.(int)
		return ok && port >= 1 && port <= 65535
	default:
		return true
	}
}

func optionKind(key string, value any) string {
	if len(optionChoices(key)) > 0 {
		return "select"
	}
	switch value.(type) {
	case bool:
		return "boolean"
	case int, int64:
		return "integer"
	case float64:
		return "number"
	case []string:
		return "string-list"
	default:
		return "string"
	}
}

func baseOptionKind(value any) string {
	switch value.(type) {
	case bool:
		return "boolean"
	case int, int64:
		return "integer"
	case float64:
		return "number"
	case []string:
		return "string-list"
	default:
		return "string"
	}
}

func optionChoices(key string) []OptionChoice {
	switch key {
	case "PROTOCOL_TYPE":
		return []OptionChoice{{Value: "SOCKS5", Label: "SOCKS5"}, {Value: "SOCKS4", Label: "SOCKS4"}}
	case "RESOLVER_TRANSPORT":
		return []OptionChoice{{Value: "auto", Label: "Automatic"}, {Value: "udp", Label: "UDP/53"}, {Value: "tcp", Label: "TCP/53"}, {Value: "dot", Label: "DNS over TLS"}, {Value: "doh", Label: "DNS over HTTPS"}}
	case "RESOLVER_BALANCING_STRATEGY":
		labels := []string{"Random", "Round robin", "Least loss", "Lowest latency", "MTU weighted", "Loss then latency", "Least-loss random pool", "Least-loss round-robin pool"}
		out := make([]OptionChoice, len(labels))
		for index, label := range labels {
			out[index] = OptionChoice{Value: index + 1, Label: label}
		}
		return out
	case "UPLOAD_COMPRESSION_TYPE", "DOWNLOAD_COMPRESSION_TYPE":
		return []OptionChoice{{Value: 0, Label: "None"}, {Value: 1, Label: "ZLIB"}, {Value: 2, Label: "ZSTD"}, {Value: 3, Label: "LZ4"}}
	case "LOG_LEVEL":
		return []OptionChoice{{Value: "DEBUG", Label: "DEBUG"}, {Value: "INFO", Label: "INFO"}, {Value: "WARN", Label: "WARN"}, {Value: "ERROR", Label: "ERROR"}}
	case "STARTUP_MODE":
		return []OptionChoice{{Value: "resolvers", Label: "Resolver scan"}, {Value: "logs", Label: "Cached logs"}, {Value: "ask", Label: "Ask"}}
	}
	return nil
}

func optionGroup(key string) string {
	switch {
	case key == "PROTOCOL_TYPE" || strings.HasPrefix(key, "LISTEN_") || strings.HasPrefix(key, "SOCKS5_"):
		return "Local proxy"
	case strings.HasPrefix(key, "LOCAL_DNS_") || strings.HasPrefix(key, "DNS_RESPONSE_"):
		return "Local DNS"
	case strings.HasPrefix(key, "RESOLVER_") || key == "QUERY_TYPES":
		return "Resolvers and transport"
	case strings.Contains(key, "DUPLICATION") || strings.HasPrefix(key, "STREAM_RESOLVER_") || strings.HasPrefix(key, "RECHECK_") || strings.HasPrefix(key, "AUTO_DISABLE_"):
		return "Delivery and failover"
	case strings.Contains(key, "COMPRESSION") || key == "BASE_ENCODE_DATA" || key == "LEGACY_SESSION_ID":
		return "Encoding and compatibility"
	case strings.Contains(key, "MTU") || key == "FAST_CONNECT":
		return "MTU discovery"
	case strings.HasPrefix(key, "PING_"):
		return "Ping policy"
	case strings.HasPrefix(key, "ARQ_") || strings.HasPrefix(key, "SESSION_INIT_"):
		return "ARQ and sessions"
	case strings.Contains(key, "WORKERS") || strings.Contains(key, "CHANNEL") || strings.Contains(key, "CAPACITY") || key == "MAX_ACTIVE_STREAMS" || key == "MAX_PACKETS_PER_BATCH":
		return "Performance and limits"
	case strings.HasPrefix(key, "LOG_") || key == "STATS_REPORT_INTERVAL_SECONDS" || key == "STARTUP_MODE" || key == "CONFIG_VERSION":
		return "Logging and startup"
	case strings.HasPrefix(key, "DNS_") || strings.HasPrefix(key, "QNAME_") || strings.HasPrefix(key, "EDNS_"):
		return "DNS query shaping"
	default:
		return "Timeouts and queues"
	}
}

func optionLabel(key string) string {
	switch key {
	case "PROTOCOL_TYPE":
		return "CottenDNS proxy protocol"
	case "LISTEN_IP":
		return "CottenDNS listen address"
	case "LISTEN_PORT":
		return "CottenDNS SOCKS port"
	}
	replacements := map[string]string{
		"DNS": "DNS", "EDNS": "EDNS", "MTU": "MTU", "ARQ": "ARQ", "RTO": "RTO",
		"SOCKS5": "SOCKS5", "UDP": "UDP", "TCP": "TCP", "TLS": "TLS", "DOH": "DoH",
		"DOT": "DoT", "QNAME": "QNAME", "NXDOMAIN": "NXDOMAIN", "RX": "RX", "TX": "TX",
		"IP": "IP", "ID": "ID", "TTL": "TTL",
	}
	parts := strings.Split(strings.ToUpper(key), "_")
	for index, part := range parts {
		if replacement, ok := replacements[part]; ok {
			parts[index] = replacement
			continue
		}
		parts[index] = strings.ToLower(part)
	}
	label := strings.Join(parts, " ")
	if label == "" {
		return key
	}
	runes := []rune(label)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func compactDescription(comments []string) string {
	if len(comments) == 0 {
		return ""
	}
	text := strings.Join(comments, " ")
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 320 {
		text = strings.TrimSpace(text[:317]) + "..."
	}
	return text
}

func isCommentDivider(value string) bool {
	trimmed := strings.Trim(value, "-= ")
	return trimmed == ""
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringValue(value any, fallback string) string {
	if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
		return text
	}
	return fallback
}

func intValue(value any, fallback int) int {
	coerced, ok := coerceValue(value, "integer")
	if !ok {
		return fallback
	}
	return coerced.(int)
}

func boolValue(value any, fallback bool) bool {
	coerced, ok := coerceValue(value, "boolean")
	if !ok {
		return fallback
	}
	return coerced.(bool)
}
