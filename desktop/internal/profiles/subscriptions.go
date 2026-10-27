package profiles

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"whitedns-desktop/internal/model"
)

const maxSubscriptionBytes = 1 << 20

type SubscriptionDocument struct {
	Source   model.SubscriptionSource
	Profiles []model.ConnectionProfile
}

func SubscriptionURL(raw string) (string, error) {
	if len(raw) > 4096 {
		return "", fmt.Errorf("subscription address is too long")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("use an HTTP or HTTPS subscription URL without embedded credentials or fragments")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid subscription port")
		}
	}
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func FetchSubscription(ctx context.Context, raw string, allowHTTP bool) (SubscriptionDocument, error) {
	address, err := SubscriptionURL(raw)
	if err != nil {
		return SubscriptionDocument{}, err
	}
	if strings.HasPrefix(address, "http://") && !allowHTTP {
		return SubscriptionDocument{}, fmt.Errorf("HTTP is unencrypted; explicit permission is required for this source")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("too many subscription redirects")
		}
		target, e := SubscriptionURL(next.URL.String())
		if e != nil {
			return e
		}
		if strings.HasPrefix(target, "http://") && (!allowHTTP || via[len(via)-1].URL.Scheme == "https") {
			return fmt.Errorf("HTTPS subscriptions cannot downgrade to HTTP")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "WhiteDNS-Desktop-Subscription/1")
	resp, err := client.Do(req)
	if err != nil {
		return SubscriptionDocument{}, fmt.Errorf("could not fetch subscription; check the connection and HTTPS certificate")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return SubscriptionDocument{}, fmt.Errorf("subscription returned HTTP %d; the account or link may be inactive or revoked", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
	if err != nil {
		return SubscriptionDocument{}, fmt.Errorf("subscription download failed")
	}
	if len(body) > maxSubscriptionBytes {
		return SubscriptionDocument{}, fmt.Errorf("subscription exceeds 1 MiB")
	}
	return ParseSubscription(address, string(body), resp.Header, allowHTTP, time.Now())
}

func ParseSubscription(address, body string, headers http.Header, allowHTTP bool, now time.Time) (SubscriptionDocument, error) {
	address, err := SubscriptionURL(address)
	if err != nil {
		return SubscriptionDocument{}, err
	}
	if len(body) > maxSubscriptionBytes {
		return SubscriptionDocument{}, fmt.Errorf("subscription exceeds 1 MiB")
	}
	body = strings.TrimPrefix(strings.TrimSpace(body), "\ufeff")
	if !strings.Contains(strings.SplitN(body, "\n", 2)[0], "://") {
		decoded, err := decodeStormDNSProfile(strings.Join(strings.Fields(body), ""))
		if err != nil {
			return SubscriptionDocument{}, fmt.Errorf("subscription must contain supported profile links or a base64 list")
		}
		body = string(decoded)
	}
	lines := strings.Split(body, "\n")
	profiles := []model.ConnectionProfile{}
	seen := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := stormDNSProfileURLPattern.FindStringSubmatch(line)
		if match == nil || match[0] != line {
			return SubscriptionDocument{}, fmt.Errorf("subscription contains an unsupported or incomplete profile")
		}
		values, err := ParseConnectionProfileImports(line, "", "")
		if err != nil {
			return SubscriptionDocument{}, fmt.Errorf("invalid subscription profile: %w", err)
		}
		p := values[0]
		profiles = append(profiles, p)
		if len(profiles) > 128 {
			return SubscriptionDocument{}, fmt.Errorf("subscription exceeds 128 profiles")
		}
	}
	if len(profiles) == 0 {
		return SubscriptionDocument{}, fmt.Errorf("subscription contains no profiles")
	}
	source := model.SubscriptionSource{URL: address, AllowHTTP: allowHTTP, UpdatedAt: now.UnixMilli(), IntervalHours: 12}
	if h, e := strconv.Atoi(headers.Get("Profile-Update-Interval")); e == nil {
		source.IntervalHours = max(1, min(168, h))
	}
	for _, part := range strings.Split(headers.Get("Subscription-Userinfo"), ";") {
		field := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(field) != 2 {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(field[1]), 10, 64)
		if err != nil || value < 0 {
			continue
		}
		switch strings.ToLower(field[0]) {
		case "upload":
			source.Upload = value
		case "download":
			source.Download = value
		case "total":
			source.Total = value
		case "expire":
			if value < 1<<53 {
				source.ExpiresAt = value * 1000
			}
		}
	}
	for i, p := range profiles {
		remote := p.RemoteID
		if remote == "" {
			if len(profiles) == 1 {
				remote = "single"
			} else {
				remote = p.ImportType + ":" + p.Domain + ":" + p.Name
			}
		}
		if seen[remote] {
			return SubscriptionDocument{}, fmt.Errorf("duplicate subscription profile identities")
		}
		seen[remote] = true
		own := source
		own.RemoteID = remote
		profiles[i].RemoteID = remote
		profiles[i].Subscription = &own
	}
	return SubscriptionDocument{Source: source, Profiles: profiles}, nil
}

func subscriptionIdentity(value string) string {
	h := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h[:18])
}

// Reconcile a validated source atomically, preserving unrelated profiles and
// explicit resolver overrides. The caller persists the resulting state once.
func ApplySubscription(state model.AppState, doc SubscriptionDocument, selectImported bool) model.AppState {
	old := map[string]model.ConnectionProfile{}
	removedResolvers := map[string]bool{}
	next := []model.ConnectionProfile{}
	for _, p := range state.ConnectionProfiles {
		if p.Subscription != nil && p.Subscription.URL == doc.Source.URL {
			old[p.Subscription.RemoteID] = p
			removedResolvers[p.ID+"-dns"] = true
		} else {
			next = append(next, p)
		}
	}
	firstID := ""
	newResolvers := []model.ResolverProfile{}
	for _, p := range doc.Profiles {
		previous, exists := old[p.RemoteID]
		p.ID = "sub-" + subscriptionIdentity(doc.Source.URL) + "-" + subscriptionIdentity(p.RemoteID)
		if exists {
			p.ID = previous.ID
		}
		if firstID == "" {
			firstID = p.ID
		}
		p.ResolverProfileID = state.SelectedResolverProfileID
		if len(p.BootstrapResolvers) > 0 {
			p.ResolverProfileID = p.ID + "-dns"
			newResolvers = append(newResolvers, model.ResolverProfile{ID: p.ResolverProfileID, Name: p.Name + " DNS", ResolverText: strings.Join(p.BootstrapResolvers, "\n")})
		}
		if exists && previous.ResolverProfileID != previous.ID+"-dns" {
			p.ResolverProfileID = previous.ResolverProfileID
		}
		next = append(next, p)
	}
	retained := map[string]bool{}
	retained[state.GlobalResolverProfileID] = true
	for _, p := range next {
		retained[p.ResolverProfileID] = true
	}
	newIDs := map[string]bool{}
	for _, r := range newResolvers {
		newIDs[r.ID] = true
	}
	resolvers := []model.ResolverProfile{}
	for _, r := range state.ResolverProfiles {
		if !newIDs[r.ID] && (!removedResolvers[r.ID] || retained[r.ID]) {
			resolvers = append(resolvers, r)
		}
	}
	state.ConnectionProfiles = next
	state.ResolverProfiles = append(resolvers, newResolvers...)
	selectedExists := false
	for _, p := range next {
		if p.ID == state.SelectedConnectionProfileID {
			selectedExists = true
		}
	}
	if selectImported || !selectedExists {
		state.SelectedConnectionProfileID = firstID
	}
	for _, p := range next {
		if p.ID == state.SelectedConnectionProfileID && p.ResolverProfileID != "" {
			state.SelectedResolverProfileID = p.ResolverProfileID
		}
	}
	return state
}
