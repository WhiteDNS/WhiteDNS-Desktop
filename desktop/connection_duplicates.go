package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	"whitedns-desktop/internal/resolver"
)

type connectionDuplicateIndex struct {
	resolvers map[string]model.ResolverProfile
	managed   map[string]string
}

func newConnectionDuplicateIndex(state model.AppState) *connectionDuplicateIndex {
	index := &connectionDuplicateIndex{resolvers: map[string]model.ResolverProfile{}, managed: map[string]string{}}
	for _, profile := range state.ResolverProfiles {
		index.resolvers[profile.ID] = profile
	}
	return index
}

func (index *connectionDuplicateIndex) key(profile model.ConnectionProfile, importing bool) string {
	if !profiles.IsExportableConnectionProfile(profile) {
		return ""
	}
	profile = model.NormalizeConnectionProfileDomains(profile)
	profile.ImportType = model.NormalizeImportType(profile.ImportType)
	resolverKey := "profile:" + strings.TrimSpace(profile.ResolverProfileID)
	if profile.ImportType == model.ImportTypeSoar {
		if importing && len(profile.BootstrapResolvers) > 0 {
			resolverKey = "managed:" + resolver.ValidateText(strings.Join(profile.BootstrapResolvers, "\n")).NormalizedText
		} else if profile.ID != "" && profile.ResolverProfileID == profile.ID+"-dns" {
			var ok bool
			resolverKey, ok = index.managed[profile.ResolverProfileID]
			if !ok {
				value, exists := index.resolvers[profile.ResolverProfileID]
				if !exists {
					return ""
				}
				page, err := profiles.ReadResolverPreviewPage(value, 0, profiles.MaxResolverPreviewLimit)
				if err != nil || page.HasMore || len(page.Resolvers) == 0 {
					return "" // Never remove profiles whose effective resolvers cannot be compared.
				}
				resolverKey = "managed:" + strings.Join(page.Resolvers, "\n")
				index.managed[profile.ResolverProfileID] = resolverKey
			}
		}
		if profile.SoarSettings == nil {
			defaults := model.DefaultSoarSettings()
			profile.SoarSettings = &defaults
		}
		profile.EncryptionMethod = 0
	} else {
		profile.SoarSettings = nil
	}
	// Names and local IDs do not affect a connection. Source/account ownership
	// does: identical endpoints from different subscriptions remain independent.
	if profile.Subscription != nil {
		profile.Subscription = &model.SubscriptionSource{URL: profile.Subscription.URL, RemoteID: profile.Subscription.RemoteID}
	}
	profile.ID, profile.Name = "", ""
	profile.ResolverProfileID = resolverKey
	profile.EncryptionKey = strings.TrimSpace(profile.EncryptionKey)
	profile.BootstrapResolvers = nil // The effective resolver identity is included above.
	raw, err := json.Marshal(profile)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (a *App) RemoveDuplicateConnectionProfiles() (model.ConnectionDeduplicationResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	index := newConnectionDuplicateIndex(a.state)
	protected := func(profile model.ConnectionProfile) bool {
		return profile.ID == model.DefaultConnectionProfileID || profile.ID == a.state.SelectedConnectionProfileID || profile.ID == a.state.Runtime.ActiveConnectionID
	}
	seen := map[string]bool{}
	for _, profile := range a.state.ConnectionProfiles {
		if protected(profile) {
			if key := index.key(profile, false); key != "" {
				seen[key] = true
			}
		}
	}
	next := a.state
	next.ConnectionProfiles = make([]model.ConnectionProfile, 0, len(a.state.ConnectionProfiles))
	removedResolvers := map[string]bool{}
	removed := 0
	for _, profile := range a.state.ConnectionProfiles {
		key := index.key(profile, false)
		if key != "" && seen[key] && !protected(profile) {
			removed++
			if profile.ImportType == model.ImportTypeSoar && profile.ResolverProfileID == profile.ID+"-dns" {
				removedResolvers[profile.ResolverProfileID] = true
			}
			continue
		}
		if key != "" {
			seen[key] = true
		}
		next.ConnectionProfiles = append(next.ConnectionProfiles, profile)
	}
	if removed == 0 {
		return model.ConnectionDeduplicationResult{State: a.state}, nil
	}
	// Keep any managed resolver still referenced by a remaining profile or selection.
	for _, profile := range next.ConnectionProfiles {
		delete(removedResolvers, profile.ResolverProfileID)
	}
	delete(removedResolvers, next.SelectedResolverProfileID)
	next.ResolverProfiles = make([]model.ResolverProfile, 0, len(a.state.ResolverProfiles))
	for _, profile := range a.state.ResolverProfiles {
		if !removedResolvers[profile.ID] {
			next.ResolverProfiles = append(next.ResolverProfiles, profile)
		}
	}
	previous := a.state
	a.state = next
	saved, err := a.saveLocked()
	if err != nil {
		a.state = previous
		return model.ConnectionDeduplicationResult{State: previous}, err
	}
	return model.ConnectionDeduplicationResult{State: saved, Removed: removed}, nil
}
