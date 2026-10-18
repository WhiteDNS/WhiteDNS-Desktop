package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
)

func attachImportedResolvers(state *model.AppState, p *model.ConnectionProfile) {
	if p.ImportType != model.ImportTypeSoar || len(p.BootstrapResolvers) == 0 {
		return
	}
	id := p.ID + "-dns"
	p.ResolverProfileID = id
	state.ResolverProfiles = append(state.ResolverProfiles, model.ResolverProfile{ID: id, Name: p.Name + " DNS", ResolverText: strings.Join(p.BootstrapResolvers, "\n")})
}

// Do not hold the app state lock during network I/O. Apply to the latest state
// after download, and never modify profiles underneath an active connection.
func (a *App) ImportSubscription(address string, allowHTTP bool) (model.AppState, error) {
	a.subscriptionMu.Lock()
	defer a.subscriptionMu.Unlock()
	a.mu.Lock()
	locked := a.connectionSelectionLockedLocked()
	a.mu.Unlock()
	if locked {
		return a.GetAppState(), fmt.Errorf("disconnect before importing subscriptions")
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	doc, err := profiles.FetchSubscription(ctx, address, allowHTTP)
	if err != nil {
		return a.GetAppState(), err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectionSelectionLockedLocked() {
		return a.state, fmt.Errorf("disconnect before changing subscription profiles")
	}
	previous := a.state
	a.state = profiles.ApplySubscription(a.state, doc, true)
	a.selectSettingsForEngineLocked(doc.Profiles[0].ImportType)
	saved, err := a.saveLocked()
	if err != nil {
		a.state = previous
		return a.state, err
	}
	return saved, nil
}

func (a *App) RefreshSubscriptions(onlyDue bool) (model.AppState, error) {
	a.subscriptionMu.Lock()
	defer a.subscriptionMu.Unlock()
	a.mu.Lock()
	if a.connectionSelectionLockedLocked() {
		s := a.state
		a.mu.Unlock()
		return s, fmt.Errorf("disconnect before refreshing subscriptions")
	}
	sources := map[string]model.SubscriptionSource{}
	for _, p := range a.state.ConnectionProfiles {
		if p.Subscription != nil {
			sources[p.Subscription.URL] = *p.Subscription
		}
	}
	a.mu.Unlock()
	failures := 0
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for _, source := range sources {
		if onlyDue && time.Now().UnixMilli()-source.UpdatedAt < int64(max(1, source.IntervalHours))*3600000 {
			continue
		}
		doc, err := profiles.FetchSubscription(ctx, source.URL, source.AllowHTTP)
		if err != nil {
			failures++
			continue
		}
		a.mu.Lock()
		if a.connectionSelectionLockedLocked() {
			a.mu.Unlock()
			return a.GetAppState(), fmt.Errorf("disconnect before refreshing subscriptions")
		}
		exists := false
		for _, p := range a.state.ConnectionProfiles {
			if p.Subscription != nil && p.Subscription.URL == source.URL {
				exists = true
			}
		}
		if exists {
			previous := a.state
			a.state = profiles.ApplySubscription(a.state, doc, false)
			for _, p := range a.state.ConnectionProfiles {
				if p.ID == a.state.SelectedConnectionProfileID {
					a.selectSettingsForEngineLocked(p.ImportType)
					break
				}
			}
			if _, err := a.saveLocked(); err != nil {
				a.state = previous
				failures++
			}
		}
		a.mu.Unlock()
	}
	if failures > 0 {
		return a.GetAppState(), fmt.Errorf("%d subscription(s) could not refresh; their saved profiles were retained", failures)
	}
	return a.GetAppState(), nil
}
