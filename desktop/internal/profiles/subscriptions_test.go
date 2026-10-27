package profiles

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"whitedns-desktop/internal/model"
)

func soarLink(t *testing.T, id string, key byte) string {
	t.Helper()
	p := model.ConnectionProfile{Name: "Soar account", ImportType: model.ImportTypeSoar, Domain: "user.soar.example.org", EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{key}, 32)), RemoteID: id, BootstrapResolvers: []string{"1.1.1.1", "8.8.8.8"}}
	options := model.DefaultSoarSettings()
	options.Country = ""
	p.SoarSettings = &options
	link, err := ExportConnectionProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func TestSoarProfileImportExportAndPinnedSettings(t *testing.T) {
	link := soarLink(t, "account", 7)
	imported, err := ParseConnectionProfileImports(link, "dns", model.ImportTypeMasterDNS)
	if err != nil {
		t.Fatal(err)
	}
	p := imported[0]
	if p.ImportType != model.ImportTypeSoar || p.SoarSettings.Country != "" || p.SoarSettings.MaxQName != 253 || p.RemoteID != "account" || len(p.BootstrapResolvers) != 2 {
		t.Fatalf("Soar profile was altered: %#v", p)
	}
	again, err := ExportConnectionProfile(p)
	if err != nil || again != link {
		t.Fatal("Soar profile round trip changed", err)
	}
	// Changing the profile's engine choice must never parse a Soar public key as MasterDNS encryption.
	bad := strings.Replace(link, "soar://", "masterdns://", 1)
	if _, err := ParseConnectionProfileImports(bad, "", ""); err == nil {
		t.Fatal("accepted public key as MasterDNS encryption key")
	}
}

func TestSubscriptionRefreshRetainsPinnedResolverFromRemovedAccount(t *testing.T) {
	state := model.DefaultAppState()
	state.GlobalResolverProfileID = "old-account-dns"
	state.ResolverProfiles = append(state.ResolverProfiles, model.ResolverProfile{ID: "old-account-dns", ResolverText: "1.1.1.1"})
	state.ConnectionProfiles = append(state.ConnectionProfiles, model.ConnectionProfile{ID: "old-account", ResolverProfileID: "old-account-dns", Subscription: &model.SubscriptionSource{URL: "https://example.org/sub"}})
	doc := SubscriptionDocument{Source: model.SubscriptionSource{URL: "https://example.org/sub"}, Profiles: []model.ConnectionProfile{{RemoteID: "new-account", Name: "Replacement", BootstrapResolvers: []string{"8.8.8.8"}}}}
	next := NormalizeState(ApplySubscription(state, doc, true))
	if next.GlobalResolverProfileID != "old-account-dns" || next.SelectedResolverProfileID != "old-account-dns" {
		t.Fatal("subscription refresh discarded the global resolver")
	}
}

func TestSubscriptionRefreshPreservesPreferencesAndPersists(t *testing.T) {
	address := "https://panel.example.org/sub/private"
	headers := http.Header{"Subscription-Userinfo": []string{"upload=12; download=34; total=10737418240; expire=2000000000"}, "Profile-Update-Interval": []string{"12"}}
	doc, err := ParseSubscription(address, base64.StdEncoding.EncodeToString([]byte(soarLink(t, "account", 7)+"\n")), headers, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state := model.DefaultAppState()
	manual := state.ConnectionProfiles[0]
	first := ApplySubscription(state, doc, true)
	id := first.SelectedConnectionProfileID
	first.ResolverProfiles = append(first.ResolverProfiles, model.ResolverProfile{ID: "personal", Name: "Personal DNS", ResolverText: "9.9.9.9"})
	for i := range first.ConnectionProfiles {
		if first.ConnectionProfiles[i].ID == id {
			first.ConnectionProfiles[i].ResolverProfileID = "personal"
		}
	}
	secondDoc, err := ParseSubscription(address, soarLink(t, "account", 8), headers, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next := ApplySubscription(first, secondDoc, false)
	if len(next.ConnectionProfiles) != 2 || next.SelectedConnectionProfileID != id || next.SelectedResolverProfileID != "personal" {
		t.Fatal("refresh duplicated profiles or lost preferences")
	}
	if !reflect.DeepEqual(next.ConnectionProfiles[0], manual) {
		t.Fatal("manual profile changed")
	}
	sub := next.ConnectionProfiles[1].Subscription
	if sub.Total != 10737418240 || sub.ExpiresAt != 2000000000000 || sub.Upload != 12 || sub.Download != 34 {
		t.Fatal("invalid metadata", sub)
	}
	store := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err := store.Save(next); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ConnectionProfiles) != len(next.ConnectionProfiles) || !reflect.DeepEqual(loaded.ConnectionProfiles[1], next.ConnectionProfiles[1]) {
		t.Fatal("subscription did not persist")
	}
	link, err := ExportConnectionProfile(loaded.ConnectionProfiles[1])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decodeStormDNSProfile(strings.SplitN(link, "://", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private") || strings.Contains(string(raw), "subscription") {
		t.Fatal("export leaked subscription credentials")
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionRejectsPartialDuplicateAndOversizedResponses(t *testing.T) {
	link := soarLink(t, "account", 7)
	for _, body := range []string{"", "<html>Error</html>", link + "\nhttps://elsewhere.example/", link + "\n" + link, strings.Repeat("x", maxSubscriptionBytes+1)} {
		if _, err := ParseSubscription("https://example.org/sub/x", body, nil, false, time.Now()); err == nil {
			t.Fatal("invalid subscription accepted")
		}
	}
}

func TestSubscriptionHTTPConsentRedirectsAndFailures(t *testing.T) {
	link := soarLink(t, "account", 7)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Profile-Update-Interval", "12")
			_, _ = w.Write([]byte(link))
		case "/redirect":
			http.Redirect(w, r, "/ok", 302)
		case "/loop":
			http.Redirect(w, r, "/loop", 302)
		case "/revoked":
			w.WriteHeader(404)
		case "/inactive":
			w.WriteHeader(403)
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", maxSubscriptionBytes+1)))
		}
	}))
	defer server.Close()
	if _, err := FetchSubscription(context.Background(), server.URL+"/ok", false); err == nil {
		t.Fatal("HTTP without consent accepted")
	}
	for _, path := range []string{"/ok", "/redirect"} {
		if doc, err := FetchSubscription(context.Background(), server.URL+path, true); err != nil || len(doc.Profiles) != 1 {
			t.Fatal("fetch failed", err)
		}
	}
	for _, path := range []string{"/loop", "/revoked", "/inactive", "/large"} {
		_, err := FetchSubscription(context.Background(), server.URL+path, true)
		if err == nil || strings.Contains(err.Error(), server.URL) {
			t.Fatal("invalid response accepted or URL leaked", err)
		}
	}
}
