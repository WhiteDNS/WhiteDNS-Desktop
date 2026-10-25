package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"whitedns-desktop/internal/model"
)

func TestParseCloudflareTrace(t *testing.T) {
	ip, countryCode := parseCloudflareTrace([]byte("fl=abc\nip=203.0.113.10\nloc=de\nwarp=off\n"))
	if ip != "203.0.113.10" {
		t.Fatalf("unexpected IP: %q", ip)
	}
	if countryCode != "DE" {
		t.Fatalf("unexpected country code: %q", countryCode)
	}
}

func TestRuntimeSOCKSProxyAddressFallsBackToLocalhost(t *testing.T) {
	address, err := runtimeSOCKSProxyAddress(model.RuntimeStatus{
		Status:     model.RuntimeConnected,
		ListenIP:   "0.0.0.0",
		ListenPort: 10886,
	})
	if err != nil {
		t.Fatal(err)
	}
	if address != "127.0.0.1:10886" {
		t.Fatalf("unexpected proxy address: %q", address)
	}
}

func TestActiveSOCKSProxyDoesNotUseMasterDNSAuthForV2RayRuntime(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[1].SOCKS5Authentication = true
	app.state.SettingsProfiles[1].SOCKSUsername = "user"
	app.state.SettingsProfiles[1].SOCKSPassword = "pass"
	app.state.V2RayProfiles = []model.V2RayProfile{{ID: "v2ray-1", Name: "V2Ray"}}
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: "v2ray-1",
		ListenIP:           "127.0.0.1",
		ListenPort:         10888,
	}

	address, auth, err := app.activeSOCKS5Proxy()
	if err != nil {
		t.Fatal(err)
	}
	if address != "127.0.0.1:10888" {
		t.Fatalf("unexpected proxy address: %q", address)
	}
	if auth != nil {
		t.Fatalf("V2Ray proxy should not inherit MasterDNS SOCKS auth, got %#v", auth)
	}
}

func TestActiveSOCKSProxyUsesMasterDNSAuthForMasterDNSRuntime(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[1].SOCKS5Authentication = true
	app.state.SettingsProfiles[1].SOCKSUsername = "user"
	app.state.SettingsProfiles[1].SOCKSPassword = "pass"
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         10886,
	}

	_, auth, err := app.activeSOCKS5Proxy()
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("expected MasterDNS SOCKS auth, got %#v", auth)
	}
}

func TestActiveProxyConfigUsesHTTPWhenRuntimeRequestsHTTP(t *testing.T) {
	app := &App{state: model.DefaultAppState()}
	app.state.SettingsProfiles[1].SOCKS5Authentication = true
	app.state.SettingsProfiles[1].SOCKSUsername = "user"
	app.state.SettingsProfiles[1].SOCKSPassword = "pass"
	app.state.Runtime = model.RuntimeStatus{
		Status:             model.RuntimeConnected,
		ActiveConnectionID: model.DefaultConnectionProfileID,
		ListenIP:           "127.0.0.1",
		ListenPort:         10886,
		ProxyProtocol:      "http",
	}

	cfg, err := app.activeProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "http" || cfg.Address != "127.0.0.1:10886" {
		t.Fatalf("unexpected proxy config: %#v", cfg)
	}
	if cfg.Auth == nil || cfg.Auth.User != "user" || cfg.Auth.Password != "pass" {
		t.Fatalf("expected HTTP proxy auth, got %#v", cfg.Auth)
	}
}

func TestProxyCountryCacheAllowsRetryAfterFailure(t *testing.T) {
	app := &App{}
	proxyAddress := "127.0.0.1:10886"
	expected := model.ProxyCountryLookupResult{
		OK:          true,
		IP:          "203.0.113.10",
		CountryCode: "DE",
		Proxy:       proxyAddress,
	}

	app.storeProxyCountry(proxyAddress, expected, nil)
	got, ok := app.cachedProxyCountry(proxyAddress)
	if !ok {
		t.Fatal("expected cached success")
	}
	if got != expected {
		t.Fatalf("unexpected cached result: %#v", got)
	}

	app.storeProxyCountry(proxyAddress, model.ProxyCountryLookupResult{Proxy: proxyAddress}, errors.New("lookup failed"))
	if got, ok = app.cachedProxyCountry(proxyAddress); ok {
		t.Fatalf("failed lookup must allow a fresh attempt, got %#v", got)
	}
	app.storeProxyCountry(proxyAddress, model.ProxyCountryLookupResult{}, nil)
	if _, ok := app.cachedProxyCountry(proxyAddress); ok {
		t.Fatal("unsuccessful result must not be cached")
	}
	app.storeProxyCountry(proxyAddress, expected, nil)
	if got, ok = app.cachedProxyCountry(proxyAddress); !ok || got != expected {
		t.Fatal("successful retry must replace the failure")
	}

	app.clearProxyCountryCache()
	if _, ok := app.cachedProxyCountry(proxyAddress); ok {
		t.Fatal("expected cache to be cleared")
	}
}

func TestCountryClientDoesNotFallBackToDirectWhenProxyFails(t *testing.T) {
	var directRequests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directRequests.Add(1)
		_, _ = w.Write([]byte("ip=203.0.113.10\nloc=IR\n"))
	}))
	defer origin.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	for _, protocol := range []string{"socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			client, err := httpClientThroughProxy(runtimeProxyConfig{Address: address, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer closeHTTPClientIdleConnections(client)
			resp, err := client.Get(origin.URL)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatal("expected failed proxy request")
			}
			if directRequests.Load() != 0 {
				t.Fatal("country request bypassed the proxy")
			}
		})
	}
}
