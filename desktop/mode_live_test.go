package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
	runtimemgr "whitedns-desktop/internal/runtime"
	"whitedns-desktop/internal/storm"
)

// Opt-in operator test. Private subscription contents and engine output never
// enter test logs. Uses an isolated runtime and exactly the specified resolvers.
func TestLiveDesktopModes(t *testing.T) {
	file := os.Getenv("WHITEDNS_LIVE_SUBSCRIPTION_FILE")
	if file == "" {
		t.Skip("private subscription not supplied")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("private subscription file unavailable")
	}
	doc, err := profiles.ParseSubscription("https://test.invalid/sub/private", string(raw), http.Header{}, false, time.Now())
	if err != nil {
		t.Fatal("private subscription could not be parsed")
	}
	engine := os.Getenv("WHITEDNS_LIVE_ENGINE")
	if engine == "" {
		engine = model.ImportTypeSoar
	}
	var connection model.ConnectionProfile
	for _, p := range doc.Profiles {
		if p.ImportType == engine {
			connection = p
			break
		}
	}
	if connection.ImportType == "" {
		t.Fatal("requested engine not present")
	}
	state := model.DefaultAppState()
	connection.ID, connection.ResolverProfileID = "private-live", "private-resolvers"
	if engine == model.ImportTypeSoar {
		options := model.DefaultSoarSettings()
		if connection.SoarSettings != nil {
			options = *connection.SoarSettings
		}
		options.Discovery = false // Tests must use exactly the two specified resolvers.
		connection.SoarSettings = &options
	}
	state.ConnectionProfiles = []model.ConnectionProfile{connection}
	state.SelectedConnectionProfileID = connection.ID
	state.ResolverProfiles = []model.ResolverProfile{{ID: "private-resolvers", Name: "Test resolvers", ResolverSource: "text", ResolverText: "1.1.1.1\n8.8.8.8"}}
	settings := model.DefaultSoarSettingsProfile()
	if engine == model.ImportTypeCottenDNS {
		settings = model.DefaultCottenDNSSettingsProfile()
	}
	if engine == model.ImportTypeMasterDNS {
		settings = model.DefaultSettingsProfile()
	}
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	settings.ListenPort, settings.StormDNSListenPort = port(), port()
	state.SettingsProfiles = []model.SettingsProfile{settings}
	state.SelectedSettingsProfileID = settings.ID
	state.TunnelMode = os.Getenv("WHITEDNS_LIVE_MODE")
	if state.TunnelMode == "" {
		state.TunnelMode = "proxy"
	}
	cfg, err := storm.BuildLaunchConfig(state)
	if err != nil {
		t.Fatal("test configuration failed")
	}
	if cfg.Resolvers != "1.1.1.1\n8.8.8.8" && cfg.Resolvers != "1.1.1.1\n8.8.8.8\n" {
		t.Fatal("unexpected test resolver list")
	}
	manager := runtimemgr.NewManager(runtimemgr.Options{
		RuntimeDir: filepath.Join(t.TempDir(), "runtime"), ClientsDir: filepath.Join(mustWorkingDir(t), "clients"), XrayCoresDir: filepath.Join(mustWorkingDir(t), "cores"),
	}, runtimemgr.Callbacks{OnState: func(status, message string) { t.Logf("state=%s stage=%s", status, message) }})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	start := time.Now()
	err = manager.Start(ctx, cfg)
	cancel()
	defer func() {
		if e := manager.Stop(); e != nil {
			t.Error("runtime cleanup failed")
		}
	}()
	if err != nil {
		t.Fatalf("startup failed after %s (private diagnostics withheld): %T", time.Since(start).Round(time.Millisecond), err)
	}
	t.Logf("mode=%s engine=%s startup=%s", state.TunnelMode, engine, time.Since(start).Round(time.Millisecond))
	runCtx, finish := context.WithTimeout(context.Background(), 3*time.Minute)
	defer finish()
	if state.TunnelMode == "vpn" {
		// A Windows client using the OS proxy, without explicit proxy options.
		script := `$ErrorActionPreference='Stop'; $target=[Uri]'https://www.cloudflare.com/cdn-cgi/trace'; $proxy=[Net.WebRequest]::GetSystemWebProxy(); $actual=$proxy.GetProxy($target); if ($actual.Host -ne '127.0.0.1' -or $actual.Port -ne ` + strconv.Itoa(cfg.PublicListenPort) + `) { throw 'Default system proxy did not update' }; $request=[Net.WebRequest]::Create($target); $request.Proxy=$proxy; $request.Timeout=35000; $response=$request.GetResponse(); try { if ([int]$response.StatusCode -ne 200) { throw 'System proxy request failed' }; 'Windows default proxy HTTPS passed' } finally { $response.Close() }`
		checkCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
		output, e := exec.CommandContext(checkCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		stop()
		if e != nil {
			t.Error("Windows default proxy request failed (private diagnostics withheld)")
		} else {
			t.Log(string(output))
		}
	}
	protocols := []string{"http", "socks5"}
	if state.TunnelMode == "tun" {
		protocols = append(protocols, "tun")
	}
	for _, protocol := range protocols {
		endpoint, _ := url.Parse(protocol + "://" + net.JoinHostPort(cfg.PublicListenIP, strconv.Itoa(cfg.PublicListenPort)))
		transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSHandshakeTimeout: 25 * time.Second, ForceAttemptHTTP2: true}
		if protocol == "tun" {
			transport.Proxy = nil
		}
		client := &http.Client{Transport: transport, Timeout: 35 * time.Second}
		for _, target := range []struct{ name, address string }{
			{"exit", "https://api.ipify.org"}, {"web", "https://www.cloudflare.com/cdn-cgi/trace"}, {"video-page", "https://www.youtube.com/"},
		} {
			began := time.Now()
			req, _ := http.NewRequestWithContext(runCtx, http.MethodGet, target.address, nil)
			resp, e := client.Do(req)
			if e != nil {
				t.Errorf("%s %s failed after %s (%T)", protocol, target.name, time.Since(began).Round(time.Millisecond), e)
				continue
			}
			n, e := io.Copy(io.Discard, io.LimitReader(resp.Body, 512<<10))
			resp.Body.Close()
			t.Logf("%s %s status=%d bytes=%d elapsed=%s complete=%t", protocol, target.name, resp.StatusCode, n, time.Since(began).Round(time.Millisecond), e == nil)
			if e != nil || resp.StatusCode != 200 {
				t.Errorf("%s %s did not complete", protocol, target.name)
			}
		}
		transport.CloseIdleConnections()
	}
}

func mustWorkingDir(t *testing.T) string {
	t.Helper()
	p, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	return p
}
