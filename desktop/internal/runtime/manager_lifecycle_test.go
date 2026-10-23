package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/storm"
)

// Disconnect must cancel validation and finish cleanup before it returns.
func TestManagerStopDuringXrayValidationDoesNotLeaveProxy(t *testing.T) {
	dir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, dir)
	gate := filepath.Join(dir, "validation-started")
	release := filepath.Join(dir, "validation-release")
	source := strings.Replace(fakeXraySource, "\"os/signal\"", "\"os/signal\"\n\"time\"", 1)
	source = strings.Replace(source, "if testOnly {", fmt.Sprintf(`if testOnly {
        if err := os.WriteFile(%q, []byte("waiting"), 0600); err != nil { panic(err) }
        for { if _, err := os.Stat(%q); err == nil { break }; time.Sleep(10*time.Millisecond) }
    `, gate, release), 1)
	src := filepath.Join(dir, "slow_xray.go")
	binary := filepath.Join(dir, testExecutableName("slow-xray"))
	if err := os.WriteFile(src, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", binary, src).CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	runner := newFakeSystemProxyRunner()
	runner.seedGNOME()
	runner.gsettings["org.gnome.system.proxy|mode"] = "'none'"
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME")
	internalPort, publicPort := freePort(t), freePort(t)
	m := NewManager(Options{RuntimeDir: filepath.Join(dir, "runtime"), BinaryPath: helper, XrayBinaryPath: binary, StartTimeout: time.Second, StopTimeout: time.Second, SystemProxyPlatform: "linux", SystemProxyRunner: runner.run}, Callbacks{})
	cfg := storm.LaunchConfig{
		Settings:          model.SettingsProfile{ListenIP: "127.0.0.1", ListenPort: publicPort},
		MasterDNSSettings: model.SettingsProfile{ListenIP: "127.0.0.1", ListenPort: internalPort},
		SetSystemProxy:    true, CoreEnabled: true, CoreProtocol: "socks", PublicListenIP: "127.0.0.1", PublicListenPort: publicPort,
		CoreConfig: fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		Resolvers:  "192.0.2.53\n",
	}
	finished := make(chan error, 1)
	go func() { finished <- m.Start(context.Background(), cfg) }()
	waitForFile(t, gate)
	m.mu.Lock()
	active := m.active
	m.mu.Unlock()
	if active == nil {
		t.Fatal("runtime disappeared before test stop")
	}
	defer func() {
		if active.xrayCmd != nil && active.xrayCmd.Process != nil {
			_ = active.xrayCmd.Process.Kill()
			if active.xrayDone != nil {
				select {
				case <-active.xrayDone:
				case <-time.After(3 * time.Second):
				}
			}
		}
		_ = m.Stop()
		restoreSystemProxyGuardWithLog(active.systemProxyGuard, nil)
	}()
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		t.Logf("Start result after Stop: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not finish")
	}
	if mode := strings.Trim(runner.gsettings["org.gnome.system.proxy|mode"], "'\""); mode != "none" {
		t.Fatalf("system proxy left enabled after Stop: %s", mode)
	}
	if m.IsRunning() {
		t.Fatal("runtime still active after Stop")
	}
	if active.xrayCmd != nil {
		t.Fatal("xray started after validation was cancelled")
	}
	files, err := os.ReadDir(m.RuntimeDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".wd-") {
			t.Fatalf("launch resource left after Stop: %s", file.Name())
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort), 100*time.Millisecond)
		if err == nil {
			c.Close()
			t.Fatalf("Stop returned, Manager.IsRunning=%t, but proxy still listens on %d", m.IsRunning(), publicPort)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The cancelled validation must not poison the next connection.
	if err := m.Start(context.Background(), cfg); err != nil {
		t.Fatalf("reconnect after cancellation: %v", err)
	}
	if !m.IsRunning() {
		t.Fatal("reconnected runtime is not active")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if mode := strings.Trim(runner.gsettings["org.gnome.system.proxy|mode"], "'\""); mode != "none" {
		t.Fatalf("system proxy not restored after reconnect: %s", mode)
	}
}

func TestManagerStopWaitsForInFlightProxyApplication(t *testing.T) {
	dir := t.TempDir()
	helper := buildFakeMasterDNSHelper(t, dir)
	xray := buildFakeXrayHelper(t, dir)
	runner := newFakeSystemProxyRunner()
	runner.seedGNOME()
	runner.gsettings["org.gnome.system.proxy|mode"] = "'none'"
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME")
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var gateOnce sync.Once
	proxyRunner := func(ctx context.Context, name string, args ...string) (string, error) {
		result, err := runner.run(ctx, name, args...)
		if name == "gsettings" && len(args) >= 4 && args[0] == "set" &&
			args[1] == "org.gnome.system.proxy" && args[2] == "mode" && strings.Contains(args[3], "manual") {
			gateOnce.Do(func() {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				// Model an OS operation that completes after cancellation.
				<-release
			})
		}
		return result, err
	}
	internalPort, publicPort := freePort(t), freePort(t)
	m := NewManager(Options{RuntimeDir: filepath.Join(dir, "runtime"), BinaryPath: helper,
		XrayBinaryPath: xray, StartTimeout: time.Second, StopTimeout: time.Second,
		SystemProxyPlatform: "linux", SystemProxyRunner: proxyRunner}, Callbacks{})
	cfg := storm.LaunchConfig{
		Settings:          model.SettingsProfile{ListenIP: "127.0.0.1", ListenPort: publicPort},
		MasterDNSSettings: model.SettingsProfile{ListenIP: "127.0.0.1", ListenPort: internalPort},
		SetSystemProxy:    true, CoreEnabled: true, CoreProtocol: "socks",
		PublicListenIP: "127.0.0.1", PublicListenPort: publicPort,
		CoreConfig: fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, publicPort),
		Resolvers:  "192.0.2.53\n",
	}
	started, stopped := make(chan error, 1), make(chan error, 1)
	go func() { started <- m.Start(context.Background(), cfg) }()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = m.Stop()
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("system proxy application did not start")
	}
	go func() { stopped <- m.Stop() }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not cancel startup")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before the in-flight proxy operation completed")
	default:
	}
	close(release)
	select {
	case err := <-started:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("startup result: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not finish after releasing the OS operation")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not finish cleanup")
	}
	if mode := strings.Trim(runner.gsettings["org.gnome.system.proxy|mode"], "'\""); mode != "none" {
		t.Fatalf("system proxy left enabled: %s", mode)
	}
	if m.IsRunning() {
		t.Fatal("runtime left active after cancellation")
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort), 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("proxy listener left active after cancellation")
	}
}
