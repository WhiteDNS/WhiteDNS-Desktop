package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/storm"
)

func TestSoarRuntimeUsesDedicatedHelperAndJSONBehindXray(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "soar.go")
	binary := filepath.Join(dir, testExecutableName("soar-client"))
	code := `package main
import("encoding/json";"flag";"fmt";"net";"os")
func main(){c:=flag.String("config","","");r:=flag.String("resolvers","","");flag.Parse();raw,e:=os.ReadFile(*c);if e!=nil{panic(e)};var cfg struct{Listen string};if e=json.Unmarshal(raw,&cfg);e!=nil{panic(e)};if os.Getenv("WHITEDNS_MTU_SCAN_CONTROL_FILE")!=""{panic("MasterDNS control leaked")};rs,e:=os.ReadFile(*r);if e!=nil||string(rs)!="1.1.1.1\n"{panic("resolver payload changed")};ln,e:=net.Listen("tcp",cfg.Listen);if e!=nil{panic(e)};fmt.Println("SOAR_READY authenticated=1 https=1");for{c,e:=ln.Accept();if e!=nil{return};c.Close()}}
`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	xray := buildFakeXrayHelper(t, dir)
	internal, public := freePort(t), freePort(t)
	m := NewManager(Options{RuntimeDir: filepath.Join(dir, "runtime"), SoarBinaryPath: binary, BinaryPath: "must-not-use-master", XrayBinaryPath: xray, StopTimeout: time.Second}, Callbacks{})
	cfg := storm.LaunchConfig{Engine: model.ImportTypeSoar, MasterDNSSettings: model.SettingsProfile{ListenIP: "127.0.0.1", ListenPort: internal}, PublicListenIP: "127.0.0.1", PublicListenPort: public, CoreEnabled: true, CoreConfig: fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d}]}`, public), ClientTOML: fmt.Sprintf(`{"listen":"127.0.0.1:%d"}`, internal), Resolvers: "1.1.1.1\n"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	file := m.active.configFile
	control := m.active.mtuScanControlFile
	m.mu.Unlock()
	if control != "" {
		t.Fatal("created MasterDNS MTU control for Soar")
	}
	if err := m.SetResolverMTUScanPaused(true); err == nil {
		t.Fatal("Soar accepted MasterDNS MTU controls")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("private runtime config not removed")
	}
}

func TestEmbeddedSoarHelperReplacesOldCopyAndNeverFallsBackToMaster(t *testing.T) {
	dir := t.TempDir()
	name := helperPlatformNameForEngine(model.ImportTypeSoar)
	m := NewManager(Options{RuntimeDir: dir, EmbeddedClientsFS: fstest.MapFS{"clients/" + name: {Data: []byte("new-soar"), Mode: 0755}}}, Callbacks{})
	stale := filepath.Join(dir, "helper", name)
	_ = os.MkdirAll(filepath.Dir(stale), 0755)
	_ = os.WriteFile(stale, []byte("old-soar"), 0755)
	path, err := m.resolveBinaryForEngine(context.Background(), model.ImportTypeSoar)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "new-soar" {
		t.Fatal("stale helper reused")
	}
	for _, candidate := range helperNameCandidatesForEngine(model.ImportTypeSoar) {
		if strings.Contains(candidate, "master") {
			t.Fatal("Soar can fall back to MasterDNS")
		}
	}
}
