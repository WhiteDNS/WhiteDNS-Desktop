package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/profiles"
)

func TestSoarScannerProfileValidationAndPorts(t *testing.T) {
	state := model.DefaultAppState()
	p := &state.ConnectionProfiles[0]
	p.ImportType = model.ImportTypeSoar
	p.Domain, p.Domains = "scan.example.org", []string{"scan.example.org"}
	p.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	app := &App{state: state}
	if got, err := app.scannerConnection(p.ID); err != nil || got.ImportType != model.ImportTypeSoar {
		t.Fatalf("Soar scanner rejected: %+v (%v)", got, err)
	}
	app.state.ConnectionProfiles[0].EncryptionKey = "invalid"
	if _, err := app.scannerConnection(p.ID); err == nil {
		t.Fatal("scanner accepted a non-Soar key")
	}
	for raw, expected := range map[string]string{
		"192.0.2.53:5353":     "192.0.2.53:5353",
		"[2001:db8::53]:5353": "[2001:db8::53]:5353",
		"192.0.2.53:53":       "192.0.2.53",
	} {
		got, ok := scannerResolversFromToken(raw)
		if !ok || !reflect.DeepEqual(got, []string{expected}) {
			t.Fatalf("resolver port changed: %q -> %v", raw, got)
		}
	}
	if _, ok := scannerResolversFromToken("192.0.2.53:0"); ok {
		t.Fatal("port zero accepted")
	}
}

func TestScannerCompletionDoesNotOvertakePendingResultEvent(t *testing.T) {
	entered, release, completed, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseEvent := sync.OnceFunc(func() { close(release) })
	defer releaseEvent()
	app := &App{scannerRunID: 1, scannerState: model.ScannerState{Status: model.ScannerRunning, Total: 1}}
	app.emitHook = func(name string, payload any) {
		if name != "scanner:state" {
			return
		}
		state := payload.(model.ScannerState)
		if state.Status == model.ScannerRunning {
			close(entered)
			<-release
		}
		if state.Status == model.ScannerCompleted {
			close(completed)
		}
	}
	go func() {
		app.handleDNSScannerLogLine(1, "WD_SCAN event=valid resolver=192.0.2.53:5353")
		app.finishDNSScannerRun(1, model.ScannerCompleted, "done")
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("result event not emitted")
	}
	select {
	case <-completed:
		t.Fatal("completion overtook a pending result event and can leave the UI running")
	case <-time.After(50 * time.Millisecond):
	}
	releaseEvent()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanner did not finish")
	}
	if app.GetScannerState().Status != model.ScannerCompleted {
		t.Fatal("completion was lost")
	}
}

func TestSoarScannerRunsDedicatedHelperPersistsResultsAndCancels(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "fake_soar.go")
	name := "soar-client-" + goruntime.GOOS + "-" + goruntime.GOARCH
	if goruntime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(dir, name)
	if err := os.WriteFile(source, []byte(fakeSoarScannerSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v %s", err, out)
	}
	t.Setenv("WHITEDNS_CLIENTS_DIR", dir)
	for _, test := range []struct{ mode, status string }{
		{"complete", model.ScannerCompleted}, {"cancel", model.ScannerCancelled}, {"fail", model.ScannerFailed},
	} {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("SCANNER_TEST_MODE", test.mode)
			work := t.TempDir()
			input := filepath.Join(work, "input.resolvers")
			if err := os.WriteFile(input, []byte("192.0.2.53:5353\n198.51.100.53\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			state := model.DefaultAppState()
			profile := &state.ConnectionProfiles[0]
			profile.ImportType = model.ImportTypeSoar
			profile.Domain, profile.Domains = "scan.example.org", []string{"scan.example.org"}
			profile.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			app := &App{
				configDir: work, store: profiles.NewStore(filepath.Join(work, "state.json")), state: state,
				scannerInputPath: input, scannerResultsPath: filepath.Join(work, "results.resolvers"),
				scannerSnapshotPath: filepath.Join(work, "snapshot.json"),
				scannerState:        model.ScannerState{InputFileName: "input.resolvers", Total: 2},
			}
			started, err := app.StartScannerScan(model.ScannerStartRequest{ConnectionProfileID: profile.ID, ScanParallel: 200})
			if err != nil {
				t.Fatal(err)
			}
			if started.Phase != "probing" || started.ScanParallel != 8 {
				t.Fatalf("wrong initial state: %+v", started)
			}
			app.scannerMu.Lock()
			runtimeDir := app.scannerRuntimeDir
			app.scannerMu.Unlock()
			defer app.CancelScannerScan()
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				scan := app.GetScannerState()
				if test.mode == "cancel" && scan.Valid == 1 && scan.Status == model.ScannerRunning {
					if _, err := app.SetScannerPaused(true); err == nil {
						t.Fatal("Soar accepted unsupported pause")
					}
					if _, err := app.CancelScannerScan(); err != nil {
						t.Fatal(err)
					}
				}
				if scan.Status == test.status {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			got := app.GetScannerState()
			if got.Status != test.status || !reflect.DeepEqual(got.ValidResolvers, []string{"192.0.2.53:5353"}) {
				t.Fatalf("wrong final scan: %+v", got)
			}
			if test.mode == "complete" && (got.Completed != 2 || got.Valid != 1 || got.Rejected != 1) {
				t.Fatalf("final progress was lost: %+v", got)
			}
			result, err := app.SaveScannerResolverProfile("Scanned Soar")
			if err != nil || result.Imported != 1 {
				t.Fatalf("save partial results: %+v (%v)", result, err)
			}
			for time.Now().Before(deadline) {
				if _, err := os.Stat(runtimeDir); os.IsNotExist(err) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
				t.Fatalf("private scan runtime not cleaned: %v", err)
			}
			loaded, _, ok := loadPersistedScannerSnapshot(app.scannerSnapshotPath, app.scannerResultsPath)
			if !ok || loaded.Status != test.status || len(loaded.ValidResolvers) != 1 {
				t.Fatalf("resume snapshot lost: %+v", loaded)
			}
		})
	}
}

const fakeSoarScannerSource = `package main
import("encoding/json";"flag";"fmt";"os";"time")
func main(){
 c:=flag.String("config","",""); r:=flag.String("resolvers","",""); scan:=flag.Bool("scan-only",false,""); flag.Parse()
 if !*scan { panic("scan-only required") }
 raw,e:=os.ReadFile(*c); if e!=nil{panic(e)}
 var cfg struct{ Zone string; Key string ` + "`json:\"server_public_key\"`" + `; Soar struct{ Discovery bool; DiscoveryConcurrency int } }
 if e=json.Unmarshal(raw,&cfg);e!=nil{panic("expected Soar JSON, not MasterDNS TOML")}
 if cfg.Zone!="scan.example.org"||cfg.Key==""||cfg.Soar.Discovery||cfg.Soar.DiscoveryConcurrency!=8{panic("wrong Soar settings")}
 input,e:=os.ReadFile(*r);if e!=nil||string(input)!="192.0.2.53:5353\n198.51.100.53\n"{panic("wrong scan input")}
 fmt.Println("WD_SCAN event=valid resolver=192.0.2.53:5353")
 fmt.Println("WD_PROGRESS phase=probing completed=1 total=2 valid=1 rejected=0 percent=50")
 switch os.Getenv("SCANNER_TEST_MODE"){case "cancel":time.Sleep(time.Hour);case "fail":os.Exit(2)}
 fmt.Println("WD_SCAN event=rejected resolver=198.51.100.53")
 fmt.Println("WD_PROGRESS phase=probing completed=2 total=2 valid=1 rejected=1 percent=100")
 fmt.Println("WD_SCAN event=complete total=2 valid=1 rejected=1")
}`
