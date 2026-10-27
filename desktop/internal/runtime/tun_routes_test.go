package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"whitedns-desktop/internal/storm"
)

func TestTunBypassIncludesEveryResolverFamilyAndPort(t *testing.T) {
	cfg := storm.LaunchConfig{Resolvers: "1.1.1.1\n1.1.1.1:5353\n[2606:4700:4700::1111]:5353\n8.8.8.0/24:5353"}
	want := []string{"1.1.1.1/32", "2606:4700:4700::1111/128", "8.8.8.0/24"}
	got, err := tunBypassPrefixes(cfg)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v: %v", got, err)
	}
	file := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(file, []byte(cfg.Resolvers), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = tunBypassPrefixes(storm.LaunchConfig{ResolversPath: file})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("file-backed: %v: %v", got, err)
	}
	for _, text := range []string{"", "127.0.0.1", "::1"} {
		if _, err := tunBypassPrefixes(storm.LaunchConfig{Resolvers: text}); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestTunCleanupRetainsJournalUntilRestorationSucceeds(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	fail := func(context.Context, string, ...string) (string, error) {
		return "permission denied", errors.New("failed")
	}
	if err := restoreTunSnapshot(context.Background(), file, fail); err == nil {
		t.Fatal("expected restore error")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("failed recovery discarded journal")
	}
	ok := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "powershell.exe" || !strings.Contains(args[len(args)-1], "Remove-NetRoute") {
			t.Fatal("unexpected restoration")
		}
		return "", nil
	}
	if err := restoreTunSnapshot(context.Background(), file, ok); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("successful recovery kept journal")
	}
}

func TestWindowsTunScriptsParse(t *testing.T) {
	if !TunModeSupported() {
		t.Skip("Windows PowerShell parser")
	}
	for name, script := range map[string]string{"setup": windowsTunSetup, "restore": windowsTunRestore} {
		file := filepath.Join(t.TempDir(), name+".ps1")
		if err := os.WriteFile(file, []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$errors=$null; $tokens=$null; [System.Management.Automation.Language.Parser]::ParseFile("+psLiteral(file)+",[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { $errors | Out-String | Write-Output; exit 1 }")
		hideConsoleWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s parser: %v: %s", name, err, out)
		}
	}
}

// Shadow every networking cmdlet: these tests never touch an adapter or route.
func TestWindowsTunTransactionWithMockedNetwork(t *testing.T) {
	if !TunModeSupported() {
		t.Skip("Windows PowerShell simulation")
	}
	for _, failAt := range []string{"0", "3"} {
		snapshot := filepath.Join(t.TempDir(), "routes.json")
		setup := windowsTunSetup[strings.Index(windowsTunSetup, "$adapter="):]
		script := `$ErrorActionPreference='Stop'
$global:mockRoutes=@([pscustomobject]@{DestinationPrefix='8.8.8.8/32'; InterfaceIndex=7; NextHop='192.168.1.1'; RouteMetric=42})
$global:created=0
function Get-NetAdapter { [CmdletBinding()]param($Name) [pscustomobject]@{ifIndex=42} }
function Find-NetRoute { [CmdletBinding()]param($RemoteIPAddress) [pscustomobject]@{InterfaceIndex=7; NextHop='192.168.1.1'} }
function Get-NetRoute { [CmdletBinding()]param($DestinationPrefix,$PolicyStore,$InterfaceIndex)
  if ($DestinationPrefix) { $global:mockRoutes | Where-Object { $_.DestinationPrefix -eq $DestinationPrefix } } else { $global:mockRoutes }
}
function New-NetIPAddress { [CmdletBinding()]param($InterfaceIndex,$IPAddress,$PrefixLength,$PolicyStore) }
function Set-NetIPInterface { [CmdletBinding()]param($InterfaceIndex,$AutomaticMetric,$InterfaceMetric) }
function Set-DnsClientServerAddress { [CmdletBinding()]param($InterfaceIndex,$ServerAddresses) }
function New-NetRoute { [CmdletBinding()]param($DestinationPrefix,$InterfaceIndex,$NextHop,$RouteMetric,$PolicyStore)
  $global:created++
  if ($global:failAt -gt 0 -and $global:created -eq $global:failAt) { throw 'injected route failure' }
  $global:mockRoutes+=@([pscustomobject]@{DestinationPrefix=$DestinationPrefix; InterfaceIndex=$InterfaceIndex; NextHop=$NextHop; RouteMetric=$RouteMetric})
}
function Remove-NetRoute { [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject)
  process { $global:mockRoutes=@($global:mockRoutes | Where-Object { -not ($_.DestinationPrefix -eq $InputObject.DestinationPrefix -and $_.InterfaceIndex -eq $InputObject.InterfaceIndex -and $_.NextHop -eq $InputObject.NextHop -and $_.RouteMetric -eq $InputObject.RouteMetric) }) }
}
` + "$global:failAt=" + failAt + "; $snapshotPath=" + psLiteral(snapshot) + "; $device='WhiteDNS Tunnel'; $prefixes=@('1.1.1.1/32','8.8.8.8/32'); $failed=$false; try {\n" + setup + "\n} catch { $failed=$true }; if (($global:failAt -gt 0) -ne $failed) { throw 'unexpected setup result' };\n" + windowsTunRestore + "\nif ($global:mockRoutes.Count -ne 1 -or $global:mockRoutes[0].RouteMetric -ne 42) { throw 'rollback did not preserve the original route' }"
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		hideConsoleWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failure point %s: %v: %s", failAt, err, out)
		}
	}
}
