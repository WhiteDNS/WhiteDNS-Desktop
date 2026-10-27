package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"whitedns-desktop/internal/model"
	"whitedns-desktop/internal/resolver"
	"whitedns-desktop/internal/storm"
)

// The bundled Xray creates a TUN device but does not configure OS routes.
// Route management is currently supported on Windows; never silently report a
// working full-device tunnel on platforms where only the adapter was created.
func TunModeSupported() bool { return goruntime.GOOS == "windows" }

func tunBypassPrefixes(cfg storm.LaunchConfig) ([]string, error) {
	var input io.Reader = strings.NewReader(cfg.Resolvers)
	if cfg.ResolversPath != "" {
		file, err := os.Open(cfg.ResolversPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		input = file
	}
	seen := map[string]bool{}
	prefixes := []string{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		validation := resolver.ValidateText(scanner.Text())
		for _, endpoint := range validation.NormalizedResolvers {
			host := endpoint
			if parsed, _, err := net.SplitHostPort(endpoint); err == nil {
				host = parsed
			}
			var prefix netip.Prefix
			if parsed, err := netip.ParsePrefix(host); err == nil {
				prefix = parsed.Masked()
			} else if addr, err := netip.ParseAddr(host); err == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				return nil, fmt.Errorf("invalid TUN resolver address: %s", endpoint)
			}
			if prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified() {
				return nil, fmt.Errorf("TUN mode requires upstream resolver IPs, not a local DNS forwarder")
			}
			value := prefix.String()
			if !seen[value] {
				seen[value] = true
				prefixes = append(prefixes, value)
			}
			if len(prefixes) > 256 {
				return nil, fmt.Errorf("TUN mode supports up to 256 resolver addresses or ranges; choose a smaller resolver list or use VPN mode")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("TUN mode needs at least one resolver")
	}
	return prefixes, nil
}

func psLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func (m *Manager) checkTunAccess(ctx context.Context, cfg storm.LaunchConfig) error {
	if !cfg.TunEnabled {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := defaultSystemProxyRunner(m.options.SystemProxyRunner)(checkCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsTunPrivilegeCheck)
	if err != nil {
		return fmt.Errorf("TUN mode requires administrator access. Restart WhiteDNS as administrator, or select VPN mode: %w", err)
	}
	return nil
}

func (m *Manager) configureTunRoutes(ctx context.Context, cfg storm.LaunchConfig, active *activeProcess) error {
	if !cfg.TunEnabled {
		return nil
	}
	if !TunModeSupported() {
		return fmt.Errorf("automatic TUN mode is currently supported on Windows; use VPN or Proxy mode on this platform")
	}
	m.state(model.RuntimeConnecting, "Configuring TUN network")
	prefixes, err := tunBypassPrefixes(cfg)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(prefixes)
	active.tunSnapshotFile = filepath.Join(m.options.RuntimeDir, ".wd-"+active.id+".tun-routes.json")
	script := "$ErrorActionPreference='Stop'; $snapshotPath=" + psLiteral(active.tunSnapshotFile) + "; $device=" + psLiteral(model.DefaultV2RayTunInterfaceName()) + "; $prefixes=ConvertFrom-Json " + psLiteral(string(raw)) + ";\n" + windowsTunSetup
	setupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	output, err := defaultSystemProxyRunner(m.options.SystemProxyRunner)(setupCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		m.restoreTunRoutes(active)
		return fmt.Errorf("TUN routing could not start. Run WhiteDNS as administrator and check that another VPN is not active: %w: %s", err, strings.TrimSpace(output))
	}
	m.log("TUN routes applied; upstream DNS resolvers stay on the original network")
	return nil
}

func (m *Manager) restoreTunRoutes(active *activeProcess) {
	if active.tunSnapshotFile == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := restoreTunSnapshot(ctx, active.tunSnapshotFile, m.options.SystemProxyRunner); err != nil {
		m.log(fmt.Sprintf("Runtime cleanup warning: TUN route cleanup will be retried at next launch: %v", err))
	}
}

func restoreTunSnapshot(ctx context.Context, path string, runner SystemProxyCommandRunner) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	script := "$ErrorActionPreference='Stop'; $snapshotPath=" + psLiteral(path) + ";\n" + windowsTunRestore
	output, err := defaultSystemProxyRunner(runner)(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	return os.Remove(path)
}

const windowsTunPrivilegeCheck = `
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator access is required' }
`

const windowsTunSetup = windowsTunPrivilegeCheck + `
$adapter=Get-NetAdapter -Name $device -ErrorAction Stop
$tunIndex=[int]$adapter.ifIndex
$plan=@()
# Resolve every bypass before installing capture routes to avoid feedback loops.
foreach ($prefix in $prefixes) {
  $address=($prefix -split '/')[0]
  $route=Find-NetRoute -RemoteIPAddress $address | Where-Object { $null -ne $_.NextHop } | Select-Object -First 1
  if ($null -eq $route -or $route.InterfaceIndex -eq $tunIndex) { throw "No original upstream route for $prefix" }
  $exists=Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex -and $_.NextHop -eq $route.NextHop }
  if (-not $exists) { $plan+=@{prefix=$prefix; index=[int]$route.InterfaceIndex; gateway=$route.NextHop} }
}
foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
  if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw "Another tunnel already owns $prefix" }
  $gateway=if ($prefix.Contains(':')) { '::' } else { '0.0.0.0' }
  $plan+=@{prefix=$prefix; index=$tunIndex; gateway=$gateway}
}
# Only this process's ephemeral adapter is configured. Existing adapters and
# default routes are never changed, so removing the added routes restores them.
New-NetIPAddress -InterfaceIndex $tunIndex -IPAddress '198.18.0.1' -PrefixLength 30 -PolicyStore ActiveStore | Out-Null
New-NetIPAddress -InterfaceIndex $tunIndex -IPAddress 'fdfe:dcba:9876::1' -PrefixLength 126 -PolicyStore ActiveStore | Out-Null
# Set DNS only on our ephemeral adapter. DNS itself travels through the tunnel
# as HTTPS; upstream encapsulation resolvers keep their physical bypass routes.
Set-NetIPInterface -InterfaceIndex $tunIndex -AutomaticMetric Disabled -InterfaceMetric 1 -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceIndex $tunIndex -ServerAddresses @('198.18.0.2','fdfe:dcba:9876::2') -ErrorAction Stop
$journal=@()
foreach ($item in $plan) {
  $journal+=@($item)
  # Journal before each mutation so crash recovery can finish partial setup.
  $json=ConvertTo-Json -InputObject @($journal) -Depth 4
  $temporary=$snapshotPath+'.tmp'
  [IO.File]::WriteAllText($temporary,$json)
  Move-Item -LiteralPath $temporary -Destination $snapshotPath -Force
  New-NetRoute -DestinationPrefix $item.prefix -InterfaceIndex $item.index -NextHop $item.gateway -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}
foreach ($item in $plan) {
  if (-not (Get-NetRoute -DestinationPrefix $item.prefix -InterfaceIndex $item.index -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $item.gateway })) { throw "TUN route verification failed for $($item.prefix)" }
}
`

const windowsTunRestore = `
[array]$journal=ConvertFrom-Json ([IO.File]::ReadAllText($snapshotPath))
[array]::Reverse($journal)
$existing=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
foreach ($item in $journal) {
  $routes=$existing | Where-Object { $_.DestinationPrefix -eq $item.prefix -and $_.InterfaceIndex -eq $item.index -and $_.NextHop -eq $item.gateway -and $_.RouteMetric -eq 1 }
  foreach ($route in $routes) { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
}
`
