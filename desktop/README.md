# WhiteDNS Desktop

Wails v2 desktop client for running the MasterDNS/StormDNS, CottenDNS or Soar Go client behind a managed Xray local proxy. Xray is an internal traffic bridge, not a DNS tunnel engine or a replacement for the selected engine.

## Release notes

- [Persian quick download guide](./DOWNLOAD_GUIDE_FA.md)
- [Persian release note for users](./RELEASE_NOTES_FA.md)
- [Persian Telegram announcement draft](./TELEGRAM_ANNOUNCEMENT_FA.md)

## Windows downloads

For normal 64-bit Windows 10/11 PCs, download the `Windows x64` package. This is the correct build for Intel and AMD processors.

Do not download `Windows ARM64` unless the device is specifically a Windows-on-ARM PC, such as a Snapdragon device or Surface Pro X. The ARM64 executable will show "This app can't run on your PC" on ordinary Intel/AMD 64-bit Windows.

## macOS downloads

For Apple Silicon Macs, download the `macos-arm64.zip` release asset. For Intel Macs, download `macos-amd64.zip`.

Use the ZIP from the GitHub Release assets. Do not distribute a raw `.app` folder from GitHub Actions artifacts, because artifact downloads can strip executable permissions and macOS will show "The application can't be opened."

## Development

```bash
make deps
make test
make dev
```

The app extracts engine-specific runtime binaries from `clients/masterdns-client-<goos>-<goarch>`, `clients/cottendns-client-<goos>-<goarch>`, and `cores/xray-<goos>-<goarch>`. Package targets reset `clients/` and `cores/`, build both DNS helpers plus the Xray core for the target platform, and embed them into the app binary. Release packages do not need separate `clients/` or `cores/` folders beside the app.

CottenDNS is vendored at the repository root from the immutable commit recorded in `vendor/cottendns.json`. The desktop option schema is generated from the pinned CottenDNS client templates. Settings profiles store sparse overrides so native `default`, `speed`, `survival`, and `tcp-survival` preset behavior remains intact. Domain, encryption, and resolver data continue to come from the dedicated connection and resolver profiles.

Resolver profiles accept IPv4, IPv6, bracketed IPv6 ports, and bounded IPv4/IPv6 CIDRs. CottenDNS defaults to IPv4 with a warm IPv6 fallback; `RESOLVER_IP_MODE` in the CottenDNS option editor can select `dual`, `ipv4`, or `ipv6` explicitly. If you keep client binaries outside the app directory, set `WHITEDNS_CLIENTS_DIR=/absolute/path/to/clients` before launching the app.

The public proxy is always served by Xray-core pinned to `v26.3.27`. During packaging, `make` reuses a matching core from `.cache/xray/` or `cores/`; if missing, it downloads the requested XTLS release asset. For development overrides, set `WHITEDNS_XRAY_BIN=/absolute/path/to/xray`.

Runtime profile data is stored under the platform user config directory in `WhiteDNS Desktop/state.json`.

The dashboard's **Quick setup** controls apply across connection and settings profiles:

- **Proxy mode** exposes the local proxy for apps configured to use it.
- **VPN mode** automatically configures the operating system's proxy after the local listener is ready. Apps must support the system proxy. On Windows, the app refreshes browser proxy settings and temporarily replaces PAC settings and old exclusions; the previous values are restored on disconnect.
- **TUN mode** routes device traffic through the DNS tunnel on Windows. Clicking Connect automatically requests Windows administrator approval when needed. On approval, WhiteDNS reopens with the same saved profiles and selections and resumes that connection once; cancelling UAC keeps the existing window open and disconnected. Already elevated instances do not prompt again. It supports up to 256 upstream resolver IPs or CIDR ranges. Upstream resolver routes bypass the TUN to prevent routing loops. The ephemeral adapter uses cached DNS over HTTPS through the selected tunnel. Soar supports TCP only: DNS is translated to TCP, other UDP (including QUIC) is blocked, and browsers use HTTPS over TCP. Soar auto-discovery is disabled for TUN because only selected resolvers have bypass routes; the saved discovery preference remains available in Proxy/VPN modes. Routes added by the app are removed on disconnect; a journal allows cleanup after an interrupted session. Automatic TUN routing is disabled on other operating systems.
- **Shared resolvers** saves pasted IP addresses to the resolver list and uses them for all existing and future connections, including subscription imports. Turning off **Use for all connections** restores each connection's saved resolver assignment. Mode and resolver changes are locked during a connection or parallel test and apply on the next connection.

Existing installations keep their settings profile's proxy behavior until a mode is selected in Quick setup.

Quick setup also imports resolver files directly, keeps a managed copy even if the original file moves, and shows the filename, valid entry count, skipped invalid entries and an expandable preview. Cancelled or rejected imports keep the previous selection. The dashboard's tunnel-latency chart probes through the active local proxy every five seconds, displays an 80-second window and stops on disconnect. `LOSS` is the percentage of failed application-level probes, not an ICMP packet-loss measurement. No samples are generated while disconnected; slow probes do not overlap and late responses from old sessions are ignored.

Chart probes reuse a session-scoped proxy/TLS connection, allow up to 20 seconds per request, and cancel pending work when the connection ends. Missed checks remain visible as gaps and red markers; the `Retrying` indicator exposes the failure reason on hover or keyboard focus. Connection details are opened from the labelled button next to the connection status.

`make build-mac` and `make build-windows` can run from macOS. `make all` builds Linux packages from non-Linux hosts through Docker. If Docker is not available, run `make build-linux` on a Linux host or use the `Desktop Release Builds` GitHub Actions workflow.

`make all` builds stripped/minified release packages for the desktop matrix. The default matrix stages macOS amd64/arm64 separately, Windows amd64/arm64, and Linux amd64/arm64. Override `ALL_MACOS_PLATFORMS`, `ALL_WINDOWS_PLATFORMS`, or `ALL_LINUX_PLATFORMS` to change the matrix.

Linux release jobs also publish native distro packages and an amd64 AppImage. Linux x64 users who want the least package-manager friction should try the `.AppImage` first. Debian and Ubuntu users can use the `.deb` package, RPM-based distributions can use the `.rpm` package, and the `.tar.gz` archive remains available as a portable fallback that still needs GTK 3 plus the matching WebKitGTK runtime from the distribution.

For newer RPM-based distributions that provide WebKitGTK 4.1 instead of 4.0, use the `linux-amd64-webkit41.rpm` asset. The older WebKitGTK 4.0 Linux assets remain for older distributions.

Pass the release version with `VERSION=1.0.0`, or use the GNU-make-safe flag form `make all -- --version 1.0.0`. Release staging writes platform folders under `build/releases/all/` and versioned compressed assets such as `WhiteDNS-Desktop-1.2.1-macos-arm64.zip`.

For Ubuntu 24.04+ Linux builds, pass `LINUX_GO_TAGS=webkit2_41` and install `libwebkit2gtk-4.1-dev`. Ubuntu 22.04 builds can use the default WebKitGTK 4.0 dependency. To build native Linux packages locally, install `dpkg-deb` and `rpmbuild`, then run `make package-linux-distros`. To include an amd64 AppImage, also include `appimage` in `LINUX_PACKAGE_FORMATS`; the packaging script downloads linuxdeploy unless `LINUXDEPLOY_BIN` points to an executable local copy.

Useful targets:

```bash
make masterdns-client
make cottendns-client
make xray-core
make build
make package
make build-mac
make build-windows
make build-linux
make package-linux-distros
make package-linux-all-docker
make build-all
make all
make clean
```
