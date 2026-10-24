# CottenDNS release and update notes — 21 October 2026

CottenDNS now accepts **Normal and CottenMax beta together** using the existing
delegated domain, shared key and server service. Users switch modes in a
compatible client and reconnect. CottenMax remains an opt-in beta.

## Downloads

| Component | Build | Download |
| --- | --- | --- |
| CottenDNS server and terminal client | `v2026.10.21.140901-0a7a241` | [Published packages](https://github.com/WhiteDNS/CottenDNS/releases/tag/v2026.10.21.140901-0a7a241) |
| Windows Desktop x64 | Beta debug, 21 October 2026 | [Download ZIP](https://github.com/WhiteDNS/WhiteDNS-Desktop/actions/runs/39601468697/artifacts/12346273079) |
| Android | Beta debug, 21 October 2026 | [Download APK ZIP](https://github.com/WhiteDNS/WhiteDNS-Android/actions/runs/39604706552/artifacts/12348436491) |
| CottenRouter | `v1.2.21` | [Published packages](https://github.com/TaJirax/CottenRouter/releases/tag/v1.2.21) |

Extract the Desktop ZIP and run the EXE. For Android, extract the ZIP and install
`app-universal-debug.apk`; the archive also contains builds for individual ABIs.
The app downloads are temporary GitHub Actions artifacts and may require GitHub
sign-in. If a link expires, check the corresponding repository's Actions page.
Desktop and Android remain debug beta builds; no stable app release was created.

## Release notes

- **Shared-profile Max mode.** CottenMax is a module inside CottenDNS. It needs
  no second server, delegated domain, configuration file or key exchange.
  The updated server accepts Normal and Max clients simultaneously.
- **UDP and TCP DNS transport.** Max can use independently verified UDP/TCP
  resolver paths for both scanning and live tunnel traffic. `auto` tests both
  paths and uses working ones. This setting selects the DNS transport; it does
  not add SOCKS5 application UDP support to Max.
- **First-response delivery repaired.** Completed DNS replies reach the
  original waiting client as well as the cache. Pending callbacks have bounds,
  timeouts and cleanup, addressing the symptom where only a repeated query
  received the cached answer. Existing clients need the corrected client build.
- **Connection readiness and recovery.** Max reports connected after
  authenticated transfer verification. Working paths retry larger QNAME sizes
  after loss rather than remaining permanently reduced. Failed unauthenticated
  TCP paths back off, and cancelled embedded dial attempts retain cancellation.
- **Updated client interfaces.** Desktop and Android expose Normal/Max mode
  selection, scan progress and working UDP/TCP paths. The terminal TUI shows
  mode, connection phase, resolver counts, transport and Max wire-size details.
- **Independent managed updates.** Router resolves the latest published
  CottenDNS release on every install/update and checks its exact version and
  Normal/Max, UDP/TCP and shared-key capabilities. Candidates are staged before
  replacement, with readiness checks and rollback on failure.
- **Session capacity.** Standalone Normal and Max default to 2,048 sessions;
  Router's optional expanded capacity raises this to at least 4,096. The current
  embedded Cotten runtime defaults to 64 when no limit is supplied. Explicit
  administrator settings and higher custom values are preserved. These ceilings
  do not guarantee a particular concurrent user count.

Max uses the Soar v0.2.3-derived transport, congestion control and lightweight
authenticated encryption. Normal-mode compression/FEC/controller options do not
control Max. Optional encrypted resolver transports and tuning are documented in
[CottenMax options](https://github.com/WhiteDNS/CottenDNS/blob/main/docs/COTTENMAX_OPTIONS.md).

Router keeps **Soar 2.2** as the older standalone option. **WhiteDNS Panel 0.5.1
stays beta only**, on its beta branch and CI artifact. Its Router installation
requires explicit `--panel-beta-bundle` selection; no stable Panel release or
Panel main-branch update is included. Panel account limits are separate from
standalone CottenDNS capacity.

## Update notes

### Router-managed CottenDNS

Use Router's backend updater so the existing integration and private listeners
are preserved:

```bash
sudo cottenrouter update --project cottendns
systemctl status cottendns cottenrouter --no-pager
journalctl -u cottendns -n 60 --no-pager
```

Use Router 1.2.21 for the current TUI and installer checks. Backend updates remain
independent of Router's version: future compatible CottenDNS releases can be
installed with the same command. Do not run the standalone server installer for
a Router-managed backend. Router must retain public UDP/TCP port 53.

Updates preserve existing capacity settings. To opt in to more session
headroom, select **expanded** in Router's CottenDNS capacity field. Higher custom
limits are preserved; quotas and rate limits remain in force.

### Standalone Linux CottenDNS

Keep a backup of the active server binary, `server_config.toml` and
`encrypt_key.txt` outside the installation directory. Download the current
installer and upgrade the existing systemd installation:

```bash
installer=$(mktemp /tmp/cottendns-update.XXXXXX)
curl -fSL https://raw.githubusercontent.com/WhiteDNS/CottenDNS/main/server_linux_install.sh -o "$installer" &&
  sudo bash "$installer" --upgrade
rm -f -- "$installer"
systemctl status cottendns --no-pager
journalctl -u cottendns -n 60 --no-pager
```

The current installer discovers the existing service directory, preserves the
active configuration/key and stores new configuration defaults separately.
Confirm the startup log says **CottenMax available alongside normal CottenDNS**.
Long domains may not fit Max's handshake; use the readiness/configuration checks
before asking clients to switch.

### Desktop, Android and terminal clients

1. Install the matching updated client. Keep the existing CottenDNS profile,
   domain and shared key.
2. Confirm **Normal** connects, then select **CottenMax beta**, save and reconnect.
3. Start with DNS transport **Auto**. Use UDP or TCP separately to compare paths
   if discovery or transfer fails on the current network.
4. For a terminal client, set `TUNNEL_MODE = "cottenmax"` and
   `RESOLVER_TRANSPORT = "auto"` in the existing configuration, then restart.
   Restore `TUNNEL_MODE = "legacy"` and reconnect to return to Normal.

A server-only or Router-only update cannot repair a client that still has the
first-response defect. Existing connections do not change engines in place.

## Verification and beta feedback

Core tests, vet and Linux/WSL race checks passed. Desktop debug CI, Android debug
CI, Router CI, Soar integration and Router release/container builds passed.
The final production smoke test passed **24/24 HTTP transfers** across two
delegated domains, Normal/Max, UDP/TCP/auto and direct/1.1.1.1 resolver paths.
These checks establish the tested paths, not reachability or speed on every ISP.

The app beta branches are `beta/cottenmax-20261021`. Desktop build commit:
`1f9e2235480f93b3e6da698f2d31715c578f1a1e`; Android:
`a0b2e04dbecaaa0bd2f55f1d18b374d633c12fe2`. Both pin core `0f1d6f0`; the later
published core changes affect server defaults, installation and documentation,
with no client/TUI runtime difference.

For beta reports, include the app/build, server version, mode, DNS transport,
device/network, resolver results and sanitized logs. Do not include shared keys
or private profile links. Real-device, mobile-network and long-session feedback
is still needed.
