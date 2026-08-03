<p align="center">
  <img src="assets/cottendns.png" alt="CottenDNS logo" width="150">
</p>

<h1 align="center">CottenDNS</h1>

<p align="center">
  <strong>A speed-first DNS tunnel for censored, lossy, and unstable networks.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-16a34a?style=flat-square"></a>
  <a href="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml"><img alt="Build and release" src="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml/badge.svg"></a>
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/TaJirax/cottenDNS?style=flat-square"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="DNS transports" src="https://img.shields.io/badge/DNS-UDP%20%7C%20TCP%20%7C%20DoT%20%7C%20DoH-4f46e5?style=flat-square">
</p>

<h3 align="center">🌐 Choose your language</h3>

<p align="center">
  <a href="README.MD">English</a> ·
  <a href="README_FA.MD">فارسی</a> ·
  <a href="README_RU.MD">Русский</a> ·
  <a href="README_ZH.MD">简体中文</a> ·
  <a href="README_ES.MD">Español</a>
</p>

<p align="center">
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest">Download</a> ·
  <a href="docs/ENGINEERING_CHANGES.md">Engineering notes</a> ·
  <a href="CONFIG_PRESETS.md">Configuration presets</a> ·
  <a href="https://t.me/whitedns">Telegram</a>
</p>

> [!IMPORTANT]
> CottenDNS exists for networks where ordinary VPNs and proxies are blocked but a usable DNS path remains. DNS tunneling is inherently slower than a normal VPN. The goal is maximum usable speed and continuity under censorship—not unrealistic clean-network throughput claims.

## Start here

| I want to… | Go to |
| --- | --- |
| Deploy a new tunnel | [Complete setup guide](#complete-setup-guide) |
| Run the server with Docker | [Docker server installation](#docker-server-installation) |
| Understand the adaptive transport system | [Automatic behavior](#automatic-behavior) |
| Pick a speed or survival profile | [Choose a profile](#choose-a-profile) |
| Check server load and tunnel health | [Monitoring](#monitoring) |
| Embed the engine in Android | [Android and engine embedding](#android-and-engine-embedding) |
| Diagnose a failed or slow connection | [Troubleshooting](#troubleshooting) |
| Review every configuration option | [Client](client_config.toml.simple) and [server](server_config.toml.simple) samples |

### At a glance

| Component | Purpose | Normal default |
| --- | --- | --- |
| Server | Authoritative DNS endpoint and tunnel egress | Linux VPS, UDP + TCP port 53 |
| Client | Resolver scanning, path selection, reliability, local proxy | SOCKS5 on `127.0.0.1:18000` |
| Carrier | Moves encrypted frames through DNS | Per-resolver `auto` between UDP/53 and TCP/53 |
| Optional carriers | Survive networks that fingerprint plain DNS | User-enabled DoT or DoH |
| Reliability | Repairs unstable delivery | ARQ, adaptive duplication, FEC, replay |
| Control plane | Keeps traffic on the best measured path | Unified per-resolver path controller |

## Project lineage and credits

CottenDNS stands on the work of two projects and their maintainers:

1. **[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)** by **Amin Mahmoudi** established the low-overhead DNS tunnel, custom ARQ, resolver balancing, session multiplexing, and harsh-network design used by this project.
2. **[StormDNS](https://github.com/nullroute1970/StormDNS)** by **NullRoute1970** continued that work and is the direct upstream lineage from which CottenDNS was derived.
3. **CottenDNS**, maintained by **tajirax**, extends that foundation while retaining compatibility with MasterDNS/StormDNS clients.

Their work deserves full credit. CottenDNS is an independent derivative, not a claim that the underlying architecture began here. All three projects preserve the MIT license lineage; see [LICENSE](LICENSE).

## What CottenDNS does

CottenDNS carries application traffic inside DNS queries and responses:

```text
Application
    │
    ▼
Local SOCKS5 / TCP listener
    │
    ▼
CottenDNS client
    │
    ├── UDP/53 ─────┐
    ├── TCP/53 ─────┤
    ├── DoT ────────┤──► DNS resolver ──► CottenDNS server ──► Internet
    └── DoH ────────┘
```

The client splits streams into DNS-sized frames, encrypts and optionally compresses them, selects a resolver/transport path, and repairs loss with ARQ and optional Reed–Solomon FEC. The server reconstructs the streams and opens the requested connection directly, through an upstream SOCKS5 server, or toward a fixed TCP target.

The built-in SOCKS5 server supports normal TCP proxying and generic UDP associations. A local DNS listener/cache is optional.

## Why it is different

| Network problem | CottenDNS response |
| --- | --- |
| UDP is fast but sometimes poisoned or throttled | Keep viable UDP; move only the affected resolver to a better transport |
| Resolver paths behave differently | Score each `(resolver, transport)` independently |
| Upload and download quality differ | Maintain separate directional delivery, failure, RTT, and confidence evidence |
| Small DNS MTUs waste capacity | Discover MTU per path and route each packet only where it fits |
| Packet loss is severe | ARQ, ACK/NACK, immediate replay, adaptive duplication, FEC, and Super-FEC |
| A forged answer arrives unusually fast | Treat it as an early warning and race one authenticated alternate |
| A path dies with frames in flight | Replay unacknowledged frames without recreating the session |
| Extra reliability traffic causes congestion | Coordinate duplication, FEC, replay, and exploration under one budget |
| Several paths are equally good | Stripe bulk packets across mature comparable paths without making copies |
| DPI fingerprints repetitive DNS | Rotate record types, reshape QNAME labels, randomize IDs/cookies, and optionally use DoT/DoH |
| Server load spikes | Bounded queues, admission checks, connection budgets, and work-conserving fairness |

## Automatic behavior

The recommended defaults enable the smart client controller:

```toml
CONFIG_PRESET = "speed"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

With these settings the client automatically:

- tries UDP and keeps it while it remains useful;
- compares UDP and TCP/53 separately for every resolver;
- switches only the failing or materially slower path;
- uses packet size, MTU, RTT, loss, direction, and confidence when routing;
- keeps alternate paths warm with a congestion-aware background budget;
- avoids stacking FEC, exploration, and unnecessary duplication;
- races a validated alternate after poison evidence;
- replays in-flight frames before waiting for the full ARQ timeout; and
- falls back to connectivity when the fastest path cannot deliver.

`auto` does **not** silently enable DoT or DoH. Those transports remain explicit user choices because some censored networks block them:

```toml
RESOLVER_TRANSPORT = "dot" # or "doh"
```

If an encrypted resolver transport fails, its survival chain can return to UDP/53 and TCP/53. You may also override individual resolvers:

```toml
RESOLVER_TRANSPORT_PATHS = { "1.1.1.1" = "doh", "8.8.8.8" = "auto", "9.9.9.9" = "tcp" }
```

## Dynamic server

The server feeds UDP, TCP/53, DoT, and DoH into the same native session engine. It does not require a separate session protocol for each carrier.

With the default:

```toml
ENCRYPTION_AUTO_DETECT = true
```

the server automatically accepts keyed client encryption methods 1–5:

| ID | Method | Authentication |
| --- | --- | --- |
| `1` | XOR | Legacy, unauthenticated |
| `2` | ChaCha20 | Legacy stream cipher, unauthenticated |
| `3` | AES-128-GCM | Authenticated |
| `4` | AES-192-GCM | Authenticated |
| `5` | AES-256-GCM | Authenticated |

AES-GCM candidates are always checked before legacy decoders. Legacy candidates must additionally match session or strict pre-session MTU semantics. Plaintext method `0` is accepted only when the server is explicitly configured for plaintext.

Different clients may therefore select different supported methods, transports, resolver paths, MTUs, compression, and reliability settings without reconfiguring the server. The server still enforces its configured safety ceilings.

## Complete setup guide

The normal deployment has three parts:

```text
[Client device] ──► [recursive DNS resolvers] ──► [delegated subdomain on VPS] ──► [Internet]
```

### Before you begin

You need:

- a domain whose DNS records you can edit;
- a Linux VPS with a public IPv4 address and root or `sudo` access;
- inbound UDP/53 and TCP/53 allowed by both the VPS firewall and the provider firewall;
- a client device running Windows, Linux, macOS, or an application embedding the engine; and
- at least a few resolvers that can reach your delegated authoritative subdomain.

> [!CAUTION]
> Port 53 may already be occupied by `systemd-resolved`, BIND, dnsmasq, or a hosting control panel. The installer detects common conflicts, but check the host before using a production DNS server. Keep TCP/22 or your management port open so firewall changes cannot lock you out.

### Step 1 — Create the DNS delegation

Choose two names:

- **nameserver host:** `ns.example.com`
- **tunnel subdomain:** `v.example.com`

Create these records at the authoritative DNS provider for `example.com`:

```dns-zone
ns.example.com.  300  IN  A   203.0.113.10
v.example.com.   300  IN  NS  ns.example.com.
```

Replace `203.0.113.10` with the VPS public IP. The first record points the nameserver name to the VPS; the second delegates the tunnel subdomain to that nameserver. Do **not** proxy either record through a CDN. A short tunnel name is preferable because every extra domain byte reduces usable DNS payload.

Wait for propagation, then verify from a machine with `dig`:

```bash
dig +short A ns.example.com
dig +short NS v.example.com
```

Expected:

```text
203.0.113.10
ns.example.com.
```

If the NS result is missing, stop here and fix delegation. Client tuning cannot compensate for incorrect DNS records.

### Step 2 — Prepare the server

Confirm that port 53 is not unexpectedly occupied:

```bash
sudo ss -lntup | grep ':53 '
```

Also allow UDP/53 and TCP/53 in the VPS provider’s network firewall or security group. The installer handles common host firewalls, but it cannot modify the provider control panel.

Create a stable installation directory and run the latest installer:

```bash
sudo install -d -m 0755 /opt/cottendns
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash
```

When prompted, enter the delegated tunnel domain—for example `v.example.com`. The installer:

1. downloads the matching server release;
2. prepares `server_config.toml`;
3. generates or preserves `encrypt_key.txt`;
4. opens UDP and TCP port 53 in supported host firewalls;
5. creates and starts `cottendns.service`; and
6. verifies the local `/healthz` endpoint.

Important files:

```text
/opt/cottendns/server_config.toml
/opt/cottendns/encrypt_key.txt
```

Read the generated key and transfer it through a secure channel:

```bash
sudo cat /opt/cottendns/encrypt_key.txt
```

Never post this key in an issue, screenshot, resolver list, or public configuration.

### Step 3 — Verify the server

Run all four checks:

```bash
systemctl is-active cottendns
systemctl status cottendns --no-pager
curl -fsS http://127.0.0.1:9090/healthz
sudo ss -lnup | grep ':53 '
sudo ss -lntp | grep ':53 '
```

You should see an active service, a healthy response, and listeners on port 53 for both UDP and TCP. If not:

```bash
journalctl -u cottendns -n 100 --no-pager
```

The metrics listener intentionally binds to localhost. Do not expose port `9090` publicly just to make these checks work.

### Docker server installation

Docker is an alternative to the systemd server installation in Steps 2 and 3.
The supported image is published from this repository to
`ghcr.io/tajirax/cottendns-server` for AMD64 and ARM64 Linux. It runs the
CottenDNS process as a non-root user, persists the configuration and encryption
key under `/data`, and includes the same local health endpoint as the native
service.

#### Requirements

- A Linux VPS with Docker Engine and the Docker Compose plugin.
- The DNS delegation from Step 1.
- Free UDP/53 and TCP/53 ports on the host.
- Inbound UDP/53 and TCP/53 allowed in both the provider firewall and the host
  firewall.

Check for an existing DNS service before starting:

```bash
sudo ss -lntup | grep ':53 '
docker --version
docker compose version
```

If BIND, dnsmasq, `systemd-resolved`, or another container owns port 53, stop or
reconfigure that service first. The container uses host networking so DNS
traffic reaches CottenDNS without Docker NAT overhead.

#### One-line installation

Replace `v.example.com` with the delegated tunnel domain:

```bash
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_docker_install.sh \
  | sudo sh -s -- --domain v.example.com
```

The installer creates `/opt/cottendns-docker`, downloads the repository-owned
Compose file, pulls the current image, starts the server, and waits until the
container health check passes. Persistent files are stored here:

```text
/opt/cottendns-docker/data/server_config.toml
/opt/cottendns-docker/data/encrypt_key.txt
/opt/cottendns-docker/.env
```

Read the generated key and transfer it securely to the client:

```bash
sudo cat /opt/cottendns-docker/data/encrypt_key.txt
```

Verify the deployment:

```bash
cd /opt/cottendns-docker
sudo docker compose ps
sudo docker compose logs --tail=100 server
curl -fsS http://127.0.0.1:9090/healthz
sudo ss -lnup | grep ':53 '
sudo ss -lntp | grep ':53 '
```

The metrics endpoint stays bound to `127.0.0.1:9090`. Do not publish it to the
Internet. For detailed health and Prometheus data, use the commands in
[Monitoring](#monitoring).

#### Configure and restart

Edit non-domain settings in the persistent server configuration, then restart
the server process:

```bash
sudoedit /opt/cottendns-docker/data/server_config.toml
cd /opt/cottendns-docker
sudo docker compose restart server
sudo docker compose logs --tail=100 server
```

The domain is controlled by `COTTENDNS_DOMAIN` in
`/opt/cottendns-docker/.env`. After changing it, recreate the container so
Compose loads the new environment:

```bash
sudoedit /opt/cottendns-docker/.env
cd /opt/cottendns-docker
sudo docker compose up -d --force-recreate
```

The entrypoint writes this value into `server_config.toml` at startup, so do not
set a different `DOMAIN` value in the TOML file.

#### Upgrade, pin, and roll back

Upgrade to the newest published image without replacing the active
configuration or encryption key:

```bash
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_docker_install.sh \
  | sudo sh -s -- --upgrade
```

Back up persistent state before an upgrade:

```bash
sudo cp -a /opt/cottendns-docker/data \
  "/opt/cottendns-docker/data.backup.$(date +%Y%m%d-%H%M%S)"
```

For a reproducible deployment, set `COTTENDNS_IMAGE_TAG` in
`/opt/cottendns-docker/.env` to a release tag instead of `latest`:

```dotenv
COTTENDNS_DOMAIN=v.example.com
COTTENDNS_IMAGE_TAG=vYYYY.MM.DD.HHMMSS-commithash
```

Apply a pinned version—or roll back by selecting the previous known-good
tag—with:

```bash
cd /opt/cottendns-docker
sudo docker compose pull
sudo docker compose up -d --remove-orphans
curl -fsS http://127.0.0.1:9090/healthz
```

Stop and remove only the container and Compose-managed resources:

```bash
cd /opt/cottendns-docker
sudo docker compose down
```

The bind-mounted `data` directory remains on disk. Preserve
`server_config.toml` and `encrypt_key.txt`; deleting or replacing the key
disconnects clients that use it.

### Step 4 — Download the correct client

Open [Releases](https://github.com/TaJirax/cottenDNS/releases/latest) and choose the archive matching the client machine:

| Platform | Typical archive |
| --- | --- |
| Windows 64-bit | `CottenDns_Client_Windows_AMD64.zip` |
| Linux x86-64 | `CottenDns_Client_Linux_AMD64.tar.gz` or `.zip` |
| Linux ARM64 | `CottenDns_Client_Linux_ARM64.tar.gz` or `.zip` |
| macOS Apple Silicon | `CottenDns_Client_Darwin_ARM64.tar.gz` or `.zip` |
| macOS Intel | `CottenDns_Client_Darwin_AMD64.tar.gz` or `.zip` |

Keep the executable, `client_config.toml`, and `client_resolvers.txt` in the same directory. Configuration paths are resolved relative to the executable unless an explicit path is provided.

### Step 5 — Configure the client

Edit only the essential values first:

```toml
DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "paste-the-server-key-here"
DATA_ENCRYPTION_METHOD = 3

PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18000

CONFIG_PRESET = "speed"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

The domain must exactly match the server. Method `3` is authenticated AES-128-GCM and is the recommended starting point. The dynamic server accepts keyed methods 1–5 by default, so other clients may use a different supported method without changing the server.

Put one resolver IP per line in `client_resolvers.txt`:

```text
# Comments and blank lines are allowed.
1.1.1.1
8.8.8.8
9.9.9.9
```

Start with a small, diverse set. A huge list of poor resolvers increases scan time and does not guarantee more throughput.

### Step 6 — First scan and first connection

Run from a terminal so you can see scan results.

Linux/macOS:

```bash
chmod +x ./CottenDns_Client_*
./CottenDns_Client_Linux_AMD64_vVERSION --config ./client_config.toml
```

Windows PowerShell:

```powershell
.\CottenDns_Client_Windows_AMD64_vVERSION.exe --config .\client_config.toml
```

During the first run, CottenDNS measures resolver reachability, MTU, latency, loss, and available UDP/TCP paths. A resolver does not enter the active pool merely because it answers ordinary DNS; it must pass tunnel validation.

For a scan without starting the local proxy:

```bash
./CottenDns_Client_Linux_AMD64_vVERSION --config ./client_config.toml --scan-only
```

Keep `STARTUP_MODE = "resolvers"` on every launch. Resolver reachability,
transport quality, poisoning, and MTU can change between restarts, so CottenDNS
always validates the complete current list. `FAST_CONNECT = true` releases a
small validated starter pool early and continues scanning the remaining
resolvers in the background without trusting results from a previous process.

### Step 7 — Test the SOCKS5 proxy

Configure an application to use:

```text
Type: SOCKS5
Host: 127.0.0.1
Port: 18000
```

Or test from a terminal:

```bash
curl --proxy socks5h://127.0.0.1:18000 https://example.com/
```

Use `socks5h`, not `socks5`, when you want hostname resolution to occur through the proxy.

### Optional — Install the Linux client as a service

The Linux client archive includes an offline systemd installer. Configure the files first, then run it from the extracted directory:

```bash
sudo bash client_linux_install.sh
systemctl status cottendns-client --no-pager
journalctl -u cottendns-client -f
```

### Safe upgrades

Upgrade the server in place:

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --upgrade
```

The upgrade path preserves the active configuration and encryption key and rolls back if the new service does not become healthy. Still keep an external backup:

```bash
sudo cp /opt/cottendns/server_config.toml /opt/cottendns/server_config.toml.manual-backup
sudo cp /opt/cottendns/encrypt_key.txt /opt/cottendns/encrypt_key.txt.manual-backup
```

For desktop clients, extract the new release separately, copy your configuration/key and resolver file, then start the new binary. Keep the previous folder until the replacement has completed a scan and passed a SOCKS test.

<details>
<summary><strong>Server installer: pinned, offline, and removal operations</strong></summary>

Install a specific release:

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --version vYYYY.MM.DD.HHMMSS-commithash
```

Install a locally built server without downloading:

```bash
python build.py
sudo bash server_linux_install.sh --local
```

Show installer options:

```bash
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | bash -s -- --help
```

Uninstall the systemd service and files managed by the installer:

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --uninstall
```

Back up `server_config.toml` and `encrypt_key.txt` before uninstalling if the deployment may be restored later.

</details>

## Choose a profile

| Profile | Use it when |
| --- | --- |
| `speed` | Default choice; viable DNS with maximum useful throughput |
| `survival` | Heavy loss, resolver instability, or aggressive censorship |
| `tcp-survival` | UDP/53 is consistently unusable and TCP/53 survives |
| `iran`, `china`, `russia`, `venezuela`, `cuba` | Client-side starting points for common regional constraints |
| `low-bandwidth` | Upload capacity and resolver query budgets are extremely limited |

Profiles are starting points, not hard-coded country detection. Real resolver behavior varies by ISP, city, time, and censorship event. Explicit TOML values always override a preset. See [CONFIG_PRESETS.md](CONFIG_PRESETS.md).

### Transport selection

| Setting | Best use | Important behavior |
| --- | --- | --- |
| `auto` | Recommended for almost everyone | Tries UDP first and compares UDP/TCP per resolver; it does not enable DoT/DoH |
| `udp` | Debugging or a known clean UDP-only environment | Pins every unoverridden resolver to UDP and disables automatic TCP selection |
| `tcp` | Networks where UDP/53 is consistently broken | Uses persistent DNS-over-TCP connections |
| `dot` | Plain DNS is fingerprinted but port 853 works | Requires the server DoT listener and correct TLS trust settings |
| `doh` | HTTPS-shaped DNS is the only reliable carrier | Requires the server DoH listener, route, and correct TLS trust settings |

Prefer `auto` over forcing the entire pool to one transport. Per-resolver policy keeps fast UDP where it works while allowing only a damaged path to use TCP:

```toml
RESOLVER_TRANSPORT = "auto"
RESOLVER_TRANSPORT_PATHS = { "1.1.1.1" = "udp", "8.8.8.8" = "auto", "9.9.9.9" = "tcp" }
```

DoT and DoH are deliberate deployments, not speed toggles. Read the TLS, certificate pinning, coexistence, and listener comments in [server_config.toml.simple](server_config.toml.simple) and [client_config.toml.simple](client_config.toml.simple) before enabling them.

## Monitoring

The default metrics listener is local-only. Plain health:

```bash
curl -s http://127.0.0.1:9090/healthz
```

Detailed JSON:

```bash
curl -s 'http://127.0.0.1:9090/healthz?details=1' | jq
```

Prometheus metrics:

```bash
curl -s http://127.0.0.1:9090/metrics
```

The detailed view includes build/uptime, sessions, streams, listener state, queue pressure, drops, codec acceptance, generic UDP, DNS upstream health, Go runtime, CPU-related runtime counters, and memory data. It intentionally excludes keys, credentials, queried domains, client addresses, and payloads.

Read the signals together:

| Signal | Healthy pattern | Investigate when |
| --- | --- | --- |
| Service and listeners | `healthz` succeeds; UDP/TCP listeners are up | Listener is down or restart count rises |
| Sessions and streams | Change with real client use | Sessions grow without cleanup or streams never open |
| Queue pressure | Usually low with short bursts | Sustained saturation, rejects, or drops increase |
| Codec acceptance | Authenticated/expected methods dominate | Invalid or rejected traffic grows sharply |
| Generic UDP | Active only when applications request it | Associations accumulate or stale drops rise |
| Go memory | May grow, then stabilize and reuse | Resident memory rises continuously with no workload growth |
| CPU | Bursts during traffic and FEC work | High CPU continues while traffic is low |

`healthz` reports server condition; it does not prove that a particular ISP resolver can carry the tunnel. Resolver viability, MTU, and path quality must be checked from the client’s network.

For operating-system process usage:

```bash
pid=$(systemctl show -p MainPID --value cottendns)
ps -p "$pid" -o pid,%cpu,%mem,rss,vsz,etime,cmd
top -p "$pid"
```

## Android and engine embedding

The Go networking engine is kept in this repository. Android applications can pin CottenDNS as a Git submodule or CI dependency and build the engine without copying it into the app repository.

Known-good engine commit:

```text
8eea49d1267b1a41441c25c75e69e6f12ad0a11f
```

The engine has been cross-compiled with CGO disabled for Android arm64, armv7, amd64, and 386. The Android wrapper should preserve the recommended defaults or pass equivalent TOML values.

Example submodule update:

```bash
git submodule update --init --recursive
cd path/to/cottenDNS
git fetch origin
git checkout 8eea49d1267b1a41441c25c75e69e6f12ad0a11f
cd ..
git add path/to/cottenDNS
git commit -m "Update CottenDNS engine"
```

## Compatibility

- New client + new server: complete feature set.
- Old client + new server: supported, including MasterDNS/StormDNS-compatible clients.
- New client + old server: most client-only routing improvements work, but current server hardening, monitoring, listeners, and policy features are unavailable.
- `PATH_CONTROLLER_MODE = "legacy"` restores the earlier client selector without changing the wire protocol.

## Security notes

- Prefer AES-GCM method `3`, `4`, or `5` for authenticated encryption.
- XOR and ChaCha20 method `2` are retained for legacy compatibility; they do not authenticate frames.
- DoT/DoH protects and disguises the client-to-resolver hop, not the resolver-to-authoritative-server hop.
- DNS volume and timing can still reveal tunnel-like behavior. No plaintext DNS tunnel is invisible to a capable observer.
- Keep `/healthz` and `/metrics` bound to localhost unless protected by firewall or an authenticated reverse proxy.
- Protect `encrypt_key.txt` and never publish it.
- Use this software only where you are authorized to do so.

## Troubleshooting

Start with the layer that failed:

| Symptom | First checks |
| --- | --- |
| Server will not start | `journalctl`, port-53 conflicts, config syntax, permissions |
| Server is healthy but every scan fails | A/NS delegation, provider firewall, matching domain/key |
| Some resolvers pass and others fail | Expected resolver filtering; keep only validated paths |
| SOCKS listener opens but browsing fails | Client logs, active streams, proxy hostname mode, server egress |
| Resolver conditions changed after restart | No action: every launch performs fresh validation |
| Fast briefly, then stalls | Queue pressure, MTU changes, loss, resolver throttling |

### No resolver passes MTU scanning

1. Verify both records: `dig +short A ns.example.com` and `dig +short NS v.example.com`.
2. Confirm the service is healthy and both UDP/TCP listeners exist with `ss`.
3. Confirm UDP and TCP port 53 are open in the provider firewall, not only the VPS firewall.
4. Confirm client and server use the exact same domain and encryption key.
5. Run the client once with `STARTUP_MODE = "resolvers"` and watch the scan output.
6. Try a shorter tunnel domain and conservative MTU bounds.
7. Test a small set of known resolver IPs instead of a large unverified list.
8. Use the `survival` profile before forcing every resolver to TCP.

### Client immediately prefers TCP

Keep `RESOLVER_TRANSPORT = "auto"`. The client should retain viable UDP and move only a resolver whose UDP path fails or becomes materially worse. Every restart performs fresh resolver and path validation.

### Connection works but is slow

- Check queue pressure and drops in `/healthz?details=1`.
- Compare the client’s delivered RTT and loss per resolver/transport, not ordinary DNS ping alone.
- Avoid increasing duplication blindly; extra copies consume the same constrained link.
- Use `speed` on clean paths and `survival` only when loss justifies it.
- Keep several genuinely independent, validated resolvers; remove consistently poor paths.
- Reduce MTU if large queries are being fragmented or discarded.
- Check whether server CPU is saturated during FEC work and whether memory is stable.
- Remember that already-compressed HTTPS/video/archive traffic gains little from tunnel compression.

### Legacy clients fail

Confirm `ENCRYPTION_AUTO_DETECT = true`, use the same encryption key, and do not enable server ceilings that reject the legacy client’s requested values.

## Documentation

| Document | Purpose |
| --- | --- |
| [Configuration presets](CONFIG_PRESETS.md) | Recommended speed/survival profiles and regional starting points |
| [Engineering changes](docs/ENGINEERING_CHANGES.md) | Protocol decisions, failure handling, tests, and measured results |
| [Client sample](client_config.toml.simple) | Complete client configuration reference |
| [Server sample](server_config.toml.simple) | Complete server configuration reference |
| [Benchmark guide](scripts/bench/README.md) | Local client/server integration benchmark |

## Build and test

Requirements: Go 1.25 or compatible current Go toolchain.

```bash
go build ./cmd/client
go build ./cmd/server
go test ./...
go vet ./...
```

Cross-platform packages:

```bash
python build.py
```

Hostile-network regression suite:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hostile-network.ps1 -Count 20 -FullRace
```

## License and acknowledgement

CottenDNS is maintained by **tajirax** and distributed under the [MIT License](LICENSE).

Special thanks and full historical credit:

- **Amin Mahmoudi** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN), the original architecture and project foundation.
- **NullRoute1970** — [StormDNS](https://github.com/nullroute1970/StormDNS), the direct upstream derivative and continued engineering lineage.
- All contributors, testers, resolver operators, and users reporting behavior from censored networks.

Project links: [issues](https://github.com/TaJirax/cottenDNS/issues) · [pull requests](https://github.com/TaJirax/cottenDNS/pulls) · [releases](https://github.com/TaJirax/cottenDNS/releases)
