# CottenMax beta in the terminal

Update the CottenDNS server before offering Max profiles. The updated server
accepts normal and Max clients together on its existing DNS listener. Keep its
delegated domains, configuration and `encrypt_key.txt` credential. A normal
client remains a useful beta fallback.

In the existing client profile, set `TUNNEL_MODE = "cottenmax"` and restart the
client. Select `"legacy"` and restart to return to normal CottenDNS. Use the same
`DOMAINS` and `ENCRYPTION_KEY`; no second Max service or key transfer is required.
The old optional Max public-key override remains supported for migrations.

The Linux client installer can select and persist the mode explicitly:

```bash
sudo bash client_linux_install.sh --mode cottenmax
sudo bash client_linux_install.sh --mode legacy
```

Omit `--mode` to preserve an existing selection. Use `--help` before installation.
The installer rejects an incompatible Max binary before stopping an existing
service. Until a Max beta release is published, install a compatible server
artifact with the server installer's `--local` option. An explicit `--version`
can select a beta tag once that release exists; the public `latest` build may
not contain Max yet. Publishing beta source alone does not update it. The
server installer explains when a binary lacks Max support. Keep the original
profile and key during upgrades.

The client dashboard displays the active mode explicitly. Press **h** or **?**
for setup requirements, current optional settings and advanced-option names.
Use **up/down** to scroll, **h/Esc** to return and **q** to quit. Noninteractive
services retain plain logs with the same setup guidance. `client --help` lists
Max-specific constraints beside its generated configuration flags. CLI
overrides affect that process only; edit the profile to persist a selection.

Max Auto now authenticates independent UDP/TCP DNS paths at startup and uses
them for live proxy traffic. Explicit `udp`/`tcp` pins one transport. Run
`client -config client_config.toml -resolvers client_resolvers.txt -scan-only`
for an authenticated scan of both paths in Auto mode, without starting the
proxy. The updated beta server supplies its bounded internal transfer probe.
Results include separate observed query-name/reply sizes per transport and one
final result per resolver. The dashboard and app logs show verified resolver
endpoints and actual UDP/TCP path counts instead of a legacy-only balancer count.

The server console explains the shared setup and client-side mode selection.
After initialization, check its **CottenMax available alongside normal
CottenDNS** readiness message. Long unsupported domains are reported and retain
normal-mode service; they cannot be assumed usable by Max. The server has no
separate fullscreen dashboard: its installation menu and systemd logs are the
operator interfaces. `server --help` documents the compatibility mode setting.

Start with defaults. Discovery/cache, EDNS padding, label-count jitter and the
experimental QNAME loss guard remain opt-in. Encrypted resolver transports
require compatible resolvers and certificate verification. New HTTP/3 and DoQ
client options do not create authoritative listeners; existing optional server
DoT/DoH listeners are configured separately. Hard query-rate budgets require
normal mode. See [the options guide](COTTENMAX_OPTIONS.md) for supported settings,
limitations and resolver-hop details.

Release bundles place `COTTENMAX_OPTIONS.md` beside the binary; source checkouts
keep the same guide under `docs/`.
