# WhiteDNS Desktop

WhiteDNS Desktop is a desktop application for running a local DNS tunneling client, with a proxy mode and a managed system proxy, for macOS, Windows, and Linux.

> **NOTICE:** WhiteDNS is source-available proprietary software. The code is published for transparency, review, and contribution to this official project only. You may not copy the app into a separate product, publish modified builds, repackage installers, redistribute binaries, clone the branding, or reuse the WhiteDNS name, logo, icon, design, or visual identity. See [LICENSE.MD](./LICENSE.MD).

> **DOWNLOAD WARNING:** Releases are published only from this repository. A WhiteDNS Desktop installer found on any other site, mirror, or marketplace is not an official build and may be modified, outdated, or unsafe.

Official channel: [https://t.me/whitedns](https://t.me/whitedns)

## Download and subscriptions

Download the official [latest desktop release](https://github.com/WhiteDNS/WhiteDNS-Desktop/releases/latest).
Use the Windows x64 ZIP on ordinary Intel/AMD PCs; Windows ARM64 is for Windows on ARM.
macOS and Linux packages are available for Intel/AMD and ARM64.

To use a WhiteDNS Soar panel account:

1. Copy its **subscription URL** from the panel.
2. Open **Connections → Import**, paste the HTTPS URL, then choose **Import**.
3. Select the imported connection and connect. The account's DNS resolvers and Soar settings are imported together.
4. Use **Refresh subscriptions** while disconnected to receive account changes. Due subscriptions also refresh when the app opens while disconnected.

A `soar://` profile link can also be imported, but does not receive subscription updates.
HTTP subscriptions need explicit consent because they are unencrypted. Keep subscription URLs and full backups private.
Saved profiles remain available when a subscription download fails; the server still enforces expiry and quotas.
See [the Soar and subscription guide](docs/SOAR-SUBSCRIPTIONS.md).

## Credits

WhiteDNS is backed by the [MasterDNS Client](https://github.com/masterking32/MasterDnsVPN)
project, integrates [Lantern Soar](https://github.com/getlantern/soar), and vendors the CottenDNS engine from
[TaJirax/cottenDNS](https://github.com/TaJirax/cottenDNS) at the commit pinned
in [`vendor/cottendns.json`](./vendor/cottendns.json).

The desktop shell is built with [Wails](https://wails.io), and the proxy hop
uses [Xray-core](https://github.com/XTLS/Xray-core). The MasterDNS and StormDNS
engines are vendored in-tree under their own terms. Soar v0.2.3 is Apache-2.0 licensed, with the same WhiteDNS transport changes used in Android 1.6.8; see [third-party notices](THIRD_PARTY_NOTICES.md).

## Features

- DNS tunneling client for macOS, Windows, and Linux.
- Selectable engine: CottenDNS, MasterDNS, StormDNS, or Soar.
- Local SOCKS5 and HTTP proxy, with an optional managed system proxy that is
  restored on disconnect and after an unclean exit.
- Multi-domain connection profiles, with import, export, and bulk management.
- Resolver profile management with validation, plus a DNS resolver scanner.
- IPv4 and IPv6 resolver endpoints, including bracketed ports and bounded CIDR
  imports, with automatic IPv4-to-IPv6 failover or selectable dual-stack modes.
- Full CottenDNS option editor covering the complete engine schema, grouped by
  category, showing the value each profile will actually run with.
- Engine presets, including speed, survival, and TCP-survival.
- Live connection progress, resolver state, traffic statistics, and logs.
- HTTPS subscriptions with refresh, account traffic/quota/expiry metadata, and cached profiles.
- Soar advanced transport, discovery, DNS packet and stream settings with help on each question mark.
- Full backup and restore of every saved profile through native file dialogs.

## Building

Requires Go 1.26.9+, Node 24+, and the Wails CLI.

```sh
make -C desktop deps     # install frontend and Go dependencies
make -C desktop build    # build the frontend and desktop binary
make -C desktop test     # Go tests and the frontend production build
```

Release packages for the full platform matrix are produced by the
`Desktop Release Builds` workflow from a `desktop-v*` tag.

## Reporting problems

Open an issue with the app version, your operating system, and the relevant
runtime log. Encryption keys and credentials are redacted from exported
diagnostics; please check any log you attach before posting it.

## Security

Report vulnerabilities privately to the official WhiteDNS team via the channel
above rather than opening a public issue. Section 6 of the license covers
security research and responsible disclosure.
