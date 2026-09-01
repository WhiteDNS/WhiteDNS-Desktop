# WhiteDNS Desktop

WhiteDNS Desktop is a desktop application for running a local DNS tunneling client, with a proxy mode and a managed system proxy, for macOS, Windows, and Linux.

> **NOTICE:** WhiteDNS is source-available proprietary software. The code is published for transparency, review, and contribution to this official project only. You may not copy the app into a separate product, publish modified builds, repackage installers, redistribute binaries, clone the branding, or reuse the WhiteDNS name, logo, icon, design, or visual identity. See [LICENSE.MD](./LICENSE.MD).

> **DOWNLOAD WARNING:** Releases are published only from this repository. A WhiteDNS Desktop installer found on any other site, mirror, or marketplace is not an official build and may be modified, outdated, or unsafe.

Official channel: [https://t.me/whitedns](https://t.me/whitedns)

## Credits

WhiteDNS is backed by the [MasterDNS Client](https://github.com/masterking32/MasterDnsVPN)
project and vendors the CottenDNS engine from
[TaJirax/cottenDNS](https://github.com/TaJirax/cottenDNS) at the commit pinned
in [`vendor/cottendns.json`](./vendor/cottendns.json).

The desktop shell is built with [Wails](https://wails.io), and the proxy hop
uses [Xray-core](https://github.com/XTLS/Xray-core). The MasterDNS and StormDNS
engines are vendored in-tree under their own terms.

## Features

- DNS tunneling client for macOS, Windows, and Linux.
- Selectable engine: CottenDNS, MasterDNS, or StormDNS.
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
- Full backup and restore of every saved profile through native file dialogs.

## Building

Requires Go 1.25+, Node 24+, and the Wails CLI.

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
