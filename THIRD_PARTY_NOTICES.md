# Third-party notices

WhiteDNS Desktop contains independently licensed components. The WhiteDNS application license does not replace the licenses of those components.

## Lantern Soar

Soar is a project of **Lantern**, not an original WhiteDNS tunneling protocol.

- Original source: https://github.com/getlantern/soar
- Upstream version: v0.2.3, commit a8af533d82284f5e6ab13b706552596c108bacf2
- License: Apache License 2.0, retained in `Soar/third_party/soar/LICENSE` and distributed as `licenses/Soar-LICENSE.txt`.
- WhiteDNS modifications: `Soar/third_party/soar/WHITEDNS_CHANGES.md`.
- Wrapper and patched engine copied from official WhiteDNS Android 1.6.8, pinned in `vendor/soar.json`. These changes are WhiteDNS modifications, not an upstream Lantern release.

The Soar helper also uses Go and golang.org/x/crypto and golang.org/x/sys under their BSD-style licenses. Their full license texts are included in release packages under `licenses/`.

## Other engines and desktop components

MasterDNS: https://github.com/masterking32/MasterDnsVPN — see the vendored `MasterDnsVPN` source and its license.

CottenDNS: https://github.com/TaJirax/cottenDNS — pinned in `vendor/cottendns.json`; see the vendored `CottenDNS` source and its license.

StormDNS: see the vendored `StormDNS` source and its license.

Wails: https://github.com/wailsapp/wails (MIT). Xray-core: https://github.com/XTLS/Xray-core (MPL-2.0), downloaded unmodified by the packaging scripts from its pinned official release.

Frontend and other Go dependency licenses remain those of their respective authors; exact versions are recorded in the lock files and Go module files.

## Resolver datasets

The Iranian resolver/range snapshots come from KevinNet DNS, commit a331430 (2026-05-26), under the MIT License. The complete attribution and permission notice is retained in `Soar/data/THIRD_PARTY.md` and included in release packages as `licenses/Soar-DATA-NOTICES.md`.
