# WhiteDNS Desktop 1.4.4

Update the embedded CottenDNS core to `7db7b73658c791cce62300d29647e4d369d6e1e4`, matching WhiteDNS Android 1.6.13 and the latest CottenDNS server.

- Fix CottenMax authenticating but stalling during transfer verification when large resolver lists contain many unreachable candidates. Working paths carry real traffic while bounded checks rotate across remaining candidates.
- Remove the quadratic startup cost when constructing large resolver pools. Keep real stream and control data out of oversized query-name trials, and give slow successful scan handshakes a fresh transfer-proof deadline.
- Add client-controlled download Reed-Solomon FEC in CottenMax settings. It is off by default, requires an updated FEC-capable server, and consumes additional bandwidth when enabled. Defaults are 4 data shards and 1 recovery shard; supported ranges are 2-16 and 1-4. Original data sends immediately and existing retransmission remains available.
- Allow optional discovery targets and total query windows up to 4,096. Existing defaults remain 16 healthy discovery resolvers and 256 outstanding queries; per-path and discovery-concurrency limits retain their existing bounds.
- Preserve FEC options across profiles, settings imports/exports, and generated engine configurations. Existing Max-capable servers remain compatible when FEC is off.
- Verify every release package embeds the freshly built helper from the recorded source snapshot, with its exact core version and target architecture.

Keep the existing domain, shared key, and Router configuration. Upgrade the server before enabling download FEC. Use CottenMax mode to scan for Max-compatible paths: ordinary DNS lookups and Normal-mode scans do not establish Max compatibility. Candidate lists are not guarantees that every resolver works on every network.

Windows x64/ARM64, macOS Intel/Apple Silicon, and Linux x64/ARM64 packages are built by CI. The affected Samsung/Shatel connection still requires real-device confirmation; the updated server has passed authenticated Max/FEC transfer checks over UDP and TCP through Router and 1.1.1.1.
