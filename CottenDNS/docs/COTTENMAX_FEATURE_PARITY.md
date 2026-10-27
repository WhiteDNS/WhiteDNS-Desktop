# CottenMax feature parity audit

Audited 2026-10-25 against core `7db7b736`, before this branch's experiments.
This is a source audit, not a benchmark result. Experimental implementation and
measurements should be reviewed separately before promotion to a release.

No feature can be promised to have zero performance regression on every device,
resolver and network. An opt-in feature, disabled by default, can preserve the
existing default protocol and avoid allocating its feature state. Its enabled
path still needs measurements of useful throughput, latency, DNS bytes, query
count, CPU and memory. A faster cipher benchmark alone does not establish a
faster tunnel.

## Features already shared

| Normal feature | CottenMax baseline | Speed and bandwidth implications |
| --- | --- | --- |
| SOCKS4/5 TCP CONNECT, HTTP proxy and fixed TCP forwarding | Supported through the Max stream adapter. | Existing entry points can be retained; no new wire feature is needed. |
| Local DNS, cache and concurrent-query deduplication | Supported; authenticated `dns:0` streams use the normal server resolver. | Cached answers avoid tunnel work. A cold exchange uses a framed stream. |
| UDP/TCP resolver transport, explicit DoT/DoH/HTTP3/DoQ | Supported. Max Auto can use UDP and TCP paths independently. | Encrypted transport setup, padding and reachability can change latency and bytes; these transports are explicit choices. |
| Large resolver lists, authenticated discovery and optional discovery cache | Supported. | More candidates do not guarantee more independent usable paths. Scouting and query windows must stay bounded. |
| Path health, size discovery, loss recovery and stream multiplexing | Supported with Max's own transport machinery. | Keep Max's byte-range retransmission, implicit upload ACKs and per-path congestion/size adaptation rather than copying Normal ARQ settings. |
| Download Reed-Solomon FEC | Optional client request, off by default; requires server support. | Original data is sent immediately. Enabled parity consumes bandwidth and computation; disabled sessions avoid FEC state. |
| Random DNS transaction IDs and injected NXDOMAIN handling | Already implemented. | These are not missing features that need another compatibility layer. |

Evidence: `internal/client/cottenmax.go:148` and `:256` (stream/config adapter),
`internal/client/http_proxy.go:132` (HTTP),
`internal/client/dns_listener.go:308` and `internal/cottenmax/dns.go:50` (DNS),
`internal/cottenmax/engine/client.go:1086` (bounded scouting), `:1151` (query IDs)
and `:1355` (NXDOMAIN), and
`internal/cottenmax/engine/session_fec.go:11` (FEC confirmation).

## Remaining differences and priorities

| Feature | Baseline difference | Cost and recommended priority |
| --- | --- | --- |
| Multiple simultaneously active domains | Max uses lazy domain failover for new connections, with independent sessions. Normal shares a session across its domain/resolver pool. | **High: experiment with independent streams across domains first.** Bound the total query budget and retain default failover. Additional sessions, discovery and socket state have a cost. |
| Authenticated server-advertised domains | Normal can learn and persist bounded standby domains; Max cannot. | **High: a low-frequency control feature.** Validate and authenticate additions before use; do not add polling to an idle tunnel. |
| Adaptive download FEC | Normal has loss-triggered FEC and parity controls; Max requests fixed session parameters. | **Medium: measure before adding.** Activate only when recovery saves more than parity costs. Loss measurement and retransmission remain necessary. |
| More DNS record carriers | Max carries TXT or switches to AAAA after qualifying REFUSED failures. Normal has configured carriers and adaptive selection. | **Medium: opt-in resolver compatibility trials.** Avoid sending useful traffic through unproven carriers. Different record packing can reduce payload capacity or increase queries. |
| Hard query-rate budgets | Normal supports total, resolver and domain caps; Max rejects these settings. | **Medium for throttled networks.** Useful throughput may improve under a real upstream cap, but a hard cap intentionally limits the send rate. Zero/default must remain off. |
| ZSTD/LZ4/ZLIB compression | Available in Normal, absent in Max. Normal skips small, high-entropy or non-shrinking output. | **Lower until workload evidence exists.** Plaintext can save bytes; TLS/media payloads may not. Sampling, codec work and compression framing have costs even when savings are small. |
| SOCKS5 UDP ASSOCIATE | Supported in Normal; explicitly rejected in Max. | **Separate feature project.** Needs authenticated datagram service/framing, bounded queues and expiration. Keep TCP sessions free of datagram state; measure latency and loss behavior separately. |
| General duplication and domain-diverse duplicate controls | Normal exposes these controls; Max has its own upload-tail duplicate behavior. | **Lower: avoid copying controls blindly.** Extra copies spend scarce DNS query and bandwidth budgets and can compete with FEC. |
| Normal encryption-method selector | Normal provides XOR, raw ChaCha20 and AES-GCM methods. Max uses its own authenticated packet cipher and ephemeral session keys. | **Benchmark alternatives without weakening the default.** XOR and raw ChaCha20 are unauthenticated and are not equivalent replacements for Max's AEAD. Compare CPU cost and actual tunnel goodput separately. |

Evidence: `internal/client/domain_rotation.go:108`,
`internal/udpserver/domain_rotation.go:74`, `internal/config/server.go:230`,
`internal/cottenmax/engine/session_fec.go:14`,
`internal/cottenmax/engine/client.go:996` and `:1262`,
`internal/client/carrier_selector.go:98`, `internal/config/tunnel_mode.go:38`,
`internal/compression/types.go:129`, `internal/client/socks_manager.go:254`,
`internal/security/codec.go:166`, and `internal/cottenmax/engine/crypto.go:38`.

## What multiple domains means

Normal builds the full configured domain/resolver connection pool
(`internal/client/client_utils.go:576`). Its server validates a session by
session ID, cookie and codec, rather than binding it to one served domain
(`internal/udpserver/server_session.go:51`). Normal data streams normally pin
a preferred connection for ordering, but can change that connection after
failure or pacing (`internal/client/stream_resolver.go:420`). Optional duplicate
copies can prefer different domains (`:237`). Normal does not simply round-robin
every packet of a stream across every domain.

Baseline Max starts one primary engine. Additional domains activate lazily
after failed or timed-out dials, and the successful domain becomes preferred.
Each domain has an independent authenticated session. Existing streams never
move or replay their bytes (`internal/cottenmax/domains.go:89` and `:183`). The
server also starts an independent engine per zone
(`internal/cottenmax/server.go:113`). Delegation to the same VPS does not make
those session tables shared.

An opt-in active-domain experiment can distribute **separate streams** across
authenticated domains without changing ordinary packet framing. This does not
make one stream survive a failed domain or increase the capacity of a single
stream. Shared-session packet scheduling across domains would require further
client/server ownership and session-state work.

Active domains need domain-specific size and health tracking, and an aggregate
query budget. Starting several ordinary engines with the full configured
`MaxInflight` each would multiply the permitted flight as well as session and
socket costs. A fair comparison must hold the total budget constant and include
a case where one domain is dead or much slower. A working single-domain default
must retain its existing startup and scheduling behavior.
