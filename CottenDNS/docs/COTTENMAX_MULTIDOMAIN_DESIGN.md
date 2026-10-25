# CottenMax multi-domain experiment and future design

This document describes the experimental branch only. The connection-balancing prototype is implemented through the Go adapter API; the elastic limiter and shared-session alias design below are **unimplemented proposals**. Default CottenMax behavior is unchanged. This document makes no release or zero-performance-regression claim.

## Current behavior

| Mode | How domains participate | Existing stream after its domain fails |
| --- | --- | --- |
| Normal CottenDNS | Builds a pool of resolver/domain pairs. Stream data normally uses a preferred connection; balancing, resend failover and optional duplicate copies can choose other pairs. | Can select a replacement pair within the existing Normal session. This is not a claim that every packet is striped across all domains. |
| Default CottenMax | Uses a preferred domain and creates independently authenticated standby engines lazily when a new connection fails. | Remains attached to its original engine/session; application bytes are not replayed into a new connection. |
| Experimental parallel CottenMax | Assigns new independent connections by least-active count, with round-robin ties. More than one domain can carry traffic simultaneously. Failed opening attempts fall through to another domain; later openings can retry recovered domains. | Remains attached to its original engine/session, exactly as in default Max. |

Normal's active `DOMAINS` pool is distinct from `STANDBY_DOMAINS`, which are reserved for rotation after failed scans. See [`BuildConnectionMap`](../internal/client/client_utils.go), [`selectTargetConnectionsForPacket` and preferred-connection failover](../internal/client/stream_resolver.go), and [standby rotation](../internal/client/domain_rotation.go).

Default Max is implemented by [`domainFailover`](../internal/cottenmax/domains.go). The server currently starts a separate engine for each zone, so each domain owns a different session registry; see [`NewServer`](../internal/cottenmax/server.go).

## Implemented prototype and its limit

Set `cottenmax.ClientConfig.DomainStrategy = "parallel"` in the experimental Go adapter. Empty or `"failover"` preserves the default. This is not currently exposed as a new TOML, Android or desktop option.

The prototype partitions a single configured `MaxInflight` fairly across domains. For example, a total of 64 across two domains gives each engine 32, including HELLO, discovery, data and poll queries. The sum stays at 64; adding a domain does not silently double query capacity. Every domain requires at least one slot.

This fixed partition can leave capacity unused: one active flow on A cannot borrow idle B's 32 slots, and a failed B retains its allocation. It therefore cannot satisfy an unconditional requirement to add domains without reducing performance. Simultaneous independent flows and independent per-domain network limits are separate cases to measure.

[`DomainStats`](../internal/cottenmax/domains_parallel.go) reports configured domains, started/established state, active opening/connection reservations, successful assignment counts, flight allocations and resolver-path statistics. The [integration tests](../internal/cottenmax/domains_parallel_test.go) exercise actual loopback UDP DNS, simultaneous domain sessions, aggregate flight bounds, concurrent assignment, recovery and cancellation. A separate test blocks A after an application transfer: a new B connection works while the existing A stream reaches its read deadline without reassignment or replay. These tests establish behavior, not Internet throughput.

## Alternative: an elastic global flight limiter

Independent engines could share one optional limiter while retaining the full configured local ceiling. An engine could borrow all otherwise idle capacity, while the sum of live queries remains bounded. This would address fixed-partition waste but would not enable existing-stream migration.

Required integration points in [`engine/client.go`](../internal/cottenmax/engine/client.go):

1. Acquire a permit **before** `session.build`, QNAME-probe state changes, or HELLO send timestamps. Building a frame before a denied acquisition can strand bytes already recorded as sent. Tail duplicates need their own permit.
2. Give every pending query an independent ownership flag. Release exactly once on authenticated data/HELLO completion, declared loss, TCP-link failure or client close. Forged, truncated and unauthenticated error replies must not release early. Expired queries retained for late answers must not release twice.
3. Return permits on local construction failure. Closing or cancelling an idle owner must remove its wait entry and release its owned permits.
4. Maintain a FIFO queue of waiting engines, with one entry per owner. A queued competitor gets the next available acquisition before a fast engine refills its entire flight. Otherwise a lone engine may borrow the full budget.
5. Wake owners through nonblocking scheduler-channel sends. The limiter must never acquire another engine's mutex: engine-to-limiter is the only lock direction. Keep a queue position only while there is real unsent work blocked on budget; remove idle or closed heads so they cannot stall everyone.

A nil limiter must allocate nothing and take no shared lock on the default path. Optional branches and enabled-mode lock contention still require measurement. Tests must cover fairness, cancellation, late/duplicate answers, forged replies, TCP failure and close during acquisition. An inflight ceiling also does not replace a queries-per-second limit.

## Preferred future architecture: one session across verified aliases

For continuity of an existing stream, use one client engine/session with paths identified by resolver **and** domain, and one server session/HELLO registry shared across explicitly configured alias zones. Streams, packet numbers, ACK/replay state, FEC and query budgeting then remain shared. ARQ could retransmit pending stream bytes through another verified alias without opening or replaying an application connection.

The current [cryptographic transcript and packet authentication](../internal/cottenmax/engine/crypto.go) bind ephemeral keys, session identity and packet numbers, not the DNS suffix. Thus this architecture need not add a per-data-packet domain field. The DNS name already selects the alias. Client payload budgeting and query construction must use the selected path's zone; the server must parse the matched zone and generate its zone-specific empty answers correctly. See [DNS framing](../internal/cottenmax/engine/dnswire.go) and [server query handling](../internal/cottenmax/engine/server.go).

**Compatibility guard:** sharing a pinned identity key is insufficient. Old per-zone engines produce different live sessions even with the same key. Save the complete initial signed HELLO reply/transcript. Probe another alias using the **same client ephemeral key**, and require its complete reply to match before admitting that alias to the existing session. A shared server HELLO cache naturally returns the same reply. A mismatch must leave the primary session usable and mark that alias incompatible.

The current `onHelloLocked` marks a path successful before returning for an already established session; alias mode must validate the session match first. It must also avoid sending existing-session scouts into an unverified alias: an old zone can answer with a signed unknown-session response that would otherwise close the healthy session. Authenticate the alias with HELLO first.

This remains a coordinated client/server change. Bound resolver/domain path growth, TCP sockets and discovery work; keep MTU observations per domain while respecting shared physical-resolver limits. Preserve global server session/stream/queue limits when combining registries. Validate healthy single-domain throughput, shared and independent bottlenecks, loss, mixed old/new servers, and existing-stream cross-domain recovery before proposing it for release.
