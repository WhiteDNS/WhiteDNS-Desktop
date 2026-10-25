# CottenMax traffic profiles

CottenMax clients can choose `full` or `low`. Use `low` when the DNS query volume
from Max needs to be reduced, including when a VPS provider reports excessive
packet rates. It trades speed and connection concurrency for lower traffic.
The existing `full` behavior remains the default.

```toml
TUNNEL_MODE = "cottenmax"
COTTENMAX_TRAFFIC_PROFILE = "low"
```

Restart or reconnect the client after changing the profile. To restore the
current unrestricted query rate, set `COTTENMAX_TRAFFIC_PROFILE = "full"`.
Values ignore surrounding whitespace and letter case; an empty or omitted value
means `full`. Unknown values are rejected. The equivalent command-line setting
is `--cottenmax-traffic-profile low`.

## What the profiles change

| Control | `full` | `low` |
| --- | --- | --- |
| Aggregate Max DNS query rate | No added rate ceiling | 100 queries/second, burst 4 |
| Outstanding queries per domain engine | Existing configured value, default 256 | At most 32; experimental parallel mode partitions one total of 32 |
| Queries outstanding on one resolver path | Existing configured value, default 256 | At most 8 |
| Concurrent streams per Max session | Existing client/server limits, up to 512 | At most 64, also subject to existing limits |
| New stream attempts | Existing behavior | 2/second, burst 4, shared across domains |
| Engine TCP/DoT resolver connection attempts | Existing behavior | 2/second, burst 2, shared across domains; transport-managed DoH/HTTP3/DoQ connections are excluded |
| Held response polling | Existing setting, default 500 ms | At least 1000 ms |
| Discovery healthy-resolver target | Existing setting, default 16 | At most 4 |
| Discovery workers and pacing | Existing settings, default 16 workers / 20 ms | At most 2 workers / at least 250 ms pacing |
| Initial configured resolver fanout | Existing behavior | Starts with 2; remaining endpoints stay eligible for paced checking |
| Discovery address-range sampling | Existing opt-in setting | Disabled, including when configured |
| Duplicate upload-tail queries | Existing recovery behavior | Disabled; ordinary retransmission remains active |

Smaller user-configured window or stream limits remain smaller. The low profile
applies its ceilings when creating the Max client; it does not rewrite the TOML
tuning values. Switching back to `full` restores those configured values.
Stream admission and engine TCP/DoT connection waits are cancellable by the
caller or client closure. Stream attempts include probes and fallback attempts,
so an unreachable destination does not bypass pacing by failing quickly. The
100-query/second budget and 2-new-stream/second budget are each shared across all
domains. The separate engine TCP/DoT connection budget is also shared across
domains, but does not govern connections managed by the DoH, HTTP/3 or DoQ
transport adapters. Queries sent through those adapters still consume the shared
100-query/second budget.

Separate domain sessions each retain their own stream ceiling. In the default
failover strategy, each domain engine also has its own outstanding-query ceiling
of at most 32; existing streams may remain active on an earlier domain after new
connections move elsewhere. This can exceed 32 outstanding queries across all
engines, while their aggregate query rate remains capped. The experimental
parallel strategy instead partitions one total outstanding-query budget of at
most 32 across the domain engines.

Full retains congestion control, retransmission, authentication, finite queues
and existing resource bounds. Its lack of an artificial query-rate ceiling does
not remove those controls.

The low query budget is shared across all domains, resolvers and transports
belonging to one Max client. It includes authentication and discovery queries,
size probes, retransmissions and ordinary data/held polls; any explicitly
duplicated query uses a token too. Upload-tail duplication is disabled in low.
Changing from UDP to TCP, DoT, DoH, HTTP/3 or DoQ does not create another Max
budget. The engine schedules queries before sending, so waiting for a budget
does not hold a session lock or count unsent traffic as lost.

The rate is a token-bucket ceiling, not an exact packet rate over every short
interval: an initial allowance and recovered idle allowance can send up to four
queries close together. Lost packets still consume tokens. DNS transport retries
outside the tunnel, recursive forwarding and network control packets can change
the packet rate observed at a VPS.

The budget governs tunnel query creation. A stalled TCP or encrypted transport
can later flush buffered work, so its wire packet spacing need not match the
scheduler exactly. Hostname resolution performed while loading a resolver
configuration also uses the operating system's normal DNS facilities.

## Client and server scope

This is a client-side traffic policy and does not require another wire protocol
or a new server setting. The server continues accepting both profiles with the
same domain and shared key. Every client that needs the lower traffic policy
must select `low`; one client cannot constrain other clients. For example, ten
busy clients can together generate about 1000 Max DNS queries/second before
recursive forwarding or transport effects. A server running other services also
has their traffic to account for.

Normal CottenDNS (`TUNNEL_MODE = "legacy"`) keeps its existing behavior. Generic
`QUERY_RATE_LIMIT_*` settings remain unsupported in Max and are rejected rather
than silently ignored; the dedicated traffic profile does not implement those
independent global, per-resolver and per-domain budgets.

Optional download FEC still works in both profiles. Its parity traffic consumes
the same available query/response capacity, so it can reduce useful speed under
the low budget. It is not automatically enabled by choosing either profile.

## Responding to a VPS notice

If a notice concerns scanning, distinguish the traffic source. Resolver
discovery is initiated by the client device; it does not make the CottenDNS
server scan the resolver list. VPS outbound destination connections come from
authenticated client stream requests. Low therefore also paces new stream
attempts, including failed targets, and disables random resolver-range sampling.
It does not add new port restrictions or establish that scanning caused a
particular notice. Clients choosing full, another application on the VPS, or
unsolicited incoming traffic remain outside one low client's policy.

Ask the provider for the reported direction, measured packets/second or
bytes/second, time window and the allowed threshold. Those details distinguish
high DNS query volume from a bandwidth allowance, many TCP connections, a DNS
configuration problem or another process using the VPS. Keep the notice and
compare the provider's measurements after applying `low` to the active clients.

The profile lowers client-generated DNS load; it does not establish a universal
safe VPS traffic level or guarantee provider approval. It is not an exact
bandwidth cap: resolver behavior, name/answer sizes, loss, active clients and
other server traffic determine the observed bandwidth. A server-wide provider
limit needs a separate aggregate deployment policy that accounts for all users.

## Expected tradeoffs

The maximum useful speed depends on payload capacity per DNS exchange, not just
the number of queries. Low can substantially reduce throughput and make large
resolver scans take longer. Authentication and probes compete with traffic for
the same budget; a slow or lossy resolver can therefore take longer to qualify.
Fully idle sessions retain the existing silence behavior. Local tests can verify
the scheduler and successful transfers, but only measurements from the affected
deployment can establish whether the provider's reported limit is satisfied.

## Measured load and speed

Measured implementation: `7934e3c2714627aa2b6ca9bf7058a5fb770ae9e2`.
Windows x64, Ryzen 7 6800H, Go 1.26.5, actual UDP DNS through a loopback relay
adding the stated latency/loss. Three sequential randomized repetitions per
case. Both modes use the original eight-byte-tag cipher, QNAME 101 and answer
512 bytes. Four connections use two domains in the experimental parallel mode;
input flight 128 is reduced by the low profile. Download payload is 128 KiB
total, upload 32 KiB total. Each received byte is checked.

| Workload | Full goodput | Low goodput | Full queries/s | Low queries/s | Query-rate reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| 80 ms download | 3.172 Mbps | 0.310 Mbps | 1034.7 | 97.8 | 90.5% |
| 80 ms upload | 0.322 Mbps | 0.0244 Mbps | 1313.4 | 99.3 | 92.4% |
| 120 ms download, 3% loss each way | 1.441 Mbps | 0.210 Mbps | 498.8 | 73.2 | 85.3% |

These are medians during the payload phase, with startup and connection opening
recorded separately. Congestion and loss can keep low below its allowed rate.
Both domains carried data in all profile cases. For the 80 ms cases, median
opening time for four connections increased from about 162 ms to 1.10 seconds
because new connection attempts are paced.

Low primarily spreads traffic over more time. It does not remove the cost of
transferring the same data: median query totals were 346 versus 331 for download
and 1069 versus 1066 for upload. Thus it addresses rate/burst pressure rather
than guaranteeing a smaller monthly data bill or eliminating a scanning report.

The current full profile also completed an 8 MiB single-connection loopback
download at median 68.139 Mbps (range 67.096–73.879), versus 68.040 Mbps
(66.267–73.907) for the retained prior laboratory binary. The 0.15% difference
and overlapping ranges show no detectable slowdown in this case; three samples
do not establish zero overhead for every workload. The prior binary is identified
by SHA256, not a claimed source commit. Nested-worktree Go VCS metadata is
misleading here; the metadata file explains the provenance limitation.

All **24 transfer measurements passed**, alongside ordinary/experimental engine
tests, configuration/runtime tests, client/server builds and vet. The full
[Go Test CI](https://github.com/WhiteDNS/CottenDNS/actions/runs/40210934076)
passed, including race and end-to-end checks. Focused UDP integration checks
also verify shared short-window pacing, cancellation, healthy transfers through
both domains, and continued resolver vetting under busy traffic.

See [raw runs](../experiment-results/traffic-profiles-windows-amd64/runs.jsonl),
[medians and ranges](../experiment-results/traffic-profiles-windows-amd64/summary.json),
[hardware/binary metadata](../experiment-results/traffic-profiles-windows-amd64/metadata.json),
and [the reproduction driver](../scripts/experiments/max_traffic_matrix.py).
These measurements do not reproduce a provider's abuse classifier, an affected
phone or an actual Shatel/VPS path.
