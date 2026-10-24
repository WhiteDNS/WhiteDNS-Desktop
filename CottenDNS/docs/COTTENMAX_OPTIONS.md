# CottenMax options

Early beta implementation, updated 2026-10-21. These options require the
updated client; CottenMax also requires the updated CottenDNS server. Publishing
the beta source does not update the public latest release automatically. Use
matching Max-capable server and client builds. Historical local measurements
do not establish performance on a particular ISP.

## One profile, two internal modes

CottenMax is a transport module inside the CottenDNS client/server, using the
existing delegated `DOMAINS` and `ENCRYPTION_KEY`. In an existing client profile:

```toml
TUNNEL_MODE = "cottenmax"
```

The updated server accepts normal and Max clients on the same listener and
configuration. Keep `encrypt_key.txt`; no additional Max key, config file,
service or DNS delegation is required. The core adds `cottenmax-v1.` internally;
do not add that prefix to `DOMAINS`. Selecting `"legacy"` reconnects using the
normal engine. There is no automatic downgrade after an authentication failure.

Max derives its signing identity from the existing shared credential. Holders
of that credential share the identity trust boundary. Session encryption still
uses fresh X25519 keys and directional ChaCha20-Poly1305. Old explicit
`COTTENMAX_KEY_FILE`/`COTTENMAX_SERVER_PUBLIC_KEY` pairs remain a migration option;
remove both old settings to adopt the single-credential setup. Existing files
are not deleted. Normal-mode cipher settings/defaults have not changed.

## Session and per-client capacity

Normal CottenDNS and Max use the same server configuration. Session slots
are tunnel sessions, not user accounts or a guarantee of simultaneous users.
The existing shared credential does not identify individual people.

`MAX_ACTIVE_SESSIONS` bounds each mode's session table; Max divides its budget
across the configured Max domains. `MAX_STREAMS_PER_SESSION` controls normal
streams and also bounds Max. Max additionally uses `COTTENMAX_MAX_STREAMS`
(default **256**, allowed **1..512**). An updated client can use up to **512**
Max streams, further limited by its existing `MAX_ACTIVE_STREAMS`. Older
clients retain their old cap. No second key, service or configuration file
is needed. Restart the server after changing limits and reconnect clients.

For an intentional capacity increase on a standalone beta server:

```toml
MAX_ACTIVE_SESSIONS = 4096
MAX_STREAMS_PER_SESSION = 4096
COTTENMAX_MAX_STREAMS = 512
```

In CottenRouter's CottenDNS install/edit form, choose **expanded** in
**Capacity**, or add `--expanded-capacity` to the existing install/configure
command. This explicitly raises minimum server limits to 4096 sessions,
1024 normal streams/session and 512 Max streams/session. It preserves higher
custom limits. The Router TCP ceiling rises to at least 512, with 64 per source
IP; backend TCP limits rise to at least 1024 total and 512 per loopback source.
The backend sees Router's loopback address for every forwarded TCP connection;
its per-IP allowance therefore covers the full public Router connection budget.
Keep the form's existing domains and transport choices when configuring.
Leaving **keep** preserves existing capacity values, including on updates.

Query-rate, byte, queue, idle-timeout and global Max stream budgets remain
bounded and unchanged. Max's control queue reserves headroom for 512 streams;
active session admission still rejects excess streams. A local test transferred
byte-exact data over 300 simultaneous Max streams, above the former 256 cap.
This does not establish a 4096-user load capacity. Monitor RAM, CPU, descriptors
and rejection counters before increasing custom limits further.

## Useful options adopted from the two audits

| Option | Implemented behavior | Default |
| --- | --- | --- |
| Resolver transports | Normal and Max support UDP, TCP, explicit DoT, DoH, HTTP/3 and DoQ. Max Auto probes UDP/TCP independently and both can carry live traffic. | `RESOLVER_TRANSPORT = "auto"`; encrypted transports remain explicit. |
| HTTP/3 fallback | Optional fallback from HTTP/3 to TLS-protected DoH; never to plaintext DNS. | `RESOLVER_HTTP3_FALLBACK = false` |
| EDNS query padding | Pads queries in encrypted resolver modes only; does not request padded responses. | `DNS_PADDING_BLOCK_SIZE = 0` (off) |
| Custom resolver ports | UDP/TCP entries retain distinct ports on the same IP; exact duplicate endpoints collapse. | Omitted entry port means 53. |
| QNAME label-count shaping | Optional Max-only variation in the number of payload labels, with capacity reserved for extra separators. | `QNAME_LABEL_COUNT_JITTER = false` |
| Domain/VPS failover | Up to eight total active/standby domains, authenticated independent sessions, lazy backup activation for new dials. | Existing primary only; per-attempt timeout 3000 ms when backups exist. |
| Resolver diversity/discovery | Bounded, paced authenticated candidate testing; respects the selected address family. | Disabled; country unspecified; address-range sampling off. |
| Discovery persistence/bootstrap | Optional expiring resolver hints, isolated by domain, credential fingerprint, transport settings, family and explicit network label. | No persistence unless a cache base path is supplied. |
| Idle traffic discipline | Retains Soar held polls and fully idle silence instead of adding constant dummy beacons. | Hold 500 ms. |
| Adaptive startup/recovery | Conservative initial sizes, background size discovery, authenticated path learning, multipath congestion control, byte-range retransmission and implicit upload ACKs. | Enabled as part of Max. |

Encrypted resolver transports protect `client -> recursive resolver`. They do
not automatically encrypt `recursive resolver -> authoritative server`, hide
the zone from the resolver, or make a blocked server/domain reachable. New DoQ
and HTTP/3 support is on the client resolver hop; it does not add those listeners
to the CottenDNS authoritative server.

The resolver must actually support the chosen protocol/port and forward the
tunnel zone. Many resolver IPs can share one upstream or rate limit. Test the
authenticated tunnel from the affected connection rather than assuming a
successful ordinary DNS lookup proves the path.

## Larger healthy resolver pools and optional download FEC

Explicit candidate lists have no first-64 cutoff: every supplied resolver remains
eligible for authenticated checking. Discovery's `RESOLVER_DISCOVERY_WANT` can
now request 1..4096 distinct healthy resolvers (default 16). Candidate discovery
concurrency remains bounded at 64 and its pacing remains active. The optional
`COTTENMAX_MAX_INFLIGHT` global query window accepts 1..4096 (default 256), while
`COTTENMAX_MAX_PATH_WINDOW` remains 1..1024. A larger healthy resolver pool does
not require flooding every candidate or increasing the default query window.

Client-controlled download Reed-Solomon FEC is optional:

```toml
COTTENMAX_FEC_DOWNLOAD_ENABLED = false
COTTENMAX_FEC_DATA_SHARDS = 4
COTTENMAX_FEC_PARITY_SHARDS = 1
```

Enable it only with an updated FEC-capable CottenDNS server. It is independent
of the Normal-mode server FEC settings. The client requests the parameters in
an authenticated session control frame, and the server confirms them in an
ordinary answer. No new HELLO round trip is added. With FEC off, no FEC frames,
source headers, parity queries, or decoder history are created; existing Max
servers remain compatible. FEC on requires confirmation and never silently
claims recovery support from an older server.

Configured data blocks are 2..16 packets with 1..4 recovery shards. Original
data leaves immediately and carries no FEC header. Separate encrypted parity
frames identify existing packet numbers, split to the actual DNS-answer budget,
and recover lost download frames before ARQ retransmission when enough shards
arrive. Short tails flush without waiting for unrelated traffic. Histories and
repair queues are bounded; parity is best-effort, is not protected by more
parity, and uses already solicited DNS answers. Existing ARQ remains the fallback.
Upload traffic continues to use the existing ARQ mechanism.

Parity consumes real bandwidth and answer slots: 4 data / 1 parity is a useful
starting point, not a free speed increase. Metadata and MTU fragmentation add to
the nominal 25% parity ratio. Keep the default off on healthy or bandwidth-bound
paths; test it on the affected lossy connection before retaining it. The global
query and congestion ceilings remain in force with FEC enabled.

## Resolver lists and compatibility

A resolver list is a candidate pool, not a list of guaranteed tunnel paths.
CottenMax can consider the complete Android bundled list, including thousands
of entries. It rotates bounded checks across unverified candidates while giving
authenticated paths priority for real traffic. It does not wait for every entry
to finish before connecting, and large lists cannot reserve every in-flight
query slot for discovery. Healthy paths retain their configured congestion and
in-flight ceilings; no smaller global window is imposed as a workaround.

A compatible resolver must be reachable from the current network using the
selected transport and port, recurse to the complete `cottenmax-v1.` tunnel
subtree, and preserve the encoded query and response. Max starts with TXT
answers and can use its indexed AAAA carrier after an explicit TXT refusal.
An ordinary A lookup, ping, or successful Normal-mode scan does not establish
Max support. The authoritative test is a verified server handshake followed by
an exact upload/download challenge for the actual domain, credential, network,
and transport. A resolver that filters TXT without an explicit refusal may
still be unsuitable; encrypted transports also require endpoint support and
valid certificate verification.

Use **CottenMax** when scanning a Max profile. Auto scans test UDP and TCP
independently across the entire supplied list, with bounded workers. Slow
successful authentication receives a fresh bounded transfer-check deadline;
optional large sizing does not invalidate a successful small transfer. A full
scan of thousands of unreachable endpoints can take a long time. Keep known
working results in the profile while retesting other candidates; reachability
can differ by ISP and change over time.

Size-discovery queries remain fully padded to the trial length but carry no
application data, so a rejected large-QNAME trial does not strand the startup
challenge or real stream data. Verification errors identify stream opening,
challenge writing, or reply reading to distinguish those failure stages.

## UDP/TCP connections and authenticated MTU scans

With `TUNNEL_MODE = "cottenmax"`, `RESOLVER_TRANSPORT = "auto"` creates
independent UDP and TCP DNS paths for each configured or discovered resolver.
Both carry the actual tunnel streams into the existing device proxy; this does
not add application UDP proxying. A working UDP path does not hide a TCP-only
resolver elsewhere in the pool. Authentication, congestion windows, query-name
capacity and answer-size learning stay separate for each transport. The live
scheduler selects paths using delivered replies, latency, loss and available
window, and recovers in-flight stream data when a path fails.

Select `"udp"` or `"tcp"` to test or pin one DNS transport. Explicit encrypted
resolver modes retain their protocol and TLS verification; they never acquire
plaintext UDP/TCP siblings. Concurrent TCP/TLS handshakes are bounded, and the
local proxy starts without waiting for a full scan. A short startup handshake
learns usable paths immediately instead of waiting for the first proxy request.

The standalone scan now supports Max:

```bash
./client -config client_config.toml -resolvers client_resolvers.txt -scan-only
```

In Auto mode it tests both transports per resolver with separate deadlines and
sessions. It authenticates the server, verifies a small byte-exact transfer,
then sends a bounded sizing transfer. Update the beta server too: its internal
authenticated probe endpoint needs no new service, key or outbound connection.
The scan opens no local proxy or DNS listener. Existing clients can still use
ordinary Max streams with the updated server.

`WD_SCAN event=path` reports `transport`, `authenticated`, `transfer_verified`,
`qname_bytes` and `answer_bytes`. Sizes are conservative **observed DNS wire
sizes**, not plaintext application MTUs or a claim that every configured
ceiling was reached. Runtime sizing continues to adapt on real traffic. A slow
path that passes the small transfer remains usable if its sizing deadline runs
out. A handshake alone does not count as a usable scan result.

Resolver totals count each endpoint once if either selected transport works.
Discovery's desired resolver count and candidate concurrency also count distinct
endpoints, while keeping their UDP/TCP capabilities separate. Scans use the
configured resolver parallelism, capped at 16 simultaneous path probes; normal
startup continues without this scan. Desktop's CottenDNS scanner uses the selected
Normal/Max settings and resolver transport. Android's scanner preserves the
profile's mode and optional Max settings.

## Encrypted resolver examples

These are additions to an existing profile, not complete replacement configs.
Use actual cooperating resolver IPs and certificate names. All configured
resolvers share the TLS name/pin, protocol port and DoH path settings.

```toml
RESOLVER_TRANSPORT = "doh3"
RESOLVER_DOH_PORT = 443
RESOLVER_DOH_PATH = "/dns-query"
RESOLVER_TLS_SERVER_NAME = "resolver.example"
RESOLVER_TLS_INSECURE_SKIP_VERIFY = false
RESOLVER_HTTP3_FALLBACK = true
DNS_PADDING_BLOCK_SIZE = 128
```

For DoQ, instead select:

```toml
RESOLVER_TRANSPORT = "doq"
RESOLVER_DOQ_PORT = 853
```

Keep the appropriate TLS verification settings. `"doh"` selects TLS DoH without
HTTP/3; `"dot"` uses `RESOLVER_DOT_PORT` (default 853). Resolver addresses are
numeric IPs, avoiding an implicit system-DNS bootstrap lookup. A trusted
`RESOLVER_TLS_PIN` pins the resolver certificate's SPKI; it is not a new tunnel
key. Max refuses unverified encrypted DNS without a pin.

TLS/QUIC setup can add cold-start latency. Connections are reused for later
queries; measure an optional transport before replacing a working one.

HTTP/3 and DoQ require usable QUIC/UDP connectivity. QUIC requires support for
UDP payloads of at least 1200 bytes; they cannot replace ordinary DNS on every
restricted path. See [RFC 9000 section 14](https://www.rfc-editor.org/rfc/rfc9000.html#section-14),
[DoQ RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html), and
[HTTP/3 RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html).

Padding accepts 0 or 16..4096 bytes and is rejected for plaintext/auto modes.
It adds bandwidth and may affect packetization; it reduces some length leakage
on the encrypted hop, not all traffic analysis. Existing EDNS padding is
preserved. See [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830.html#section-6).

For custom ordinary UDP/TCP resolver ports, a resolver file may contain:

```text
192.0.2.53:53
192.0.2.53:5353
[2001:db8::53]:5353
```

These are documentation addresses: replace them with resolvers you operate or
are permitted to use that actually listen there. Encrypted modes instead use
the protocol-wide `RESOLVER_DOT_PORT`, `RESOLVER_DOH_PORT` or `RESOLVER_DOQ_PORT`;
different entry ports do not select independent encrypted endpoints. Public NS
delegation does not specify an authoritative port; ordinary recursive traffic
still reaches authoritative DNS on port 53.

## Domain failover

```toml
TUNNEL_MODE = "cottenmax"
DOMAINS = ["v.example.com"]
STANDBY_DOMAINS = ["t.other.example"]
COTTENMAX_FAILOVER_AFTER_MILLISECONDS = 3000
```

Each domain needs working delegation to an updated server with the same
existing encryption key. `DOMAINS[0]` starts first; additional `DOMAINS` and
`STANDBY_DOMAINS` are ordered alternatives. Backups activate lazily after a
failed/timed-out attempt, so the primary's normal startup avoids an extra scan
or handshake. The last successful domain is preferred for subsequent dials.

The timeout range is 100..60000 ms. Increase it if a usable path needs longer
to establish or confirm a destination. Failover does not move established
streams, replay application bytes, stripe across servers, or copy session
tables between VPS instances. Applications must reconnect failed streams.
Automatic server-advertised domain updates remain a normal-mode feature.

## Resolver discovery and optional cache

```toml
RESOLVER_DISCOVERY_ENABLED = true
RESOLVER_DISCOVERY_COUNTRY = "IR"
RESOLVER_DISCOVERY_CANDIDATES = ["192.0.2.53:5353"]
RESOLVER_DISCOVERY_WANT = 16
RESOLVER_DISCOVERY_CONCURRENCY = 16
RESOLVER_DISCOVERY_PACE_MILLISECONDS = 20
RESOLVER_DISCOVERY_SAMPLE_RANGES = 0
RESOLVER_DISCOVERY_CACHE_FILE = "resolver-hints.json"
RESOLVER_DISCOVERY_NETWORK_ID = "home-network"
```

Replace the documentation address with an actual candidate. Discovery uses
cached/extra candidates, readable system resolvers and bundled country/global
lists. It does not run a full startup scan before an explicit working path can
connect. On platforms where `/etc/resolv.conf` is unavailable, system-resolver
discovery is unavailable; bundled/explicit candidates still work. A missing or
empty resolver file is permitted only for opted-in Max discovery with usable
candidates. Discovery does not promise the bundled candidates speak your
selected encrypted transport or match its configured TLS identity.

`WANT` accepts 1..4096 and `CONCURRENCY` 1..64; pace accepts 1..60000 ms; extra candidates
are limited to 256 endpoints. Range sampling accepts 0..4096 and is a separate
explicit opt-in; zero does not sample address ranges. Pacing limits candidate
addition, not the total tunnel query rate.

The cache is optional: an empty path or disabled discovery produces no cache
writes. A relative path is resolved beside the config. A 24-character opaque
scope suffix is appended to the base path for each domain/profile/network
scope. Each file holds at most 256 endpoints/64 KiB, expires after 24 hours,
and is replaced atomically using POSIX mode 0600 where supported. Corrupt,
stale, substantially future-dated and mismatched cache files are ignored. Raw credentials,
domain names and network labels are not stored. Old scope files can be removed
when no longer needed; they are not automatically deleted.

Cached endpoints must authenticate again on every run. The optional network
label is supplied by the user/app, not inferred reliably from the network.
Change it when switching networks if separate hints are desired. Offline
resolver files and existing profile/link import remain available; authenticated
automatic remote profile/list updates are not implemented here.

## Performance controls and limits

| Setting | Default | Accepted range / behavior |
| --- | --- | --- |
| `COTTENMAX_QNAME_LOSS_GUARD` | false | Experimental authenticated near-cap loss guard; see below. |
| `COTTENMAX_SAFE_QNAME` | 101 | 64..253; must fit the domain and handshake. |
| `COTTENMAX_MAX_QNAME` | 253 | At least the safe size, at most 253. |
| `COTTENMAX_MAX_ANSWER` | 1232 | 512..1232 bytes; paths still begin conservatively. |
| `COTTENMAX_MAX_PATH_WINDOW` | 256 | 1..1024 queries per path; congestion control grows from a small window. |
| `COTTENMAX_MAX_INFLIGHT` | 256 | 1..4096 outstanding queries across paths. |
| `COTTENMAX_SESSION_IDLE_MILLISECONDS` | 90000 | 1000..90000; retires idle sessions before server expiry. |
| `COTTENMAX_HOLD_MILLISECONDS` | 500 | 0..1500 in 100 ms steps; 0 disables held polls. |
| `QNAME_LABEL_LENGTH` | 63 in default config | 16..63 for Max; presets/explicit values may change it. |
| `QNAME_LABEL_COUNT_JITTER` | false | Optional extra labels reduce payload capacity. |

`COTTENMAX_QNAME_LOSS_GUARD = true` is an explicit experiment, off by default.
It delays a loss-triggered name-size downgrade while a near-cap query received
an authenticated answer within one current path RTO. Smaller replies cannot
keep a larger cap alive; stale proof restores the original safe-size fallback.
Congestion control and retransmission remain active. Paired local trials found
lower query cost on the tested random-loss path but slower transfers on one
healthy delayed path. It is not a general speed preset; keep it off unless
measurements on the affected connection justify it.

Larger windows or smaller labels are not universally faster. Keep defaults
unless repeatable measurements justify an override. Max keeps authenticated
size adaptation, TXT/AAAA fallback and fully idle silence; the new optional
features do not replace its reliability machinery. Transparent fixed-forward
and local DNS streams pipeline OPEN/data; SOCKS/HTTP still await confirmed
destination success. Local DNS completes the first cold request directly.

Hard `QUERY_RATE_LIMIT_*` budgets and SOCKS UDP ASSOCIATE remain unsupported in
Max. Normal-mode compression/FEC/duplication/carrier-selection settings do not
govern the Max engine. Validate the beta on the actual device and connection,
including reconnects and network changes. Loopback tests do not establish
reachability or performance on a particular ISP.

## Deferred options

| Audit proposal | Status |
| --- | --- |
| DNSCrypt | Not implemented; needs resolver identity/bootstrap and a separate transport adapter. |
| Early keyed admission before HELLO / active-probe resistance | Not implemented; needs a wire-compatibility and overhead plan. Max still answers recognizable valid HELLO probes before stream admission. |
| Authenticated automatic resolver/profile updates | Deferred; needs expiry, versioning and rollback protection. Discovery caches are not remote configuration updates. |
| Max NULL/HTTPS/SVCB/private RR carriers | Deferred pending resolver/goodput tests. Normal mode retains its existing NULL/HTTPS/SVCB options. |
| Anycast/CDN authoritative hosting and cross-server striping | Deployment/session-state work; not provided by the client failover option. A conventional web CDN is insufficient. |
| Cover queries, constant beacons and OS traffic mimicry | Not enabled; bandwidth/battery cost and detection benefit need measurements. |
| TTL/SOA/order/count/other tiny field channels, cache storage and logging-service relays | Not added to the bidirectional tunnel; normalization, capacity and reliability problems remain. |

Correct authoritative DNS behavior and existing offline bootstrap/import paths
are retained. No claimed whitelist immunity, censorship guarantee, automatic
DNSCrypt selection, arbitrary domain fronting or new non-DNS relay is included.
