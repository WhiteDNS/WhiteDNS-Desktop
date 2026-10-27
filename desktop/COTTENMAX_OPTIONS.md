# CottenMax options

Local development implementation, updated 2026-10-19. These options require the
updated client; CottenMax also requires the updated CottenDNS server. They do
not describe an already published release. Historical measurements remain in
[the dated performance record](COTTENMAX_PERFORMANCE_2026-10-19.md).

## One profile, two internal modes

CottenMax is a transport module inside the CottenDNS client/server, using the
existing delegated `DOMAINS` and `ENCRYPTION_KEY`. In an existing client profile:

```toml
TUNNEL_MODE = "cottenmax"
```

In Settings, choose **CottenDNS**, then **CottenMax**, and select **Full** or
**Low** in the traffic profile selector. Save and reconnect to apply a change.
The selected profile is preserved in app settings and TOML imports/exports:

```toml
COTTENMAX_TRAFFIC_PROFILE = "low" # or "full" (default)
COTTENMAX_LOW_REDUCTION_PERCENT = 35 # 10..90, used only in Low
```

Low exposes a **Speed reduction target** slider from 10% to 90%, default 35%.
This is an approximate target relative to Full; measured speed depends on the
network and resolver. Switching to Full retains the percentage for later and
ignores it.

Full retains the existing Max behavior. Low reduces DNS query starts, new
connection attempts, resolver discovery and pending query windows. Both use the
same authenticated protocol, key and Max server; no per-mode server setting is
needed. Existing profiles without this option continue to use Full. The rate
limits apply to one client, so a provider's total load also depends on how many
clients share a server. Performance depends on the resolver and network.

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

## Useful options adopted from the two audits

| Option | Implemented behavior | Default |
| --- | --- | --- |
| Encrypted resolver coverage | Normal and Max support explicit DoT, DoH, DoH over HTTP/3, and DoQ. | `RESOLVER_TRANSPORT = "auto"`: ordinary UDP with TCP fallback; encrypted transports are explicit. |
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

`WANT` and `CONCURRENCY` accept 1..64; pace accepts 1..60000 ms; extra candidates
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
| `COTTENMAX_MAX_INFLIGHT` | 256 | 1..1024 outstanding queries across paths. |
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
govern the Max engine. The [experiment guide](COTTENMAX_EXPERIMENT.md) describes
compatibility and test commands. Loopback tests do not establish reachability
or performance on a particular ISP.

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
