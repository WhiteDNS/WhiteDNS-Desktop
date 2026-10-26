# CottenMax feature parity, multiple domains, and encryption measurements

Date: 2026-10-25. Branch: `experiment/cottenmax-parity-multidomain-crypto`.
Measured source: `8f691923844ddef398877a4cf34b7ff8fb541197`, based on released main `7db7b73658c791cce62300d29647e4d369d6e1e4`.

Later work on this branch adds an optional [low/full traffic profile](COTTENMAX_TRAFFIC_PROFILES.md) to reduce query volume and new-connection bursts. The 513 measurements below remain the original cipher/domain investigation at the source commit above; they are not low-profile measurements.

## Findings and recommendations

CottenMax can use multiple domains concurrently for separate connections. The prototype proves this with real UDP DNS traffic and verified data. It is not yet equivalent to Normal's ability to move an existing stream between domain paths. Its fixed division of the query budget also creates substantial regressions when only one domain has useful work. Do not enable this prototype by default.

Keep the current authenticated ChaCha construction as the tunnel-speed baseline. Hardware AES is cheaper in CPU time, but its larger authentication tag reduces useful bytes in small DNS queries. No tested replacement improved every workload. A wire-identical ChaCha allocation optimization is a better candidate for further investigation, although these runs do not establish a universal speed improvement from it.

For broader parity, prioritize authenticated domain refresh and a shared-session domain-path design. Adaptive FEC, compression, and additional DNS carriers should be optional and selected from measured network conditions. No evidence supports promising that all these features can be enabled with zero performance cost.

## Multiple-domain tunnel speed

Values below are median **application goodput in Mbps**, three runs per case. Each cell is **one domain → two parallel domains (change)**. All cases have an aggregate limit of 128 outstanding queries; parallel mode partitions it into 64 + 64. FEC is off.

| Network/workload | Windows x64 | Linux x64 | Linux ARM64 |
|---|---:|---:|---:|
| One connection, 80 ms RTT | 3.983 → 2.253 (-43.4%) | 3.677 → 2.238 (-39.1%) | 3.670 → 2.240 (-39.0%) |
| Four connections, 80 ms RTT | 4.511 → 4.709 (+4.4%) | 4.303 → 4.458 (+3.6%) | 4.484 → 4.458 (-0.6%) |
| Four connections, one shared 120 QPS limit | 0.328 → 0.280 (-14.4%) | 0.333 → 0.296 (-11.2%) | 0.342 → 0.297 (-13.0%) |
| Four connections, independent 120 QPS limit per domain | 0.336 → 0.606 (+80.3%) | 0.338 → 0.609 (+80.4%) | 0.337 → 0.627 (+86.0%) |
| Four connections, second domain blackholed | 4.506 → 2.417 (-46.4%) | 4.299 → 2.386 (-44.5%) | 4.481 → 2.348 (-47.6%) |

Two domains help when they expose genuinely independent capacity. They cannot double a resolver's shared bottleneck. The blocked-domain and one-connection cases expose wasted fixed partitions: the working engine cannot borrow the other engine's 64-query share. Simply doubling the total flight budget would confound that comparison and can overload constrained resolvers.

The existing two-domain failover mode was measured separately and remains in the raw summaries. Its unused standby is lazy; it does not aggregate domain capacity. Small differences from the one-domain baseline are measurement/congestion-timing variation, not evidence of a standby-domain speed feature.

The parallel prototype balances new connections by active connection count. Existing connections retain their original engine, packet-number space, ACK state, congestion state, and FEC state. Tests explicitly confirm that blocking an established connection's domain stalls that connection while a new connection can use the surviving domain; it does **not** migrate or replay the old connection. Normal uses a domain-by-resolver pool and can change an existing stream's selected path after failure; it does not blindly round-robin every packet either.

The preferred next design is one client engine/session with domain-specific paths and one server session registry shared by configured aliases. That preserves one flight budget and allows the existing ARQ stream to retransmit through another verified alias. A same-key check is insufficient: an alias must return the same authenticated HELLO transcript to prove it shares the live session. This refactor is a design recommendation, not implemented or benchmarked here. See [the domain design review](COTTENMAX_MULTIDOMAIN_DESIGN.md), including the smaller elastic-budget alternative.

## Encryption and actual tunnel speed

All alternatives preserve authenticated encryption and the existing packet-number header protection. `-12`, `-16`, and `-8` below denote authentication-tag bytes. AES-128-GCM uses a 128-bit key, not a 128-byte packet/tag. The stack-tag variant retains the exact original keys and wire bytes and removes one 16-byte tag allocation per packet.

At **80 ms RTT**, with QNAME capped at 101 and DNS answers capped at 512 bytes, each cell is **download / upload Mbps**, median of three:

| Matched laboratory cipher | Tag bytes | Windows x64 | Linux x64 | Linux ARM64 |
|---|---:|---:|---:|---:|
| Original ChaCha20-Poly1305-8 | 8 | 3.984 / 0.308 | 3.676 / 0.306 | 3.673 / 0.305 |
| ChaCha20-Poly1305-8, stack tag | 8 | 3.980 / 0.309 | 3.675 / 0.307 | 3.674 / 0.306 |
| AES-128-GCM-12 | 12 | 3.978 / 0.270 | 3.683 / 0.269 | 3.670 / 0.268 |
| AES-256-GCM-12 | 12 | 3.982 / 0.282 | 3.675 / 0.268 | 3.671 / 0.267 |
| AES-128-GCM-16 | 16 | 3.971 / 0.240 | 3.444 / 0.230 | 3.431 / 0.229 |
| Standard ChaCha20-Poly1305-16 | 16 | 3.976 / 0.231 | 3.667 / 0.230 | 3.676 / 0.229 |

AES-128-GCM-12 reduced upload goodput by about **12.4–12.5%** across these machines. Standard ChaCha with a 16-byte tag reduced it by about **25%**. Added tag bytes displace stream data and increase the query count: on Windows, AES-128-GCM-12 needed about 43,856 queries/MiB versus 37,568 for the original cipher in this upload profile. The observed penalty depends on name capacity, frame boundaries, ACK/congestion scheduling, and loss; tag size alone is not a universal percentage formula.

With **no added RTT or loss**, median download / upload Mbps was:

| Cipher | Windows x64 | Linux x64 | Linux ARM64 |
|---|---:|---:|---:|
| Original ChaCha-8 | 78.858 / 7.727 | 65.595 / 20.452 | 65.320 / 23.917 |
| ChaCha-8, stack tag | 79.815 / 8.025 | 65.391 / 21.027 | 65.570 / 24.055 |
| AES-128-GCM-12 | 64.841 / 6.909 | 64.603 / 17.740 | 64.983 / 21.456 |
| AES-256-GCM-12 | 65.700 / 7.034 | 64.521 / 18.034 | 64.567 / 21.740 |
| AES-128-GCM-16 | 64.228 / 5.613 | 64.132 / 15.397 | 63.890 / 17.947 |
| Standard ChaCha-16 | 65.141 / 5.715 | 64.051 / 15.029 | 63.750 / 17.277 |

The stack-tag variant's loopback upload medians improved by 0.6–3.9%, but it was not consistently better across all profiles: Linux x64 wide-name upload measured 1.074 versus 1.168 Mbps (-8.1%), and lossy samples varied substantially. Keep it experimental until that behavior is understood. These results do not justify changing the default cipher.

The wide-name profile uses QNAME 253 / answer 1232 bytes and showed much smaller tag-related speed differences, but those larger packets are not supported reliably by every resolver. The 120 ms / 3% request-loss / 3% response-loss profiles are retained with their full ranges in the summaries. Their short transfers and changing retransmission schedules produce large variance; they do not establish a reliable cipher ranking under loss.

### Packet CPU cost is a different measurement

Median nanoseconds for **200-byte upstream Seal / Open**, including packet-number protection, encryption/authentication, and allocations:

| Cipher | Linux x64, native | Linux ARM64, native | Linux x64, AES acceleration disabled |
|---|---:|---:|---:|
| Original ChaCha-8 | 657 / 614 | 1103 / 1057 | 687 / 636 |
| AES-128-GCM-12 | 333 / 250 | 526 / 473 | 1666 / 1627 |

Hardware AES roughly halved packet CPU cost here while still lowering small-query tunnel upload speed. Without AES acceleration, its cost rose sharply. Go documents that generic AES also lacks the hardware implementation's constant-time guarantee. The ARM runner is a Neoverse server CPU, not either affected Samsung phone; absolute speeds and hardware support must not be extrapolated to those devices. See [Linux packet details](../experiment-results/linux-crypto-notes.md) and [Windows packet details](../experiment-results/crypto-notes.md).

Normal's raw ChaCha20 and XOR modes were not transplanted: they do not provide the packet authentication required by Max's protocol. Plaintext and custom reduced-round ciphers were not used as speed candidates. Normal AES-192 was not measured; AES-128 and AES-256 bracketed the key-size comparison. Normal's cipher IDs and wire formats are not directly compatible with these Max suites.

Go's [GCM API](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize) supports 12–16-byte tags, [standard ChaCha20-Poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305) uses 16, and [the AES package](https://pkg.go.dev/crypto/aes) describes the hardware/constant-time distinction. No manual eight-byte GCM truncation or weaker custom cipher was introduced to force a favorable payload comparison.

## Feature parity and cost

Max already shares proxy entry points, authenticated local DNS/cache support, multiple resolver transports, resolver discovery/health, path sizing, byte-range ARQ, and optional client-requested download FEC. It does not need another copy of those mechanisms.

| Addition | Recommended approach | Performance boundary |
|---|---|---|
| Authenticated domain refresh | Bounded trusted updates through an infrequent control exchange; verify before activation | No new field in every data packet; refresh still has occasional traffic/CPU cost |
| Existing-stream domain failover | One engine/session across verified server aliases | Avoid separate congestion/FEC state and wasted fixed partitions; benchmark the refactor |
| Adaptive download FEC | Default off; reuse loss/RTT observations and enable only when recovery saves retransmission time | Parity consumes bandwidth; useful under loss, costly on clean paths |
| ZSTD/LZ4/ZLIB compression | Optional, bounded work; skip unsuitable data | Can help plaintext; TLS/media often offer little benefit and still cost CPU |
| Additional DNS record carriers | Probe/cache suitability, then select a usable carrier | Can improve compatibility; extra probes and less efficient encodings have a cost |
| Hard query budgets | Optional limits for throttled resolvers, using existing scheduler accounting | Intentionally trades peak rate for reliability |
| SOCKS5 UDP ASSOCIATE | Separate bounded authenticated datagram design | Additional framing/queues/expiry; not a free reuse of TCP streams |

See [the source-backed parity audit](COTTENMAX_FEATURE_PARITY.md) for code references and implementation priorities. Keeping new features disabled can preserve current behavior; enabling them requires workload-specific measurement. Compression, parity, duplication, and hard rate limits cannot all be described as free.

## What was built, validated, and isolated

- Added opt-in `ClientConfig.DomainStrategy = "parallel"`, connection distribution statistics, bounded aggregate flight partitions, failed-domain cooldown/recovery for new opens, and cancellation/close handling. Empty strategy and `"failover"` retain the existing default behavior. This is a Go API experiment, not an Android/desktop settings release.
- Added six matched cipher choices behind `-tags maxexperiment`. The ordinary build retains the original packet-cipher code with constant tag length and no experiment-selector branches. The optimized stack-tag choice is wire-identical; the other alternatives require matched laboratory endpoints and have no production negotiation.
- Added a real UDP DNS transfer harness and a sequential randomized matrix. Every transfer is byte-verified; uploads wait for a receiver confirmation. No plaintext is counted merely because it was accepted by a client buffer.
- Domain tests cover simultaneous use, balanced assignments, total flight limits, default lazy standby behavior, blocked-domain recovery, cancellation, close, and the explicit existing-stream migration limitation.
- Cipher tests cover both directions, every-byte tampering, truncation, wrong packet numbers/query bindings, replay suppression, and wire equality for the stack-tag optimization across varied sizes/keys/nonces/associated data. These are engineering checks, not an independent cryptographic audit.

All **513 transfer cases completed with zero failures**: 171 each on Windows x64, Linux x64, and Linux ARM64. Both Linux ordinary/experimental validation jobs passed. The existing full GoTest workflow also passed, including race and end-to-end checks. See [experiment CI](https://github.com/WhiteDNS/CottenDNS/actions/runs/40190515950) and [ordinary CI](https://github.com/WhiteDNS/CottenDNS/actions/runs/40190515902).

Main, production releases, mobile/desktop release branches, and the live server were not changed for this investigation.

## Reproduction and measurement limits

Go 1.26.5 was used throughout. Windows: Ryzen 7 6800H, 16 logical CPUs. Linux x64: four-vCPU AMD EPYC 9V45 VM. Linux ARM64: four-vCPU Neoverse-N2. Packet microbenchmarks use one Go worker, five 150 ms repetitions on Windows and three 100 ms repetitions on Linux. They report plaintext processing rate, not tunnel goodput. Windows power/temperature/background activity and hosted-runner scheduling were not controlled.

Every tunnel case runs in a fresh process, sequentially on each machine, with three repetitions in seeded randomized order. All comparisons use the tagged laboratory baseline; they do not separately quantify any selector overhead versus an ordinary production binary. Random incompressible payloads prevent compression from confounding cipher results. Authentication, optional-domain warmup, and stream opening are outside payload timing and recorded separately. The timer includes the transfer-start request and upload confirmation. Answers are actual DNS packets over loopback UDP, with a relay adding half the configured RTT in each direction and independently seeded loss; there is no Internet/ISP path in this harness.

Default matrix sizing: QNAME 101, answer 512, flight 128, one connection, FEC off. Crypto profiles: 8 MiB loopback download; 512 KiB loopback upload; 512 KiB download / 64 KiB upload at 80 ms; 256 KiB download / 32 KiB upload at 120 ms with 3% loss each direction; 128 KiB upload at 80 ms with QNAME 253 / answer 1232. Domain profiles: 512 KiB single-connection download; four 256 KiB downloads; four 64 KiB downloads under the shared or per-domain 120 QPS cap (burst 8); four 256 KiB downloads with the standby blackholed. Domain names are equal-length `a.test` / `b.test` on one server.

Peak outstanding queries are sampled every 10 ms and never exceeded 128 in these runs; the focused integration test also checks the aggregate cap at a smaller limit. DNS byte counts exclude UDP/IP/link headers. Raw runs retain actual loss/rate-drop counts, query counts per domain, assignments, timing, and errors. Three samples establish observed medians/ranges, not confidence intervals or universal no-regression guarantees. This does not reproduce Shatel censorship, the 4000-resolver Android list, phone thermal behavior, or the reported Android 14 connection failure.

```sh
git switch experiment/cottenmax-parity-multidomain-crypto
mkdir -p .bench
go build -tags maxexperiment -trimpath -o .bench/maxexperiment ./cmd/maxexperiment
python scripts/experiments/max_matrix.py --binary .bench/maxexperiment --output experiment-results/my-machine --runs 3
go test -tags maxexperiment ./internal/cottenmax/... -count=1 -timeout 180s
```

On Windows use an `.exe` binary path. Create `.bench` first if needed. Do not change the process-wide experimental cipher while any endpoint is alive. The Linux AES-disable experiment is packet-CPU-only; no software-AES tunnel matrix was measured. The retained Windows AES-disable attempt was ineffective and is explicitly labeled as such.

Raw bundles and all profile medians/ranges:

- [Windows runs](../experiment-results/windows-amd64/runs.jsonl), [summary](../experiment-results/windows-amd64/summary.json), [metadata](../experiment-results/windows-amd64/metadata.json).
- [Linux x64 runs](../experiment-results/linux-amd64/runs.jsonl), [summary](../experiment-results/linux-amd64/summary.json), [metadata](../experiment-results/linux-amd64/metadata.json).
- [Linux ARM64 runs](../experiment-results/linux-arm64/runs.jsonl), [summary](../experiment-results/linux-arm64/summary.json), [metadata](../experiment-results/linux-arm64/metadata.json).
- [Combined CSV](../experiment-results/tunnel-summary.csv), [CI artifact provenance](../experiment-results/ci-artifact-manifest.json).
