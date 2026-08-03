# CottenDNS — Improvement Design & Roadmap Menu

> Status: **proposal / menu**. Nothing here is implemented yet. The goal is to lay out
> every worthwhile improvement with enough detail to pick a roadmap. Each item lists
> **Problem → Proposal → Touch points → Effort → Risk → Payoff** so we can triage.
>
> Effort scale: S (≤½ day) · M (1–2 days) · L (3–5 days) · XL (>1 week).
> Payoff is rated specifically for the censorship/slow-link threat model in `AGENTS.md`.

---

## Theme A — Traffic shaping & DPI resistance (the "randomizer")

This is the headline area you asked about. Key framing: **randomize content/shape, not
timing.** The target network's DPI is entropy/protocol-based and the link is already
latency-starved, so anything that adds round-trips or delay is a bad trade. The current
on-the-wire fingerprints are:

1. Every tunnel query is **TXT** (`Enums.DNS_RECORD_TYPE_TXT`, hardcoded in
   [tunnel_query.go:24](internal/client/tunnel_query.go#L24) and [:36](internal/client/tunnel_query.go#L36)).
2. Every tunnel response is **TXT** (hardcoded in
   [transport.go:240](internal/dnsparser/transport.go#L240) / [:313](internal/dnsparser/transport.go#L313);
   extractor only reads TXT at [transport.go:599](internal/dnsparser/transport.go#L599)).
3. High-entropy, long subdomain labels (base32 of encrypted bytes) under a single zone.
4. High query volume concentrated on `Domains[0]` even though `DOMAINS` is a list
   (today the tunnel effectively uses `Domains[0]` — see
   [async_runtime.go:481](internal/client/async_runtime.go#L481),
   [client_utils.go:556](internal/client/client_utils.go#L556)).

### A1. Query-type rotation (upstream) — **cheap win**
- **Problem:** 100% TXT queries is a strong, trivially-matched signature.
- **Proposal:** Pick the question `qType` per query from a configurable weighted whitelist.
  Upstream data lives in the QNAME, so *the question type does not affect decodability* —
  the server already reads data from the name regardless of `qType`. Restrict to
  resolver-friendly types that public recursors reliably forward: `A, AAAA, TXT, CNAME,
  MX, HTTPS`. Avoid `NULL` (often dropped by recursors).
- **Touch points:** `tunnel_query.go` (stop hardcoding TXT), new
  `internal/client/qtype_policy.go`, config key `QUERY_TYPE_ROTATION` + weights, server
  acceptance list `IsSupportedTunnelDNSQuery` ([dnsparser/policy.go](internal/dnsparser/policy.go)).
- **Effort:** S–M · **Risk:** Low (see A2 caveat) · **Payoff:** High.

### A2. Matching multi-RR-type responses (downstream) — **the real work**
- **Problem:** A well-behaved recursive resolver expects the *answer* RR type to match the
  question. If A1 sends `qType=A` but the auth server answers TXT, some recursors reject or
  refuse to cache. So A1 is only fully safe once responses can match.
- **Proposal:** Add per-type response encoders + matching extractors:
  - `TXT` (current, best density for payload) — keep.
  - `CNAME` / `MX` / `NS`: RDATA is a DNS *name* → encode payload as base32 labels (lower
    density, looks ordinary).
  - `A` / `AAAA`: 4 / 16 payload bytes per record → low density, use as low-bandwidth
    "cover" traffic / small control responses, blends in best.
  - `HTTPS`/`SVCB`: arbitrary key-value params, decent capacity, very modern-looking.
- **Touch points:** `transport.go` (`BuildVPNResponsePacket`, new `buildXResponsePacket`,
  generalize `extractTXTAnswerPayloads` → `extractAnswerPayloads`), server response path
  ([udpserver/server_session.go](internal/udpserver/server_session.go)), wire-format
  versioning so old/new clients interop.
- **Effort:** L · **Risk:** Medium (wire-format change; needs interop tests) · **Payoff:** High.
- **Decision needed:** which 2–3 types for v1. Recommend **TXT + CNAME + A/AAAA**.

### A3. Domain rotation across the configured zone list
- **Problem:** `DOMAINS` is a list but volume concentrates on `Domains[0]`, so one zone
  carries the whole signature.
- **Proposal:** Round-robin / weighted spread of tunnel queries across all `DOMAINS`
  (with per-domain resolver-health awareness so a sick zone is skipped). Pairs naturally
  with the existing per-domain MTU caps in [mtu.go:316](internal/client/mtu.go#L316).
- **Touch points:** tunnel send path, balancer, MTU cap map.
- **Effort:** M · **Risk:** Low–Medium · **Payoff:** Medium–High.

### A4. Label-entropy reduction (optional, advanced)
- **Problem:** base32 labels are uniformly high-entropy — itself a statistical tell vs.
  real hostnames.
- **Proposal:** Optional dictionary/syllable codec that maps bytes to pronounceable-ish
  labels (lower density, higher realism). Make it a config-selectable codec alongside the
  existing `internal/basecodec`.
- **Effort:** L · **Risk:** Medium (density loss hurts the bandwidth budget) · **Payoff:**
  Medium — only worth it if statistical detection is observed.

### A6. Domain-diverse (multi-path) packet duplication
- **Problem:** The client already duplicates packets across N connections
  (`UploadPacketDuplicationCount` etc. → `selectTargetConnectionsForPacket`
  [stream_resolver.go:73](internal/client/stream_resolver.go#L73), picking unique
  connections via `balancer.GetUniqueConnections`). But "unique connection" today can mean
  the *same domain* via different resolvers, so duplicates may share a zone — losing both
  the redundancy benefit (correlated loss/blocking per zone) and the signature-spread
  benefit.
- **Proposal:** Bias duplicate selection toward **distinct domains** (a Connection is a
  `domain × resolver` pair — see `connectionsByKey` at [client.go:331](internal/client/client.go#L331)).
  When duplicating, prefer one connection per domain before doubling up within a domain.
  This makes the N copies traverse genuinely independent paths, which on a lossy link
  raises delivery probability *and* spreads the per-zone query volume (synergistic with A3).
- **Touch points:** `balancer.GetUniqueConnections` (add domain-diversity preference),
  `selectTargetConnectionsForPacket`, the cached stream connection plan
  ([stream_resolver.go:108](internal/client/stream_resolver.go#L108)), config flag
  `DUPLICATION_PREFER_DISTINCT_DOMAINS`.
- **Effort:** M · **Risk:** Low–Medium (interacts with the resend/preferred-connection
  logic; needs care so failover still works) · **Payoff:** **High** — directly targets the
  "packet loss is the norm" constraint while also helping DPI spread.
- **Note:** the bandwidth cost of duplication is real (every copy is another full query);
  this is a tuning lever, not a free win. Pairs with per-direction counts already in config.

---

## Theme B — Security / crypto hardening

### B1. Authenticated-encryption clarity
- **Problem:** Methods 1 (XOR) and 2 (ChaCha20) are **unauthenticated** — an active
  attacker can tamper undetected. Only AES-GCM (methods 3–5) provides integrity. This isn't
  documented and method numbering hides it. ([security/codec.go:81-100](internal/security/codec.go#L81))
- **Proposal:** Document the integrity guarantees per method; add a startup warning when a
  non-AEAD method is selected; consider ChaCha20-**Poly1305** as an authenticated stream
  option (it's in `golang.org/x/crypto`).
- **Effort:** S (docs+warning) / M (add ChaCha20-Poly1305) · **Risk:** Low · **Payoff:**
  Medium.

### B2. Key derivation
- **Problem:** `deriveKey` uses MD5 for method 3 and raw zero-padded key bytes for methods
  1/4 ([security/codec.go:367](internal/security/codec.go#L367)). Weak stretching of the
  shared secret.
- **Proposal:** Move to a single modern KDF (HKDF-SHA256, already pullable from x/crypto)
  for all AEAD methods, with a per-deployment salt. Keep back-compat behind a version flag.
- **Effort:** M · **Risk:** Medium (changes derived keys → coordinated client/server
  rollout) · **Payoff:** Medium.

### B3. Nonce-collision budget note
- AES-GCM uses a random 12-byte nonce per message (~2³² safe-message birthday bound). Fine
  today; document the limit and consider a counter+random hybrid if a single key ever does
  huge volumes. **Effort:** S · **Payoff:** Low (mostly documentation).

### B4. Expanded / modern AEAD cipher suite
- **Motivation (yours):** offer rarer, stronger encryption methods.
- **Honest framing — what this does and does NOT buy:** the chosen cipher is **invisible on
  the wire**. Ciphertext from XOR, ChaCha20, or AES-GCM is all uniformly high-entropy bytes
  that then get base32-encoded into DNS labels, so a censor's DPI cannot distinguish ciphers
  and a "rarer" method does **not** change the fingerprint or aid evasion. The real evasion
  levers are Theme A (query/response type, domain spread, label entropy). What a bigger
  cipher menu *does* buy is **cryptographic robustness and operator choice** — and it
  composes with B1 (authentication) and B2 (KDF).
- **Proposal:** Add modern AEAD options as new method IDs: **ChaCha20-Poly1305** (authenticated,
  fast in software — good default for the low-power routers this often runs on),
  **XChaCha20-Poly1305** (192-bit nonce → no nonce-reuse worry, simplifies B3), and
  optionally **AES-GCM-SIV** (nonce-misuse-resistant). Keep the method-ID scheme backward
  compatible; never silently remap existing IDs.
- **Touch points:** [security/codec.go](internal/security/codec.go) (`NewCodec` switch,
  `deriveKey`, `requiredDerivedKeyLength`), config `DATA_ENCRYPTION_METHOD` docs, codec tests.
- **Effort:** M · **Risk:** Low–Medium (must coordinate client/server method IDs) ·
  **Payoff:** Medium — security/robustness, **not** DPI evasion. Bundle with B1.

---

## Theme C — Code quality & maintainability

### C1. Decompose `asyncStreamDispatcher`
- **Problem:** ~400-line, 4–5-deep function in
  [dispatcher.go](internal/client/dispatcher.go) — the highest-risk concurrency code in the
  client, hard to review or test in isolation.
- **Proposal:** Extract `selectNextStream()`, `packControlBlocks()`,
  `buildOutboundTask()`. Pure refactor, behavior-preserving, add focused unit tests for the
  packing logic.
- **Effort:** M · **Risk:** Low–Medium (touches hot path; needs `-race` test pass) ·
  **Payoff:** Medium (de-risks all future scheduler work).

### C2. Split `transport.go`
- **Problem:** ~800 lines mixing query build / response build / chunk assembly / TXT
  extraction / name encoding.
- **Proposal:** Split into `query.go`, `response.go`, `txtchunk.go`, `name.go`. Naturally
  precedes A2 (multi-RR responses).
- **Effort:** S–M · **Risk:** Low · **Payoff:** Medium.

### C3. Small cleanups
- Remove the redefined `min` at [transport.go:796](internal/dnsparser/transport.go#L796) —
  Go 1.25 has builtin `min`/`max` (you already use builtin `max` elsewhere). **S/Low.**
- Rename `Stream_client` → `clientStream` (idiomatic Go); run a `staticcheck` pass and add
  it to CI alongside `go vet`. **S/Low.**

---

## Theme D — Performance (already strong; marginal)

### D1. Static analysis & allocation audit in CI
- Add `staticcheck` + `go test -bench` regression gate to the existing
  `.github/workflows`. Catches accidental allocations in the hot encode/encrypt path.
  **Effort:** S · **Payoff:** Medium (prevents regressions).

### D2. Verify zero-alloc on the multi-RR path
- When A2 lands, ensure the new per-type encoders reuse buffer pools like the TXT path
  (`appendLengthPrefixed*`). Add bench coverage. **Effort:** S (alongside A2).

---

## Theme E — Testing & validation

### E1. End-to-end interop test in CI
- **Problem:** `AGENTS.md` notes no integration/E2E test in CI (the bench tool is
  standalone). Wire-format changes (A2/B2) are risky without one.
- **Proposal:** Promote `scripts/bench` into a CI job that spins server+client, pushes
  traffic, and asserts throughput + correctness. Gate A2/B2 on it.
- **Effort:** M · **Risk:** Low · **Payoff:** High (unblocks safe protocol changes).

### E2. Cross-version interop matrix
- Once wire format is versioned, test new-client/old-server and vice-versa. **Effort:** M.

---

## Suggested roadmaps (pick one)

**Roadmap 1 — "DPI resistance first" (your stated interest)**
`C2 (split transport)` → `E1 (E2E test)` → `A1 (query rotation)` → `A2 (multi-RR responses)` → `A3 (domain rotation)`.
Rationale: refactor + safety net first, then the high-payoff anti-fingerprint work on solid ground.

**Roadmap 2 — "Cheapest visible win now"**
`A1` alone, answering with TXT but accepting the qtype-mismatch risk on lenient resolvers,
as a fast experiment — then decide if A2 is justified by real-world resolver behavior.

**Roadmap 3 — "Harden before extend"**
`B1` → `B2` → `C1` → then Theme A. Rationale: lock down crypto/integrity before changing
the wire format.

**Roadmap 4 — "Quality pass"**
`C1` + `C2` + `C3` + `D1` + `E1`. No behavior change; pure de-risking and developer-velocity.

---

## Open decisions for you
1. Which **response RR types** for A2 v1? (recommend TXT + CNAME + A/AAAA)
2. Is **active-attacker integrity** in scope, or is passive-DPI the only threat? (drives
   how far B1/B2 go)
3. Are we free to make a **breaking wire-format change** with coordinated client/server
   rollout, or must new clients interop with old servers? (drives versioning effort)
4. Which **roadmap** above — or a custom mix?
