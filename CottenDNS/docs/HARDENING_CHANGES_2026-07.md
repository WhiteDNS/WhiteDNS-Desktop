# CottenDNS — Security & Robustness Hardening (July 2026)

A record of a focused hardening pass on CottenDNS: what each change fixes, how it
works, how it is wired into the data path, and how to operate it. Written to sit
alongside [ENGINEERING_CHANGES.md](ENGINEERING_CHANGES.md) — read that first for
the system model (client → recursive resolvers → authoritative server, TCP over
DNS). Every change here is additive with safe defaults, so existing deployments
upgrade cleanly (see [§8 Upgrade & compatibility](#8-upgrade--compatibility)).

**Date:** 2026-07-17
**Scope:** server + client binaries, config templates, tests.
**Net:** 19 files, +532 / −19. All packages build; `go vet` clean; full unit
suite green.

---

## Table of contents

1. [Encryption key no longer logged in cleartext](#1-encryption-key-no-longer-logged-in-cleartext)
2. [Active-session cap (default 2048, like TCP)](#2-active-session-cap-default-2048-like-tcp)
3. [Default admin (SOCKS5) password hardened](#3-default-admin-socks5-password-hardened)
4. [Super-FEC: loss-aware last-ditch recovery band](#4-super-fec-loss-aware-last-ditch-recovery-band)
5. [MTU-weighted mode: run at the highest MTU a viable subset supports](#5-mtu-weighted-mode-run-at-the-highest-mtu-a-viable-subset-supports)
6. [Transport MTU weighting is now goodput-aware](#6-transport-mtu-weighting-is-now-goodput-aware)
7. [Whole-code audit findings](#7-whole-code-audit-findings)
8. [Upgrade & compatibility](#8-upgrade--compatibility)
9. [Config quick reference (new keys)](#9-config-quick-reference-new-keys)

---

## 1. Encryption key no longer logged in cleartext

**Problem.** On startup the server logged the raw active encryption key at INFO:

```
🔑 Active Encryption Key: <raw key in cleartext>
```

Logs get shipped to aggregators, cached, tailed over SSH, and shoulder-surfed.
For a tool whose entire threat model is a hostile network operator, printing the
symmetric key into a log stream is a direct key-exposure path.

**Fix.** The server now logs only a **non-reversible fingerprint** — the first 8
hex chars of `SHA-256(key)` — via a new helper:

- `security.KeyFingerprint(key string) string` — [internal/security/encryption_key.go](../internal/security/encryption_key.go)
- Log line ([cmd/server/main.go](../cmd/server/main.go)):

```
🔑 Active Encryption Key Fingerprint: 1a2b3c4d (sha256; raw key never logged)
```

**Why this is enough.** Operators still get a stable identifier to confirm the
client and server loaded the *same* key (matching fingerprints), but the key
itself never enters the log stream. The client never logged the key; a scan for
`%+v` config dumps confirmed no other leak path.

**Operational note.** The one-line installer still prints the key **once** to the
operator's terminal at install time, read from the `0600` `encrypt_key.txt` file
(the operator needs it to configure clients). That is a deliberate one-time
console display, not a running log. The installer's readiness probe greps for the
substring `Active Encryption Key`, which the new line preserves — so the upgrade
flow is unaffected.

---

## 2. Active-session cap (default 2048, like TCP)

**Problem.** The session table was bounded only by the 16-bit session-ID space
(`maxServerSessionSlots = 65535`). Keeping tens of thousands of sessions alive is
far more memory/CPU load than one node should carry, and it makes session-init
floods cheap: an attacker could push the server toward 65k live sessions.

**Fix.** New server config `MAX_ACTIVE_SESSIONS` (default **2048**, the same
ceiling as `TCP_MAX_CONNS`), enforced at allocation time:

- `sessionStore.maxActiveSessions` threaded through `newSessionStore` —
  [internal/udpserver/session.go](../internal/udpserver/session.go)
- `allocateSlotLocked` refuses a new slot once `activeCount` reaches the cap,
  returning `ErrSessionTableFull` (the existing back-pressure error), so
  session-init requests past the cap are rejected until a slot frees.
- Wired from config in [internal/udpserver/server.go](../internal/udpserver/server.go);
  clamped to `1..65535` in [internal/config/server.go](../internal/config/server.go).

**Test.** `TestSessionStoreHonorsMaxActiveSessionsCap` fills the store to the cap
and asserts the next `findOrCreate` returns `ErrSessionTableFull`.

---

## 3. Default admin (SOCKS5) password hardened

**Problem.** The shipped default upstream-SOCKS5 credential was `admin` /
`123456` — the canonical weak default.

**Fix.** Default password changed to `C0tt0n-C@ndy-Cl0ud!` in both the code
default ([internal/config/server.go](../internal/config/server.go)) and the
shipped template ([server_config.toml.simple](../server_config.toml.simple)),
with an inline note that it is still a placeholder to change before enabling
`SOCKS5_AUTH`.

**Scope note.** This is the *upstream* SOCKS5 credential, used only when
`USE_EXTERNAL_SOCKS5 = true` **and** `SOCKS5_AUTH = true` (both off by default).
The new default affects **fresh installs only**; existing installs keep whatever
they set.

---

## 4. Super-FEC: loss-aware last-ditch recovery band

**Background.** Auto-FEC ([ENGINEERING_CHANGES.md §3](ENGINEERING_CHANGES.md))
turns on download-path Reed-Solomon parity once measured loss crosses
`FEC_AUTO_LOSS_THRESHOLD`, scaling parity to the loss up to `FEC_AUTO_MAX_PARITY`.
Under *pathological* loss two things went wrong: parity kept climbing without
bound toward a hopeless rebuild (server CPU/bandwidth burn), and there was no
distinct policy for "the link is basically dead, stop trying."

**Design.** A **Super-FEC** band sits on top of auto-FEC, defined by a loss floor
and ceiling (defaults 0.75 / 0.85). The parity policy is now banded:

| Measured download loss | Parity policy |
|---|---|
| `< FEC_AUTO_LOSS_THRESHOLD` for 1–2 windows | Relax toward base parity as anti-flap hysteresis |
| `< FEC_AUTO_LOSS_THRESHOLD` for 3 consecutive windows | Fully disengage FEC; raw ARQ with zero parity/encoding overhead |
| `threshold … FEC_SUPER_LOSS_FLOOR` | Normal `ParityForLoss` scaling, clamped to `FEC_AUTO_MAX_PARITY` |
| `FEC_SUPER_LOSS_FLOOR … FEC_SUPER_LOSS_CEIL` | **Super-FEC:** parity scaled to the *measured* loss, lifted above the auto ceiling up to `FEC_SUPER_MAX_PARITY` |
| `> FEC_SUPER_LOSS_CEIL` | **Drop, don't rebuild:** stop escalating, relax to base parity, leave the block to ARQ |

**Loss-aware, not a flat slam.** The key refinement: inside the band, parity is
`fec.ParityForLoss(blockSize, loss)` — so 76 % loss buys *less* parity than 84 %.
It is lifted above the normal `FEC_AUTO_MAX_PARITY` ceiling (that lift is the
whole point of "super"), capped by `FEC_SUPER_MAX_PARITY` (0 = the Reed-Solomon
hard limit for the block, computed by the new `fec.MaxParity(dataShards)`).

**Above the ceiling = protect the server.** Beyond `FEC_SUPER_LOSS_CEIL` the link
is treated as dead. Spending 20×+ parity to rebuild a block that will not arrive
only strains the server, so the encoder relaxes to base parity and the
unrecoverable block is left to ARQ — an explicit "drop instead of rebuild."

**Wiring.**
- `Stream_server.ConfigureSuperFEC(enabled, lossFloor, lossCeil, maxParity)` and
  the banded logic in `maybeAdjustAutoFEC` — [internal/udpserver/stream_server.go](../internal/udpserver/stream_server.go)
- Armed per download stream alongside auto-FEC in
  [internal/udpserver/server_session.go](../internal/udpserver/server_session.go)
- `fec.MaxParity` + exported `Encoder.Parity()` (for testability) —
  [internal/fec/fec.go](../internal/fec/fec.go), [internal/fec/stream.go](../internal/fec/stream.go)

**Tests** ([internal/udpserver/stream_fec_test.go](../internal/udpserver/stream_fec_test.go)):
- `…SuperFECIsLossAwareInBand` — higher in-band loss earns strictly more parity, and exceeds the auto ceiling.
- `…SuperFECRespectsMaxParityCap` — the band honors `FEC_SUPER_MAX_PARITY`.
- `…SuperFECDropsAboveCeiling` — above the ceiling, parity relaxes to base.
- `…SuperFECDisabledUsesScaledParity` — with Super-FEC off, normal scaling is unchanged.

---

## 5. MTU-weighted mode: run at the highest MTU a viable subset supports

**Problem.** The session runs at a single operating-point MTU. The default
adaptive selector (`selectMTUOperatingPoint`) maximizes `(upload+download) ×
pool-size`, which biases toward *including more resolvers at a lower MTU*. The
side effect: a resolver that can carry a much larger MTU gets **capped down to
the crowd's common denominator**. A fast resolver's headroom was wasted.

**Fix (MTU-weighted mode only).** When `RESOLVER_BALANCING_STRATEGY = 5`
(MTU-weighted), the session now selects the **highest** MTU that at least
`MTU_WEIGHTED_MIN_POOL` resolvers can sustain, demoting slower resolvers to the
backup tier. So high-capability resolvers actually run at their higher MTU.

- `selectMTUOperatingPointPreferHigh(conns, minPool)` — among all per-resolver
  `(upload, download)` candidates whose sustaining pool has ≥ `minPool` members,
  pick the largest download MTU (tie-break: larger upload, then larger pool).
  [internal/client/mtu_cluster.go](../internal/client/mtu_cluster.go)
- Selected via `Client.selectOperatingPoint`, used by both the startup
  `finalizeMTUSelection` and the mid-session `recomputeMTUOperatingPoint` —
  [internal/client/mtu.go](../internal/client/mtu.go)

**Redundancy guard.** `MTU_WEIGHTED_MIN_POOL` (default **2**) is the safety floor:
if no raised MTU keeps at least that many resolvers, the selector falls back to
the throughput-optimal point so a single fast outlier can never strand the
session. Higher value = safer/lower MTU; lower = more aggressive/higher MTU.

**Trade-off (honest caveat).** Download response sizing is a single session-wide
value the server negotiates at session-init; it cannot be per-resolver without a
protocol change. So "use a higher MTU" necessarily means *raising the session
point and moving slower resolvers to reserve* — trading a little pool breadth for
larger packets. That trade is opt-in: it only applies in MTU-weighted mode, which
an operator selects deliberately. All other balancing strategies keep the
throughput-optimal behavior unchanged.

**Tests** ([internal/client/mtu_cluster_test.go](../internal/client/mtu_cluster_test.go)):
- `…PreferHigh_RunsAtHighestSustainableMTU` — 2 fast + 50 slow resolvers: baseline picks the crowd (1000); prefer-high with minPool=2 raises to 8000.
- `…PreferHigh_FallsBackWhenPoolTooSmall` — only one resolver sustains the top MTU → falls back to the optimal point rather than stranding.

---

## 6. Transport MTU weighting is now goodput-aware

**Problem.** In MTU-weighted balancing, resolvers were selected with probability
proportional to raw download MTU. That *over-favors a resolver assigned a big MTU
it cannot actually sustain*: a high-MTU-but-lossy resolver got the most traffic
even though it drops a large share of packets at that size.

**Fix.** Selection weight is now **effective goodput = MTU × (1 − measured
loss)**, so a resolver is weighted by the throughput it can *really* deliver, not
its nominal size. A high-MTU resolver that is clean keeps full weight; one that is
lossy is automatically discounted toward its real capacity. A near-fully-lossy
resolver keeps a floor weight of 1 so it is never starved entirely and can
recover if its loss estimate improves.

- `mtuGoodputWeight(conn)` + updated `weightedByMTUConnection` —
  [internal/client/balancer.go](../internal/client/balancer.go)

**Test.** `TestMTUGoodputWeightDiscountsLossyResolvers`
([internal/client/balancer_test.go](../internal/client/balancer_test.go)) — a
1000-MTU resolver at 80 % loss (goodput ≈ 200) weighs less than a clean 500-MTU
resolver; floors and unknown-MTU cases hold.

---

## 7. Whole-code audit findings

A pass across ~32.7k lines / 73 test files. **Overall the codebase is clean,
well-tested, and well-documented:** no `panic()` on production paths, no
`TODO/FIXME/HACK` debt markers, `crypto/rand` used correctly (with `math/rand/v2`
only as a fallback and for cosmetic DNS-0x20 case jitter), consistent config
validation/clamping. The items below are recommendations, **not yet applied** —
they are interop- or CI-policy decisions for the maintainer.

### Worth acting on

- **Default cipher is XOR** (`DATA_ENCRYPTION_METHOD = 1`) on both client and
  server. XOR with a repeating key provides no real confidentiality — a genuine
  weakness for a censorship-evasion tool. Real ciphers already exist in the codec
  (2 = ChaCha20, 5 = AES-256-GCM). Recommend defaulting to ChaCha20 or
  AES-256-GCM. **Must be a coordinated client+server change** (or rely on the
  server's `ENCRYPTION_AUTO_DETECT`, already on). Left unchanged because it alters
  an interop-affecting default.
- **CI does not run `go test -race`** ([.github/workflows/go-test.yml](../.github/workflows/go-test.yml)).
  The code is heavily concurrent (atomics, mutexes, ~27 goroutines, sliding-window
  FEC counters). The Linux test job can run `-race` with cgo — recommend adding it.
  (It could not be run in the Windows dev environment: no gcc/cgo.)
- **`staticcheck` is `continue-on-error`** in CI. Fine as a bootstrap; promote to a
  required check once a clean run is confirmed so quality does not regress.

### Minor / optional

- The installer prints the encryption key to the operator console at install time
  ([server_linux_install.sh](../server_linux_install.sh)) — intentional and not a
  running log, but could be gated behind a `--show-key` flag.
- ~156 deliberately-ignored errors (`_ =`), mostly best-effort socket writes and
  `systemctl` calls; spot-checked and appropriate, not bugs.

---

## 8. Upgrade & compatibility

**Redeploy required: yes** — all fixes live in compiled code:

- **Server binary:** key-logging, session cap, Super-FEC.
- **Client binary:** MTU-weighted higher-MTU selection, goodput weighting.

**Config is backward-compatible.** The six new keys (`MAX_ACTIVE_SESSIONS`,
`FEC_SUPER_ENABLED`, `FEC_SUPER_LOSS_FLOOR`, `FEC_SUPER_LOSS_CEIL`,
`FEC_SUPER_MAX_PARITY`, `MTU_WEIGHTED_MIN_POOL`) are additive with safe code
defaults, and the TOML loader ignores unknown keys. So the **new binary reads an
old config fine** and applies every fix via defaults.

**`CONFIG_VERSION` intentionally not bumped** (server template stays `13`). The
one-line installer restores the operator's existing config when the version
matches, so an upgrade keeps `DOMAIN` and all custom settings *and* still gets the
new safe defaults from the new binary — no manual config edits needed. Bumping the
version would have forced a reconfigure for no benefit, since no migration is
required.

**Release note.** In non-local mode the installer pulls the latest GitHub release,
so a new release/build containing these commits must be published for existing
nodes to pick them up via the one-line script.

---

## 9. Config quick reference (new keys)

### Server (`server_config.toml`)

| Key | Default | Meaning |
|---|---|---|
| `MAX_ACTIVE_SESSIONS` | `2048` | Max concurrent live sessions; session-init past this is refused. Range 1..65535. |
| `FEC_SUPER_ENABLED` | `true` | Enable the Super-FEC extreme-loss band. |
| `FEC_SUPER_LOSS_FLOOR` | `0.75` | Loss fraction at which the Super-FEC band engages. |
| `FEC_SUPER_LOSS_CEIL` | `0.85` | Above this loss, stop rebuilding: relax to base parity, leave the block to ARQ. |
| `FEC_SUPER_MAX_PARITY` | `0` | Per-block parity cap inside the band. 0 = Reed-Solomon hard limit for the block. |

### Client (`client_config.toml`)

| Key | Default | Meaning |
|---|---|---|
| `MTU_WEIGHTED_MIN_POOL` | `2` | (MTU-weighted mode only) Min resolvers that must sustain a raised MTU before the session adopts it. Redundancy floor. |

*No default cipher or password change is silently applied to existing configs;
see §3 and §7.*
