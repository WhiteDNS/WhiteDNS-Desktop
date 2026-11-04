# Production Normal / Max comparison

`cmd/normalmaxbench` runs unmodified production client/server executables on
loopback. A UDP DNS relay applies the same RTT, independent request/response loss,
maximum presentation-format question-name length, and maximum UDP DNS response
length to each mode. Oversize messages are dropped and counted. It opens no
external resolver or destination connection.

The final relay uses one deadline queue and one writer per direction. Packets
are released in receive-deadline order, so a requested zero-reordering path does
not acquire arbitrary reordering from concurrent per-packet timer callbacks.
The old `timer` relay remains available with `-relay-order timer` for reproducing
historical exploratory runs. Those datasets must not be pooled with ordered
results; the changed harness hash and `relay_order` result field identify them.

Both modes use the existing fixed TCP-forwarding interface, as in the project's
original integration benchmark. SOCKS deliberately rejects private destinations;
the harness does not weaken that policy. The target verifies seeded random,
incompressible payloads byte for byte. Normal retains its app preset,
compression, duplication, ARQ, worker, and MTU-discovery settings. All server FEC
modes and Max client FEC are explicitly disabled. Normal's LZ4 compression remains
enabled; incompressible data does not give compression an artificial advantage.

The desktop fixture is the app-rendered default Normal configuration with the
selected AES-256 method. The Android fixture records the app's Normal defaults,
including XOR and duplication 3/7. These ciphers have different guarantees: XOR
does not provide Max's packet authentication. The benchmark intentionally keeps
the real app choices, rather than slowing Normal with a different cipher.
`normal_encryption_method` in raw result options describes Normal only; Max
continues to use its production ChaCha20/Poly1305 packet protection and eight-byte
tag. The server is identical across cases: default preset, AES-256 default,
encryption auto-detection, and a public, fixed, non-secret benchmark credential.

Cold MTU discovery, authentication, transfer proof, stream opening, and target
readiness happen before payload timing and have their own counters. A target
readiness acknowledgement proves each connection reached the target. The timed
part includes a one-byte `G` start signal, payload, and a two-byte `OK` confirming
verification. No download bytes are prefetched before the timer. The handshake
and timing envelope is identical in all modes. The payload timer excludes process
startup and fixed-forward connection setup, so this is bulk tunnel goodput, not
time to first page.

Query rate counts starts at the client-facing relay, including retries and empty
polls. DNS byte counts exclude IP/UDP headers. A short connection-open wave can
exceed the Low profile's sustained two-dials/second limit because its burst is
four; the single-flow cases do not characterize sustained connection churn.
Startup failures remain failures, never zero-throughput ranking entries. The
stock CLI's minimum download MTU 1000 is incompatible with some bounded paths;
the main comparisons use the real apps' lower minima instead.

Build (PowerShell):

```powershell
$env:GOTOOLCHAIN='local'
go build -buildvcs=false -trimpath -o .bench/normalmax/normalmaxbench.exe ./cmd/normalmaxbench
go build -buildvcs=false -trimpath -o .bench/normalmax/client-percentage.exe ./cmd/client
go build -buildvcs=false -trimpath -o .bench/normalmax/server.exe ./cmd/server
```

The measured percentage-profile runs deliberately retain the server executable
built before percentage pacing was added, demonstrating compatibility with the
existing wire protocol. Its SHA-256 is captured in each metadata file.

```powershell
python scripts/experiments/normal_max_matrix.py `
  --output experiment-results/normal-max-percentage-wide `
  --client .bench/normalmax/client-percentage.exe `
  --modes normal-android normal-desktop max-full max-low-10 max-low-35 max-low-90 `
  --profiles healthy-wide-download healthy-wide-upload `
  --android-template scripts/experiments/normal_max_android.toml `
  --desktop-template scripts/experiments/normal_max_desktop.toml --runs 3
```

Each repetition randomizes case order with seed `9143 + repetition_index`;
payload/loss seeds are `3400 + repetition_index`. One process/case runs at a time.
Metadata captures binary/template hashes, source commit and tracked diff hash,
platform, CPU count, and `GODEBUG`. Full generated configs and logs remain in each
runtime directory. Summaries report medians and ranges of successful transfers.

These are controlled, local DNS experiments, not observations on physical phones,
Shatel, provider abuse-detection systems, recursive resolver farms, or congested
shared VPSs. The rate-reduction setting is a scheduler target, not a promise that
application goodput falls by precisely that percentage on every network or that
every Low setting is faster than every Normal configuration.

## Final ordered dataset

The final comparison in `experiment-results/normal-max-final/` combines fresh
wide and narrow measurements using the
**same harness, client and server executable hashes**. The client and harness
were rebuilt from the final validated core pin with `-buildvcs=false`; historical
exploratory cases are not pooled into the final dataset. The combining script rejects
duplicate cases, mixed executables, failures, non-ordered relays and incomplete
byte verification:

```powershell
python scripts/experiments/normal_max_matrix.py `
  --binary .bench/normalmax/normalmaxbench-final-77bf87db.exe `
  --client .bench/normalmax/client-final-77bf87db.exe `
  --server .bench/normalmax/server.exe `
  --output experiment-results/normal-max-final-wide `
  --modes normal-android normal-desktop max-full max-low-10 max-low-35 max-low-90 `
  --profiles bulk-wide-download bulk-wide-upload `
  --android-template scripts/experiments/normal_max_android.toml `
  --desktop-template scripts/experiments/normal_max_desktop.toml --runs 3

python scripts/experiments/normal_max_matrix.py `
  --binary .bench/normalmax/normalmaxbench-final-77bf87db.exe `
  --client .bench/normalmax/client-final-77bf87db.exe `
  --server .bench/normalmax/server.exe `
  --output experiment-results/normal-max-final-narrow `
  --modes max-full max-low-10 max-low-35 max-low-90 `
  --profiles bulk-narrow-download bulk-narrow-upload --runs 3

python scripts/experiments/normal_max_combine.py --inputs `
  experiment-results/normal-max-final-wide `
  experiment-results/normal-max-final-narrow `
  --output experiment-results/normal-max-final `
  --validated-core-pin 77bf87db28af6b64a4b6c404074982235272ed9b `
  --build-manifest .bench/normalmax/final-build-identity.json

python scripts/experiments/normal_max_summarize.py `
  --input experiment-results/normal-max-final `
  --output experiment-results/normal-max-final/comparison.csv

python scripts/experiments/plot_low_percentages.py `
  --csv experiment-results/normal-max-final/comparison.csv `
  --output docs/benchmarks/cottenmax-adjustable-low `
  --caption '80 ms RTT, one flow, no injected loss; 2 MiB download / 256 KiB upload; 3 runs per case. Error bars show observed ranges.'
```

The `*-final-77bf87db.exe` names refer to the fresh builds and commands recorded
in the committed `build-identity.json`; the server path refers to the retained
earlier executable. Rebuilding a server now is useful for new comparisons but
cannot reproduce the retained binary's exact hash. Plotting requires matplotlib.
Per-bundle metadata describes the worktree at run time and carries a generic
historical note about older binaries; the final build manifest and matching
hashes establish that every final client/harness was the fresh validated build.

Each bulk download transfers 2 MiB and each bulk upload 256 KiB. There are three
repetitions per mode and shape. Both app Normal configurations are measured on
the wide 253/1232 path; the narrow 101/512 path compares the four Max settings
without inventing an unmeasured Normal baseline. Normal Android uses its app
XOR configuration, Desktop its app-selected AES-256 configuration. The same
unchanged server auto-detects both and accepts all Max settings.

The final build manifest records the clean production source check, actual
engine source directory, build commands and executable hashes. These measurements
use the default UDP socket factory. Binary hashes identify exactly what was
measured, and the pinned source is separately covered by source tests and CI.
