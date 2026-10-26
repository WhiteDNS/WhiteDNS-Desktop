# CottenMax cipher laboratory notes

The ordinary build still compiles the original eight-byte-tag ChaCha packet implementation. The experimental selector is compiled only with `-tags maxexperiment`. Do not select a new suite while any endpoint is alive. Both laboratory endpoints must use the same suite; there is no on-wire negotiation and alternatives are not compatible with released servers. The stack-tag suite is intentionally wire-identical to the original.

Machine: AMD Ryzen 7 6800H, 8 cores / 16 logical processors; Go 1.26.5 Windows/amd64. Five repetitions, 150 ms per benchmark, one worker, normal crypto acceleration. Power state, temperature and background OS activity were not controlled. Report medians and raw ranges, not a universal speed guarantee.

Measurements include the actual packet number header protection, nonce, authentication, allocation, and traffic encryption/decryption. `testing.B` MB/s counts plaintext bytes and is **not DNS tunnel goodput**. The separate end-to-end harness is required before deciding tunnel speed.

| Laboratory suite | Tag bytes | Upstream Seal/Open, 200 B (ns) | Downstream Seal/Open, 1200 B (ns) |
|---|---:|---:|---:|
| chacha20-poly1305-8 | 8 | 869.1 / 763.6 | 2780.0 / 2531.0 |
| chacha20-poly1305-8-stacktag | 8 | 817.5 / 747.8 | 3567.0 / 2664.0 |
| aes-128-gcm-12 | 12 | 614.1 / 359.4 | 875.9 / 672.9 |
| aes-256-gcm-12 | 12 | 397.6 / 329.1 | 946.1 / 706.9 |
| aes-128-gcm-16 | 16 | 391.1 / 318.5 | 913.7 / 660.6 |
| chacha20-poly1305-16 | 16 | 463.9 / 393.1 | 2164.0 / 1036.0 |

The stack-tag experiment removes exactly one 16-byte tag allocation per packet; it changes neither algorithm nor bytes. It is not uniformly faster in this noisy desktop run, so do not promise a tunnel speed increase from it. AES and standard ChaCha have much faster packet-CPU paths here, but require four or eight additional tag bytes. At a fixed DNS payload budget those bytes displace useful data; a CPU-only gain can coexist with lower tunnel throughput. The relative ordering of AES-128 and AES-256 is too noisy to rank from this run.

Validation: all suites passed upstream/downstream round trips, modification of every packet byte, truncation, wrong expanded packet-number authentication, wrong-query reply binding, and session replay suppression. The stack-tag implementation matched both the original and standard ChaCha truncated to eight tag bytes across 1,233 plaintext lengths x 8 associated-data lengths, plus 128 distinct random keys with varied nonce/AD/data. These are engineering checks, not an independent cryptographic audit.

The original implementation was moved verbatim to `crypto_cipher.go` under `!maxexperiment`; source comparison against branch HEAD confirmed exact equality of its packet-cipher functions. The normal compiler still sees constant tag size and no suite-selection branches.

No plaintext/XOR or reduced-round custom cipher was added. AES-GCM uses Go standard-library AEAD; standard ChaCha uses golang.org/x/crypto AEAD; all retain existing ChaCha packet-number header protection to isolate traffic-AEAD cost. Alternative cipher traffic keys are domain-separated by the suite name.

A second five-repeat run requested `GODEBUG=cpu.aes=off,cpu.pclmulqdq=off`, but the installed Go 1.26.5 Windows runtime does not honor those flags at CPU initialization. It is saved as `crypto-packet-windows-godebug-ineffective.txt`, **not a software-AES result**. `runtime/proc.go` initializes CPU flags before Windows environment acquisition; a standard-library AES check still measured AES-128 at 7.491 ns per 16-byte block.

Primary API sources: [Go cipher.NewGCMWithTagSize](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize) supports 12-16-byte tags; [Go ChaCha20-Poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305) has a 16-byte tag. [Go AES](https://pkg.go.dev/crypto/aes) documents that generic software AES does not provide the hardware implementation's constant-time guarantee. Thus a generic/software AES fallback should not be treated as an automatically suitable deployment choice.

Reproduce the packet measurements:

```powershell
go test -tags maxexperiment ./internal/cottenmax/engine -run "^$" -bench "^BenchmarkExperimentPacketCrypto$" -benchmem -benchtime 150ms -count 5 -cpu 1
go test -tags maxexperiment ./internal/cottenmax/engine -run TestExperiment -count 1 -timeout 90s
```
