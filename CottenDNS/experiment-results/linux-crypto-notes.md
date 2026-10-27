# Linux CI packet cipher comparisons

Source commit: 8f691923844ddef398877a4cf34b7ff8fb541197. Experiment workflow run 40190515950 and ordinary GoTest run 40190515902 both completed successfully. Downloaded artifact ZIP SHA256 hashes matched GitHub metadata. Extracted measurements are retained beside the generated median JSON files; repository packet logs normalize trailing spaces in the CPU header without changing measured values.

Go 1.26.5 Linux, one benchmark worker, 100 ms per operation, three repetitions. These values include actual header protection and packet allocations but are packet CPU cost, not DNS tunnel speed.

AMD64 host: virtualized AMD EPYC 9V45, 4 logical CPUs (2 cores / 2 threads), AES-NI and PCLMULQDQ present. ARM64 host: virtualized Neoverse-N2, 4 cores, AES and PMULL present. The ARM server CPU is not an Android A52/A30 CPU and neither host measures the affected mobile network. Cross-host clock speeds, implementation optimizations, scheduling and VM noise differ; compare suites within each host, not raw x86-versus-ARM nanoseconds as an architecture ranking.

## Linux AMD64 native

| Suite | 200B upstream Seal/Open (ns) | 1200B downstream Seal/Open (ns) |
|---|---:|---:|
| chacha20-poly1305-8 | 656.9 / 614.1 | 2279.0 / 2115.0 |
| chacha20-poly1305-8-stacktag | 649.9 / 612.8 | 2254.0 / 2115.0 |
| aes-128-gcm-12 | 332.8 / 250.4 | 661.1 / 512.9 |
| aes-256-gcm-12 | 349.5 / 262.0 | 688.3 / 525.6 |
| aes-128-gcm-16 | 332.4 / 255.1 | 665.5 / 528.2 |
| chacha20-poly1305-16 | 414.9 / 376.0 | 985.0 / 962.9 |

## Linux AMD64 AES disabled

| Suite | 200B upstream Seal/Open (ns) | 1200B downstream Seal/Open (ns) |
|---|---:|---:|
| chacha20-poly1305-8 | 687.3 / 636.0 | 2335.0 / 2173.0 |
| chacha20-poly1305-8-stacktag | 669.9 / 638.0 | 2332.0 / 2159.0 |
| aes-128-gcm-12 | 1666.0 / 1627.0 | 7774.0 / 7614.0 |
| aes-256-gcm-12 | 1867.0 / 1866.0 | 8931.0 / 8610.0 |
| aes-128-gcm-16 | 1651.0 / 1623.0 | 7378.0 / 7234.0 |
| chacha20-poly1305-16 | 408.2 / 360.3 | 942.4 / 909.2 |

## Linux ARM64 native

| Suite | 200B upstream Seal/Open (ns) | 1200B downstream Seal/Open (ns) |
|---|---:|---:|
| chacha20-poly1305-8 | 1103.0 / 1057.0 | 2542.0 / 2314.0 |
| chacha20-poly1305-8-stacktag | 1078.0 / 1057.0 | 2521.0 / 2284.0 |
| aes-128-gcm-12 | 525.5 / 472.8 | 1165.0 / 901.4 |
| aes-256-gcm-12 | 537.1 / 481.4 | 1224.0 / 948.7 |
| aes-128-gcm-16 | 520.1 / 473.6 | 1161.0 / 904.5 |
| chacha20-poly1305-16 | 1088.0 / 1045.0 | 2550.0 / 2295.0 |

## Interpreting the AES-disabled run

The AMD64 job log explicitly records GODEBUG=cpu.aes=off,cpu.pclmulqdq=off for the no-AES step. Unlike Windows, the installed Go runtime reads GODEBUG early on Linux before CPU initialization. The Go AES implementation selects assembly only when cpu.X86HasAES plus SSE flags are true, and GCM also requires cpu.X86HasPCLMULQDQ. The result confirms the intended change: AES128-GCM12 200B Seal/Open costs increased from 332.8/250.4 ns to 1666/1627 ns (5.0x/6.5x); 1200B downstream Seal/Open increased 11.8x/14.8x. ChaCha timings stayed in the same broad range. These checks support that the no-AES comparison is effective on Linux, unlike the earlier ineffective Windows flag experiment.

Hardware AES is attractive for CPU savings. Without it, AES-GCM12 is substantially slower than the existing ChaCha and standard ChaCha on this host. Generic Go AES also lacks the hardware implementation's constant-time guarantee, so this is not a deployment recommendation. Standard ChaCha16 is faster than the truncated implementation on this x86 CPU, while on the measured ARM64 CPU its cost is approximately unchanged; its extra eight wire bytes remain in both cases.

The wire-identical stack-tag change consistently removes one 16-byte allocation but gives only a small median CPU change here; do not claim a zero-regression tunnel-speed guarantee. AES12 adds four authentication bytes and standard ChaCha/AES16 add eight, reducing useful payload at a fixed DNS budget. The separate end-to-end measurements determine the net effect.

Primary API sources: [GCM tag sizes](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize), [AES implementation](https://pkg.go.dev/crypto/aes), and [ChaCha20-Poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305). The local Go 1.26.5 runtime source and CI job log provide the CPU-disable verification described above.
