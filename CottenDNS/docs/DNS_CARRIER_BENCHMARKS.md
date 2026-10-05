# DNS carrier speed check - 2026-09-27

## Conditions

Local UDP loopback benchmark of the working tree based on `cdf084f528c5833eeb77f1b9a29ecf0ceae89f86`, including the small-carrier MTU and ARQ retransmission fixes. This is not a Cloudflare or Internet benchmark and does not establish public recursive resolver compatibility.

- Windows amd64, Go 1.26.5, AMD Ryzen 7 6800H (8 cores / 16 logical processors).
- AES-128-GCM and replay protection enabled; compression disabled.
- One local resolver/server at `127.0.0.1:5300`, domain `a.io`.
- Each query type ran alone, sequentially: three 16 MiB uploads and three 16 MiB downloads.
- Maximum download MTU 1200, minimum 16; upload MTU negotiated to 115 for every type.
- Throughput is total completed payload bytes divided by total measured transfer time. Upload timing includes the receiver acknowledgement. Payloads are checked; partial or failed runs cause a nonzero exit.
- Full transfers are measured, not periodic telemetry snapshots. Bulk downloads take under a second; small differences do not establish a stable ranking.

## Results

All 84 final transfers completed successfully. Speeds are MiB/s.

| Query type | Upload | Download | Negotiated download MTU | Transfers |
| --- | ---: | ---: | ---: | ---: |
| TXT | 3.072 | 22.088 | 1200 | 6/6 |
| NULL | 2.840 | 22.994 | 1200 | 6/6 |
| HTTPS | 2.995 | 23.810 | 1200 | 6/6 |
| SVCB | 3.036 | 24.453 | 1200 | 6/6 |
| A | 3.026 | 10.322 | 672 | 6/6 |
| AAAA | 3.104 | 21.086 | 1200 | 6/6 |
| CNAME | 3.107 | 3.533 | 115 | 6/6 |
| MX | 3.085 | 3.559 | 115 | 6/6 |
| NS | 2.931 | 3.333 | 115 | 6/6 |
| PTR | 3.025 | 3.594 | 115 | 6/6 |
| SRV | 3.045 | 3.631 | 115 | 6/6 |
| CAA | 3.057 | 3.682 | 115 | 6/6 |
| NAPTR | 3.111 | 3.839 | 115 | 6/6 |
| SOA | 3.116 | 3.615 | 115 | 6/6 |

TXT, NULL, HTTPS and SVCB carry bulk responses. A and AAAA use address responses. CNAME and the remaining types use bounded CNAME responses; these results do not imply native MX, NS, PTR, SRV, CAA, NAPTR or SOA payload encoding. See [DNS setup and carrier support](DNS_RECORD_TYPES.md).

This is a carrier comparison, not a controlled before/after encryption benchmark. It cannot establish an overall speed increase against earlier measurements with different MTUs, timing or machine load.

## Bugs and validation

The initial small-carrier test exposed a download-probe boundary below the server's 30-byte minimum. The client now respects that minimum, allowing discovery to search usable intermediate sizes.

An earlier MX run stalled. Investigation found a real ARQ race: a fast dequeue could mark a retry dispatched before the producer overwrote that state. A deterministic regression failed before the fix and passes afterward. This is a plausible stall mechanism, not proof of the cause of that particular MX run. The full final matrix passed after the fix.

Validation passed: `go test ./...`, `go vet ./...`, race tests for ARQ/client/server/benchmark, native client/server builds, and an uncached encrypted 64 KiB end-to-end echo for all 14 types.

## Reproduce

From the repository root:

```sh
go run scripts/bench/bench.go -query-types TXT -runs 3 -bytes 16777216 -download-mtu 1200
go run scripts/bench/bench.go -query-types NULL -runs 3 -bytes 16777216 -download-mtu 1200 -force-build=false
```

Repeat sequentially for each type. Benchmark instances share a runtime directory and ports; do not run them concurrently. Local diagnostic logs are in `.bench/carrier-speed-fixed-20260927/` (ignored by Git).
