# CottenDNS Benchmark Suite

This directory contains the core benchmarking tools for CottenDNS, now enhanced with high-precision timing and standalone tool capabilities inspired by the `slipstream-rust` methodology.

## Tools

### 1. `bench.go` (Go-based Orchestrator and Benchmarker)

The primary tool for end-to-end performance testing. It builds the server and client, orchestrates a local tunnel, and measures complete payload transfers with monotonic timing.

#### High-Precision Timing
The timer starts immediately before the first payload I/O, after the local TCP
connection opens. Receive timing includes waiting for the first payload.
Upload timing ends only after the receiver confirms the complete payload with
`OK`. Short transfers, corrupt payloads, and incomplete acknowledgements fail
the run; an incomplete set of requested runs exits nonzero.

#### Usage (Full Orchestration)

To run a standard end-to-end benchmark through the CottenDNS tunnel:

```bash
go run scripts/bench/bench.go -runs 3 -bytes 10485760
```

#### CLI Options
| Flag | Description | Default |
|------|-------------|---------|
| `-runs` | Number of runs for each direction | 3 |
| `-bytes` | Total payload size in bytes | 100MiB |
| `-force-build` | Rebuild server and client binaries | true |
| `-client-port` | Port for the local client listener | 18080 |
| `-server-port` | Port for the UDP server listener | 5300 |
| `-path-controller` | Compare `unified` or rollback `legacy` client behavior | unified |
| `-query-types` | Comma-separated query types to test in isolation or rotation | TXT |
| `-direction` | `both`, `upload`, or `download` | both |
| `-download-mtu` | Maximum download MTU; discovery may negotiate a smaller value | 1200 |

---

### 2. Standalone Mode (Tool Mode)

`bench.go` can also be used as a standalone source/sink tool, similar to `tcp_bench.py`. This is useful for testing manual configurations or other TCP links.

#### Modes
- `sink`: Listens for a connection and discards received data (sends "OK" at the end).
- `source`: Listens for a connection and sends data.
- `send`: Connects to a target and sends data (waits for "OK" at the end).
- `recv`: Connects to a target and receives data.

#### Examples

**Start a sink server (receiver):**
```bash
go run scripts/bench/bench.go -mode sink -addr :9090
```

**Run a sender (client):**
```bash
go run scripts/bench/bench.go -mode send -addr 127.0.0.1:9090 -bytes 100000000
```

**JSON Output:**
To get raw data for analysis:
```bash
go run scripts/bench/bench.go -mode send -addr 127.0.0.1:9090 -json
```

---

## Directory Structure

- `.bench/local_snapshot_go/bin`: Compiled benchmark binaries.
- `.bench/local_snapshot_go/runtime`: Temporary configuration and log files.

## Methodology

1. **First-Byte Start**: The timer starts just before the first payload `Read` or `Write`.
2. **ACK Synchronization**: For "Exfil" scenarios, the sink sends an "OK" acknowledgment to ensure all data has cleared the tunnel before the timer stops.
3. **Monotonic Timing**: Uses Go's monotonic clock for sub-millisecond precision.

## DNS carrier comparisons

Use `-query-types NULL`, `-query-types HTTPS`, or another supported type. Run
one type at a time to avoid masking failures with a working alternative.
The maximum download MTU is common across runs; actual negotiated capacity
is smaller for A/AAAA/CNAME-based carriers. Use `-download-mtu 4000` to reproduce
the older bulk-carrier benchmark ceiling.

This is a loopback measurement, not a Cloudflare or Internet throughput claim.
Keep encryption enabled and use several sufficiently long runs. Payloads are
deterministic `a` bytes, validated by the receiver; compression is disabled in
the orchestrated tunnel. Runtime logs are replaced by the next invocation, so
copy logs out if needed. Run invocations sequentially.
