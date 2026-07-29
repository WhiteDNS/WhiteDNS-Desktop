# Protocol Pipeline

For each endpoint, the Go engine runs a conservative pipeline:

1. Validate host and port.
2. TCP connect retries with timing and consistency scoring.
3. If TCP succeeds, attempt TLS handshake with SNI, ALPN, TLS version, cipher suite, and certificate metadata.
4. Attempt HTTP/HTTPS HEAD and GET with redirect detection.
5. Attempt WebSocket upgrade and verify HTTP 101 plus `Sec-WebSocket-Accept`.
6. If enabled, run UDP request/response attempts.
7. If enabled, run QUIC handshake with `h3` ALPN.
8. If enabled, run DNS query over UDP and TCP.
9. Compute RTT, jitter, timeout frequency, packet-loss estimate, stability, grade, classification, and confidence.

## False Positive Reduction

An endpoint is not considered tunnel-ready just because a port is open. The score penalizes:

- low retry consistency
- timeout-heavy behavior
- high jitter
- missing TLS/HTTP/WebSocket/QUIC/DNS evidence
- open-port-only results

Open TCP with no higher-level protocol evidence is classified as `False Positive`.

## Classification

- `Tunnel Ready`: stable TCP plus meaningful protocol evidence such as TLS, WebSocket, or QUIC.
- `Partially Usable`: usable signals exist but not enough for high confidence.
- `Unstable`: intermittent or weak behavior.
- `Blocked`: no meaningful connectivity.
- `False Positive`: open-port behavior without reliable tunnel-relevant protocol support.

Grades:

- `A+`: Excellent
- `A`: Stable
- `B`: Usable
- `C`: Weak
- `D`: Unstable
- `F`: Unusable
