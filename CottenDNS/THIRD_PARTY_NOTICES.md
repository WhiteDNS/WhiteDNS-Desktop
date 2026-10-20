# Third-party transport

The experimental CottenMax adapter uses a source copy derived from
github.com/getlantern/soar v0.2.3
(commit a8af533d82284f5e6ab13b706552596c108bacf2), developed by the Lantern
team and distributed under the Apache License 2.0. Its license is included in
SOAR_LICENSE.txt. Source: https://github.com/getlantern/soar/tree/v0.2.3

The transport copy is in internal/cottenmax/engine. CottenDNS modifications
are documented in that directory's NOTICE.cottendns.txt and marked in modified
source files. They adjust recovery/scheduling and adapter integration; the
wire format and cryptography retain upstream's implementation. The separately
pinned module remains an independent test and benchmark comparator.

CottenMax is a CottenDNS integration of that transport, not an independent
implementation of Soar's protocol or cryptography. The existing CottenDNS
engine and project lineage retain their existing license and attribution.

Soar's bundled resolver/range data attribution is retained below and in
internal/cottenmax/engine/data/THIRD_PARTY.md.
CottenMax exposes Soar's authenticated resolver discovery as an explicit opt-in.
Bundled discovery and range sampling remain disabled by default.

# Third-party data

`resolvers/ir.txt` and `ranges/ir.txt` are copied unmodified from KevinNet DNS
(https://github.com/kamalalhagh/kevinnet-dns.git, commit a331430, 2026-05-26).
`resolvers/ir.txt` is KevinNet's snapshot of the range-scout WhiteDNS list; `ranges/ir.txt` aggregates RIPE/IRINN allocations.

KevinNet DNS is distributed under the MIT License:

```
MIT License

Copyright (c) 2026 Kevin Haji

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

# Optional QUIC resolver transports

DNS-over-QUIC and DNS-over-HTTPS/HTTP3 use github.com/quic-go/quic-go v0.63.0
under the MIT License, copyright 2016 the quic-go authors & Google, Inc.
Its complete license is included in QUIC_GO_LICENSE.txt.
Source: https://github.com/quic-go/quic-go/tree/v0.63.0

HTTP3 header compression uses github.com/quic-go/qpack v0.6.0 under the MIT
License, copyright 2019 Marten Seemann. Its complete license is included in
QPACK_LICENSE.txt. Source: https://github.com/quic-go/qpack/tree/v0.6.0

These resolver transports are optional and do not replace CottenDNS/Max's
domain, server credential or end-to-end tunnel protocol.
