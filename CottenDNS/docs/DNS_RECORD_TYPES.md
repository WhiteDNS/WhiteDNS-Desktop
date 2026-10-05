# DNS record types and Cloudflare setup

## Domain records and tunnel carriers have different jobs

For a Cloudflare-hosted parent zone `example.com`, delegate a short tunnel
subdomain to your CottenDNS server:

| Cloudflare type | Name | Content | Purpose |
| --- | --- | --- | --- |
| A | ns | Your VPS IPv4 address | Locate the nameserver; DNS only |
| AAAA (optional) | ns | Your VPS public IPv6 address | IPv6 nameserver address; DNS only |
| NS | v | ns.example.com | Delegate `v.example.com` to CottenDNS |

The nameserver needs a reachable address, using A, AAAA, or both. IPv6-only
nameservers require a recursive resolver that can reach them over IPv6. Allow
UDP/53 and TCP/53 on the server. Configure `v.example.com` as the server domain
and the client tunnel domain. A nameserver target must be a hostname with
address records, not a CNAME alias.

Adding a TXT, NULL, MX, or HTTPS record at the parent DNS provider does not
forward DNS questions to the address in that record. These records are data,
not delegation. A CNAME is an alias, not a nameserver delegation. Cloudflare's
HTTP proxy is not a CottenDNS UDP/53 forwarder. CottenDNS cannot change those
DNS protocol rules or Cloudflare's supported zone-record menu.

Cloudflare documents this in [Delegate subdomains](https://developers.cloudflare.com/dns/manage-dns-records/how-to/subdomains-outside-cloudflare/)
and [DNS record types](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/).
Cloudflare hosting the parent zone is also separate from choosing Cloudflare's
1.1.1.1 recursive resolver on the client.

## Select the tunnel's query types in the client

The delegation above already routes different QTYPEs to CottenDNS. No additional
Cloudflare zone entries are needed for them:

```toml
QUERY_TYPES = ["TXT", "NULL", "HTTPS", "SVCB"]
```

For an isolated test, configure one type at a time, such as `QUERY_TYPES = ["NULL"]`.
The server selects the response encoding from the question automatically.

| Client query type | Current response carrier | Capacity / compatibility |
| --- | --- | --- |
| TXT | TXT strings | Bulk data; existing default |
| NULL | Raw NULL RDATA | Bulk data, minimal record encoding; resolver support must be tested |
| HTTPS, SVCB | Private SvcParam value | Bulk data; resolver support must be tested |
| A, AAAA | Address records when enabled, otherwise bounded CNAME | MTU-limited; not equivalent to bulk carriers |
| CNAME | Encoded CNAME target | Small frames, limited by DNS name length |
| MX, NS, PTR, SRV, CAA, NAPTR, SOA | Encoded CNAME target | Accepted query types, not native response encodings; small frames |

Selecting every type is not automatically faster. Keep a working bulk carrier
for downloads, and let MTU discovery negotiate the path's actual limits. Do not
force a large minimum download MTU with a small carrier. Resolver policy,
CNAME chasing, EDNS limits, filtering, and loss can change which types work.
A local client/server success does not prove that a public recursive resolver
will carry the same replies.

A small-carrier-only configuration needs a compatible lower MTU bound, for example:

```toml
QUERY_TYPES = ["CNAME"]
MIN_DOWNLOAD_MTU = 30
```

The client now keeps the actual download probe at or above the server's
30-byte wire minimum. Previously a smaller configured lower bound could make
both boundary probes fail and incorrectly reject an otherwise usable carrier.


Measured results for all 14 types: [2026-09-27 local speed check](DNS_CARRIER_BENCHMARKS.md).

## Reproduce the speed check

```sh
go run scripts/bench/bench.go -query-types NULL -runs 3 -bytes 33554432 -download-mtu 1200
# Reuse the built binaries for the next type:
go run scripts/bench/bench.go -query-types HTTPS -runs 3 -bytes 33554432 -download-mtu 1200 -force-build=false
```

This starts a local server and client; it does **not** measure Cloudflare's
network. AES-GCM and replay protection remain enabled, compression is disabled,
and the benchmark checks complete payload delivery. Run carriers sequentially
on an otherwise idle machine. See [benchmark instructions](../scripts/bench/README.md).

## Validation

```sh
go test ./...
go vet ./...
go test -race ./internal/arq ./internal/client ./internal/udpserver ./scripts/bench
go test -tags e2e -count=1 -run TestTunnelEndToEndSingleCarriers -timeout 600s ./test/e2e
```

Use `-count=1` for this integration test because it builds external client/server
executables; Go's package test cache does not track all of those source inputs.
The matrix tests all 14 accepted query types individually with AES-GCM and a
byte-exact 64 KiB echo.

The carrier audit also fixed a retransmission scheduling race: retry state is
now registered before enqueue, so a fast dequeue cannot be overwritten as
undispatched. A lost retransmission therefore remains eligible for another
retry. The fix changes no DNS fields or wire overhead.
