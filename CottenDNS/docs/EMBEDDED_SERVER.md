# Managed server embedding

`cottendns-go/server` exposes one isolated, fixed AES-256-GCM account behind a
caller-owned UDP/TCP DNS router. It starts no network listeners, reads no key
file, and changes no firewall or service settings. Domains and keys are unique
per account. The caller owns DNS framing, bounded ingress queues and transport
connection limits.

Call `server.New(ctx, server.Config{Domain, Key, DialContext, ExchangeDNS,
Allowed})`, pass complete DNS messages to `HandleDNS`, then call `Close` after
cancelling the account. Every policy hook is required. TCP streams and generic
UDP endpoints use `DialContext`; tunneled DNS messages use `ExchangeDNS` before
the built-in DNS cache. A denied hook never falls back to direct egress.
Implement cancellable hooks with destination validation, durable usage
reservations, shared rate limits and connection tracking. Close tracked egress
connections immediately on quota exhaustion, revocation or account deletion.

The embedding uses bounded per-account sessions, queues and ARQ windows. Hosts
should create instances lazily because the protocol's session table has fixed
per-instance memory overhead. It does not provide a multi-user database or a
capacity guarantee. The standalone CLI retains its existing configuration.

`server.Config.MaxActiveSessions` optionally sets the combined native and legacy
session limit for an account. Zero retains the embedded default of 64;
explicit values must be 1–65535. Native clients can use at most 65280 session IDs
and legacy clients 255. This setting changes admission capacity, not the wire
format or the per-session stream limit, and does not guarantee host capacity.

`server.Config.MaxStreamsPerSession` optionally bounds data streams in each
session. Zero retains the embedded default of 128; explicit values must be
1–65535. The control stream (ID zero) is excluded, and existing streams remain
usable when the limit is reached. Stream state is allocated as streams open.
The caller owns aggregate egress limits across sessions and accounts.

`cottendns-go/probe.CheckHTTP` runs the native client against an account and
checks HTTPS through the tunnel. It takes credentials in memory, uses private
temporary files and a loopback SOCKS listener, and cleans up after cancellation.
Run diagnostic probes in separate processes; client QNAME shaping is global.
This helper is intended for installation diagnostics, not as an application
proxy or a substitute for testing reachability from the end user's network.

Both APIs preserve the WhiteDNS fork's encrypted downstream wire format.
An older upstream server without that extension cannot serve a current native
encrypted WhiteDNS client. Do not replace this revision with an untested
upstream build based only on matching project names.
