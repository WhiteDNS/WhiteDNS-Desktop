# WhiteDNS Desktop 1.4.9

Pre-release with a redesigned dashboard and simpler connection setup.

- Choose Proxy, VPN (system proxy), or Windows TUN mode directly from Quick setup.
- Paste shared resolvers or import a resolver file for all current and future connections. Expand the input or file preview without losing per-connection resolver assignments.
- Use a responsive dashboard with clearer connection details, resolver health, community links, and an 80-second tunnel latency chart. Failed checks appear as gaps with retry details; slow checks reuse connections and never overlap.
- Windows TUN requests administrator approval automatically, reopens WhiteDNS with the saved selections, and resumes the requested connection. Cancelling the Windows request keeps the current window open.
- Improve Windows VPN proxy activation, notify running applications of changes, and restore previous proxy/PAC settings on disconnect.
- Route TUN DNS through the selected tunnel with caching. Keep upstream resolver routes outside TUN and restrict Soar TUN to selected resolvers to prevent discovery routing loops.
- Keep the CottenMax improvements shipped in 1.4.8.
- Keep parallel connection tests isolated from the machine's system proxy and TUN routes; apply the selected mode only when connecting the winning profile.

Windows TUN is currently limited to Windows. Soar carries TCP traffic; DNS is handled through the tunnel, while other UDP, including QUIC, is blocked in Soar TUN mode. VPN mode configures the OS proxy and requires applications that support it.

Existing profiles are preserved. Mode changes apply to the next connection. Real connection checks on the test machine covered Soar Proxy, Windows system proxy, and administrator TUN using the supplied test subscription; YouTube page retrieval was checked, not video playback. Results can vary with the user's network and resolver reachability.
