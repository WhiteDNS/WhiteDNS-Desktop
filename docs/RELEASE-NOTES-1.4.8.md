# WhiteDNS Desktop 1.4.8

- Choose CottenMax **Full** or **Low** in the client. Low targets a 35% speed reduction by default; the target is adjustable from 10% to 90% and is saved with the profile. Actual throughput depends on the resolver and network.
- Preserve the CottenMax initial and maximum QNAME controls for adaptive path sizing and the optional client-requested download FEC settings.
- Include the Desktop 1.4.7 profile-import and duplicate-cleanup fixes, Windows text context menu, and dark-mode display fixes.

The same Max-capable server accepts both traffic profiles. Reconnect after changing the profile or reduction target. Low reduces query and new-connection rates; it does not guarantee a particular throughput or VPS provider policy outcome.

Release artifacts are built and verified by the Desktop Release Builds workflow. See the [traffic profile measurements](https://github.com/WhiteDNS/CottenDNS/blob/c917f9fa20533c7fc006d3cb768e3237294c00d6/docs/COTTENMAX_TRAFFIC_PROFILES.md) for the test conditions and observed speed differences.
