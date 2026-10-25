# WhiteDNS Desktop 1.4.6

Fix misleading proxy locations when country detection fails, including on CottenMax connections. The dashboard now displays a country only when the lookup through the active proxy succeeds. Profile names and account domains no longer determine the displayed location.

A failed lookup displays Unknown with a retry button. Temporary lookup failures are no longer cached for the entire connection. Hover over Location to see the lookup result or error.

No profile, server, or subscription changes are required. This update retains the CottenMax handshake fixes from 1.4.5. Android 1.6.14 and Server Management 0.10.0 remain current.

Validation includes desktop Go regressions, browser checks for failed lookups and recovery, verified Iranian egress, and HTTP/SOCKS tests confirming that a failed proxy request does not fall back to a direct connection. These checks do not establish the real exit country of an individual user's connection.
