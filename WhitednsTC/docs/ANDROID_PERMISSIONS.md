# Android Permissions

WhiteDns TC declares only permissions required for endpoint testing and visible background work:

- `INTERNET`: required for TCP, TLS, HTTP, WebSocket, UDP, QUIC, and DNS probes.
- `ACCESS_NETWORK_STATE`: used to make future scan scheduling aware of network state.
- `FOREGROUND_SERVICE`: required for user-visible active scans.
- `FOREGROUND_SERVICE_DATA_SYNC`: Android 14+ foreground service type for scan work.
- `POST_NOTIFICATIONS`: Android 13+ notification permission for foreground scan notification visibility.
- `WAKE_LOCK`: reserved for long user-approved scans where Android may otherwise suspend work.

No contacts, location, SMS, advertising ID, or account permissions are used.
