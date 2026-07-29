# Architecture

WhiteDns TC uses Clean Architecture boundaries:

- UI: Compose screens render state and dispatch actions.
- ViewModel: owns scan state, cancellation, filters, and export text.
- Domain: endpoint, options, result models and repository interface.
- Data: Room persistence, import/export, repository implementation.
- Engine: Go native scanner bound through gomobile.

The Android layer never decides protocol truth. It stores and displays results returned by the Go engine. The bridge passes JSON to avoid fragile generated model bindings and to keep the gomobile API narrow:

```text
Compose -> RootViewModel -> ScanRepository -> GoEngineBridge -> tunnelengine.aar
                                               |
                                               v
                                          Room history
```

## Concurrency

The repository deduplicates endpoints and uses adaptive coroutine concurrency:

- small batches: 6 concurrent endpoints
- medium batches: 16 concurrent endpoints
- large batches: 32 concurrent endpoints

The Go batch API also has an internal bounded worker pool for future direct batch use. Scans run on `Dispatchers.IO`; the UI remains cancelable and avoids ANR-prone blocking calls.

## Persistence

Room stores each scan result as a flattened row plus the raw engine JSON. Flattened columns make filtering fast; raw JSON preserves protocol details such as certificate information, ALPN, status codes, and error categories.

## Foreground Work

Bulk scans start `ScanForegroundService` so Android treats the scan as user-visible data-sync work. WorkManager is scaffolded for explicit scheduled retests, but no automatic retesting is enabled by default.
