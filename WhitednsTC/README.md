# WhiteDns TC

WhiteDns TC is an Android 8+ endpoint testing and tunnel-readiness verifier for endpoints explicitly supplied or approved by the user. It is not a mass scanner and contains no discovery logic, telemetry, analytics, or hidden upload path.

## Build

Prerequisites:

- Android SDK with platform 36 installed
- JDK 17. On this machine, Android Studio's bundled JBR works:
  `set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr`
- Go 1.25+ and `gomobile`/`gobind`

Build the Go engine AAR:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_go_aar.ps1
```

Build the Android debug APK:

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\gradlew.bat assembleDebug
```

APK output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

## Project Structure

- `engine/tunnelengine`: Go protocol engine exposed through gomobile JSON functions.
- `app/src/main/java/com/tunnelcheck/app/engine`: Kotlin bridge into the Go AAR.
- `data/local`: Room database and DAO.
- `data/repo`: repository, adaptive concurrency, foreground-service orchestration.
- `data/export`: endpoint import parsing and JSON/CSV/TXT export.
- `ui`: Jetpack Compose Material 3 screens.
- `service`: foreground scan service.
- `worker`: WorkManager entry point for explicit scheduled retest work.

## Current Features

- Quick test for one host and multiple ports.
- Bulk import from TXT, CSV, and JSON-like endpoint lists.
- Real Go protocol probes for TCP, TLS, HTTP/HTTPS, WebSocket upgrade, UDP response, QUIC/H3 handshake, and DNS over UDP/TCP.
- Conservative weighted scoring with false-positive reduction.
- Room-backed history with filters for Tunnel Ready, TLS, WebSocket, low latency, and high stability.
- JSON, CSV, and TXT export.
- Foreground service during active scans and coroutine cancellation from UI.

## Safety Boundary

WhiteDns TC only tests endpoints the user enters, imports, or explicitly approves through feeds. There is no IP range expansion, no background discovery, and no telemetry. Community feed support should remain opt-in and should treat every imported URL as user-approved input.
