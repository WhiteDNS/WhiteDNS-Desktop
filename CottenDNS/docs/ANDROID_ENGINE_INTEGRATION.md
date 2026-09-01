# Android external-engine integration

The CottenDNS client engine is owned and versioned by this repository. Android
applications may vendor the complete repository under `third_party/CottenDns`
or check it out during CI. In either case, record an immutable full commit SHA
and build exactly that source; do not maintain an untracked fork of engine files.

## CI contract

1. Check out the Android application repository.
2. Check out the configured CottenDNS upstream into a temporary, sibling, or
   `third_party/CottenDns` directory at a pinned full commit SHA. Do not track a
   moving branch for release builds.
3. Install the Go version from `go.mod` and Android NDK `29.0.14206865`.
4. From the CottenDNS checkout, run:

   ```bash
   NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865" \
     OUTPUT_DIR="$GITHUB_WORKSPACE/app/src/main/jniLibs" \
     bash scripts/build-android-client.sh all
   ```

5. Package the generated `libcottendns_client.so` under `arm64-v8a`,
   `armeabi-v7a`, `x86_64`, and `x86`.
6. Record and verify the pinned CottenDNS SHA in Android build metadata.

Example GitHub Actions checkout (replace the placeholder with the reviewed
engine commit):

```yaml
- uses: actions/checkout@v4
- uses: actions/checkout@v4
  with:
    repository: WhiteDNS/CottenDns
    ref: 0123456789abcdef0123456789abcdef01234567
    path: .engine/CottenDns
- uses: actions/setup-go@v5
  with:
    go-version-file: .engine/CottenDns/go.mod
- name: Build CottenDNS Android engine
  working-directory: .engine/CottenDns
  run: |
    NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865" \
      OUTPUT_DIR="$GITHUB_WORKSPACE/app/src/main/jniLibs" \
      bash scripts/build-android-client.sh all
```

The outputs are Android executables with a `.so` packaging name, matching the
existing launcher contract. The linker flags provide 16 KiB page compatibility.

## Android-facing engine features

- Android builds exclude `internal/clientui` and the Bubble Tea/Lip Gloss
  dependency graph. `TERMINAL_UI` is intentionally ignored on Android; consume
  the stable `WD_*` lines from stdout instead.
- Emit `RESOLVER_IP_MODE = "auto"` to prefer IPv4 and use configured IPv6
  resolvers as fallback. The accepted values are `auto`, `dual`, `ipv4`, and
  `ipv6`. Resolver files accept bare IPv4, bare IPv6, `[IPv6]:port`, and
  `IPv4:port` entries.
- `FAST_CONNECT` releases startup after a safe resolver pool is ready and keeps
  scanning the remaining fleet at background priority.
- `LEGACY_SESSION_ID` selects legacy one-byte framing per client while the
  server continues accepting native and legacy clients simultaneously.
- `MAX_ACTIVE_STREAMS` and `LOCAL_HANDSHAKE_TIMEOUT_SECONDS` bound stalled or
  excessive local SOCKS clients.
- `-scan-only` performs resolver/MTU discovery without starting the tunnel.
- Machine output is emitted at every log level: `WD_PROGRESS`, `WD_RESOLVERS`,
  and `WD_SCAN`.
- Generic SOCKS5 UDP, DNS fallback, loss recovery, adaptive duplication, and
  server-advertised fairness remain part of this source tree.

Pinning the engine SHA makes debug and release builds use identical engine code
and prevents stale prebuilt binaries from silently surviving an app merge.

## Vendored-source update checklist

When the Android repository stores a source snapshot, replace the entire
`third_party/CottenDns` directory from the reviewed commit and update
`third_party/CottenDns.UPSTREAM` in the same change. Never overlay only changed
Go files: `go.mod`, `go.sum`, build-tagged files, scripts, and config defaults
are part of the engine contract.

After updating, run the engine's `go test ./...` and
`scripts/build-android-client.sh all`, then run the Android renderer tests. The
Android config renderer must explicitly output:

```toml
RESOLVER_IP_MODE = "auto"
STARTUP_MODE = "resolvers"
TERMINAL_UI = "plain"
```

The last value is documentation for shared configs; the Android build remains
non-interactive even if it is omitted or changed.
