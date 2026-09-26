# Vendoring CottenDNS in WhiteDNS clients

CottenDNS remains a normal command-line application, but its source tree is
also a versioned engine dependency of WhiteDNS Android and WhiteDNS Desktop.
Consumer releases must pin a full reviewed commit SHA and copy the complete
repository rather than selecting individual Go files.

## Compatibility contract

| Consumer | Vendored path | Required synchronization |
|---|---|---|
| WhiteDNS Android | `third_party/CottenDns` | Replace the full source snapshot and update `third_party/CottenDns.UPSTREAM`. Build all four Android ABIs and run the Kotlin config-renderer tests. |
| WhiteDNS Desktop | `CottenDNS` | Replace the full source snapshot, update `vendor/cottendns.json`, and copy the four `client_config*.toml` templates into `desktop/internal/cottendns`. Run both engine and desktop tests. |

The desktop template copies are significant: its dynamic settings schema is
parsed from them. Copying the engine without the templates would make new keys
such as `RESOLVER_IP_MODE` work at runtime but remain missing from the desktop
settings UI.

## IPv6 settings expected from consumers

- Use `RESOLVER_IP_MODE = "auto"` by default. This preserves IPv4 preference
  and activates IPv6 fallback only when IPv6 resolvers were supplied.
- Preserve IPv6 resolver brackets when a port is present, for example
  `[2001:4860:4860::8888]:53`. Bare IPv6 addresses use the selected transport's
  default port.
- Do not filter IPv6 entries out of resolver import, persistence, scan results,
  or `WD_RESOLVERS` telemetry.
- TCP/53 and UDP/53 use the same family-selection policy. DoT and DoH also
  accept IPv6 endpoints when configured.
- `TERMINAL_UI = "plain"` is appropriate for GUI-supervised processes. Android
  additionally excludes the desktop TUI at build time. On desktop, even an
  explicit `TERMINAL_UI = "tui"` safely falls back to plain mode when stdin or
  stdout is a pipe.
- GUI and Android launchers never wait at the interactive startup question.
  When an older config omits `STARTUP_MODE`, a non-terminal process uses the
  resolver-file path immediately; interactive shells retain the normal prompt.

Resolver address family remains a client-to-recursive-resolver transport choice.
Native keyed clients now require encrypted downstream responses, negotiated in
an existing response-mode byte. Upgrade the server together with these clients;
there is no automatic fallback to unauthenticated plaintext. Explicit legacy
session mode retains its older wire contract. The AES modes authenticate both
directions; XOR and unauthenticated ChaCha20 do not provide replay protection.

CI draft releases include `CottenDNS-Android-<version>.zip` with all four
`jniLibs/<abi>/libcottendns_client.so` files, an immutable source commit manifest,
and checksums. Copy these into the Android app and rebuild/reinstall its APK;
the packaged-only installer does not import a raw `.so` at runtime.

## Release gate

Before updating either consumer pin:

1. Run `go test ./...`, `go vet ./...`, and build the client and server.
2. Cross-compile Android arm64-v8a, armeabi-v7a, x86_64, and x86 with
   `scripts/build-android-client.sh all`.
3. Confirm the Android dependency list does not include `internal/clientui`,
   Bubble Tea, or Lip Gloss.
4. In WhiteDNS Desktop, verify the dynamic schema contains
   `RESOLVER_IP_MODE` and its four choices, then build the bundled CottenDNS
   helper on every release platform.
5. Test an IPv4-only list, an IPv6-only list, and a mixed list in `auto` mode.
