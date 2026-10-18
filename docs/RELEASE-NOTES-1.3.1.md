# WhiteDNS Desktop 1.3.1

## Soar on desktop

- Import WhiteDNS `soar://` accounts and connect using the same pinned Lantern Soar v0.2.3 engine and WhiteDNS transport fixes as Android 1.6.8.
- Tune resolver transport, Iran-first/global discovery, DNS packet limits, concurrency, stream windows and timeouts. Each field has help on its question mark.
- Choose Automatic or Limited path presets. MasterDNS encryption, MTU and preset-test controls are kept separate from Soar.
- Use the existing local HTTP/SOCKS proxy or managed system proxy. Soar authenticates and verifies outbound HTTPS before reporting ready.

## Full subscriptions

- In **Connections → Import**, paste the panel's HTTPS subscription URL.
- Refresh while disconnected, or let due sources refresh when the app opens while disconnected. View last-received traffic, quota and expiry metadata.
- Refresh preserves unrelated profiles, account selection and manual resolver overrides. Failed downloads retain cached profiles. Server limits still apply.
- HTTP subscriptions require explicit consent. HTTPS certificate validation and downgrade protection are enabled.

## Upgrade

Close the old app, replace it with the matching package below, and reopen it. Existing MasterDNS, StormDNS and CottenDNS profiles keep their engines and remain in the same user-data location. A full backup before upgrading is useful; it contains private account and subscription information.

Windows x64 is for Intel/AMD PCs. Windows ARM64 is for Windows on ARM. Pick the corresponding x64 or ARM64 package for macOS/Linux. The Windows ZIP includes the standalone executable and license notices; keep the notices when redistributing an official package. Platform signing/notarization is unchanged from earlier releases.

A subscription URL updates accounts; a `soar://` link imports a standalone snapshot. The desktop app uses proxy routing; applications need to honor that proxy. No new full-device VPN mode is introduced.

## Windows reliability

Release builds use Go 1.26.9. Repeated restricted-DNS tests exposed the older Go Windows UDP memory-corruption failure; see [Go issue 77975](https://github.com/golang/go/issues/77975). The updated toolchain includes its fix. The vendored Soar wire protocol is unchanged.

## Validation

Go tests cover subscription parsing, refresh, persistence, save-failure rollback, active-connection protection, old profile behavior, engine separation and runtime cleanup. Browser checks cover import, HTTP consent, refresh, Soar editing, question-only help and multiple window sizes. Real HTTPS through the desktop Soar → Xray path was checked on Windows with both HTTP and SOCKS5 proxies and the expected server exit IP. Release CI builds all six OS/architecture targets and verifies the embedded Soar helper. This does not replace physical testing of every OS or a test inside Iran.

Soar is developed by **Lantern**. WhiteDNS integrates it with separately documented transport changes; see [third-party notices](https://github.com/WhiteDNS/WhiteDNS-Desktop/blob/main/THIRD_PARTY_NOTICES.md).

## فارسی

پشتیبانی Soar، لینک ساب کامل و تنظیمات پیشرفته به نسخهٔ دسکتاپ اضافه شد. لینک ساب پنل را در **Connections → Import** وارد کنید. برای دریافت تغییرات، اتصال را قطع و **Refresh subscriptions** را بزنید. پروفایل‌های قبلی حفظ می‌شوند؛ اگر دریافت ساب خطا بدهد، نسخهٔ ذخیره‌شده حذف نمی‌شود. محدودیت حجم و انقضا از سمت سرور اعمال می‌شود.
