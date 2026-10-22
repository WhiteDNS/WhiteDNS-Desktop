# Soar and subscription guide

Desktop 1.3.1 supports the same `soar://` profile schema and pinned Soar engine as WhiteDNS Android 1.6.8. A compatible WhiteDNS Soar panel can supply a full HTTPS subscription or an individual profile link. Existing MasterDNS, StormDNS and CottenDNS profiles keep their engines.

## Import and refresh

Open **Connections → Import** and paste the subscription URL. HTTPS is recommended. HTTP requires the checkbox consent before Import is enabled. Disconnect before importing or refreshing subscriptions. The app refreshes due sources at startup while disconnected (12 hours by default, or the server's 1–168 hour interval).

Refresh reconciles profiles using provider account IDs, updates keys and Soar settings, and preserves unrelated profiles, the selected account where it still exists, and manually selected resolver profiles. Accounts removed by a successful response are removed from that subscription. Failed, empty, malformed, inactive or revoked responses keep the previously saved profiles and show a refresh error. A saved profile does not bypass server quota, expiry or revocation.

Traffic values and expiry are the last metadata received from the provider, not a live billing feed. Local traffic statistics serve a different purpose. A `soar://` export includes one account's settings but excludes its subscription URL. A full backup includes subscription URLs: store it securely.

The fetcher validates certificates, rejects HTTPS-to-HTTP redirects, limits redirects and download size, and accepts plain or base64 lists of supported profile links. A subscription URL grants access to its profiles: share it only with the intended user.

## Soar settings

Open a Soar connection to edit its advanced settings. Help appears on the **?** control. **Automatic** uses adaptive query sizing and two desired healthy paths. **Limited path** uses smaller DNS packets and less concurrency for restrictive paths. Neither preset guarantees higher speed.

Resolver transport can use automatic UDP with TCP fallback, both from startup, TCP only, or UDP only. Iran-first discovery prioritizes Iranian candidates before the global list; it does not select the exit country. Disable discovery to use only the selected resolver list.

Soar encryption is fixed by its protocol; MasterDNS encryption methods and MTU controls do not apply. Account domains and base64 Ed25519 public keys must match the server. Soar requires a single account domain, at most 45 ASCII characters. Subscription refresh replaces provider-owned settings; export an individual profile to keep an independent copy.

## Scope and checks

The desktop app exposes a local HTTP/SOCKS proxy and an optional managed system proxy. It does not add a full-device Android VPN interface. Applications must honor the proxy or be configured to use it.

Release validation covers parser/persistence/refresh failures, engine isolation, runtime startup and cleanup, real HTTPS through Soar → Xray over HTTP and SOCKS5 on Windows, and browser interactions at multiple window sizes. CI builds Windows, macOS and Linux for x64 and ARM64. Build success is not a physical runtime test on each OS; access from Iran has not been verified during this release.

## راهنمای کوتاه فارسی

در پنل، لینک ساب حساب را کپی کنید. در برنامه به **Connections → Import** بروید، لینک HTTPS را وارد و Import را بزنید. سپس حساب را انتخاب و متصل شوید. برای گرفتن تغییرات حساب، اتصال را قطع و **Refresh subscriptions** را بزنید. اگر دریافت ساب خطا بدهد، کانفیگ ذخیره‌شده حذف نمی‌شود؛ محدودیت حجم و انقضا همچنان از سمت سرور اعمال می‌شود. تنظیمات پیشرفتهٔ Soar در صفحهٔ ویرایش همان حساب قرار دارند و توضیح هر گزینه روی علامت **؟** نمایش داده می‌شود.
