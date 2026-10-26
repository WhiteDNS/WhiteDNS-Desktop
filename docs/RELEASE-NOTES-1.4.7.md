# WhiteDNS Desktop 1.4.7

This is a pre-release for testing the connection import, duplicate cleanup and Windows display fixes. WhiteDNS Desktop 1.4.6 remains the stable release.

- Prevent duplicate connection profiles when importing the same link again or pasting repeated links in one batch. The import result reports how many duplicates were skipped.
- Add **Remove duplicates** to Connections for cleaning up existing duplicates. Keep the selected and active profiles, different engine/key/resolver/Soar settings, and independent subscription sources.
- Enable the Windows text context menu for right-click Copy/Paste in production builds.
- Detect the engine from profile links and payload markers automatically. Move the manual choice into **Legacy link options** for older links without an engine marker; those links retain the MasterDNS default.
- Fix transparent dark-mode dialogs on older WebView2 engines by using compatible theme colors. Keep the Import dialog scrollable when advanced options need more space.

Existing profiles do not need to be re-imported. Duplicate cleanup is explicit; import skips matching profiles automatically. An unsuccessful settings-file save leaves the previous in-memory state intact.

Validation includes the desktop Go suite, persistence-failure and duplicate/engine/resolver regressions, a Windows x64 production build, and browser interaction checks for light/dark Import, Edit and Export dialogs on Chromium 145 and Edge 109 at desktop and smaller window sizes. The native Windows right-click menu has been enabled and compiled but has not been manually exercised. These checks do not establish connectivity on a user's network.
