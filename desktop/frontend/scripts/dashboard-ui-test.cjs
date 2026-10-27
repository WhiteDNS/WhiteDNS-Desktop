// Synthetic bridge for UI behavior; Go tests cover parsing and persistence.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.DESKTOP_PLAYWRIGHT || 'playwright');
const fixture = JSON.parse(fs.readFileSync(process.env.DESKTOP_UI_FIXTURE, 'utf8'));
const root = path.resolve(__dirname, '../dist');
const out = process.env.DESKTOP_SCREENSHOTS || path.resolve(__dirname, '../../../.cache/dashboard-ui');
fs.mkdirSync(out, { recursive: true });

function bridge(fixture) {
  let state = JSON.parse(sessionStorage.getItem('dashboard-fixture') || 'null') || structuredClone(fixture);
  state.selectedConnectionProfileId = 'cotten-ui';
  state.connectionProfiles.find(p => p.id === 'cotten-ui').resolverProfileId = state.resolverProfiles[0].id;
  state.resolverProfiles[0].resolverText = '9.9.9.9';
  state.selectedSettingsProfileId = 'cotten-ui-settings';
  window.testCalls = [];
  const clone = () => structuredClone(state);
  const save = () => { sessionStorage.setItem('dashboard-fixture', JSON.stringify(state)); return clone(); };
  const validate = text => {
    const entries = text.split(/\s+/).filter(Boolean);
    const invalidEntries = entries.filter(v => !/^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(v));
    return { normalizedResolvers: entries, invalidEntries, normalizedText: entries.join('\n'), isValid: entries.length > 0 && invalidEntries.length === 0 };
  };
  const methods = {
    GetAppState: async () => clone(), GetTunModeSupported: async () => true,
    RefreshSubscriptions: async () => clone(),
    GetDefaultSettingsProfile: async () => structuredClone(state.settingsProfiles[0]),
    GetCottenDNSOptionSchema: async () => fixture._cottenSchema || [],
    GetScannerState: async () => ({ status: 'idle', validResolvers: [] }),
    GetParallelTestState: async () => ({ status: 'idle', presets: [] }),
    GetValidatorState: async () => ({ status: 'idle', results: [] }),
    ValidateResolverText: async text => validate(text),
    CheckFirewallStatus: async () => ({ enabled: false, supported: true }),
    SetTunnelMode: async mode => { window.testCalls.push(['mode', mode]); state.tunnelMode = mode; return save(); },
    SaveGlobalResolvers: async text => {
      if (!validate(text).isValid) throw new Error('Enter valid resolver addresses.');
      window.testCalls.push(['save', text]);
      const profile = { id: 'shared', name: 'Shared resolvers', resolverText: text };
      state.resolverProfiles = state.resolverProfiles.filter(p => p.id !== profile.id).concat(profile);
      state.globalResolverProfileId = profile.id; state.selectedResolverProfileId = profile.id;
      return save();
    },
    SetGlobalResolverProfile: async id => { window.testCalls.push(['global', id]); state.globalResolverProfileId = id; return save(); },
    StartConnection: async () => { state.runtime.status = 'connecting'; state.runtime.runtimeType = 'masterdns'; return clone(); },
  };
  window.go = { main: { App: new Proxy(methods, { get: (target, key) => target[key] || (async () => []) }) } };
  window.runtime = { EventsOn: () => () => {}, InitializeNotifications: async () => {}, CleanupNotifications: async () => {} };
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const errors = [], results = [];
  try {
    for (const theme of ['dark', 'light']) {
      for (const width of [1920, 1366, 1100, 900, 375, 320]) {
        const page = await browser.newPage({ viewport: { width, height: width === 1920 ? 1000 : 740 }, colorScheme: theme });
        page.on('pageerror', error => { errors.push(error.message); console.error(error.message); });
        await page.addInitScript(bridge, fixture);
        await page.addInitScript(t => { localStorage.setItem('whitedns-ui-theme', t); localStorage.setItem('whitedns.desktop.vpnMovedNotice.dismissed', '1'); }, theme);
        await page.route('http://whitedns.test/**', async route => {
          const pathname = decodeURIComponent(new URL(route.request().url()).pathname);
          const file = path.resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
          if (!file.startsWith(root + path.sep)) return route.fulfill({ status: 404, body: '' });
          const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.png': 'image/png' };
          try { await route.fulfill({ contentType: mime[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) }); }
          catch { await route.fulfill({ status: 404, body: '' }); }
        });
        await page.goto('http://whitedns.test/');
        const mode = page.getByRole('radio', { name: 'VPN mode', exact: true });
        await mode.waitFor();
        await mode.click();
        await page.waitForFunction(() => window.testCalls.some(v => v[0] === 'mode' && v[1] === 'vpn'));
        await page.getByRole('radio', { name: 'TUN mode', exact: true }).click();
        await page.waitForFunction(() => window.testCalls.some(v => v[0] === 'mode' && v[1] === 'tun'));
        await page.getByRole('radio', { name: 'Proxy mode', exact: true }).click();
        const field = page.getByRole('textbox', { name: 'Shared resolvers', exact: true });
        await field.fill('1.1.1.1\n8.8.8.8');
        await page.getByRole('button', { name: 'Save & use for all', exact: true }).click();
        await page.getByText('Shared resolvers saved and enabled.', { exact: true }).waitFor();
        const toggle = page.getByRole('switch', { name: 'Use for all connections', exact: true });
        await toggle.click();
        await page.getByText('Off · each connection uses its own resolver profile', { exact: true }).waitFor();
        await field.fill('1.1.1.1\n8.8.8.8');
        await page.getByRole('button', { name: 'Save & use for all', exact: true }).click();
        await page.getByText('Shared resolvers saved and enabled.', { exact: true }).waitFor();
        await page.reload();
        await page.getByText('Using Shared resolvers for every connection', { exact: true }).waitFor();
        assert.equal(await page.getByRole('radio', { name: 'Proxy mode', exact: true }).getAttribute('aria-checked'), 'true');
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${theme} ${width}: horizontal overflow`);
        assert.ok(await page.locator('.quick-setup').evaluate(el => el.scrollWidth <= el.clientWidth + 1), 'Quick setup content overflow');
        await page.getByRole('button', { name: 'Connect', exact: true }).waitFor({ state: 'visible' });
        await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === 'Connect' && !b.disabled));
        await page.screenshot({ path: path.join(out, `dashboard-${theme}-${width}.png`), fullPage: true });
        await page.getByRole('button', { name: 'Connect', exact: true }).click();
        await page.getByText('Disconnect to change these settings', { exact: true }).waitFor();
        assert.ok(await page.getByRole('radio', { name: 'VPN mode', exact: true }).isDisabled());
        assert.ok(await field.isDisabled());
        results.push({ theme, width });
        await page.close();
      }
    }
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ results, errors }, null, 2));
    console.log('PASS: mode changes, resolver save and scope, reload persistence, connected locks, and 12 responsive theme/viewport combinations.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
