// End-to-end interaction checks against a synthetic Wails bridge. All graph
// values in these review screenshots are test measurements, not a live server.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.DESKTOP_PLAYWRIGHT || 'playwright');
const fixture = JSON.parse(fs.readFileSync(process.env.DESKTOP_UI_FIXTURE, 'utf8'));
const root = path.resolve(__dirname, '../dist');
const out = process.env.DESKTOP_SCREENSHOTS || path.resolve(__dirname, '../../../.cache/approved-design');
fs.mkdirSync(out, { recursive: true });

function installBridge({ fixture, connected }) {
  const state = structuredClone(fixture);
  const addresses = ['1.1.1.1', '8.8.8.8', ...Array.from({ length: 22 }, (_, i) => `9.9.9.${i + 1}`)];
  state.tunnelMode = 'proxy';
  state.selectedConnectionProfileId = 'cotten-ui';
  Object.assign(state.connectionProfiles.find(p => p.id === 'cotten-ui'), { name: 'Jadid · Cotten', domain: 'dns.example.org', domains: ['dns.example.org'], resolverProfileId: state.resolverProfiles[0].id });
  state.resolverProfiles[0].resolverText = '1.1.1.1\n8.8.8.8:53';
  state.selectedSettingsProfileId = 'cotten-ui-settings';
  Object.assign(state.settingsProfiles.find(p => p.id === 'cotten-ui-settings'), { name: 'CottenDNS preset', cottenDnsOptions: { TUNNEL_MODE: 'normal' } });
  const file = { id: 'file-shared', name: 'resolvers', sourceFileName: 'resolvers.txt', resolverSource: 'file', resolverFile: 'managed/resolvers.txt', resolverCount: 24, resolverPreview: addresses.slice(0, 16), resolverText: '' };
  window.testCalls = [];
  window.testProbeCount = 0;
  window.testFailPing = false;
  const clone = () => structuredClone(state);
  const importFile = () => {
    state.resolverProfiles = state.resolverProfiles.filter(p => p.id !== file.id).concat(file);
    state.globalResolverProfileId = file.id;
    state.selectedResolverProfileId = file.id;
  };
  const connect = () => {
    Object.assign(state.runtime, { status: 'connected', runtimeType: 'masterdns', activeConnectionId: 'cotten-ui', listenIp: '127.0.0.1', localProxyIp: '127.0.0.1', listenPort: 10886, proxyProtocol: 'socks' });
    state.runtime.resolverState = { activeResolvers: addresses.slice(0, 2), validResolvers: addresses, standbyResolvers: addresses.slice(2), activeCount: 2, validCount: 24, standbyCount: 22, rejectedCount: 0, activeComplete: true, validComplete: true, standbyComplete: true };
  };
  if (connected) { importFile(); connect(); }
  const methods = {
    GetAppState: async () => clone(), RefreshSubscriptions: async () => clone(), GetTunModeSupported: async () => true,
    GetScannerState: async () => ({ status: 'idle', validResolvers: [] }),
    GetParallelTestState: async () => ({ status: 'idle', candidates: [], selectedPresetIds: [] }),
    GetValidatorState: async () => ({ status: 'idle', results: [] }),
    GetCottenDNSOptionSchema: async () => state._cottenSchema || [], CheckFirewallStatus: async () => ({ enabled: false, supported: true }),
    ValidateResolverText: async text => ({ isValid: !!text.trim(), normalizedResolvers: text.split('\n').filter(Boolean), normalizedText: text, invalidEntries: [] }),
    LookupProxyCountry: async () => ({ ok: true, countryCode: 'DE', ip: '203.0.113.2' }),
    SetTunnelMode: async mode => { state.tunnelMode = mode; return clone(); },
    SetGlobalResolverProfile: async id => { state.globalResolverProfileId = id; return clone(); },
    ImportGlobalResolverFile: async () => {
      window.testCalls.push(['import-file']);
      if (window.testPickerCancel) return { state: clone(), profile: {}, imported: 0, skipped: 0 };
      if (window.testPickerInvalid) throw new Error('Resolver file must contain at least one valid resolver.');
      importFile(); return { state: clone(), profile: file, imported: 24, skipped: 0 };
    },
    GetResolverProfilePreview: async (id, offset, limit) => ({ resolvers: addresses.slice(offset, offset + limit), total: 24, hasMore: offset + limit < 24 }),
    SaveGlobalResolvers: async text => {
      if (text.includes('invalid')) throw new Error('Enter valid resolver addresses.');
      const profile = { id: 'pasted', name: 'Shared resolvers', resolverText: text };
      state.resolverProfiles = state.resolverProfiles.filter(p => p.id !== profile.id).concat(profile);
      state.globalResolverProfileId = profile.id; state.selectedResolverProfileId = profile.id;
      return clone();
    },
    StartConnection: async () => { connect(); return clone(); },
    StopConnection: async () => { Object.assign(state.runtime, { status: 'disconnected', runtimeType: '', activeConnectionId: '', listenPort: 0 }); return clone(); },
    PingCloudflare: async () => ({ ok: true, latencyMs: 82 }),
    ProbeTunnelLatency: async () => {
      const index = window.testProbeCount++;
      if (window.testSlowPing) return new Promise(resolve => { window.testResolvePing = resolve; });
      if (window.testFailPing) return { ok: false, latencyMs: 0, message: 'Synthetic timeout' };
      return { ok: true, latencyMs: [78, 79, 81, 82, 90, 80, 79, 83, 81, 82, 82, 80, 78, 89, 82, 88, 80][index % 17], message: 'Synthetic tunnel response' };
    },
  };
  window.go = { main: { App: new Proxy(methods, { get: (target, key) => target[key] || (async () => []) }) } };
  window.runtime = { EventsOn: () => () => {}, BrowserOpenURL: url => window.testCalls.push(['url', url]), InitializeNotifications: async () => {}, CleanupNotifications: async () => {} };
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const errors = [], layouts = [];
  async function open(theme, width, connected, height = width >= 1600 ? 1040 : 768) {
    const page = await browser.newPage({ viewport: { width, height }, colorScheme: theme });
    page.on('pageerror', error => { errors.push(error.message); console.error(error.stack); });
    await page.clock.install({ time: new Date('2026-10-27T12:00:00Z') });
    await page.addInitScript(installBridge, { fixture, connected });
    await page.addInitScript(theme => localStorage.setItem('whitedns-ui-theme', theme), theme);
    await page.route('http://whitedns.test/**', async route => {
      const url = new URL(route.request().url());
      const file = path.resolve(root, '.' + (url.pathname === '/' ? '/index.html' : url.pathname));
      if (!file.startsWith(root + path.sep)) return route.fulfill({ status: 404, body: '' });
      const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2' };
      try { await route.fulfill({ contentType: mime[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) }); }
      catch { await route.fulfill({ status: 404, body: '' }); }
    });
    await page.goto('http://whitedns.test/');
    await page.getByRole('radio', { name: 'Proxy mode', exact: true }).waitFor();
    await page.clock.runFor(100);
    return page;
  }
  try {
    const page = await open('dark', 1920, false);
    assert.equal(await page.getByText('Get WhiteVPN', { exact: true }).count(), 0);
    assert.equal(await page.getByText('Source: WhiteDNS Telegram', { exact: true }).count(), 0);
    assert.equal(await page.getByRole('radio', { name: 'Proxy mode', exact: true }).evaluate(el => getComputedStyle(el).borderTopColor), 'rgb(9, 206, 114)');
    for (const name of ['YouTube', 'Telegram']) await page.getByRole('link', { name: `WhiteDNS on ${name}`, exact: true }).click();
    assert.deepEqual(await page.evaluate(() => window.testCalls.filter(c => c[0] === 'url').map(c => c[1])), ['https://www.youtube.com/@WhiteDNS?sub_confirmation=1', 'https://t.me/whitedns']);
    await page.getByRole('button', { name: 'Import file', exact: true }).click();
    await page.getByText('resolvers.txt', { exact: true }).waitFor();
    await page.clock.runFor(300);
    await page.getByRole('switch', { name: 'Use for all connections', exact: true }).evaluate(el => el.getAnimations().forEach(animation => animation.finish()));
    assert.equal(await page.getByRole('switch', { name: 'Use for all connections', exact: true }).evaluate(el => getComputedStyle(el).backgroundColor), 'rgb(9, 206, 114)');
    const field = page.getByRole('textbox', { name: 'Shared resolvers', exact: true });
    const small = (await field.boundingBox()).height;
    await page.getByRole('button', { name: 'Expand resolver input', exact: true }).click();
    assert.ok((await field.boundingBox()).height > small + 60);
    await page.getByRole('button', { name: 'Collapse resolver input', exact: true }).click();
    await page.evaluate(() => { window.testPickerCancel = true; });
    await page.getByRole('button', { name: 'Replace', exact: true }).click();
    assert.equal(await field.inputValue(), '1.1.1.1\n8.8.8.8');
    await page.evaluate(() => { window.testPickerCancel = false; window.testPickerInvalid = true; });
    await page.getByRole('button', { name: 'Replace', exact: true }).click();
    await page.getByText('Resolver file must contain at least one valid resolver.', { exact: true }).first().waitFor();
    assert.equal(await page.getByText('resolvers.txt', { exact: true }).count(), 1);
    await page.evaluate(() => { window.testPickerInvalid = false; });
    await page.getByRole('button', { name: 'Replace', exact: true }).click();
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.getByRole('button', { name: 'Disconnect', exact: true }).waitFor();
    const detailsToggle = page.getByRole('button', { name: 'Connection details', exact: true });
    await detailsToggle.click();
    assert.ok(await page.locator('#connection-details-panel').isVisible());
    await detailsToggle.click();
    assert.equal(await page.locator('#connection-details-panel').isVisible(), false);
    assert.ok(await page.getByRole('button', { name: 'Import file', exact: true }).isDisabled());
    assert.ok(await page.getByRole('button', { name: 'Replace', exact: true }).isDisabled());
    await page.clock.runFor(25_000);
    assert.ok(await page.evaluate(() => window.testProbeCount >= 5));
    assert.ok(await page.locator('.latency-line').count());
    await page.evaluate(() => { window.testFailPing = true; });
    await page.clock.runFor(5_000);
    assert.ok(await page.locator('.latency-failure').count());
    const probeDetails = page.getByRole('button', { name: 'Tunnel probe details', exact: true });
    await probeDetails.focus();
    await page.getByRole('tooltip').waitFor();
    assert.ok((await page.getByRole('tooltip').innerText()).includes('Synthetic timeout'));
    assert.equal(await page.getByText('Latest tunnel probe failed. Retrying automatically.', { exact: true }).count(), 0);
    await page.screenshot({ path: path.join(out, 'probe-failure-details.png'), fullPage: true });
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await page.getByRole('button', { name: 'Connect', exact: true }).waitFor();
    assert.equal(await page.locator('.latency-line').count(), 0);
    const stopped = await page.evaluate(() => window.testProbeCount);
    await page.clock.runFor(10_000);
    assert.equal(await page.evaluate(() => window.testProbeCount), stopped);
    await page.evaluate(() => { window.testFailPing = false; window.testSlowPing = true; });
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.clock.runFor(11_000);
    assert.equal(await page.evaluate(() => window.testProbeCount), stopped + 1, 'slow probes must not overlap');
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await page.evaluate(() => window.testResolvePing({ ok: true, latencyMs: 9999 }));
    assert.equal(await page.locator('.latency-point').count(), 0, 'stale response was applied to a disconnected session');
    await page.close();

    const sizes = process.env.DESKTOP_TEST_SIZES ? JSON.parse(process.env.DESKTOP_TEST_SIZES) : [[1920,1040],[1920,900],[1600,900],[1366,768],[1280,720],[1100,700],[1024,620],[900,620],[860,620],[375,812],[320,640],[2560,1440]];
    for (const theme of ['dark', 'light']) for (const [width, height] of sizes) {
      const page = await open(theme, width, true, height);
      await page.clock.runFor(Number(process.env.DESKTOP_SAMPLE_WINDOW_MS || 80_000));
      assert.ok(await page.locator('.latency-line').count(), 'no measured curve');
      assert.ok(await page.locator('.tunnel-latency').evaluate(el => el.querySelector('.latency-timeline').getBoundingClientRect().bottom <= el.getBoundingClientRect().bottom - 4), `${theme} ${width}: chart time labels are clipped`);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${theme} ${width}: horizontal overflow`);
      assert.ok(await page.locator('.quick-setup').evaluate(el => el.scrollWidth <= el.clientWidth + 1));
      assert.ok(await page.locator('.quick-setup').evaluate(el => {
        const card = el.getBoundingClientRect();
        return [...el.querySelectorAll('button, textarea')].every(control => { const r = control.getBoundingClientRect(); return !r.width || !r.height || (r.left >= card.left && r.right <= card.right); });
      }), `${theme} ${width}: a resolver control is clipped`);
      const boxes = await page.evaluate(() => Object.fromEntries(['.dashboard-status', '.quick-setup', '.dashboard-health', '.tunnel-latency'].map(selector => { const r = document.querySelector(selector).getBoundingClientRect(); return [selector, { y: r.y, height: r.height, bottom: r.bottom }]; })));
      if (height >= 1000) {
        assert.ok(boxes['.tunnel-latency'].bottom <= height - 12, `${width}x${height}: desktop panels exceed viewport`);
        assert.ok(boxes['.tunnel-latency'].bottom >= height - 32, `${width}x${height}: unused space below the chart`);
      }
      const ordered = Object.values(boxes);
      assert.ok(ordered.every((box, i) => i === 0 || box.y >= ordered[i-1].bottom + 8), 'panels overlap');
      await page.screenshot({ path: path.join(out, `connected-${theme}-${width}x${height}.png`), fullPage: true });
      layouts.push({ theme, width, height, boxes });
      if (width === 860 || width <= 375) {
        await page.evaluate(() => { window.testFailPing = true; });
        await page.clock.runFor(5_000);
        await page.getByRole('button', { name: 'Tunnel probe details', exact: true }).waitFor();
        assert.ok(await page.locator('.latency-summary').evaluate(el => {
          const card = el.closest('.tunnel-latency').getBoundingClientRect();
          return [...el.children].every(child => child.getBoundingClientRect().right <= card.right - 8);
        }), `${theme} ${width}: retry status or latency statistics overflow`);
        await page.screenshot({ path: path.join(out, `retrying-${theme}-${width}x${height}.png`), fullPage: true });
      }
      await page.close();
    }
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(out, 'approved-design-results.json'), JSON.stringify({ layouts, errors }, null, 2));
    console.log(`PASS: details controls, probe diagnostics, failure handling, sampling lifecycle and ${layouts.length} responsive size/theme combinations.`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
