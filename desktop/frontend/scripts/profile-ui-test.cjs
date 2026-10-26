// Uses a synthetic bridge; Go tests cover real parsing, persistence and deduplication.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.DESKTOP_PLAYWRIGHT || 'playwright');
const fixture = JSON.parse(fs.readFileSync(process.env.DESKTOP_UI_FIXTURE, 'utf8'));
const root = path.resolve(__dirname, '../dist');
const out = process.env.DESKTOP_SCREENSHOTS || path.resolve(__dirname, '../../../.cache/profile-ui');
fs.mkdirSync(out, { recursive: true });

function installBridge(state) {
  let current = structuredClone(state);
  const original = current.connectionProfiles.find(p => p.id === 'cotten-ui');
  current.connectionProfiles.push({ ...original, id: 'synthetic-duplicate', name: 'Duplicate connection' });
  window.testCalls = [];
  const clone = () => structuredClone(current);
  const methods = {
    GetAppState: async () => clone(),
    RefreshSubscriptions: async () => clone(),
    ValidateResolverText: async raw => ({ isValid: true, normalizedResolvers: raw.split(/\r?\n/).filter(Boolean), normalizedText: raw, invalidEntries: [] }),
    GetSystemLANIP: async () => '192.0.2.1',
    GetValidatorState: async () => ({ status: 'idle', results: [], ports: [], ranges: [], retained: 0 }),
    GetScannerState: async () => ({ status: 'idle', mode: 'manual', paused: false, validResolvers: [], testingPaths: [], workingPaths: [] }),
    GetParallelTestState: async () => ({ status: 'idle', candidates: [], resolverResults: [], selectedPresetIds: [] }),
    GetCottenDNSOptionSchema: async () => current._cottenSchema || [],
    CheckFirewallStatus: async () => ({ supported: false, enabled: false }),
    SelectConnectionProfile: async id => { current.selectedConnectionProfileId = id; return clone(); },
    ImportConnectionProfiles: async (raw, type) => {
      window.testCalls.push(['import', raw, type]);
      return { state: clone(), imported: 0, skipped: 2 };
    },
    RemoveDuplicateConnectionProfiles: async () => {
      window.testCalls.push(['remove-duplicates']);
      current.connectionProfiles = current.connectionProfiles.filter(p => p.id !== 'synthetic-duplicate');
      return { state: clone(), removed: 1 };
    },
    ExportAllConnectionProfileLinks: async () => 'cottendns://synthetic-export',
    SaveConnectionProfile: async profile => {
      current.connectionProfiles = current.connectionProfiles.map(p => p.id === profile.id ? profile : p);
      return clone();
    },
  };
  window.go = { main: { App: new Proxy(methods, { get: (object, key) => object[key] || (async () => []) }) } };
  window.runtime = { EventsOn: () => () => {}, InitializeNotifications: async () => {}, CleanupNotifications: async () => {} };
}

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.DESKTOP_CHROME ? { executablePath: process.env.DESKTOP_CHROME } : {}) });
  const errors = [], results = [];
  try {
    for (const theme of ['light', 'dark']) {
      for (const width of [1280, 900]) {
        const page = await browser.newPage({ viewport: { width, height: 740 }, colorScheme: theme });
        page.on('pageerror', error => { errors.push(error.message); console.error(error.stack); });
        await page.addInitScript(installBridge, fixture);
        await page.addInitScript(t => localStorage.setItem('whitedns-ui-theme', t), theme);
        await page.route('http://whitedns.test/**', async route => {
          const pathname = decodeURIComponent(new URL(route.request().url()).pathname);
          const file = path.resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
          if (!file.startsWith(root + path.sep)) return route.fulfill({ status: 404, body: '' });
          const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png' };
          try { await route.fulfill({ contentType: mime[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) }); }
          catch { await route.fulfill({ status: 404, body: '' }); }
        });
        await page.goto('http://whitedns.test/');
        await page.getByRole('button', { name: 'Connections', exact: true }).click();
        await page.getByRole('button', { name: 'Remove duplicate connections', exact: true }).click();
        await page.getByText('Removed 1 duplicate connection profile.', { exact: true }).waitFor();
        assert.equal(await page.getByText('Duplicate connection', { exact: true }).count(), 0);
        await page.getByRole('button', { name: 'Import', exact: true }).click();
        const dialog = page.getByRole('dialog');
        await dialog.waitFor();
        assert.equal(await dialog.getByRole('combobox').count(), 0, 'type selector must be hidden initially');
        const field = dialog.getByRole('textbox', { name: 'Profiles', exact: true });
        await field.fill('cottendns://synthetic\nmasterdns://synthetic');
        await page.waitForTimeout(350);
        const background = await dialog.evaluate(el => getComputedStyle(el).backgroundColor);
        assert.notEqual(background, 'rgba(0, 0, 0, 0)', 'dialog must stay opaque');
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'page must fit viewport');
        await page.screenshot({ path: path.join(out, `import-${theme}-${width}.png`), fullPage: true });
        await dialog.getByRole('button', { name: 'Import', exact: true }).click();
        await dialog.waitFor({ state: 'hidden' });
        await page.getByText('Imported 0 connection profiles. Skipped 2 duplicates.', { exact: true }).waitFor();
        assert.ok(await page.evaluate(() => window.testCalls.some(call => call[0] === 'import' && call[2] === '')));
        await page.getByRole('button', { name: 'Import', exact: true }).click();
        await dialog.locator('summary').click();
        const type = dialog.getByRole('combobox', { name: 'Legacy link type', exact: true });
        await type.click();
        await page.getByRole('option', { name: 'StormDNS', exact: true }).click();
        await field.fill('stormdns://synthetic');
        await page.setViewportSize({ width, height: 620 });
        await dialog.getByRole('button', { name: 'Import', exact: true }).click();
        await dialog.waitFor({ state: 'hidden' });
        assert.ok(await page.evaluate(() => window.testCalls.some(call => call[0] === 'import' && call[2] === 'stormdns')));
        await page.getByRole('button', { name: 'Export all', exact: true }).click();
        await dialog.waitFor();
        assert.notEqual(await dialog.evaluate(el => getComputedStyle(el).backgroundColor), 'rgba(0, 0, 0, 0)');
        await page.screenshot({ path: path.join(out, `export-${theme}-${width}.png`), fullPage: true });
        await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
        await dialog.waitFor({ state: 'hidden' });
        await page.locator('tr[role=button]').filter({ hasText: 'Cotten Test' }).click();
        await dialog.waitFor();
        assert.notEqual(await dialog.evaluate(el => getComputedStyle(el).backgroundColor), 'rgba(0, 0, 0, 0)');
        await page.screenshot({ path: path.join(out, `edit-${theme}-${width}.png`), fullPage: true });
        results.push({ theme, width, background });
        await page.close();
      }
    }
    assert.deepEqual(errors, []);
    const report = { version: browser.version(), results, errors };
    fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(report, null, 2));
    console.log('PASS: duplicate cleanup, automatic/legacy import, skipped counts, opaque import/edit/export dialogs and responsive layouts.');
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
