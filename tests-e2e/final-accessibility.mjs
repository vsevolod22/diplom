import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium, expect } from '@playwright/test';
import { createServer } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

// Inert browser evidence only: no backend, real credentials, scanner, Engine or provider.
// Run directly, not as part of the historical/frozen proof suites.
assert.ok(
  process.argv.slice(2).every((arg) => arg === '--manual'),
  'Only --manual is supported',
);
const manual = process.argv.includes('--manual');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cache = await mkdtemp(join(tmpdir(), 'dip-final-a11y-'));
const report = {
  baseline: '636b834 (working-tree source; see git status)',
  checks: [],
  requests: [],
  blockedExternal: [],
  browserErrors: [],
};
let server;
let browser;
let context;
const deadline = setTimeout(
  () => {
    console.error('FAIL: final accessibility exceeded its absolute execution budget');
    process.exitCode = 1;
    void cleanup();
  },
  manual ? 375_000 : 75_000,
);
let cleaning;
function cleanup() {
  return (cleaning ??= (async () => {
    clearTimeout(deadline);
    try {
      await context?.close();
    } finally {
      try {
        await browser?.close();
      } finally {
        try {
          await server?.close();
        } finally {
          await rm(cache, { recursive: true, force: true });
        }
      }
    }
  })());
}
async function tabTo(page, locator) {
  for (let step = 0; step < 80; step++) {
    if (await locator.evaluate((element) => element === document.activeElement)) return step;
    await page.keyboard.press('Tab');
  }
  throw new Error('Target was not keyboard reachable in 80 Tab steps');
}
async function axTree(page) {
  const session = await context.newCDPSession(page);
  try {
    return (await session.send('Accessibility.getFullAXTree')).nodes.filter((node) => !node.ignored);
  } finally {
    await session.detach();
  }
}
try {
  server = await createServer({
    root,
    configFile: false,
    envDir: false,
    envPrefix: [],
    cacheDir: cache,
    optimizeDeps: { include: ['react', 'react-dom', 'react-dom/client'] },
    plugins: [
      tailwindcss(),
      react(),
      svgr(),
      tsconfigPaths({ root }),
      {
        name: 'inert-final-announcer-probe',
        resolveId(id) {
          if (id === 'virtual:final-accessibility') return id;
        },
        load(id) {
          if (id !== 'virtual:final-accessibility') return;
          return `import React from 'react';
          import { createRoot } from 'react-dom/client';
          import { flushSync } from 'react-dom';
          import { ScanStatusAnnouncement } from '/src/features/scans/ScanStatusAnnouncement.tsx';
          export async function probe() {
            const host = document.createElement('div');
            document.body.append(host);
            const root = createRoot(host);
            const scan = { scanId: 'synthetic-announcer-only', state: 'running', stage: 'secret', percent: 0 };
            const render = () => flushSync(() => root.render(React.createElement(ScanStatusAnnouncement, { scan: { ...scan } })));
            try {
              render();
              const region = host.querySelector('[aria-live]');
              if (!region) throw new Error('Announcer component did not commit its live region');
              const messages = [];
              const observer = new MutationObserver(() => { if (region.textContent) messages.push(region.textContent); });
              observer.observe(region, { subtree: true, characterData: true, childList: true });
              const tick = () => new Promise(resolve => requestAnimationFrame(resolve));
              try {
                const initial = region.textContent;
                for (let percent = 0; percent <= 100; percent++) { scan.percent = percent; render(); await tick(); }
                const percentMessages = [...messages];
                scan.stage = 'sbom'; render(); await tick();
                scan.state = 'completed'; render(); await tick();
                for (let index = 0; index < 10; index++) { render(); await tick(); }
                const repeatedMessages = [...messages];
                scan.scanId = 'other-synthetic-announcer'; render(); await tick();
                return { initial, percentMessages, repeatedMessages, reset: region.textContent,
                  live: region.getAttribute('aria-live'), atomic: region.getAttribute('aria-atomic') };
              } finally { observer.disconnect(); }
            } finally { flushSync(() => root.unmount()); host.remove(); }
          }`;
        },
      },
    ],
    server: {
      host: '127.0.0.1',
      port: 0,
      hmr: false,
      proxy: undefined,
      watch: null,
      fs: {
        deny: ['.env', '.env.*', '**/.local-auth/**', '**/*.sqlite', '**/*.sqlite-*', '**/*.pem', '**/*.key'],
      },
    },
  });
  await server.listen();
  const address = server.httpServer.address();
  assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: !manual });
  context = await browser.newContext({
    viewport: { width: 375, height: 900 },
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  const id = '00000000-0000-4000-8000-000000000023';
  const status = {
    scanId: id,
    state: 'running',
    imageReference: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`,
    checks: ['secret'],
    perCheck: { secret: null },
    result: null,
  };
  let authenticated = false;
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) {
      report.blockedExternal.push(url.origin);
      return route.abort();
    }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    report.requests.push({ method: request.method(), path: url.pathname });
    const json = (body, code = 200) =>
      route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/api/v1/auth/me')
      return authenticated
        ? json({ id: 'synthetic-final-a11y', email: 'a11y@example.invalid' })
        : json({ errorCode: 'UNAUTHORIZED' }, 401);
    if (authenticated && url.pathname === `/api/v1/browser/scans/${id}` && request.method() === 'GET')
      return json(status);
    if (
      authenticated &&
      url.pathname === `/api/v1/browser/scans/${id}/cancel` &&
      request.method() === 'POST'
    ) {
      assert.equal(request.postData(), '{}');
      status.state = 'cancelled';
      return json({ scanId: id, state: 'cancelled' });
    }
    return json({ errorCode: 'INERT_TEST_BACKEND_UNAVAILABLE' }, 503);
  });
  const page = await context.newPage();
  page.setDefaultTimeout(8_000);
  page.on('pageerror', (error) => report.browserErrors.push(error.message));

  await page.goto(`${origin}/demo/scans/partial-demo`);
  const filters = page.getByRole('button', { name: 'Фильтры', exact: true });
  await expect(filters).toBeVisible();
  const steps = await tabTo(page, filters);
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: 'Фильтры находок' });
  await expect(dialog).toBeVisible();
  const category = dialog.getByRole('combobox', { name: 'Категория', exact: true });
  await expect(category).toBeFocused();
  const tree = await axTree(page);
  const axDialog = tree.find(
    (node) => node.role?.value === 'dialog' && node.name?.value === 'Фильтры находок',
  );
  assert.ok(axDialog, 'Dialog role/name must reach Chromium accessibility tree');
  assert.match(axDialog.description?.value ?? '', /Категория выбирает набор/);
  assert.ok(tree.some((node) => node.role?.value === 'combobox' && node.name?.value === 'Категория'));
  // Native option selection is fixture setup, NOT keyboard/SR evidence: headless
  // macOS ArrowDown attempts did not establish a committed native selection.
  await category.selectOption('secret');
  await expect(category).toHaveValue('secret');
  for (let index = 0; index < 8; index++) {
    await page.keyboard.press('Tab');
    assert.equal(
      await dialog.evaluate((element) => element.contains(document.activeElement)),
      true,
      'Tab must remain in modal',
    );
  }
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(filters).toBeFocused();
  const partialTree = await axTree(page);
  assert.ok(partialTree.some((node) => node.name?.value?.includes('База уязвимостей недоступна')));
  assert.equal(await page.locator('.scan-a1__scene:visible').first().getAttribute('aria-hidden'), 'true');
  report.checks.push({
    name: 'actual demo route: keyboard/modal + AX roles/names/description + textual failure',
    result: 'PASS',
    tabStepsToFilters: steps,
    nativeOptionKeyboard: 'NOT_VERIFIED; selection uses selectOption for fixture setup',
  });

  await page.goto(`${origin}/demo/scans/new`);
  const tabs = page.getByRole('tablist', { name: 'Памятка о подготовке скана' });
  const target = tabs.getByRole('tab', { name: '01 / Цель' });
  await expect(target).toBeVisible();
  await tabTo(page, target);
  await page.keyboard.press('ArrowRight');
  await expect(tabs.getByRole('tab', { name: '02 / Границы' })).toBeFocused();
  await expect(tabs.getByRole('tab', { name: '02 / Границы' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
  assert.match(await page.getByRole('main').ariaSnapshot(), /Запуск недоступен.*disabled/);
  report.checks.push({
    name: 'actual demo create: keyboard tabs, selected state and disabled launch in ARIA snapshot',
    result: 'PASS',
  });

  authenticated = true;
  await page.goto(`${origin}/scans/${id}`);
  const cancel = page.getByRole('button', { name: 'Отменить скан', exact: true });
  await expect(cancel).toBeVisible();
  const live = page.locator('.scan-a1__state-main [aria-live="polite"]');
  await expect(live).toHaveText('');
  await expect(live).toHaveAttribute('aria-atomic', 'true');
  await tabTo(page, cancel);
  page.once('dialog', (prompt) => {
    assert.equal(prompt.type(), 'confirm');
    void prompt.accept();
  });
  await page.keyboard.press('Enter');
  await expect(live).toHaveText('Итог скана: Отменён');
  await expect(cancel).toHaveCount(0);
  const terminalTree = await axTree(page);
  const announcement = terminalTree.find((node) => node.name?.value === 'Итог скана: Отменён');
  assert.ok(announcement, 'Terminal text must be exposed, not display:none');
  assert.ok(
    terminalTree.some((node) =>
      node.properties?.some((property) => property.name === 'live' && property.value?.value === 'polite'),
    ),
  );
  report.checks.push({
    name: 'actual protected route + synthetic auth/status/cancel: keyboard confirm -> GET -> atomic polite text in AX tree',
    result: 'PASS',
    announcement: announcement.name.value,
  });

  const burst = await page.evaluate(async () => {
    const { probe } = await import('/@id/virtual:final-accessibility');
    return probe();
  });
  assert.equal(burst.initial, '');
  assert.deepEqual(burst.percentMessages, []);
  assert.deepEqual(burst.repeatedMessages, ['Этап скана: sbom', 'Итог скана: Завершён']);
  assert.equal(burst.reset, '');
  assert.equal(burst.live, 'polite');
  assert.equal(burst.atomic, 'true');
  report.checks.push({
    name: 'actual announcer component: 101 committed synthetic percent renders, one stage/terminal message, repeated terminal and identity reset',
    result: 'PASS',
    ...burst,
  });
  assert.deepEqual(report.blockedExternal, []);
  assert.deepEqual(report.browserErrors, []);
  assert.deepEqual(
    report.requests.filter((request) => request.method !== 'GET'),
    [{ method: 'POST', path: `/api/v1/browser/scans/${id}/cancel` }],
  );
  report.checks.push({
    name: 'network fence: every API response synthetic, one intercepted cancel POST, no external requests or browser errors',
    result: 'PASS',
  });
  if (manual) {
    status.state = 'running';
    await page.goto(`${origin}/demo/scans/partial-demo`);
    console.log(
      `MANUAL: isolated synthetic browser held for 5 minutes; VoiceOver is NOT enabled automatically.\nDemo: ${origin}/demo/scans/partial-demo\nCreate: ${origin}/demo/scans/new\nSynthetic cancel/terminal: ${origin}/scans/${id}\nAll API requests remain intercepted. Ctrl+C ends the hold with cleanup. Record actual heard results separately; this script cannot certify them.`,
    );
    const stop = new AbortController();
    const end = () => stop.abort();
    process.once('SIGINT', end);
    process.once('SIGTERM', end);
    try {
      await delay(300_000, undefined, { signal: stop.signal });
    } catch (error) {
      if (error.name !== 'AbortError') throw error;
    } finally {
      process.off('SIGINT', end);
      process.off('SIGTERM', end);
    }
    report.manual = 'Operator window provided; audible acceptance NOT recorded or inferred';
    assert.deepEqual(report.blockedExternal, []);
    assert.deepEqual(report.browserErrors, []);
  }
} catch (error) {
  report.checks.push({
    name: 'execution',
    result: 'FAIL',
    error: error instanceof Error ? error.message : String(error),
  });
  process.exitCode = 1;
} finally {
  try {
    await cleanup();
    report.cleanup = 'PASS: browser/context/listener closed; temporary Vite cache removed';
  } catch (error) {
    report.cleanup = `FAIL: ${error.message}`;
    process.exitCode = 1;
  }
  console.log(JSON.stringify(report, null, 2));
}
