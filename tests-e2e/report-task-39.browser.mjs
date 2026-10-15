import { chromium, expect } from '@playwright/test';
import { createServer } from 'vite';
import { writeFile } from 'node:fs/promises';

// Synthetic actual-route proof only. No private env, external API, scanner or model.
const id = '00000000-0000-4000-8000-000000000039';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const clock = Date.parse('2026-10-08T12:00:00.000Z');
const checkedAt = new Date(clock).toISOString();
const metadata = { resultContractVersion: 2, workerCheckedAt: clock, checkedAt,
  db: { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`, manifestDigest: `sha256:${'b'.repeat(64)}`,
    artifactSha256: 'c'.repeat(64), metadataSha256: 'd'.repeat(64), dbSha256: 'e'.repeat(64),
    updatedAt: '2026-10-06T12:00:00.000000001Z', downloadedAt: '2026-10-06T13:00:00.000Z', nextUpdate: '2026-10-07T12:00:00.000Z' },
  usableUntil: '2026-10-20T12:00:00.000000001Z',
  dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: clock, status: 'stale-but-usable', warnings: ['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE'] },
};
const finding = (index, changed = false) => ({ findingId: `synthetic-${index}`, cveId: `CVE-2026-123${index}`, ecosystem: 'apk',
  packageName: `synthetic-package-${index}`, installedVersion: '1.0', fixedVersion: changed ? '1.1' : '9.0', severity: changed ? 'LOW' : 'CRITICAL' });
const successful = (index, changed = false) => ({ ...metadata, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', scannerVersion: '0.69.3',
  os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' }, findingCount: 3, findings: [finding(index, changed)], nextCursor: index < 2 ? index + 1 : null });
const reportStatus = mode => {
  const check = { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', findingCount: mode === 'zero' ? 0 : 3,
    os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } };
  if (mode === 'unsupported') { check.outcome = 'unsupported'; check.reason = 'OS_UNKNOWN'; check.checksVersion = 'archive1'; check.errorCode = null; delete check.findingCount; }
  return { scanId: id, digest, imageReference: image, platform: 'linux/amd64', state: mode === 'scanning' ? 'running' : 'completed',
    checks: ['secret', 'sbom', 'vuln'], perCheck: {
      secret: { check: 'secret', outcome: 'checked', coverage: 'image', errorCode: null, scannerVersion: '0.69.3', checkedAt, findingCount: 1 },
      sbom: { check: 'sbom', outcome: 'checked', coverage: 'image', scannerVersion: '0.69.3', checkedAt, componentCount: 1 },
      vuln: ['missing', 'scanning'].includes(mode) ? null : check,
    }, result: null };
};
const server = await createServer({ configFile: 'tests-e2e/report-task-39.vite.config.ts', envDir: false,
  server: { host: '127.0.0.1', port: 0, proxy: undefined } });
const output = 'test-results/report-task-39-laptop';
const results = [];
const visualOnly = process.argv.includes('--visual-only');
const balanced = process.argv.includes('--balanced');
const contractReset = process.argv.includes('--contract-reset');

async function runContractReset(origin, browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce', serviceWorkers: 'block' });
  const page = await context.newPage(); page.setDefaultTimeout(10000);
  const cursors = [], requests = [], errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) return route.abort();
    if (!url.pathname.startsWith('/api/')) return route.continue();
    const method = route.request().method(); requests.push({ path: url.pathname, method });
    if (method !== 'GET') return route.abort();
    const respond = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (url.pathname === '/api/v1/auth/me') return respond({ id: 'synthetic-author', email: 'fixture@example.invalid' });
    if (url.pathname.includes('/llm/')) return respond({ errorCode: 'SUMMARY_DISABLED' }, 503);
    if (url.pathname === `/api/v1/browser/scans/${id}`) {
      const status = reportStatus('pages'); status.checks = ['vuln']; delete status.perCheck.secret; delete status.perCheck.sbom;
      return respond(status);
    }
    if (!url.pathname.endsWith('/vuln')) return respond({ errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    const cursor = url.searchParams.get('cursor'); cursors.push(cursor);
    const wire = successful(Number(cursor ?? 0), cursors.length === 5);
    if (cursors.length === 2) wire.resultContractVersion = 3;
    if (cursors.length === 6) delete wire.dbPolicy;
    if (cursors.length === 8) return respond({ errorCode: 'SCAN_UNAVAILABLE' }, 503);
    return respond(wire);
  });
  try {
    await page.goto(`${origin}/scans/${id}`);
    const cve = page.getByRole('region', { name: 'Результаты CVE' });
    const top = cve.getByRole('navigation', { name: 'Пагинация CVE · сверху' });
    const next = () => top.getByRole('button', { name: 'Далее · CVE · сверху' }).click();
    const retry = () => cve.getByRole('button', { name: 'Повторить загрузку CVE' }).click();
    const cleared = async () => {
      await expect(cve.getByRole('alert')).toContainText('Прежние данные и cursors сброшены');
      await expect(cve.getByText(/^CVE-2026-123[0-2]$/)).toHaveCount(0);
      await expect(cve.getByRole('navigation')).toHaveCount(0);
      await expect(cve.getByText(/Сохранён прежний подтверждённый снимок/)).toHaveCount(0);
      await expect(cve.getByText(/Подтверждённый итог CVE/)).toHaveCount(0);
    };
    await expect(cve.getByText('CVE-2026-1230', { exact: true })).toBeVisible();
    await next(); await cleared();
    await cve.screenshot({ path: `${output}/p2-contract-reset-1280.png` });
    await retry(); await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await next(); await expect(cve.getByText('Строки 2–2')).toBeVisible();
    await top.getByRole('button', { name: 'Назад · CVE · сверху' }).click();
    await expect(cve.getByText(/Сохранён прежний подтверждённый снимок/)).toBeVisible();
    await expect(cve.getByText('CVE-2026-1231', { exact: true })).toBeVisible();
    for (const button of await cve.getByRole('navigation').getByRole('button').all()) await expect(button).toBeDisabled();
    await cve.screenshot({ path: `${output}/p2-c4-retained-1280.png` });
    await retry(); await cleared();
    await cve.screenshot({ path: `${output}/p2-c4-metadata-cleared-1280.png` });
    await retry(); await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await next(); await expect(cve.getByRole('alert')).toContainText('Показана предыдущая подтверждённая страница');
    await expect(cve.getByText('CVE-2026-1230', { exact: true })).toBeVisible();
    await expect(cve.getByRole('navigation')).toHaveCount(2);
    await cve.screenshot({ path: `${output}/p2-503-retained-1280.png` });
    await retry(); await expect(cve.getByText('Строки 2–2')).toBeVisible();
    await expect(cve.getByRole('alert')).toHaveCount(0);
    expect(cursors).toEqual([null, '1', null, '1', null, null, null, '1', '1']);
    expect(requests.filter(request => request.method !== 'GET')).toEqual([]);
    expect(errors).toEqual([]);
    await page.screenshot({ path: `${output}/p2-recovered-report-1280.png`, fullPage: true });
    results.push({ width: 1280, contractReset: true, status: 'passed', cursors, requests, errors });
    console.log('ONE1280 actual mocked route: unknown receipt strict reset, C4→malformed recovery clear,503 retention/same cursor — PASS');
  } finally { await context.close(); }
}
let browser;
try {
  await server.listen();
  const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true });
  if (contractReset) await runContractReset(origin, browser);
  else for (const width of [320, 1024, 1280, 1440]) {
    const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce', serviceWorkers: 'block' });
    const page = await context.newPage(); page.setDefaultTimeout(10000);
    const requests = [], errors = [];
    let mode = 'pages', failNext = true, replayChanged = false;
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const method = route.request().method();
      requests.push({ path: url.pathname, cursor: url.searchParams.get('cursor'), method });
      if (method !== 'GET') return route.abort();
      const respond = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
      if (url.pathname === '/api/v1/auth/me') return respond({ id: 'synthetic-author', email: 'fixture@example.invalid' });
      if (url.pathname.includes('/llm/')) return respond({ errorCode: 'SUMMARY_DISABLED' }, 503);
      if (url.pathname === `/api/v1/browser/scans/${id}`) return respond(reportStatus(mode));
      if (url.pathname.endsWith('/results')) return respond({ findings: [{ findingId: 'secret1', ruleId: 'REDACTED_RULE', line: null, evidenceRef: 'redacted:1' }], nextCursor: null, coverage: reportStatus(mode).perCheck.secret });
      if (url.pathname.endsWith('/sbom')) return respond({ outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, scannerVersion: '0.69.3', checkedAt, componentCount: 1, components: [{ ecosystem: 'apk', name: 'fixture-package', version: '1' }], nextCursor: null });
      if (!url.pathname.endsWith('/vuln')) return respond({ errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
      const index = Number(url.searchParams.get('cursor') ?? 0);
      if (mode === 'unsupported') return respond({ ...metadata, outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN',
        os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' }, findings: [], nextCursor: null });
      if (mode === 'zero') return respond({ ...successful(0), findingCount: 0, findings: [], nextCursor: null });
      if (index === 1 && failNext) { failNext = false; await new Promise(resolve => setTimeout(resolve, 200)); return respond({ errorCode: 'SCAN_UNAVAILABLE' }, 503); }
      return respond(successful(index, index === 0 && replayChanged));
    });
    await page.goto(`${origin}/scans/${id}`);
    const cve = page.getByRole('region', { name: 'Результаты CVE' });
    await expect(cve.getByText('CVE-2026-1230', { exact: true })).toBeVisible();
    await expect(cve.getByText(/DB_DATA_OLDER_THAN_24H:/)).toBeVisible();
    await expect(cve.getByText(/DB_PUBLICATION_OVERDUE:/)).toBeVisible();
    const top = cve.getByRole('navigation', { name: 'Пагинация CVE · сверху' });
    const bottom = cve.getByRole('navigation', { name: 'Пагинация CVE · снизу' });
    await expect(top).toBeVisible(); await expect(bottom).toBeVisible();
    await expect(cve.getByRole('status')).toHaveCount(1);
    const coverage = page.getByRole('region', { name: 'Покрытие проверок' });
    const findings = page.getByRole('region', { name: 'Результаты проверок' });
    const coverageBox = await coverage.boundingBox(), findingsBox = await findings.boundingBox();
    expect(Math.abs(coverageBox.width - findingsBox.width)).toBeLessThan(2);
    expect(findingsBox.y).toBeGreaterThan(coverageBox.y + coverageBox.height);
    expect(findingsBox.width).toBeGreaterThan(width < 400 ? 240 : width * 0.72);
    const geometry = await top.locator('button').evaluateAll(buttons => buttons.map(button => ({ height: button.getBoundingClientRect().height, font: parseFloat(getComputedStyle(button).fontSize), overflow: button.scrollWidth > button.clientWidth + 1 })));
    for (const button of geometry) { expect(button.height).toBeGreaterThanOrEqual(44); expect(button.font).toBeGreaterThanOrEqual(14); expect(button.overflow).toBe(false); }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(coverage.locator('.scan-a1__coverage > li')).toHaveCount(3);
    await expect(page.getByRole('region', { name: 'Результаты Secrets' }).getByText('Подтверждённый итог Secrets: 1')).toBeVisible();
    await expect(page.getByRole('region', { name: 'Пакеты SBOM' }).getByText('Подтверждённый итог SBOM: 1')).toBeVisible();
    await page.screenshot({ path: `${output}/${balanced ? 'balanced-' : ''}${visualOnly ? 'final-' : ''}report-${width}.png`, fullPage: true });
    await cve.screenshot({ path: `${output}/${balanced ? 'balanced-' : ''}${visualOnly ? 'final-' : ''}cve-${width}.png` });
    if (visualOnly) {
      const color = await top.getByRole('button', { name: 'Далее · CVE · сверху' }).evaluate(button => getComputedStyle(button).backgroundColor);
      expect(color).toBe('rgb(209, 255, 94)');
      results.push({ width, status: 'passed', visualOnly, coverageBox, findingsBox, geometry, color, errors });
      expect(errors).toEqual([]); console.log(`${width}px final scoped pager paint/layout/fonts/buttons — PASS`);
      await context.close(); continue;
    }
    const nextTop = top.getByRole('button', { name: 'Далее · CVE · сверху' });
    await nextTop.focus(); await expect(nextTop).toHaveCSS('outline-style', 'solid');
    await nextTop.click(); await expect(bottom.getByRole('button', { name: 'Далее · CVE' })).toBeDisabled();
    await expect(cve.getByRole('alert')).toContainText('Показана предыдущая подтверждённая страница');
    await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await cve.getByRole('button', { name: 'Повторить загрузку CVE' }).click();
    await expect(cve.getByText('Строки 2–2')).toBeVisible();
    await bottom.getByRole('button', { name: 'Далее · CVE' }).click();
    await expect(cve.getByText('Строки 3–3')).toBeVisible();
    await bottom.getByRole('button', { name: 'Назад · CVE' }).click();
    await expect(cve.getByText('Строки 2–2')).toBeVisible();
    replayChanged = true;
    await top.getByRole('button', { name: 'Назад · CVE · сверху' }).click();
    await expect(cve.getByRole('alert')).toContainText('Содержимое посещённой страницы изменилось');
    await expect(cve.getByText('CVE-2026-1231', { exact: true })).toBeVisible();
    await expect(cve.getByText(/Сохранён прежний подтверждённый снимок/)).toBeVisible();
    await expect(nextTop).toBeDisabled();
    await cve.screenshot({ path: `${output}/stale-${width}.png` });
    replayChanged = false;
    await cve.getByRole('button', { name: 'Повторить загрузку CVE' }).click();
    await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await expect(cve.getByRole('alert')).toHaveCount(0);
    await page.reload();
    await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await expect(cve.getByText(/47 полных ч/)).toBeVisible();
    for (const state of ['unsupported', 'zero', 'missing', 'scanning']) {
      mode = state; await page.reload();
      if (state === 'unsupported') await expect(cve.getByText(/CVE не поддерживаются:/)).toBeVisible();
      else if (state === 'zero') await expect(cve.getByText(/0 CVE в выполненной/)).toBeVisible();
      else await expect(cve.getByText(/Ожидаем результат CVE/)).toBeVisible();
      await expect(cve.getByRole('navigation')).toHaveCount(0);
      await expect(cve.getByRole('button')).toHaveCount(0);
      await cve.screenshot({ path: `${output}/${state}-${width}.png` });
    }
    expect(requests.filter(request => request.method !== 'GET')).toEqual([]);
    expect(errors).toEqual([]);
    results.push({ width, status: 'passed', coverageBox, findingsBox, geometry, requests, errors });
    console.log(`${width}px actual mock route multipage/error/retry/stale/reload/unsupported/zero/missing/scanning, geometry/font/buttons — PASS`);
    await context.close();
  }
} catch (error) {
  results.push({ status: 'failed', message: error.stack }); throw error;
} finally {
  await writeFile(`${output}/${contractReset ? 'p2-browser-contract-reset' : `browser-${balanced ? 'balanced-' : ''}${visualOnly ? 'visual-recheck' : 'initial'}`}.json`, JSON.stringify(results, null, 2));
  await browser?.close(); await server.close();
}
