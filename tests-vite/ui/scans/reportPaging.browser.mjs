import { chromium, expect } from '@playwright/test';
import { createServer } from 'vite';

// All API data below is synthetic. No auth writes, scanner, model or remote service runs.
const scanId = '00000000-0000-4000-8000-000000000039';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const checkedAt = '2026-10-08T00:00:00.000Z';
const provenanceRef = `target-${'b'.repeat(64)}`;
const plain = (value) => ({ value, state: 'available', redacted: false });
const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const assessment = (source, severity, score) => ({
  source,
  provenanceRef,
  language: 'en',
  severity,
  fixedVersion: source === 'nvd' ? '2.0' : '1.5',
  title: plain('Synthetic package advisory'),
  description: plain('Synthetic description; an assessment is evidence, not a guarantee.'),
  cvss: {
    family: 'v3',
    version: '3.1',
    versionState: 'available',
    reportedScore: score,
    scoreState: 'available',
    vector,
    vectorState: 'available',
  },
});
const coverage = (check) => ({
  check,
  coverage: 'image',
  outcome: 'checked',
  ...(check === 'secret' ? { errorCode: null } : {}),
  scannerVersion: '0.69.3',
  checkedAt,
  ...(check === 'sbom' ? { componentCount: 3 } : { findingCount: 3 }),
});
const status = {
  scanId,
  state: 'completed',
  digest,
  platform: 'linux/amd64',
  imageReference: image,
  checks: ['secret', 'sbom', 'vuln'],
  perCheck: { secret: coverage('secret'), sbom: coverage('sbom'), vuln: coverage('vuln') },
  result: null,
};
function report(kind, index) {
  const nextCursor = index < 2 ? index + 1 : null;
  if (kind === 'results')
    return {
      findings: [
        {
          findingId: `synthetic-secret-${index}`,
          ruleId: 'REDACTED_RULE',
          line: null,
          evidenceRef: `redacted:${index}`,
        },
      ],
      nextCursor,
      coverage: coverage('secret'),
    };
  const base = {
    outcome: 'checked',
    coverage: 'image',
    image,
    platform: 'linux/amd64',
    scannerVersion: '0.69.3',
    checkedAt,
    nextCursor,
  };
  if (kind === 'sbom')
    return {
      ...base,
      componentCount: 3,
      os: { name: 'alpine', version: '3.21' },
      components: [{ ecosystem: 'apk', name: `synthetic-component-${index}`, version: '1.0' }],
    };
  return {
    ...base,
    findingCount: 3,
    os: { outcome: 'checked' },
    node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' },
    findings: [
      {
        findingId: `synthetic-vuln-${index}`,
        cveId: `CVE-2026-123${index}`,
        ecosystem: 'apk',
        packageName: `synthetic-package-${index}`,
        installedVersion: '1.0',
        fixedVersion: '1.5',
        severity: index === 0 ? 'LOW' : 'CRITICAL',
        severitySources: ['alpine', 'nvd'],
        provenanceRef,
        advisory: {
          schemaVersion: 1,
          state: 'available',
          assessments: [assessment('alpine', 'LOW', 3.1), assessment('nvd', 'CRITICAL', 9.8)],
          references: [],
          conflicts: ['severity', 'fixedVersion', 'cvss'],
          conflictState: 'present',
          limitations: [],
        },
      },
    ],
  };
}

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } });
let browser;
try {
  await server.listen();
  const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true });
  for (const width of [320, 375, 1280]) {
    const context = await browser.newContext({
      viewport: { width, height: 850 },
      reducedMotion: 'reduce',
      serviceWorkers: 'block',
    });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const requests = [];
    const errors = [];
    let failNext = true;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const method = route.request().method();
      requests.push({ path: url.pathname, cursor: url.searchParams.get('cursor'), method });
      if (method !== 'GET') return route.abort();
      const respond = (data, statusCode = 200) =>
        route.fulfill({ status: statusCode, contentType: 'application/json', body: JSON.stringify(data) });
      if (url.pathname === '/api/v1/auth/me')
        return respond({ id: 'synthetic-alice', email: 'fixture@example.invalid' });
      if (url.pathname.endsWith('/llm/context')) return respond({ errorCode: 'SUMMARY_DISABLED' }, 503);
      if (url.pathname === `/api/v1/browser/scans/${scanId}`) return respond(status);
      const kind = ['results', 'vuln', 'sbom'].find((kind) => url.pathname.endsWith(`/${kind}`));
      if (!kind) return respond({ errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
      const index = Number(url.searchParams.get('cursor') ?? '0');
      if (kind === 'vuln' && index === 1 && failNext) {
        failNext = false;
        await new Promise((resolve) => setTimeout(resolve, 200));
        return respond({ errorCode: 'SCAN_UNAVAILABLE' }, 503);
      }
      return respond(report(kind, index));
    });
    await page.goto(`${origin}/scans/${scanId}`);
    const cve = page.getByRole('region', { name: 'Результаты CVE' });
    const secrets = page.getByRole('region', { name: 'Результаты Secrets' });
    const sbom = page.getByRole('region', { name: 'Пакеты SBOM' });
    await expect(cve.getByText('CVE-2026-1230', { exact: true })).toBeVisible();
    await expect(cve.getByText(/Отдельный источник сообщает CRITICAL/)).toBeVisible();
    await expect(cve.getByText(/Источники расходятся/)).toBeVisible();
    await expect(cve.getByText('Подтверждённый итог CVE: 3')).toBeVisible();
    await expect(secrets.getByText('Подтверждённый итог Secrets: 3')).toBeVisible();
    await expect(sbom.getByText('Подтверждённый итог SBOM: 3')).toBeVisible();
    await page.screenshot({ path: `test-results/task39-report-${width}.png`, fullPage: true });
    await cve.screenshot({ path: `test-results/task39-cve-${width}.png` });
    const summary = cve.locator('.scan-vuln-row__details > summary').first();
    await summary.focus();
    await expect(summary).toBeFocused();
    await expect(summary).toHaveCSS('outline-style', 'solid');
    await page.keyboard.press('Enter');
    await expect(cve.getByText(/оценка источника: 9.8/)).toBeVisible();
    await expect(cve.getByText(/оценка источника: 3.1/)).toBeVisible();
    const nvd = cve.getByRole('link', { name: /NVD · открыть/ });
    await expect(nvd).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-1230');
    await expect(nvd).toHaveAttribute('rel', 'noopener noreferrer');
    await expect(nvd).toHaveAttribute('referrerpolicy', 'no-referrer');
    await cve.screenshot({ path: `test-results/task39-cve-details-${width}.png` });
    const next = cve.getByRole('button', { name: 'Далее · CVE' });
    await next.click();
    await expect(next).toBeDisabled();
    await expect(cve.getByText('Строки 1–1')).toBeVisible();
    await expect(cve.getByRole('alert')).toContainText('Показана предыдущая подтверждённая страница');
    await expect(cve.getByText('CVE-2026-1230', { exact: true })).toBeVisible();
    await expect(cve.getByText('Страница 2', { exact: true })).toHaveCount(0);
    await cve.getByRole('button', { name: 'Повторить загрузку CVE' }).click();
    await expect(cve.getByText('Строки 2–2')).toBeVisible();
    await expect(secrets.getByText('Страница 1', { exact: true })).toBeVisible();
    await expect(sbom.getByText('Страница 1', { exact: true })).toBeVisible();
    await next.click();
    await expect(cve.getByText('Строки 3–3')).toBeVisible();
    await expect(next).toBeDisabled();
    await cve.getByRole('button', { name: 'Назад · CVE' }).click();
    await expect(cve.getByText('Строки 2–2')).toBeVisible();
    await secrets.getByRole('button', { name: 'Далее · Secrets' }).click();
    await expect(secrets.getByText('Строки 2–2')).toBeVisible();
    await sbom.getByRole('button', { name: 'Далее · SBOM' }).click();
    await expect(sbom.getByText('Строки 2–2')).toBeVisible();
    if (width < 640) {
      const trigger = page.getByRole('button', { name: 'Фильтры' });
      await trigger.click();
      const dialog = page.getByRole('dialog', { name: 'Фильтры находок' });
      await dialog.getByLabel('Категория').selectOption('secret');
      await page.keyboard.press('Escape');
      await expect(trigger).toBeFocused();
      await expect(cve).toBeHidden();
      await trigger.click();
      await dialog.getByLabel('Категория').selectOption('all');
      await page.keyboard.press('Escape');
    } else {
      await page.getByLabel('Категория').selectOption('secret');
      await expect(cve).toBeHidden();
      await page.getByLabel('Категория').selectOption('all');
    }
    await expect(cve.getByText('Страница 2', { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    expect(
      requests.filter((request) => request.path.endsWith('/vuln')).map((request) => request.cursor),
    ).toEqual([null, '1', '1', '2', '1']);
    expect(requests.filter((request) => request.method !== 'GET')).toHaveLength(0);
    expect(errors).toEqual([]);
    console.log(
      `${width}px: mocked actual route, independent pages, pending/error/retry/back, keyboard disclosure/filter focus, canonical links, no overflow, no POST — PASS`,
    );
    await context.close();
  }
} finally {
  await browser?.close();
  await server.close();
}
