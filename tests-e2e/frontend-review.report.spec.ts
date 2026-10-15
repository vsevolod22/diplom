import { expect, test } from '@playwright/test';

// Current actual-route UI with an independent synthetic report-v1 responder.
// No scanner/backend/provider is started; all non-local requests are blocked.
const id = '00000000-0000-4000-8000-000000000039';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const checkedAt = '2026-10-08T12:00:00.000Z';
const findings = Array.from({ length: 30 }, (_, index) => ({
  findingId: `review-${index}`, cveId: `CVE-2026-${1000 + index}`, ecosystem: 'apk',
  packageName: `package-${index}`, installedVersion: '1.0', fixedVersion: '9.0',
  severity: index < 10 ? 'CRITICAL' : index < 20 ? 'HIGH' : 'LOW',
}));
const components = Array.from({ length: 30 }, (_, index) => ({ ecosystem: index < 15 ? 'apk' : 'npm', name: `package-${String(index).padStart(2, '0')}`, version: '1' }));
const secrets = Array.from({ length: 30 }, (_, index) => ({ findingId: `secret-${index}`, ruleId: index < 15 ? 'RULE_A' : 'RULE_B', line: index % 2 ? index : null, evidenceRef: `redacted:${index}` }));
const coverage = (check: string) => ({ check, coverage: 'image', outcome: 'checked', scannerVersion: 'synthetic', checkedAt,
  ...(check === 'sbom' ? { componentCount: 30 } : { findingCount: 30 }), ...(check === 'secret' ? { errorCode: null } : {}) });
const status = { scanId: id, digest, imageReference: image, platform: 'linux/amd64', state: 'completed', checks: ['secret', 'sbom', 'vuln'],
  perCheck: { secret: coverage('secret'), sbom: coverage('sbom'), vuln: coverage('vuln') }, result: null };

for (const width of [320, 375, 1024, 1280, 1440]) {
  test(`current report-v1 ${width}px: independent pagers, errors, filters, reload and revocation`, async ({ page, baseURL }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const requests: { path: string; query: string; method: string }[] = [];
    const errors: string[] = [];
    let failNext = true;
    let revoked = false;
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      requests.push({ path: url.pathname, query: url.search, method: route.request().method() });
      const json = (body: unknown, code = 200) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(body) });
      if (route.request().method() !== 'GET') return route.abort();
      if (url.pathname === '/api/v1/auth/me') return json({ id: 'synthetic-review', email: 'review@example.invalid' });
      if (url.pathname.includes('/llm/')) return json({ errorCode: 'SUMMARY_DISABLED' }, 503);
      if (url.pathname === `/api/v1/browser/scans/${id}`) return json(status);
      if (revoked) return json({ errorCode: 'SCAN_UNAVAILABLE' }, 403);
      const kind = url.pathname.split('/').at(-1);
      if (!['vuln', 'sbom', 'results'].includes(kind!)) return json({ errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
      const limit = Number(url.searchParams.get('limit'));
      const offset = Number(url.searchParams.get('cursor')?.split(':')[1] ?? 0);
      const sort = url.searchParams.get('sort');
      const severity = url.searchParams.get('severity')?.split(',') ?? null;
      const ecosystem = url.searchParams.get('ecosystem');
      const name = url.searchParams.get('name')?.toLowerCase() ?? null;
      const ruleId = url.searchParams.get('ruleId');
      const linePresence = url.searchParams.get('linePresence');
      if (url.searchParams.get('view') !== 'report-v1') return json({ errorCode: 'INVALID_REPORT_QUERY' }, 400);
      if (kind === 'vuln' && offset > 0 && failNext) {
        failNext = false;
        await new Promise(resolve => setTimeout(resolve, 200));
        return json({ errorCode: 'SCAN_UNAVAILABLE' }, 503);
      }
      const selected = kind === 'vuln' ? findings.filter(row => !severity || severity.includes(row.severity)) : kind === 'sbom' ? components.filter(row => (!ecosystem || row.ecosystem === ecosystem) && (!name || row.name.includes(name))) : secrets.filter(row => (!ruleId || row.ruleId === ruleId) && (!linePresence || (linePresence === 'known') === (row.line !== null)));
      if (kind === 'vuln') {
              const rank = { LOW: 1, HIGH: 3, CRITICAL: 4 };
              selected.sort((a, b) => ((rank[(a as typeof findings[number]).severity as keyof typeof rank] ?? 0) - (rank[(b as typeof findings[number]).severity as keyof typeof rank] ?? 0)) * (sort === 'severity:desc' ? -1 : 1));
            }
            const rows = selected.slice(offset, offset + limit);
      const pageMeta = { version: 1, limit, offset, returnedCount: rows.length, totalCount: 30, matchedCount: selected.length, sort,
        filters: kind === 'vuln' ? { severity } : kind === 'sbom' ? { ecosystem, name } : { ruleId, linePresence } };
      const nextCursor = offset + rows.length < selected.length ? `review:${offset + rows.length}` : null;
      if (kind === 'results') return json({ findings: rows, nextCursor, coverage: coverage('secret'), page: pageMeta });
      return json({ outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', scannerVersion: 'synthetic', checkedAt,
        ...(kind === 'sbom' ? { componentCount: 30, components: rows, os: { name: 'alpine', version: '3.21' } } : { findingCount: 30, findings: rows }), nextCursor, page: pageMeta });
    });
    await page.goto(`/scans/${id}`);
    const cve = page.getByRole('region', { name: 'Результаты CVE', exact: true });
    const sbom = page.getByRole('region', { name: 'Пакеты SBOM' });
    const secret = page.getByRole('region', { name: 'Результаты Secrets' });
    await expect(cve.getByText('CVE-2026-1000', { exact: true })).toBeVisible();
    await expect(sbom.getByText('package-00', { exact: true })).toBeVisible();
    await expect(secret.getByText('ID: secret-0', { exact: true })).toBeVisible();
    const top = cve.getByRole('navigation', { name: 'Пагинация CVE · сверху' });
    const next = top.getByRole('button', { name: 'Далее · CVE · сверху' });
    await next.focus();
    await page.keyboard.press('Enter');
    await expect(next).toBeDisabled();
    await expect(cve.getByRole('alert')).toContainText('Показана предыдущая подтверждённая страница');
    await expect(cve.getByText('Строки 1–25')).toBeVisible();
    await cve.getByRole('button', { name: 'Повторить загрузку CVE' }).click();
    await expect(cve.getByText('Строки 26–30')).toBeVisible();
    await expect(next).toBeDisabled();
    await expect(sbom.getByText('Строки 1–25')).toBeVisible();
    await expect(secret.getByText('Строки 1–25')).toBeVisible();
    await top.getByRole('button', { name: 'Назад · CVE · сверху' }).click();
    await expect(cve.getByText('Строки 1–25')).toBeVisible();
    for (const size of ['5', '10', '25', '50']) {
      await cve.getByLabel('Строк на странице · CVE').selectOption(size);
      await expect(cve.getByText(`Строки 1–${Math.min(Number(size), 30)}`)).toBeVisible();
    }
    await cve.getByLabel('Уровень опасности (severity) · CVE').selectOption('HIGH,CRITICAL');
    await expect(cve.getByText('Совпадений во всём отчёте CVE: 20')).toBeVisible();
    await expect(cve.getByText('Полный итог CVE: 30')).toBeVisible();
    await expect(cve.getByText('CVE-2026-1029', { exact: true })).toHaveCount(0);
        await cve.getByLabel('Сортировка · CVE').selectOption('severity:asc');
        await expect(cve.locator('.scan-vuln-row').first()).toContainText('CVE-2026-1010');
    await sbom.getByLabel('Имя пакета · SBOM').fill('PACKAGE-2');
    await sbom.getByRole('button', { name: 'Применить имя · SBOM' }).click();
    await expect(sbom.getByText('Совпадений во всём отчёте SBOM: 10')).toBeVisible();
    await secret.getByLabel('Rule ID · Secrets').fill('NO_MATCH');
    await secret.getByRole('button', { name: 'Применить Rule ID', exact: true }).click();
    await expect(secret.getByText(/Нет совпадений глобального фильтра Secrets/)).toBeVisible();
    await expect(secret.getByText('Полный итог Secrets: 30')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: testInfo.outputPath(`report-${width}.png`), fullPage: true });
    await page.reload();
    await expect(cve.getByText('Строки 1–25')).toBeVisible();
    revoked = true;
    await cve.getByRole('button', { name: 'Далее · CVE · сверху' }).click();
    await expect(cve.getByRole('alert')).toContainText('Доступ к отчёту утрачен');
    await expect(cve.getByText('CVE-2026-1000', { exact: true })).toHaveCount(0);
    await expect(cve.getByRole('navigation')).toHaveCount(0);
    expect(errors).toEqual([]);
    expect(requests.every(request => request.method === 'GET')).toBe(true);
    await testInfo.attach('synthetic-requests', { body: JSON.stringify(requests), contentType: 'application/json' });
  });
}

for (const action of ['restore', 'move', 'terminal'] as const) {
  test(`current discovery Chromium native disabled blur: ${action}`, async ({ page, baseURL }) => {
    await page.setViewportSize({ width: 375, height: 900 });
    let release: (() => void) | undefined;
    const policy = { pageSize: 12, maxPages: 5, maxCandidates: 60, maxActivePerProcess: 8, maxActivePerSubject: 2,
      maxRequestsPerSubject: 30, rateWindowMs: 60000, maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' };
    const candidate = (index: number) => ({ label: `Alpine · browser-proof-${index}`, reference: `registry-1.docker.io/library/alpine:proof-${index}`,
      scannable: true, eligibility: 'alpine-only', reason: 'Synthetic tag only', kind: 'tag', tagConfirmed: true,
      checks: { secret: true, sbom: true, vuln: 'conditional' } });
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const json = (body: unknown) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
      if (url.pathname === '/api/v1/auth/me') return json({ id: 'discovery-proof', email: 'proof@example.invalid' });
      if (url.pathname.endsWith('/images/eligibility')) return json({ imageReference: route.request().postDataJSON().imageReference,
        eligible: false, eligibility: 'unsupported', allowedCheckSets: [], reason: 'UNSUPPORTED_SCAN' });
      if (!url.pathname.endsWith('/images')) return route.abort();
      const second = url.searchParams.has('cursor');
      if (second) await new Promise<void>(resolve => { release = resolve; });
      const terminal = second && action === 'terminal';
      return json({ items: [candidate(second ? 2 : 1)], loaded: second ? 2 : 1, pages: second ? 2 : 1,
        nextCursor: terminal ? null : (second ? 'b' : 'a').repeat(48), state: terminal ? 'terminal' : 'more-available', policy });
    });
    await page.goto('/scans/new');
    const search = page.getByRole('searchbox', { name: 'Поиск по доступным образам' });
    await search.fill('browserproof');
    const selected = page.getByRole('button', { name: /Alpine · browser-proof-1/ });
    await selected.click();
    await expect(selected).toHaveAttribute('aria-pressed', 'true');
    const more = page.getByRole('button', { name: 'Показать ещё' });
    await more.focus();
    await page.keyboard.press('Enter');
    await expect(more).toBeDisabled();
    await expect.poll(() => typeof release).toBe('function');
    if (action === 'move') await search.focus();
    release!();
    await expect(page.getByRole('button', { name: /Alpine · browser-proof-2/ })).toBeVisible();
    await expect(selected).toHaveAttribute('aria-pressed', 'true');
    if (action === 'restore') await expect(more).toBeFocused();
    else if (action === 'move') await expect(search).toBeFocused();
    else await expect(page.getByRole('status', { name: 'Состояние поиска Docker Hub' })).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  });
}
