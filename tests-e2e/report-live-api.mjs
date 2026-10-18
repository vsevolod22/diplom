// Run: node tests-e2e/report-live-api.mjs
// Synthetic seeded report + current UI + real Nest/auth/SQLite over loopback HTTP.
// Not Trivy, deployment, scanner admission, provider/LLM or live-data acceptance.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const file = fileURLToPath(import.meta.url);
const root = resolve(dirname(file), '..');
const apiRequire = createRequire(join(root, 'server/api/package.json'));
const password = 'synthetic-report-password-1234';
const ownerEmail = 'report-owner@example.com';
const otherEmail = 'report-other@example.com';
const count = 61;
const safeEnv = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot']
  .filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
const source = path => pathToFileURL(join(root, path)).href;

async function apiChild() {
  await import(apiRequire.resolve('reflect-metadata'));
  const { NestFactory } = await import(apiRequire.resolve('@nestjs/core'));
  const { AppModule } = await import(source('server/api/src/app.module.ts'));
  const { LedgerStore } = await import(source('server/api/src/ledger/ledger-store.ts'));
  const { normalizeAdvisory } = await import(source('server/api/src/worker/vuln-advisory.ts'));
  let app;
  let stop;
  const stopped = new Promise(resolveStop => { stop = resolveStop; });
  process.on('message', message => { if (message === 'stop') stop(); });
  process.once('disconnect', stop);
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  const timer = setTimeout(stop, 180_000);
  try {
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const apiOrigin = `http://127.0.0.1:${app.getHttpServer().address().port}`;
    const register = async email => {
      const response = await fetch(`${apiOrigin}/api/v1/auth/register`, { method: 'POST',
        headers: { origin: process.env.AUTH_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }) });
      assert.equal(response.status, 201);
      return response.json();
    };
    const owner = await register(ownerEmail), other = await register(otherEmail);
    // Explicit disposable account enrollment; retain the real production browser guard.
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = `${owner.id},${other.id}`;
    const ledger = app.get(LedgerStore).ledger;
    const digest = `sha256:${'a'.repeat(64)}`;
    const image = `registry-1.docker.io/library/alpine@${digest}`;
    const scanId = ledger.enqueue({ subject: owner.id, idempotencyKey: 'report-live-api',
      registry: 'registry-1.docker.io', repository: 'library/alpine', digest,
      platform: 'linux/amd64', checks: '["secret","sbom","vuln"]', scope: 'image' }).scanId;
    const job = ledger.claim();
    assert.equal(job.scanId, scanId);
    const provenanceRef = `target-${'b'.repeat(64)}`;
    const findings = Array.from({ length: count }, (_, i) => {
      const cveId = `CVE-2026-${String(i).padStart(4, '0')}`;
      const packageName = `pkg-${String(i).padStart(2, '0')}`;
      const advisory = normalizeAdvisory({ Title: `Synthetic issue ${i}`,
        Description: '<script>unsafe markup</script>Safe synthetic advisory https://example.invalid CANARY-private',
        Severity: i < 31 ? 'LOW' : 'HIGH', SeveritySource: 'nvd', DataSource: { ID: 'nvd' } }, provenanceRef, cveId);
      assert.ok(!JSON.stringify(advisory).includes('CANARY'));
      return { findingId: `vuln-${createHash('sha256').update(JSON.stringify(['apk', provenanceRef, cveId, packageName, '1.2-r0'])).digest('hex')}`,
        cveId, ecosystem: 'apk', provenanceRef, packageName, installedVersion: '1.2-r0', fixedVersion: null,
        severity: i < 31 ? 'LOW' : 'HIGH', severitySources: ['nvd'], advisory };
    });
    const outcomes = [
      { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: Array.from({ length: count }, (_, i) => ({
        findingId: `secret-${i}-0`, ruleId: i < 31 ? 'rule-known' : 'rule-unknown', line: i < 31 ? i : null,
        evidenceRef: `result-${i}-secret-0` })) },
      { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3', sbom: { image, platform: 'linux/amd64',
        os: { name: 'alpine', version: '3.20' }, components: Array.from({ length: count }, (_, i) => ({
          ecosystem: i < 31 ? 'apk' : 'npm', name: `pkg-${String(i).padStart(2, '0')}`, version: '1' })) } },
      { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3', image, findings },
    ];
    assert.equal(ledger.finishCombined(scanId, job.attempts, outcomes, undefined, job.leaseToken), true);
    const { NGINX_ARCHIVE_TARGET } = await import(source('server/api/src/oci/bounded-image-archive.ts'));
    const seedCancellation = async mode => {
      const target = mode === 'archive' || mode === 'storage-error' ? NGINX_ARCHIVE_TARGET : {
        registry: 'registry-1.docker.io', repository: 'library/alpine', digest, platform: 'linux/amd64' };
      const id = ledger.enqueue({ ...target, subject: owner.id, idempotencyKey: `cancel-${mode}`,
        checks: '["secret","sbom","vuln"]', scope: 'image' }).scanId;
      if (mode === 'storage-error') {
        const { default: Database } = await import(apiRequire.resolve('better-sqlite3'));
        const { consumeOne } = await import(source('server/api/src/worker/outbox-consumer.ts'));
        // This connection and trigger touch only the freshly created disposable ledger.
        const raw = new Database(process.env.SCAN_LEDGER_PATH);
        try {
          raw.exec(`CREATE TRIGGER reject_browser_checkpoint BEFORE INSERT ON scan_checkpoints
            WHEN NEW.scan_id = '${id}' AND NEW.check_name = 'sbom'
            BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_STORAGE_CANARY'); END`);
          const envelope = { receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
            archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1',
            resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
            scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
              expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 } };
          const neverScan = async () => { throw new Error('Unexpected real scanner invocation'); };
          await assert.rejects(consumeOne(ledger, { timeoutMs: 1000, dbDir: dirname(process.env.SCAN_LEDGER_PATH), archivePolicy: 'proof' },
            neverScan, Date.now(), neverScan, neverScan, async (_checks, options) => {
              assert.equal(options.onCheckpoint('secret', { ...envelope, secret: { outcome: 'checked', findings: outcomes[0].findings } }), true);
              options.onCheckpoint('sbom', { ...envelope, sbom: { outcome: 'checked', sbom: {
                ...outcomes[1].sbom, image: `${target.registry}/${target.repository}@${target.digest}` } } });
              throw new Error('Checkpoint storage failure was swallowed');
            }), error => error.code === 'SQLITE_CONSTRAINT_TRIGGER' && error.message === 'SYNTHETIC_STORAGE_CANARY');
          assert.equal(ledger.state(id, owner.id), 'running');
          assert.equal(ledger.archiveResult(id, owner.id), undefined);
          assert.equal(ledger.result(id, owner.id), undefined);
          assert.deepEqual(ledger.events(id, owner.id, null).map(event => event.state), ['queued', 'running']);
          assert.deepEqual(raw.prepare('SELECT check_name FROM scan_checkpoints WHERE scan_id = ?').all(id), [{ check_name: 'secret' }]);
        } finally {
          raw.exec('DROP TRIGGER IF EXISTS reject_browser_checkpoint');
          raw.close();
        }
        return { id, mode };
      }
      const claim = ledger.claim();
      assert.equal(claim.scanId, id);
      if (mode === 'ordinary') {
        assert.equal(ledger.checkpointCombined(claim, outcomes[0]), true);
        assert.equal(ledger.checkpointCombined(claim, outcomes[2]), true);
      } else if (mode === 'archive') {
        assert.equal(ledger.checkpointArchive(claim, 'sbom', {
          receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
            archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1',
            resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
          scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
            expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
          sbom: { outcome: 'checked', sbom: { ...outcomes[1].sbom, image: `${target.registry}/${target.repository}@${target.digest}` } },
        }), true);
      }
      return { id, mode };
    };
    const cancellations = [];
    for (const mode of ['ordinary', 'archive', 'empty']) cancellations.push(await seedCancellation(mode));
    // Respect the real per-owner active-scan cap: seed the fourth case only after browser cancellations.
    process.on('message', async message => {
      if (message !== 'seed-storage-error') return;
      try { process.send({ cancellation: await seedCancellation('storage-error') }); }
      catch (error) { process.send({ fixtureError: String(error) }); }
    });
    process.send({ apiOrigin, scanId, count, cancellations });
    await stopped;
  } finally {
    clearTimeout(timer);
    if (app) await app.close();
    if (process.connected) process.disconnect();
  }
}

async function managed() {
  const { chromium, expect: baseExpect } = await import('@playwright/test');
  const expect = baseExpect.configure({ timeout: 7000 });
  const { createServer } = await import('vite');
  const [{ default: react }, { default: tailwindcss }, { default: svgr }, { default: tsconfigPaths }] = await Promise.all([
    import('@vitejs/plugin-react-swc'), import('@tailwindcss/vite'), import('vite-plugin-svgr'), import('vite-tsconfig-paths'),
  ]);
  const directory = await mkdtemp(join(tmpdir(), 'report-live-api-'));
  const sockets = new Set(), errors = [], egress = [], receipts = [], checks = [];
  let api, vite, browser, apiOrigin, origin;
  let childClosed;
  const started = Date.now();
  const allocator = net.createServer();
  let abort;
  const aborted = new Promise((_, reject) => { abort = () => reject(new Error('Managed integration deadline/signal')); });
  const timer = setTimeout(abort, 180_000);
  process.once('SIGTERM', abort);
  process.once('SIGINT', abort);
  const closedPort = address => new Promise(resolveClosed => {
    if (!address) return resolveClosed(true);
    const url = new URL(address), socket = net.connect({ host: '127.0.0.1', port: Number(url.port) });
    socket.once('connect', () => { socket.destroy(); resolveClosed(false); });
    socket.once('error', () => resolveClosed(true));
    socket.setTimeout(1000, () => { socket.destroy(); resolveClosed(false); });
  });
  try {
    await Promise.race([aborted, (async () => {
      await new Promise(resolveListen => allocator.listen(0, '127.0.0.1', resolveListen));
      const port = allocator.address().port;
      await new Promise(resolveClose => allocator.close(resolveClose));
      origin = `http://127.0.0.1:${port}`;
      api = spawn(process.execPath, ['--import', apiRequire.resolve('tsx/esm'), file, '--api-child'], {
        cwd: join(root, 'server/api'), env: { ...safeEnv, NODE_ENV: 'test',
          AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
          AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true' }, stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
      });
      childClosed = once(api, 'close');
      const ready = await Promise.race([once(api, 'message').then(([value]) => value),
        childClosed.then(([code]) => { throw new Error(`API fixture exited before readiness (${code})`); })]);
      apiOrigin = ready.apiOrigin;
      const scanPath = `/api/v1/browser/scans/${ready.scanId}`;
      vite = await createServer({ root, configFile: false, envDir: false, cacheDir: join(directory, 'vite-cache'),
        plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
        server: { host: '127.0.0.1', port, strictPort: true, hmr: false, proxy: { '/api/v1': { target: apiOrigin, changeOrigin: false } } },
      });
      vite.httpServer.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
      await vite.listen();
      browser = await chromium.launch({ headless: true });
      const newContext = async () => {
        const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce', serviceWorkers: 'block' });
        // No mocked HTTP: only block non-loopback browser egress; every app/API request continues untouched.
        await context.route('**/*', route => {
          const url = new URL(route.request().url());
          if (url.origin === origin) return route.continue();
          egress.push(url.origin); return route.abort();
        });
        context.on('page', page => {
          page.setDefaultTimeout(7000);
          page.on('pageerror', error => errors.push(error.message));
        });
        return context;
      };
      const context = await newContext(), page = await context.newPage();
      const login = async (target, email) => {
        await target.goto(`${origin}/login`);
        await target.getByLabel('Email', { exact: true }).fill(email);
        await target.getByLabel('Пароль', { exact: true }).fill(password);
        const response = target.waitForResponse(r => r.url() === `${origin}/api/v1/auth/login` && r.request().method() === 'POST');
        const [loginResponse] = await Promise.all([response, target.getByRole('button', { name: 'Войти', exact: true }).click()]);
        assert.equal(loginResponse.status(), 200);
        await expect(target.getByRole('heading', { name: 'Вы вошли' })).toBeVisible();
      };
      await login(page, ownerEmail);
      const cookie = (await context.cookies(origin)).find(value => value.name === 'demo_session');
      assert.ok(cookie?.httpOnly && cookie.sameSite === 'Lax');
      await page.goto(`${origin}/scans/${ready.scanId}`);
      const specs = [
        { kind: 'vuln', label: 'CVE', region: 'Результаты CVE', rows: 'ul.scan-vuln-list > li', sort: 'severity:desc' },
        { kind: 'sbom', label: 'SBOM', region: 'Пакеты SBOM', rows: 'ul.scan-report-inventory > li', sort: 'name:asc' },
        { kind: 'results', label: 'Secrets', region: 'Результаты Secrets', rows: 'ul.scan-report-inventory > li', sort: 'ruleId:asc' },
      ];
      const rowsOf = (spec, value) => spec.kind === 'sbom' ? value.components : value.findings;
      const rowId = (spec, row) => spec.kind === 'sbom' ? row.name : row.findingId;
      const verify = async (spec, value) => {
        const section = page.getByRole('region', { name: spec.region, exact: true });
        const rows = rowsOf(spec, value);
        assert.equal(value.page.version, 1); assert.equal(value.page.totalCount, count);
        await expect(section.locator('[aria-busy]')).toHaveAttribute('aria-busy', 'false');
        await expect(section.getByRole('alert')).toHaveCount(0);
        await expect(section.locator(spec.rows)).toHaveCount(rows.length);
        await expect(section.getByRole('status').first()).toContainText(`Совпадений во всём отчёте ${spec.label}: ${value.page.matchedCount}`);
        const text = await section.locator(spec.rows).allTextContents();
        rows.forEach((row, index) => assert.ok(text[index].includes(spec.kind === 'vuln' ? row.cveId : spec.kind === 'sbom' ? row.name : row.findingId)));
        receipts.push({ kind: spec.kind, ...value.page, nextCursor: value.nextCursor !== null });
        return section;
      };
      const change = async (spec, action, expected, hasCursor = false) => {
        const response = page.waitForResponse(r => {
          const url = new URL(r.url());
          return url.pathname === `${scanPath}/${spec.kind}` && url.searchParams.get('view') === 'report-v1' &&
            url.searchParams.has('cursor') === hasCursor && Object.entries(expected).every(([key, value]) => url.searchParams.get(key) === String(value));
        });
        const [wire] = await Promise.all([response, action()]); assert.equal(wire.status(), 200); assert.equal(wire.headers()['cache-control'], 'no-store');
        const value = await wire.json(); await verify(spec, value); return value;
      };
      for (const spec of specs) {
        const section = page.getByRole('region', { name: spec.region, exact: true });
        await expect(section.locator(spec.rows)).toHaveCount(25);
        for (const limit of [5, 10, 25, 50]) {
          let value = await change(spec, () => section.getByLabel(`Строк на странице · ${spec.label}`).selectOption(String(limit)), { limit, sort: spec.sort });
          const firstIds = rowsOf(spec, value).map(row => rowId(spec, row));
          value = await change(spec, () => section.getByRole('button', { name: `Далее · ${spec.label} · сверху`, exact: true }).click(), { limit }, true);
          assert.equal(value.page.offset, limit);
          value = await change(spec, () => section.getByRole('button', { name: `Назад · ${spec.label}`, exact: true }).click(), { limit });
          assert.equal(value.page.offset, 0); assert.deepEqual(rowsOf(spec, value).map(row => rowId(spec, row)), firstIds);
          const ids = [...firstIds];
          for (let hop = 0; value.nextCursor && hop < count; hop++) {
            value = await change(spec, () => section.getByRole('button', { name: `Далее · ${spec.label}`, exact: true }).click(), { limit }, true);
            ids.push(...rowsOf(spec, value).map(row => rowId(spec, row)));
          }
          assert.equal(value.nextCursor, null); assert.equal(ids.length, count); assert.equal(new Set(ids).size, count);
          await expect(section.getByRole('button', { name: `Далее · ${spec.label}`, exact: true })).toBeDisabled();
          checks.push(`${spec.label}: limit=${limit}, complete unique traversal + top-next/bottom-back`);
        }
      }
      const [cve, sbom, secret] = specs;
      const cveSection = page.getByRole('region', { name: cve.region, exact: true });
      let value = await change(cve, () => cveSection.getByLabel('Уровень опасности (severity) · CVE').selectOption('HIGH'), { severity: 'HIGH' });
      assert.equal(value.page.matchedCount, 30); assert.ok(value.findings.every(row => row.severity === 'HIGH'));
      value = await change(cve, () => cveSection.getByLabel('Сортировка · CVE').selectOption('severity:asc'), { sort: 'severity:asc', severity: 'HIGH' });
      assert.equal(value.page.offset, 0);
      value = await change(cve, () => cveSection.getByLabel('Уровень опасности (severity) · CVE').selectOption(''), { sort: 'severity:asc' });
      assert.equal(value.findings[0].severity, 'LOW');
      assert.ok(value.findings[0].advisory); assert.ok(!JSON.stringify(value).includes('CANARY'));
      const advisoryCard = cveSection.locator('li.scan-vuln-row').first();
      await advisoryCard.locator('summary').click();
      await expect(advisoryCard.locator('details')).toHaveAttribute('open', '');
      await expect(advisoryCard.getByText(/Safe synthetic advisory/)).toBeVisible();
      assert.ok(!(await cveSection.innerText()).includes('CANARY'));
      const sbomSection = page.getByRole('region', { name: sbom.region, exact: true });
      value = await change(sbom, () => sbomSection.getByLabel('Экосистема · SBOM').selectOption('npm'), { ecosystem: 'npm' });
      assert.equal(value.page.matchedCount, 30);
      value = await change(sbom, () => sbomSection.getByLabel('Сортировка · SBOM').selectOption('name:desc'), { sort: 'name:desc', ecosystem: 'npm' });
      assert.equal(value.components[0].name, 'pkg-60');
      await sbomSection.getByLabel('Имя пакета · SBOM', { exact: true }).fill('PKG-5');
      value = await change(sbom, () => sbomSection.getByRole('button', { name: 'Применить имя · SBOM', exact: true }).click(), { name: 'pkg-5', ecosystem: 'npm' });
      assert.equal(value.page.filters.name, 'pkg-5'); assert.equal(value.page.matchedCount, 10);
      const secretSection = page.getByRole('region', { name: secret.region, exact: true });
      value = await change(secret, () => secretSection.getByLabel('Номер строки · Secrets').selectOption('unknown'), { linePresence: 'unknown' });
      assert.equal(value.page.matchedCount, 30); assert.ok(value.findings.every(row => row.line === null));
      await secretSection.getByLabel('Rule ID · Secrets', { exact: true }).fill('rule-unknown');
      value = await change(secret, () => secretSection.getByRole('button', { name: 'Применить Rule ID', exact: true }).click(), { ruleId: 'rule-unknown', linePresence: 'unknown' });
      assert.equal(value.page.matchedCount, 30);
      await change(secret, () => secretSection.getByLabel('Сортировка · Secrets').selectOption('line:desc'), { sort: 'line:desc', ruleId: 'rule-unknown' });
      checks.push('Global severity, ecosystem + normalized ASCII name, ruleId + unknown-line filters; all three sort controls; normalized advisory decoded/rendered');
      value = await change(cve, () => cveSection.getByLabel('Уровень опасности (severity) · CVE').selectOption('UNKNOWN'), { severity: 'UNKNOWN' });
      assert.equal(value.page.matchedCount, 0); assert.equal(value.nextCursor, null);
      await expect(cveSection.getByText(/Нет совпадений глобального фильтра CVE/)).toBeVisible();
      await expect(cveSection.getByRole('navigation')).toHaveCount(0);
      value = await change(cve, () => cveSection.getByLabel('Уровень опасности (severity) · CVE').selectOption(''), { sort: 'severity:asc' });
      assert.equal(value.page.offset, 0); assert.equal(value.page.matchedCount, count);
      await sbomSection.getByLabel('Имя пакета · SBOM', { exact: true }).fill('no-such-package');
      value = await change(sbom, () => sbomSection.getByRole('button', { name: 'Применить имя · SBOM', exact: true }).click(), { name: 'no-such-package', ecosystem: 'npm' });
      assert.equal(value.page.matchedCount, 0); assert.equal(value.nextCursor, null);
      await expect(sbomSection.getByText(/Нет совпадений глобального фильтра SBOM/)).toBeVisible();
      await expect(sbomSection.getByRole('navigation')).toHaveCount(0);
      value = await change(sbom, () => sbomSection.getByRole('button', { name: 'Сбросить имя · SBOM', exact: true }).click(), { ecosystem: 'npm' });
      assert.equal(value.page.offset, 0); assert.equal(value.page.matchedCount, 30); assert.equal(value.page.filters.name, null);
      await expect(sbomSection.getByLabel('Имя пакета · SBOM', { exact: true })).toHaveValue('');
      await secretSection.getByLabel('Rule ID · Secrets', { exact: true }).fill('no-such-rule');
      value = await change(secret, () => secretSection.getByRole('button', { name: 'Применить Rule ID', exact: true }).click(), { ruleId: 'no-such-rule', linePresence: 'unknown' });
      assert.equal(value.page.matchedCount, 0); assert.equal(value.nextCursor, null);
      await expect(secretSection.getByText(/Нет совпадений глобального фильтра Secrets/)).toBeVisible();
      await expect(secretSection.getByRole('navigation')).toHaveCount(0);
      value = await change(secret, () => secretSection.getByRole('button', { name: 'Сбросить Rule ID', exact: true }).click(), { linePresence: 'unknown' });
      assert.equal(value.page.offset, 0); assert.equal(value.page.matchedCount, 30); assert.equal(value.page.filters.ruleId, null);
      await expect(secretSection.getByLabel('Rule ID · Secrets', { exact: true })).toHaveValue('');
      checks.push('All categories: global zero matches retain whole totals, hide empty pagers and recover first pages through real filter reset controls');
      value = await change(secret, () => secretSection.getByLabel('Номер строки · Secrets').selectOption('known'), { linePresence: 'known', sort: 'line:desc' });
      assert.equal(value.page.matchedCount, 31);
      assert.deepEqual(value.findings.map(row => row.line), Array.from({ length: 31 }, (_, i) => 30 - i));
      await expect(secretSection.getByText('secret · Строка 0', { exact: true })).toBeVisible();
      value = await change(secret, () => secretSection.getByLabel('Сортировка · Secrets').selectOption('line:asc'), { linePresence: 'known', sort: 'line:asc' });
      assert.deepEqual(value.findings.map(row => row.line), Array.from({ length: 31 }, (_, i) => i));
      for (const sort of ['line:asc', 'line:desc']) {
        value = await change(secret, () => sort === 'line:asc'
          ? secretSection.getByLabel('Номер строки · Secrets').selectOption('')
          : secretSection.getByLabel('Сортировка · Secrets').selectOption(sort), { sort });
        assert.equal(value.page.matchedCount, count); assert.equal(value.page.filters.linePresence, null);
        assert.deepEqual(value.findings.slice(0, 31).map(row => row.line), Array.from({ length: 31 }, (_, i) => sort === 'line:asc' ? i : 30 - i));
        assert.ok(value.findings.slice(31).length > 0);
        assert.ok(value.findings.slice(31).every(row => row.line === null));
      }
      checks.push('Secrets: line zero is known and rendered; numeric ascending/descending order keeps unknown lines last');
      const reloadReplies = specs.map(spec => page.waitForResponse(r => new URL(r.url()).pathname === `${scanPath}/${spec.kind}` && new URL(r.url()).searchParams.get('view') === 'report-v1'));
      await page.reload();
      for (const [index, response] of (await Promise.all(reloadReplies)).entries()) {
        assert.equal(new URL(response.url()).searchParams.has('cursor'), false);
        const body = await response.json(); assert.equal(body.page.offset, 0); assert.equal(body.page.limit, 25);
        assert.ok(Object.values(body.page.filters).every(filter => filter === null));
        await verify(specs[index], body);
      }
      checks.push('Reload: real owner cookie retained; fresh report-v1 first pages, default filters/limit, no persisted opaque cursor');
      const anonymous = await newContext(), anonymousPage = await anonymous.newPage();
      await anonymousPage.goto(`${origin}/login`);
      for (const suffix of ['', '/vuln?view=report-v1', '/sbom?view=report-v1', '/results?view=report-v1']) {
        const response = await anonymous.request.get(`${origin}${scanPath}${suffix}`); assert.equal(response.status(), 401);
      }
      await anonymousPage.goto(`${origin}/scans/${ready.scanId}`);
      await expect(anonymousPage.getByRole('link', { name: 'войдите', exact: true })).toBeVisible();
      await expect(anonymousPage.locator('.scan-vuln-row')).toHaveCount(0);
      checks.push('Anonymous: status + three real report endpoints 401; UI login-required guard, no report rows');
      const foreign = await newContext(), foreignPage = await foreign.newPage();
      await login(foreignPage, otherEmail);
      for (const suffix of ['', '/vuln?view=report-v1&cursor=malformed', '/sbom?view=report-v1', '/results?view=report-v1']) {
        const response = await foreign.request.get(`${origin}${scanPath}${suffix}`); assert.equal(response.status(), 404);
        assert.ok(!(await response.text()).includes('CVE-2026'));
      }
      const denied = foreignPage.waitForResponse(r => new URL(r.url()).pathname === scanPath);
      await foreignPage.goto(`${origin}/scans/${ready.scanId}`); assert.equal((await denied).status(), 404);
      await expect(foreignPage.getByRole('alert')).toContainText('Не удалось получить данные скана');
      await expect(foreignPage.locator('.scan-vuln-row')).toHaveCount(0);
      checks.push('Foreign enrolled account: status + all report endpoints 404 (including malformed cursor); no owner rows in UI');
      for (const scenario of [...ready.cancellations, { mode: 'storage-error' }]) {
        const mode = scenario.mode;
        let id = scenario.id;
        if (mode === 'storage-error') {
          const seeded = once(api, 'message');
          api.send('seed-storage-error');
          const [reply] = await seeded;
          assert.equal(reply.fixtureError, undefined);
          assert.equal(reply.cancellation.mode, mode);
          id = reply.cancellation.id;
        }
        const path = `/api/v1/browser/scans/${id}`;
        const saved = mode === 'ordinary' ? ['secret', 'vuln'] : mode === 'archive' ? ['sbom'] : mode === 'storage-error' ? ['secret'] : [];
        await page.goto(`${origin}/scans/${id}`);
        await expect(page.getByRole('button', { name: 'Отменить скан', exact: true })).toBeVisible();
        await expect(page.locator('.scan-vuln-row')).toHaveCount(0);
        if (mode === 'storage-error') {
          const response = await context.request.get(`${origin}${path}`);
          assert.equal(response.status(), 200);
          const snapshot = await response.json();
          assert.equal(snapshot.state, 'running');
          assert.ok(Object.values(snapshot.perCheck).every(value => value === null));
          for (const spec of specs) {
            const section = page.getByRole('region', { name: spec.region, exact: true });
            await expect(section.locator(spec.rows)).toHaveCount(0);
            await expect(section.getByText(/Полный итог.*: 0|SCAN_FAILED/)).toHaveCount(0);
          }
          await expect(page.locator('body')).not.toContainText('SYNTHETIC_STORAGE_CANARY');
        }
        page.once('dialog', dialog => dialog.accept());
        const cancelled = page.waitForResponse(r => new URL(r.url()).pathname === `${path}/cancel`);
        await page.getByRole('button', { name: 'Отменить скан', exact: true }).click();
        assert.equal((await cancelled).status(), 200);
        await expect(page.getByText(saved.length ? /Сканирование отменено\. Сохранены результаты завершённых проверок/ : /Сканирование отменено\. Сохранённых результатов завершённых проверок нет/)).toBeVisible();
        await expect(page.getByText('Скан отменён; realtime остановлен')).toBeVisible();
        await expect(page.getByText(/завершённый результат не сохранён/)).toHaveCount(3 - saved.length);
        const beforeReload = await (await context.request.get(`${origin}${path}`)).json();
        assert.equal(beforeReload.state, 'cancelled');
        assert.deepEqual(Object.keys(beforeReload.perCheck).filter(key => beforeReload.perCheck[key] !== null), saved);
        for (const spec of specs.filter(spec => saved.includes(spec.kind === 'results' ? 'secret' : spec.kind))) {
          const section = page.getByRole('region', { name: spec.region, exact: true });
          await expect(section.locator(spec.rows)).toHaveCount(25);
          await section.getByRole('button', { name: `Далее · ${spec.label} · сверху`, exact: true }).click();
          await expect(section.getByText('Строки 26–50', { exact: true })).toBeVisible();
          await section.getByRole('button', { name: `Далее · ${spec.label} · сверху`, exact: true }).click();
          await expect(section.locator(spec.rows)).toHaveCount(11);
          await expect(section.getByText(`Полный итог ${spec.label}: 61`, { exact: true })).toBeVisible();
        }
        const events = await (await context.request.get(`${origin}${path}/events`)).text();
        assert.equal([...events.matchAll(/"state":"cancelled"/g)].length, 1);
        assert.doesNotMatch(events, /"state":"completed"|"state":"failed"|SYNTHETIC_STORAGE_CANARY/);
        await page.reload();
        await expect(page.getByText('Скан отменён; realtime остановлен')).toBeVisible();
        assert.deepEqual(await (await context.request.get(`${origin}${path}`)).json(), beforeReload);
        for (const spec of specs.filter(spec => saved.includes(spec.kind === 'results' ? 'secret' : spec.kind))) {
          await expect(page.getByRole('region', { name: spec.region, exact: true }).locator(spec.rows)).toHaveCount(25);
        }
        for (const suffix of ['', '/results?view=report-v1', '/sbom?view=report-v1', '/vuln?view=report-v1', '/events']) {
          assert.equal((await foreign.request.get(`${origin}${path}${suffix}`)).status(), 404);
          assert.equal((await anonymous.request.get(`${origin}${path}${suffix}`)).status(), 401);
        }
        await foreignPage.goto(`${origin}/scans/${id}`);
        await expect(foreignPage.getByRole('alert')).toContainText('Не удалось получить данные скана');
        await expect(foreignPage.locator('.scan-report-sections')).toHaveCount(0);
        await anonymousPage.goto(`${origin}/scans/${id}`);
        await expect(anonymousPage.getByRole('link', { name: 'войдите', exact: true })).toBeVisible();
        await expect(anonymousPage.locator('.scan-report-sections')).toHaveCount(0);
        await expect(page.locator('body')).not.toContainText('SYNTHETIC_STORAGE_CANARY');
        checks.push(`Cancellation ${mode}: real button/POST + GET, saved subset ${saved.join(',') || 'none'}, all saved pages, unknown siblings, SSE, reload and HTTP/UI owner fences`);
        if (mode === 'storage-error') checks.push('Storage error: real consumer propagates SQLite failure after Secrets checkpoint; running/unknown before cancel, retained Secrets only afterwards, no fabricated failed/zero outcome or raw error in UI');
      }
      await page.goto(`${origin}/account`);
      await page.getByRole('button', { name: 'Выйти из аккаунта', exact: true }).click();
      await expect(page).toHaveURL(/\/login$/);
      await page.goto(`${origin}/scans/${ready.scanId}`);
      await expect(page.getByRole('link', { name: 'войдите', exact: true })).toBeVisible();
      await expect(page.locator('.scan-vuln-row')).toHaveCount(0);
      checks.push('Real HTTP logout revokes owner session; revisiting report cannot republish owner cache');
      assert.deepEqual(errors, []); assert.deepEqual(egress, []);
    })()]);
  } finally {
    clearTimeout(timer);
    process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort);
    if (allocator.listening) await new Promise(resolveClose => allocator.close(resolveClose));
    if (browser) await browser.close();
    for (const socket of sockets) socket.destroy();
    if (vite) await vite.close();
    if (api && api.exitCode === null && api.signalCode === null) {
      if (api.connected) api.send('stop'); else api.kill('SIGTERM');
      const killTimer = setTimeout(() => api.kill('SIGKILL'), 5000);
      try { await childClosed; } finally { clearTimeout(killTimer); }
    }
    await rm(directory, { recursive: true, force: true });
    assert.ok(await closedPort(origin), 'Vite loopback listener leaked');
    assert.ok(await closedPort(apiOrigin), 'Nest loopback listener leaked');
    console.log(JSON.stringify({ cleanup: 'PASS', browserClosed: !!browser, apiExitCode: api?.exitCode,
      listenersClosed: true, temporarySqliteAndCacheRemoved: true }));
  }
  console.log(JSON.stringify({ status: 'PASS', scope: 'DIP39/41 synthetic seeded report / real ephemeral Nest HTTP + SQLite / current UI',
    durationMs: Date.now() - started, browser: browser.version(), checks, confirmedReportPages: receipts.length,
    browserErrors: errors.length, externalBrowserRequests: egress.length, mockedHttp: false,
    docker: false, actualTrivy: false, deployment: false, llmCalls: 0 }, null, 2));
}

if (process.argv.includes('--api-child')) {
  await apiChild();
} else if (process.argv.includes('--managed')) {
  await managed();
} else {
  // Re-exec before importing Vite/Nest/browser libraries, excluding private env, NODE_OPTIONS and keys.
  const child = spawn(process.execPath, [file, '--managed'], { cwd: root, env: safeEnv,
    stdio: 'inherit', detached: true });
  const killOwnedGroup = () => {
    if (!child.pid) return;
    try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Owned process group already exited. */ }
  };
  let hardStop;
  const terminate = () => {
    child.kill('SIGTERM');
    hardStop ??= setTimeout(killOwnedGroup, 5000);
  };
  const deadline = setTimeout(terminate, 230_000);
  process.once('SIGTERM', terminate); process.once('SIGINT', terminate);
  try {
    const [code] = await once(child, 'close');
    process.exitCode = code ?? 1;
    if (code !== 0) killOwnedGroup();
  } finally {
    clearTimeout(deadline); clearTimeout(hardStop);
    process.removeListener('SIGTERM', terminate); process.removeListener('SIGINT', terminate);
    if (child.exitCode === null && child.signalCode === null) killOwnedGroup();
  }
}
