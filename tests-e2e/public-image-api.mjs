// Run: node tests-e2e/public-image-api.mjs
// Actual Chromium/current Vite UI/PublicImageModule HTTP/auth/SQLite/consumer.
// OCI transport, readiness and public archive outcomes are controlled fixtures;
// not native Trivy, archive acquisition, CVE DB, deployment or live-image evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { createRequire } from 'node:module';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const file = fileURLToPath(import.meta.url), root = resolve(dirname(file), '..');
const apiRequire = createRequire(join(root, 'server/api/package.json'));
const safeEnv = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot']
  .filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
const accounts = { password: 'disposable-browser-proof-password-1234', ownerEmail: 'public-browser-owner@example.com', otherEmail: 'public-browser-other@example.com' };
const canary = 'PUBLIC_BROWSER_CANARY_NEVER_PUBLISH';
const selectedChecks = ['secret', 'sbom', 'config'];
async function bounded(operation, milliseconds, label) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(label)), milliseconds); })]); }
  finally { clearTimeout(timer); }
}

async function apiChild() {
  let fixture, stop;
  const stopped = new Promise(resolveStop => { stop = resolveStop; });
  const timer = setTimeout(stop, 110_000);
  const command = async message => {
    if (message === 'stop') { stop(); return; }
    if (!message || message.kind !== 'consume' || !Number.isSafeInteger(message.requestId) || typeof message.scanId !== 'string') return;
    try {
      const result = await bounded(fixture.consume(message.scanId), 18_000, 'controlled consumer timeout');
      if (process.connected) process.send({ kind: 'consumed', requestId: message.requestId, result });
    } catch { if (process.connected) process.send({ kind: 'failure', stage: 'controlled-consumer', requestId: message.requestId }); stop(); process.exitCode = 1; }
  };
  process.on('message', command);
  process.once('disconnect', stop); process.once('SIGTERM', stop); process.once('SIGINT', stop);
  try {
    const { startPublicImageBrowserFixture } = await import(pathToFileURL(join(root, 'server/api/src/scans/public-image.browser-fixture.ts')).href);
    fixture = await startPublicImageBrowserFixture(accounts);
    if (process.connected) process.send({ kind: 'ready', ...fixture.ready });
    await stopped;
  } catch { if (process.connected) process.send({ kind: 'failure', stage: 'fixture-bootstrap' }); process.exitCode = 1; }
  finally {
    clearTimeout(timer); process.removeListener('message', command);
    process.removeListener('disconnect', stop); process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
    try { await bounded(fixture?.close(), 5000, 'fixture cleanup timeout'); } catch { process.exitCode = 1; }
    if (process.connected) process.disconnect();
  }
}

function listenerClosed(address) {
  return new Promise(resolveClosed => {
    if (!address) { resolveClosed(true); return; }
    const socket = net.connect({ host: '127.0.0.1', port: Number(new URL(address).port) });
    socket.once('connect', () => { socket.destroy(); resolveClosed(false); });
    socket.once('error', () => { socket.destroy(); resolveClosed(true); });
    socket.setTimeout(1000, () => { socket.destroy(); resolveClosed(false); });
  });
}

async function managed() {
  const directory = await mkdtemp(join(tmpdir(), 'public-image-browser-'));
  const sockets = new Set(), checks = [], observed = [], errors = [], egress = [];
  const allocator = net.createServer();
  let api, apiClosed, vite, browser, apiOrigin, origin, browserVersion, failure;
  let browserClosed = false;
  let stage = 'dependencies';
  let abort;
  const interrupted = new Promise((_, reject) => { abort = () => reject(new Error('proof interrupted')); });
  const timer = setTimeout(abort, 100_000);
  process.once('SIGTERM', abort); process.once('SIGINT', abort);
  const started = Date.now();
  try {
    await Promise.race([interrupted, (async () => {
      const { chromium, expect: baseExpect } = await import('@playwright/test');
      const expect = baseExpect.configure({ timeout: 10_000 });
      const { createServer } = await import('vite');
      const [{ default: react }, { default: tailwindcss }, { default: svgr }, { default: tsconfigPaths }] = await Promise.all([
        import('@vitejs/plugin-react-swc'), import('@tailwindcss/vite'), import('vite-plugin-svgr'), import('vite-tsconfig-paths'),
      ]);
      stage = 'disposable-api-bootstrap';
      await new Promise(resolveListen => allocator.listen(0, '127.0.0.1', resolveListen));
      const port = allocator.address().port;
      await new Promise(resolveClose => allocator.close(resolveClose));
      origin = `http://127.0.0.1:${port}`;
      api = spawn(process.execPath, ['--import', apiRequire.resolve('tsx/esm'), file, '--api-child'], {
        cwd: join(root, 'server/api'), env: { ...safeEnv, NODE_ENV: 'test', PUBLIC_IMAGE_PROOF_DIR: directory,
          AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
          AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false',
          SCAN_VULN_ENABLED: 'false', SCAN_VULN_RELEASE_DIR: '', SCAN_JWT_SECRET: 'disposable-public-browser-jwt-secret-1234',
          SCAN_JWT_ISSUER: 'public-browser-fixture', SCAN_JWT_AUDIENCE: 'public-browser-fixture' },
        // Never relay raw fixture exceptions, auth bodies, process env or scanner text.
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      apiClosed = once(api, 'close');
      const ready = await bounded(Promise.race([once(api, 'message').then(([value]) => value), apiClosed.then(() => { throw new Error('fixture exited'); })]), 20_000, 'fixture readiness timeout');
      assert.equal(ready.kind, 'ready');
      apiOrigin = ready.apiOrigin;
      assert.equal(new URL(apiOrigin).hostname, '127.0.0.1');
      const consume = scanId => bounded(new Promise((resolveConsume, reject) => {
        const requestId = 1;
        const receive = message => {
          if (message?.requestId !== requestId) return;
          api.removeListener('message', receive);
          if (message.kind === 'consumed') resolveConsume(message.result); else reject(new Error('controlled consumer failed'));
        };
        api.on('message', receive);
        api.send({ kind: 'consume', requestId, scanId }, error => { if (error) { api.removeListener('message', receive); reject(new Error('IPC closed')); } });
      }), 20_000, 'consumer response timeout');
      stage = 'disposable-vite-bootstrap';
      vite = await createServer({ root, configFile: false, envDir: false, cacheDir: join(directory, 'vite-cache'),
        plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
        server: { host: '127.0.0.1', port, strictPort: true, hmr: false, proxy: { '/api/v1': { target: apiOrigin, changeOrigin: false } } },
      });
      vite.httpServer.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
      await bounded(vite.listen(), 15_000, 'Vite listen timeout');
      stage = 'chromium-bootstrap';
      browser = await chromium.launch({ headless: true, timeout: 15_000, args: ['--disable-background-networking', '--disable-component-update',
        '--disable-default-apps', '--no-first-run', '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost'] });
      browserVersion = browser.version();
      const newContext = async () => {
        const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
        // No fulfill(), response substitution or HTTP mocking: app/API bytes flow
        // unchanged through Vite/Nest. Only non-loopback egress is denied.
        await context.route('**/*', route => {
          const url = new URL(route.request().url());
          if (url.origin === origin && url.protocol === 'http:') return route.continue();
          egress.push(url.origin); return route.abort();
        });
        context.on('page', page => {
          page.setDefaultTimeout(10_000); page.setDefaultNavigationTimeout(15_000);
          page.on('pageerror', () => errors.push('browser-page-error'));
        });
        return context;
      };
      const context = await newContext(), page = await context.newPage();
      page.on('request', request => {
        const url = new URL(request.url());
        if (url.origin === origin && request.method() === 'POST' &&
            (url.pathname === '/api/v1/browser/scans' || url.pathname === '/api/v1/browser/scans/images/eligibility')) {
          observed.push({ path: url.pathname, body: request.postDataJSON() });
        }
      });
      const login = async (target, email) => {
        await target.goto(`${origin}/login`);
        await target.getByLabel('Email', { exact: true }).fill(email);
        await target.getByLabel('Пароль', { exact: true }).fill(accounts.password);
        const response = waitResponse(target, reply => reply.url() === `${origin}/api/v1/auth/login` && reply.request().method() === 'POST');
        await target.getByRole('button', { name: 'Войти', exact: true }).click();
        assert.equal((await response).status(), 200);
        await expect(target.getByRole('heading', { name: 'Вы вошли' })).toBeVisible();
      };
      const get = (ctx, path) => {
        const url = new URL(path, origin);
        assert.equal(url.origin, origin);
        return ctx.request.get(url.href, { maxRedirects: 0, timeout: 10_000 });
      };
      // Armed waits may outlive a failed browser action; handle rejection at once
      // so cleanup cannot be interrupted by an unhandled Playwright timeout.
      const waitResponse = (target, predicate) => target.waitForResponse(predicate).catch(() => null);
      const sbomReply = (target, scanPath, ecosystem) => waitResponse(target, reply => {
        const url = new URL(reply.url());
        return url.origin === origin && url.pathname === `${scanPath}/sbom` && url.searchParams.get('view') === 'report-v1' &&
          url.searchParams.get('ecosystem') === ecosystem;
      });
      stage = 'owner-browser-login';
      await login(page, accounts.ownerEmail);
      const session = (await context.cookies(origin)).find(cookie => cookie.name === 'demo_session');
      assert.ok(session?.httpOnly && session.sameSite === 'Lax');
      stage = 'manual-reference-checks-consent';
      await page.goto(`${origin}/scans/new`);
      await page.getByRole('textbox', { name: 'Canonical reference Docker Hub' }).fill(ready.reference);
      await page.getByRole('checkbox', { name: /Secrets · проверка образа/ }).check();
      await page.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }).check();
      await page.getByRole('checkbox', { name: /Image config · OCI User metadata/ }).check();
      assert.equal(await page.getByRole('checkbox', { name: /CVE · доступно/ }).isChecked(), false);
      const submit = page.getByRole('button', { name: 'Запустить скан', exact: true });
      await page.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }).check();
      await expect(submit).toBeEnabled();
      const beforeSubmit = observed.length;
      stage = 'fresh-eligibility-before-real-post';
      const eligibilityResponse = waitResponse(page, reply => reply.url() === `${origin}/api/v1/browser/scans/images/eligibility` &&
        reply.request().postDataJSON().imageReference === ready.reference && JSON.stringify(reply.request().postDataJSON().checks) === JSON.stringify(selectedChecks));
      const createdResponse = waitResponse(page, reply => reply.url() === `${origin}/api/v1/browser/scans` && reply.request().method() === 'POST');
      await submit.click();
      const eligibility = await eligibilityResponse;
      assert.equal(eligibility.status(), 200); assert.equal((await eligibility.json()).eligible, true);
      const created = await createdResponse; assert.equal(created.status(), 202);
      const post = created.request().postDataJSON();
      assert.deepEqual(post.checks, selectedChecks); assert.equal(post.imageReference, ready.reference); assert.equal(post.scope, 'image');
      assert.deepEqual(Object.keys(post).sort(), ['checks', 'idempotencyKey', 'imageReference', 'scope']);
      const sequence = observed.slice(beforeSubmit);
      assert.equal(sequence[0].path, '/api/v1/browser/scans/images/eligibility');
      assert.equal(sequence.at(-1).path, '/api/v1/browser/scans');
      assert.equal(observed.filter(item => item.path === '/api/v1/browser/scans').length, 1);
      const { scanId } = await created.json();
      assert.match(scanId, /^[a-f0-9-]{36}$/);
      const scanPath = `/api/v1/browser/scans/${scanId}`;
      await expect(page).toHaveURL(`${origin}/scans/${scanId}`);
      await expect(page.getByText(`Закреплённая цель: ${ready.digest} · linux/amd64`, { exact: true })).toBeVisible();
      const queued = await get(context, scanPath); assert.equal(queued.status(), 200);
      assert.equal((await queued.json()).state, 'queued');
      checks.push('actual UI manual reference/checks/consent → fresh eligible HTTP response → canonical POST 202 → pinned queued status');
      stage = 'real-public-consumer-controlled-outcomes';
      const firstSbom = sbomReply(page, scanPath, null);
      const worker = await consume(scanId);
      assert.equal(worker.workerInvocations, 1); assert.equal(worker.configLoads, 2); assert.ok(worker.inspections >= 3);
      assert.deepEqual(worker.checkpoints, ['secret', 'sbom']); assert.equal(worker.state, 'completed');
      const initialWire = await (await firstSbom).json();
      assert.equal(initialWire.profile, ready.profile); assert.equal(initialWire.os.name, 'debian'); assert.equal(initialWire.os.version, '12');
      assert.deepEqual(new Set(initialWire.components.map(row => row.ecosystem)), new Set(['deb', 'npm']));
      assert.equal(initialWire.page.totalCount, 4);
      const sbom = page.getByRole('region', { name: 'Пакеты SBOM', exact: true });
      const rows = sbom.locator('ul.scan-report-inventory > li');
      await expect(rows).toHaveCount(4);
      await expect(sbom.getByRole('alert')).toHaveCount(0);
      await expect(sbom).toContainText('ОС debian 12');
      for (const name of ready.componentNames) await expect(sbom).toContainText(name);
      await expect(page.getByRole('region', { name: 'Результаты Secrets', exact: true })).toContainText('Строка 0');
      await expect(page.getByRole('heading', { name: 'Image config · только метаданные образа', exact: true })).toBeVisible();
      await expect(page.getByText('Root metadata finding отсутствует; это не гарантия безопасности.', { exact: true })).toBeVisible();
      const completedResponse = await get(context, scanPath); const completed = await completedResponse.json();
      assert.equal(completed.profile, ready.profile); assert.equal(completed.state, 'completed'); assert.equal(completed.config.config.outcome, 'checked');
      assert.equal(JSON.stringify(completed).includes(canary), false); assert.equal((await page.locator('body').innerText()).includes(canary), false);
      checks.push('actual public consumeOne/config verification/checkpoints/SQLite finalization → browser renders controlled Debian + npm + Secrets + config');
      stage = 'expanded-ecosystem-filter-ui';
      for (const [ecosystem, names] of [['npm', ['@proof/widget', 'proof-tool']], ['deb', ['libc6', 'openssl']]]) {
        const ecosystemSelect = sbom.getByLabel('Экосистема · SBOM');
        await expect(ecosystemSelect).toBeEnabled();
        const reply = sbomReply(page, scanPath, ecosystem);
        await ecosystemSelect.selectOption(ecosystem);
        const wire = await (await reply).json(); assert.equal(wire.profile, ready.profile);
        assert.equal(wire.page.totalCount, 4); assert.equal(wire.page.matchedCount, 2);
        assert.equal(wire.page.filters.ecosystem, ecosystem); assert.ok(wire.components.every(row => row.ecosystem === ecosystem));
        await expect(rows).toHaveCount(2); for (const name of names) await expect(sbom).toContainText(name);
      }
      checks.push('actual browser SBOM npm/deb selects → server report-v1 global filters → matching expanded-ecosystem rows');
      stage = 'owner-reload';
      const reloadedSbom = sbomReply(page, scanPath, null);
      await page.reload();
      const reloaded = await (await reloadedSbom).json();
      assert.equal(reloaded.profile, ready.profile); assert.equal(reloaded.page.offset, 0); assert.equal(reloaded.page.matchedCount, 4);
      assert.equal(reloaded.page.filters.ecosystem, null);
      await expect(page.getByRole('region', { name: 'Пакеты SBOM', exact: true }).locator('ul.scan-report-inventory > li')).toHaveCount(4);
      checks.push('reload retains real owner cookie and durable report; default report-v1 filter/page restored');
      stage = 'legacy-alpine-edge-browser';
      const legacyPath = `/api/v1/browser/scans/${ready.legacyId}`;
      const legacyReply = sbomReply(page, legacyPath, null);
      await page.goto(`${origin}/scans/${ready.legacyId}`);
      const legacy = await (await legacyReply).json();
      assert.equal(Object.hasOwn(legacy, 'profile'), false); assert.equal(legacy.os.version, 'edge');
      await expect(page.getByRole('region', { name: 'Пакеты SBOM', exact: true })).toContainText('ОС alpine edge');
      await expect(page.getByRole('region', { name: 'Пакеты SBOM', exact: true })).toContainText('busybox');
      await expect(page.getByRole('region', { name: 'Пакеты SBOM', exact: true }).getByRole('alert')).toHaveCount(0);
      const ordinaryLegacy = await get(context, `${legacyPath}/sbom`); assert.equal(ordinaryLegacy.status(), 200);
      assert.equal(Object.hasOwn(await ordinaryLegacy.json(), 'profile'), false);
      checks.push('real persisted unmarked legacy Alpine edge → current public endpoint → actual report UI, no relaxed public grammar');
      stage = 'foreign-owner-denial';
      const foreign = await newContext(), foreignPage = await foreign.newPage();
      await login(foreignPage, accounts.otherEmail);
      for (const suffix of ['', '/sbom', '/sbom?view=report-v1', '/results?view=report-v1']) {
        const denied = await get(foreign, `${scanPath}${suffix}`); assert.equal(denied.status(), 404);
        const text = await denied.text(); assert.equal(text.includes('libc6'), false); assert.equal(text.includes('proof-tool'), false);
      }
      await foreignPage.goto(`${origin}/scans/${scanId}`);
      await expect(foreignPage.getByRole('alert')).toContainText('Не удалось получить данные скана');
      await expect(foreignPage.locator('ul.scan-report-inventory > li')).toHaveCount(0);
      stage = 'anonymous-denial';
      const anonymous = await newContext(), anonymousPage = await anonymous.newPage();
      for (const suffix of ['', '/sbom?view=report-v1', '/results?view=report-v1']) assert.equal((await get(anonymous, `${scanPath}${suffix}`)).status(), 401);
      await anonymousPage.goto(`${origin}/scans/${scanId}`);
      await expect(anonymousPage.getByRole('link', { name: 'войдите', exact: true })).toBeVisible();
      await expect(anonymousPage.locator('ul.scan-report-inventory > li')).toHaveCount(0);
      checks.push('separate enrolled owner gets real HTTP 404/no rows; anonymous gets 401/login guard/no rows');
      stage = 'browser-safety-assertions';
      assert.deepEqual(errors, []); assert.deepEqual(egress, []);
      assert.equal(observed.filter(item => item.path === '/api/v1/browser/scans').length, 1);
    })()]);
  } catch { failure = stage; }
  finally {
    clearTimeout(timer); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort);
    try {
      if (allocator.listening) await bounded(new Promise(resolveClose => allocator.close(resolveClose)), 2000, 'allocator close timeout');
      if (browser) {
        await bounded(browser.close(), 8000, 'browser close timeout');
        assert.equal(browser.isConnected(), false); browserClosed = true;
      }
    } catch { failure ??= 'browser-cleanup'; }
    for (const socket of sockets) socket.destroy();
    try { if (vite) await bounded(vite.close(), 8000, 'Vite close timeout'); } catch { failure ??= 'vite-cleanup'; }
    if (api && api.exitCode === null && api.signalCode === null) {
      if (api.connected) api.send('stop'); else api.kill('SIGTERM');
      try { await bounded(apiClosed, 7000, 'API close timeout'); }
      catch { api.kill('SIGKILL'); await bounded(apiClosed, 3000, 'API kill timeout').catch(() => { failure ??= 'api-cleanup'; }); }
    }
    try {
      await rm(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      assert.equal(await listenerClosed(origin), true); assert.equal(await listenerClosed(apiOrigin), true);
      await assert.rejects(access(directory), { code: 'ENOENT' });
      if (browser) assert.equal(browserClosed, true);
      if (api) assert.equal(api.exitCode, 0);
      console.log(JSON.stringify({ cleanup: 'PASS', browserClosed, apiExitCode: api?.exitCode, listenersClosed: true, disposableSqliteAndViteCacheRemoved: true }));
    } catch { failure ??= 'resource-cleanup'; }
  }
  if (failure) { console.error(JSON.stringify({ status: 'FAIL', stage: failure, rawDiagnosticsSuppressed: true })); return false; }
  console.log(JSON.stringify({ status: 'PASS', scope: 'current manual public-image UI → real disposable HTTP/auth/SQLite/public consumer → controlled reports',
    durationMs: Date.now() - started, browser: browserVersion, checks, pageErrors: errors.length, externalBrowserRequests: egress.length,
    mockedHttp: false, controlledOciTransport: true, controlledReadiness: true, controlledPublicArchiveOutcomes: true,
    nativeTrivy: false, archiveAcquisition: false, cveDbQualification: false, docker: false, deployment: false }, null, 2));
  return true;
}

if (process.argv.includes('--api-child')) await apiChild();
else if (process.argv.includes('--managed')) {
  try { process.exitCode = await managed() ? 0 : 1; }
  catch { console.error(JSON.stringify({ status: 'FAIL', stage: 'managed-bootstrap', rawDiagnosticsSuppressed: true })); process.exitCode = 1; }
} else {
  // Re-exec before loading application/browser libraries; exclude private env,
  // NODE_OPTIONS and all existing local stand/DB/provider configuration.
  const child = spawn(process.execPath, [file, '--managed'], { cwd: root, env: safeEnv, stdio: 'inherit', detached: true });
  const killOwnedGroup = () => { if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Owned group already exited. */ } } };
  let hardStop;
  const terminate = () => { child.kill('SIGTERM'); hardStop ??= setTimeout(killOwnedGroup, 20_000); };
  const deadline = setTimeout(terminate, 130_000);
  process.once('SIGTERM', terminate); process.once('SIGINT', terminate);
  try { const [code] = await once(child, 'close'); process.exitCode = code ?? 1; if (code !== 0) killOwnedGroup(); }
  finally { clearTimeout(deadline); clearTimeout(hardStop); process.removeListener('SIGTERM', terminate); process.removeListener('SIGINT', terminate); }
}
