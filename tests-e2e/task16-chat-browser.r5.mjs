import { chromium, expect as baseExpect } from '@playwright/test';
import { createServer } from 'vite';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import net from 'node:net';
import { encodeDelivery } from '../server/api/src/llm/history-delivery.ts';

// Narrow supplement to258: actual source page/HTTP/parser, synthetic API only. Never start a backend/provider.
const expect = baseExpect.configure({ timeout: 3000 });
const output = 'test-results/task16-chat-browser-r5';
const candidatePath = 'docs/task16-chat-manifest.json';
const candidateHash = 'a72207c147823b819da851a9ad58028b8bd314581d0a1d229c3fe2fdf41f3261';
const scanA = '00000000-0000-4000-8000-000000000016';
const scanB = '00000000-0000-4000-8000-000000000017';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const clock = Date.parse('2026-10-08T12:00:00.000Z');
const checkedAt = new Date(clock).toISOString();
const policyVersion = 'c'.repeat(64);
const disclosure = {
  provider: 'OpenRouter', model: 'apodex/apodex-1.1-mini:free', providers: ['novita/bf16'],
  region: 'global', retention: 'no-storage', operatorApprovedRouting: true,
  providerComplianceNotProvenByDeclaration: true, requestBudgetUsd: 0, freeOnly: true,
  maxPrice: { prompt: 0, completion: 0, request: 0 },
  data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.',
  sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
  localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
};
const metadata = {
  resultContractVersion: 2, workerCheckedAt: clock, checkedAt,
  db: { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`, manifestDigest: `sha256:${'b'.repeat(64)}`,
    artifactSha256: 'c'.repeat(64), metadataSha256: 'd'.repeat(64), dbSha256: 'e'.repeat(64),
    updatedAt: '2026-10-06T12:00:00.000000001Z', downloadedAt: '2026-10-06T13:00:00.000Z', nextUpdate: '2026-10-07T12:00:00.000Z' },
  usableUntil: '2026-10-20T12:00:00.000000001Z',
  dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: clock, status: 'stale-but-usable', warnings: ['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE'] },
};
const binding = scanId => ({ scanId, digest, platform: 'linux/amd64', reportVersion: (scanId === scanA ? 'b' : 'd').repeat(64) });
const source = scanId => ({ ...binding(scanId), finding: { check: 'secret', findingId: 'secret-0-1', severity: 'UNKNOWN', ruleId: 'rule-0000000000000000', line: 1, evidenceRef: 'result-0-secret-1' } });
const status = scanId => ({ scanId, digest, imageReference: image, platform: 'linux/amd64', state: 'completed', checks: ['secret', 'sbom', 'vuln'],
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3', checkedAt, findingCount: 2 },
    sbom: { check: 'sbom', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', checkedAt, componentCount: 2 },
    vuln: { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', findingCount: 36, os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } },
  }, result: null });
const vulnPage = cursor => ({ ...metadata, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', scannerVersion: '0.69.3',
  os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' }, findingCount: 36,
  findings: Array.from({ length: 12 }, (_, j) => { const i = cursor + j + 1; return {
    findingId: `vuln-${i.toString(16).padStart(64, '0')}`, cveId: `CVE-2026-${10000 + i}`, ecosystem: 'apk', packageName: `synthetic-package-${i}`,
    installedVersion: '1.0', fixedVersion: '9.0', severity: i % 2 ? 'HIGH' : 'CRITICAL' };
  }), nextCursor: cursor < 24 ? cursor + 12 : null });
const histories = new Map();
const controls = { mode: 'success', held: null, usageUnavailable: false };
const requests = [], errors = [], egress = [], results = [], screenshots = [], sockets = new Set();
let server, browser, port, origin;
let browserClosed = false, serverClosed = false;
const started = Date.now();
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function fileIdentity(path) { const bytes = await readFile(path); return { path, bytes: bytes.length, sha256: sha(bytes) }; }
function head(owner, scanId) {
  const key = `${owner}:${scanId}`;
  if (!histories.has(key)) histories.set(key, { ...binding(scanId), epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null,
    retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' });
  return histories.get(key);
}
function usage(scanId) {
  if (controls.usageUnavailable) return { ...binding(scanId), available: false, admission: { status: 'unavailable' } };
  const counters = { limits: { input: 10000, output: 10000, costMicros: 0 }, used: { input: 500, output: 32, costMicros: 0 },
    held: { input: 0, output: 0, costMicros: 0 }, carried: { input: 0, output: 0, costMicros: 0 }, remaining: { input: 9500, output: 9968, costMicros: 0 }, warning: false, exhausted: false };
  return { ...binding(scanId), available: true, reason: 'ready', admission: { status: 'unavailable' }, window: { start: 0, end: 86400000 }, signals: [], user: counters, scan: counters };
}
const json = (res, value, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
async function api(req, res, next) {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (!url.pathname.startsWith('/api/')) return next();
  try {
    const owner = /task16-proof-owner=([AB])/.exec(req.headers.cookie ?? '')?.[1];
    if (!owner) return json(res, { errorCode: 'FIXTURE_UNAUTHENTICATED' }, 401);
    const entry = { owner, path: url.pathname, method: req.method, cursor: url.searchParams.get('cursor') };
    requests.push(entry);
    if (url.pathname === '/api/v1/auth/me') return json(res, { id: `synthetic-owner-${owner}`, email: `owner-${owner}@example.invalid` });
    const match = /^\/api\/v1\/browser\/scans\/([a-f0-9-]+)(.*)$/.exec(url.pathname);
    if (!match || ![scanA, scanB].includes(match[1])) return json(res, { errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    const [, scanId, suffix] = match;
    const history = head(owner, scanId);
    if (req.method === 'GET') {
      const cursor = Number(url.searchParams.get('cursor') ?? 0);
      if (!suffix) return json(res, status(scanId));
      if (suffix === '/results') return json(res, { findings: [{ findingId: `secret-0-${cursor}`, ruleId: 'rule-0000000000000000', line: 1, evidenceRef: `result-0-secret-${cursor}` }], nextCursor: cursor ? null : 1, coverage: status(scanId).perCheck.secret });
      if (suffix === '/sbom') return json(res, { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, scannerVersion: '0.69.3', checkedAt, componentCount: 2, components: [{ ecosystem: 'apk', name: `synthetic-inventory-${cursor}`, version: '1' }], nextCursor: cursor ? null : 1 });
      if (suffix === '/vuln') return json(res, vulnPage(cursor));
      if (suffix === '/llm/context') return json(res, { ...binding(scanId), enabled: false, policyVersion: null, disclosure: null });
      if (suffix === '/llm/history') return json(res, history);
      if (suffix === '/llm/chat/usage') return json(res, usage(scanId));
      if (suffix === '/llm/chat/context') return json(res, { ...binding(scanId), epoch: history.epoch, revision: history.revision, enabled: true, pending: false,
        policyVersion, disclosure, limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response' });
      return json(res, { errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    }
    if (req.method !== 'POST' || suffix !== '/llm/chat') return json(res, { errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    let body = '';
    for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 8192) return json(res, { errorCode: 'FIXTURE_BODY_LIMIT' }, 413); }
    const input = JSON.parse(body);
    entry.body = input; entry.accept = req.headers.accept; entry.fixtureMode = controls.mode;
    if (input.epoch !== history.epoch || input.revision !== history.revision || input.reportVersion !== binding(scanId).reportVersion)
      return json(res, { errorCode: 'LLM_HISTORY_CONFLICT' }, 409);
    if (req.headers.accept !== 'application/x-ndjson' || input.consent?.accepted !== true || input.consent.policyVersion !== policyVersion)
      return json(res, { errorCode: 'FIXTURE_INVALID_MUTATION' }, 400);
    const turnId = randomUUID();
    const common = { ...binding(scanId), epoch: history.epoch, revision: history.revision + 2, mutationId: input.mutationId, turnId };
    const success = controls.mode === 'success';
    const reply = { ...binding(scanId), kind: 'hypothesis', text: '**Синтетическая гипотеза**\n\n```text\necho synthetic-only\n```', sources: [source(scanId)] };
    const lines = encodeDelivery(success
      ? { ...common, outcome: 'completed', reply, usage: { input: 500, output: 32, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' } }
      : { ...common, outcome: 'failed', receipt: 'unavailable' }).lines;
    if (!success) {
      expect(lines).toHaveLength(1);
      const frame = JSON.parse(lines[0]);
      expect({ type: frame.type, seq: frame.seq, receipt: frame.receipt }).toEqual({ type: 'error', seq: 0, receipt: 'unavailable' });
      expect(['usage', 'text', 'source', 'reply'].some(key => key in frame)).toBe(false);
    }
    entry.frameTypes = lines.map(line => JSON.parse(line).type);
    history.revision += 2;
    history.turns.push({ id: turnId, mutationId: input.mutationId, state: success ? 'completed' : 'failed', question: input.question,
      report: binding(scanId), createdAt: clock, ...(success ? { reply } : {}) });
    await writeFile(`${output}/wire-${requests.filter(r => r.method === 'POST').length}.ndjson`, lines.join(''));
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store, no-transform', 'X-Content-Type-Options': 'nosniff' });
    res.flushHeaders();
    if (controls.mode === 'held-unavailable') { controls.held = { response: res, lines }; return; }
    const wire = Buffer.from(lines.join(''));
    res.write(wire.subarray(0, 19)); res.end(wire.subarray(19));
  } catch (error) { errors.push({ scope: 'fixture', message: error.stack }); if (!res.headersSent) json(res, { errorCode: 'FIXTURE_FAILURE' }, 500); else res.destroy(); }
}
async function keyboard(page, locator) { await locator.focus(); await expect(locator).toBeFocused(); await page.keyboard.press('Enter'); }
async function openChat(page, chat) {
  await keyboard(page, chat.getByRole('button', { name: /Открыть чат и прочитать условия|Обновить историю и условия чата/ }));
  await expect(chat.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toBeVisible();
  await expect(chat).toHaveAttribute('aria-busy', 'false');
}
async function submit(page, chat, mode, question) {
  controls.mode = mode;
  await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(question);
  const consent = chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ });
  await expect(consent).not.toBeChecked(); await consent.focus(); await page.keyboard.press('Space');
  await keyboard(page, chat.getByRole('button', { name: 'Отправить вопрос', exact: true }));
}
const report = page => Promise.all(['Покрытие проверок', 'Результаты проверок'].map(name => page.getByRole('region', { name, exact: true }).evaluate(node => node.outerHTML)));
async function screenshot(page, name) { const path = `${output}/${name}.png`; await page.screenshot({ path }); screenshots.push(path); }
function releaseHeld() { const held = controls.held; if (!held) throw new Error('Missing held error'); held.response.end(held.lines.join('')); controls.held = null; }
async function targeted() {
  const context = await browser.newContext({ viewport: { width: 375, height: 800 }, reducedMotion: 'reduce', serviceWorkers: 'block', permissions: ['clipboard-read', 'clipboard-write'] });
  await context.addCookies([{ name: 'task16-proof-owner', value: 'A', url: origin, httpOnly: true, sameSite: 'Strict' }]);
  await context.route('**/*', route => { const url = new URL(route.request().url()); if (url.origin !== origin) { egress.push(url.href); return route.abort(); } return route.continue(); });
  const page = await context.newPage(); page.setDefaultTimeout(3000);
  page.on('pageerror', error => errors.push({ scope: 'browser', message: error.message }));
  page.on('dialog', dialog => { errors.push({ scope: 'dialog', message: dialog.message() }); void dialog.dismiss(); });
  await page.goto(`${origin}/scans/${scanA}`);
  const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
  await expect(page.getByText('CVE-2026-10001', { exact: true })).toBeVisible();
  const baseline = await report(page);
  await openChat(page, chat); await submit(page, chat, 'success', 'R5 targeted copy only');
  const article = chat.locator('article').first();
  await expect(article.getByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toBeVisible();
  await expect(article.locator('code')).toHaveText('echo synthetic-only\n');
  const copy = article.getByRole('button', { name: 'Скопировать код', exact: true });
  await keyboard(page, copy);
  await expect.poll(() => copy.evaluate(node => node.nextElementSibling?.textContent)).toBe('Скопировано');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('echo synthetic-only\n');
  const geometry = await copy.evaluate(node => {
    const status = node.nextElementSibling;
    const b = node.getBoundingClientRect(), s = status.getBoundingClientRect();
    return { adjacentText: node.nextSibling?.textContent, visibleText: node.parentElement.innerText,
      button: { x: b.x, y: b.y, width: b.width, height: b.height }, status: { x: s.x, y: s.y, width: s.width, height: s.height }, gap: s.x - b.right };
  });
  expect(geometry.adjacentText).toBe(' ');
  expect(geometry.visibleText).toContain('Скопировать код Скопировано');
  expect(geometry.gap > 0 || geometry.status.y > geometry.button.y).toBe(true);
  expect(await report(page)).toEqual(baseline);
  await screenshot(page, '375-r5-copy-feedback');
  results.push({ scope: '375-copy-feedback', status: 'passed', geometry, clipboard: 'real exact plaintext', finding: 'C16-BROWSER-01 visually resolved for current candidate' });

  // Only the changed error-only terminal is delayed; no repeat of the baseline success/framing/Markdown matrix.
  await submit(page, chat, 'held-unavailable', 'R5 delayed scan error');
  await expect.poll(() => !!controls.held).toBe(true);
  await expect(chat).toHaveAttribute('aria-busy', 'true');
  await page.evaluate(id => { history.pushState({}, '', `/scans/${id}`); dispatchEvent(new PopStateEvent('popstate')); }, scanB);
  await expect(chat.getByRole('button', { name: 'Открыть чат и прочитать условия' })).toBeVisible();
  const scanBaseline = await report(page);
  releaseHeld(); await page.waitForTimeout(120);
  await expect(chat.getByRole('alert')).toHaveCount(0); await expect(chat.locator('article')).toHaveCount(0);
  expect(await report(page)).toEqual(scanBaseline);
  results.push({ scope: '375-delayed-error-scan-fence', status: 'passed', oldTerminalPublished: false });

  await openChat(page, chat); await submit(page, chat, 'held-unavailable', 'R5 delayed account error');
  await expect.poll(() => !!controls.held).toBe(true);
  await context.addCookies([{ name: 'task16-proof-owner', value: 'B', url: origin, httpOnly: true, sameSite: 'Strict' }]);
  await page.evaluate(async () => { const { switchSubject } = await import('/tests-e2e/task16-chat-browser.session.ts'); switchSubject('synthetic-owner-B'); });
  await expect(chat.getByRole('button', { name: 'Открыть чат и прочитать условия' })).toBeVisible();
  releaseHeld(); await page.waitForTimeout(120);
  await expect(chat.getByRole('alert')).toHaveCount(0); await expect(chat.locator('article')).toHaveCount(0);
  await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).toHaveCount(0);
  expect(await report(page)).toEqual(scanBaseline);
  results.push({ scope: '375-delayed-error-account-fence', status: 'passed', oldTerminalPublished: false,
    limit: 'synthetic cookie plus actual session observable injection, not backend login integration' });

  // Explicit reload is necessary to recover the actual auth query/transport after signal injection.
  await page.reload(); controls.usageUnavailable = true; await openChat(page, chat);
  await expect(chat.getByText(/Учёт недоступен, не ноль/)).toBeVisible();
  const finalBaseline = await report(page);
  const posts = requests.filter(r => r.method === 'POST').length;
  await submit(page, chat, 'unavailable', 'R5 unavailable receipt error only');
  await expect(chat.getByRole('alert')).toContainText('Не удалось безопасно прочитать ответ');
  await expect(chat).toHaveAttribute('aria-busy', 'false');
  await expect(chat.locator('article')).toHaveCount(0);
  await expect(chat.getByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toHaveCount(0);
  await expect(chat.getByText(/Последний ответ:|input 0, output 0/)).toHaveCount(0);
  await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).toHaveCount(0);
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(posts + 1);
  const finalReport = await report(page); expect(finalReport).toEqual(finalBaseline);
  await expect(page.getByText('CVE-2026-10001', { exact: true })).toBeVisible();
  const fingerprints = finalReport.map((html, index) => ({ region: ['coverage', 'findings'][index], bytes: Buffer.byteLength(html), before: sha(Buffer.from(finalBaseline[index])), after: sha(Buffer.from(html)) }));
  await chat.scrollIntoViewIfNeeded(); await screenshot(page, '375-r5-error-only');
  results.push({ scope: '375-error-only-unavailable-usage', status: 'passed', frameTypes: requests.filter(request => request.method === 'POST').at(-1).frameTypes,
    noAnswer: true, noFakeReceipt: true, noAutomaticRetry: true, reportByteIdentical: true, fingerprints });
  await writeFile(`${output}/375-final-chat-aria.yaml`, await chat.ariaSnapshot());
  await context.close();
}
async function cleanup() {
  controls.held?.response.destroy(); controls.held = null;
  if (browser) { await browser.close(); browserClosed = true; }
  for (const socket of sockets) socket.destroy();
  if (server) { await server.close(); serverClosed = true; }
}
await mkdir(output, { recursive: true });
const candidateBytes = await readFile(candidatePath);
expect(sha(candidateBytes)).toBe(candidateHash);
const candidate = JSON.parse(candidateBytes);
const sampled = [...candidate.files, ...candidate.supplemental];
for (const file of sampled) expect(await fileIdentity(file.path)).toEqual({ path: file.path, bytes: file.bytes, sha256: file.sha256 });
let failure;
const watchdog = setTimeout(() => { void cleanup().finally(() => process.exit(124)); }, 27000);
const hardStop = setTimeout(() => process.exit(124), 30000);
try {
  const allocator = net.createServer(); await new Promise(resolve => allocator.listen(0, '127.0.0.1', resolve));
  const plannedPort = allocator.address().port; await new Promise(resolve => allocator.close(resolve));
  server = await createServer({ configFile: 'tests-e2e/task16-chat-browser.independent.vite.mjs', envDir: false,
    cacheDir: `${output}/vite-cache`, server: { host: '127.0.0.1', port: plannedPort, strictPort: true, proxy: undefined, hmr: false },
    plugins: [{ name: 'synthetic-task16-r5', configureServer(vite) { vite.middlewares.use((req, res, next) => { void api(req, res, next); }); } }] });
  server.httpServer.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await server.listen(); port = server.httpServer.address().port; origin = `http://127.0.0.1:${port}`; process.send?.({ port, origin });
  browser = await chromium.launch({ headless: true }); await targeted(); expect(errors).toEqual([]); expect(egress).toEqual([]);
} catch (error) {
  failure = error; results.push({ status: 'failed', message: error.stack }); console.error(error.stack);
  for (const context of browser?.contexts() ?? []) for (const page of context.pages()) {
    await screenshot(page, 'failure').catch(() => {});
    await writeFile(`${output}/failure-dom.txt`, await page.locator('body').innerText()).catch(() => {});
  }
} finally {
  await cleanup(); clearTimeout(watchdog); clearTimeout(hardStop);
  const after = await Promise.all(sampled.map(file => fileIdentity(file.path)));
  const unchanged = sampled.every((file, i) => file.bytes === after[i].bytes && file.sha256 === after[i].sha256);
  const listenerClosed = port === undefined ? true : await new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port }); socket.once('connect', () => { socket.destroy(); resolve(false); }); socket.once('error', () => resolve(true));
    socket.setTimeout(500, () => { socket.destroy(); resolve(false); });
  });
  if (!unchanged || !listenerClosed) failure ??= new Error('Candidate drift or unclosed owned listener');
  const evidence = { task: 'DIP-TASK-16', supplementalTo: 'DIP-ARTF-258', candidate: { artifact: 'DIP-ARTF-275', bytes: candidateBytes.length, sha256: candidateHash, payloadCount: sampled.length, beforeAfterMatch: unchanged },
    status: failure ? 'failed' : 'passed', label: 'FOUR TARGETED375 CHECKS ONLY, NOT FULL SUITE', viewport: { width: 375, height: 800 }, durationMs: Date.now() - started,
    cleanup: { browserClosed, serverClosed, listenerClosed, host: '127.0.0.1', port, childWatchdogMs: 27000, hardStopMs: 30000 },
    fixtureContract: 'actual R5 encodeDelivery; one error seq0 receipt unavailable, no usage/content/done; provider stream:false',
    results, errors, egress, screenshots, productionBackend: false, providerCalls: 0, LIVE: false, Docker: false,
    limits: ['synthetic frontend fixtures only; no backend provenance/writer/DI/nginx/provider certification', 'not repeated320 baseline, full10groups/all34screenshots, backend/unit suites or fullWCAG', 'session signal injection is not real login integration'] };
  await writeFile(`${output}/results.json`, JSON.stringify(evidence, null, 2));
  await writeFile(`${output}/requests.json`, JSON.stringify(requests, null, 2));
  const localFiles = (await readdir(output)).filter(name => /\.(json|ndjson|yaml|png|txt)$/.test(name) && name !== 'manifest.json').map(name => `${output}/${name}`);
  const files = await Promise.all([candidatePath, 'src/pages/scans/ScanDetailPage.tsx', 'src/pages/scans/ScanReportSections.tsx',
    'tests-e2e/task16-chat-browser.r5.mjs', 'tests-e2e/task16-chat-browser.r5-managed.mjs', 'tests-e2e/task16-chat-browser.independent.vite.mjs',
    'tests-e2e/task16-chat-browser.session.ts', ...localFiles].map(fileIdentity));
  await writeFile(`${output}/manifest.json`, JSON.stringify({ candidate: evidence.candidate, files, selfExcluded: true }, null, 2));
  console.log(`${evidence.status.toUpperCase()} FOUR TARGETED375 CHECKS ONLY; browser closed=${browserClosed}; Vite closed=${serverClosed}; listener closed=${listenerClosed}; candidate unchanged=${unchanged}`);
}
if (failure) process.exitCode = 1;
