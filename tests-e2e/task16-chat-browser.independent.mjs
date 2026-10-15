import { chromium, expect as baseExpect } from '@playwright/test';
import { createServer } from 'vite';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { encodeDelivery, DELIVERY } from '../server/api/src/llm/history-delivery.ts';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import net from 'node:net';

// Real source-transformed React/CSS in Chromium; synthetic loopback HTTP, never LIVE/backend/provider.
const expect = baseExpect.configure({ timeout: 10000 });
const output = 'test-results/task16-chat-browser-independent';
const scanA = '00000000-0000-4000-8000-000000000016';
const scanB = '00000000-0000-4000-8000-000000000017';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const clock = Date.parse('2026-10-08T12:00:00.000Z');
const checkedAt = new Date(clock).toISOString();
const policyVersion = 'c'.repeat(64);
const retention = 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.';
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
const vulnFinding = i => ({ findingId: `vuln-${i.toString(16).padStart(64, '0')}`, cveId: `CVE-2026-${String(10000 + i)}`, ecosystem: 'apk', packageName: `synthetic-package-${i}`, installedVersion: '1.0', fixedVersion: '9.0', severity: i % 2 ? 'HIGH' : 'CRITICAL' });
const status = scanId => ({ scanId, digest, imageReference: image, platform: 'linux/amd64', state: 'completed', checks: ['secret', 'sbom', 'vuln'],
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3', checkedAt, findingCount: 2 },
    sbom: { check: 'sbom', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', checkedAt, componentCount: 2 },
    vuln: { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', findingCount: 36, os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } },
  }, result: null });
const vulnPage = i => ({ ...metadata, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', scannerVersion: '0.69.3',
  os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' }, findingCount: 36,
  findings: Array.from({ length: 12 }, (_, j) => vulnFinding(i * 12 + j + 1)), nextCursor: i < 2 ? (i + 1) * 12 : null });
const receipt = { input: 500, output: 32, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' };
const cleanReply = '**Синтетическая гипотеза** · не результат сканирования.\n\n```text\necho synthetic-only\n```';
const unfinishedReply = '- ```text\n  Синтетическая незакрытая гипотеза\n  точная копия без исполнения';
const histories = new Map();
const controls = { nextMode: 'success', hold: null, failVuln: false, exhausted: false, usageUnavailable: false };
const requests = [], fixtureErrors = [], blockedEgress = [], browserErrors = [], results = [], screenshots = [], stages = [];
const sockets = new Set();
let server, browser, origin, port, timeoutTriggered = false;
const started = performance.now();
const productionPaths = [
  'src/pages/scans/ScanDetailPage.tsx', 'src/pages/scans/ScanReportSections.tsx', 'src/pages/scans/CursorReportPager.tsx',
  'src/pages/scans/reportRowFingerprint.ts', 'src/pages/scans/VulnAdvisoryCard.tsx', 'src/pages/scans/scan-detail-a1.css',
  'src/features/scans/ScanSummaryPanel.tsx', 'src/features/scans/ScanChatPanel.tsx', 'src/features/scans/safeMarkdown.tsx',
  'src/features/scans/safeMarkdownPolicy.ts', 'src/features/scans/SafeMarkdownRenderer.tsx',
  'src/shared/api/scans/llmChatClient.ts', 'src/shared/api/scans/llmChatContract.ts',
  'src/shared/api/scans/scanTransport.ts', 'src/shared/api/scans/httpScanTransport.ts', 'src/shared/api/scans/cveDbMetadata.ts',
  'server/api/src/llm/history-delivery.ts', 'server/api/src/llm/history-contract.ts',
  'server/api/src/llm/history-sources.ts', 'server/api/src/llm/prepared-request.ts',
  'tests-e2e/task16-chat-browser.mjs', 'tests-e2e/task16-chat-browser.renderer.html',
  'tests-e2e/task16-chat-browser.renderer.tsx',
];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function hashes(paths) {
  return Promise.all(paths.map(async path => { const bytes = await readFile(path); return { path, bytes: bytes.length, sha256: sha(bytes) }; }));
}
function head(owner, scanId) {
  const key = `${owner}:${scanId}`;
  if (!histories.has(key)) histories.set(key, { ...binding(scanId), epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null, retention });
  return histories.get(key);
}
function usage(scanId) {
  if (controls.usageUnavailable) return { ...binding(scanId), available: false, admission: { status: 'unavailable' } };
  const counters = { limits: { input: 10000, output: 10000, costMicros: 0 }, used: { input: controls.exhausted ? 10000 : 500, output: 32, costMicros: 0 },
    held: { input: 0, output: 0, costMicros: 0 }, carried: { input: 0, output: 0, costMicros: 0 },
    remaining: { input: controls.exhausted ? 0 : 9500, output: 9968, costMicros: 0 }, warning: controls.exhausted, exhausted: controls.exhausted };
  return { ...binding(scanId), available: true, reason: controls.exhausted ? 'exhausted' : 'ready', admission: { status: 'unavailable' },
    window: { start: 0, end: 86400000 }, signals: [], user: counters, scan: counters };
}
const json = (response, value, code = 200) => { response.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(JSON.stringify(value)); };
const wire = frames => frames.map(frame => JSON.stringify(frame) + '\n').join('');
async function api(request, response, next) {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (!url.pathname.startsWith('/api/')) return next();
  const owner = /task16-proof-owner=([AB])/.exec(request.headers.cookie ?? '')?.[1];
  const entry = { owner: owner ?? null, path: url.pathname, cursor: url.searchParams.get('cursor'), method: request.method, accept: request.headers.accept ?? null, atMs: Math.round(performance.now() - started) };
  requests.push(entry);
  try {
    if (!owner) return json(response, { errorCode: 'FIXTURE_UNAUTHENTICATED' }, 401);
    if (url.pathname === '/api/v1/auth/me') return json(response, { id: `synthetic-owner-${owner}`, email: `owner-${owner}@example.invalid` });
    const match = /^\/api\/v1\/browser\/scans\/([a-f0-9-]+)(.*)$/.exec(url.pathname);
    if (!match || ![scanA, scanB].includes(match[1])) return json(response, { errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    const [, scanId, suffix] = match;
    const history = head(owner, scanId);
    if (request.method === 'GET') {
      const i = Number(url.searchParams.get('cursor') ?? 0);
      if (!suffix) return json(response, status(scanId));
      if (suffix === '/results') return json(response, { findings: [{ findingId: `secret-0-${i}`, ruleId: 'rule-0000000000000000', line: 1, evidenceRef: `result-0-secret-${i}` }], nextCursor: i ? null : 1, coverage: status(scanId).perCheck.secret });
      if (suffix === '/sbom') return json(response, { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, scannerVersion: '0.69.3', checkedAt, componentCount: 2, components: [{ ecosystem: 'apk', name: `synthetic-inventory-${i}`, version: '1' }], nextCursor: i ? null : 1 });
      if (suffix === '/vuln') {
        const pageIndex = i / 12; // Browser API cursors are cumulative row offsets, not page numbers.
        if (controls.failVuln && pageIndex === 1) { controls.failVuln = false; return json(response, { errorCode: 'SCAN_UNAVAILABLE' }, 503); }
        return json(response, vulnPage(pageIndex));
      }
      if (suffix === '/llm/context') return json(response, { ...binding(scanId), enabled: false, policyVersion: null, disclosure: null });
      if (suffix === '/llm/chat/context') return json(response, { ...binding(scanId), epoch: history.epoch, revision: history.revision, enabled: true, pending: false,
        policyVersion, disclosure, limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response' });
      if (suffix === '/llm/history') return json(response, history);
      if (suffix === '/llm/chat/usage') return json(response, usage(scanId));
      return json(response, { errorCode: 'FIXTURE_ROUTE_ONLY' }, 404);
    }
    let body = '';
    for await (const chunk of request) { body += chunk; if (Buffer.byteLength(body) > 8192) return json(response, { errorCode: 'FIXTURE_BODY_LIMIT' }, 413); }
    const input = JSON.parse(body);
    entry.body = input; // Exclusively synthetic questions/CAS; no real cookie/account/secret dumps.
    if (input.epoch !== history.epoch || input.revision !== history.revision || input.reportVersion !== binding(scanId).reportVersion)
      return json(response, { errorCode: 'LLM_HISTORY_CONFLICT' }, 409);
    if (suffix === '/llm/history/decision') {
      history.revision++;
      history.decisions.push({ id: randomUUID(), mutationId: input.mutationId, kind: 'user-decision', text: input.text, report: binding(scanId), sources: input.findingIds.length ? [source(scanId)] : [] });
      return json(response, history);
    }
    if (suffix !== '/llm/chat' || request.headers.accept !== 'application/x-ndjson' || input.consent?.accepted !== true || input.consent.policyVersion !== policyVersion)
      return json(response, { errorCode: 'FIXTURE_INVALID_MUTATION' }, 400);
    const mode = controls.nextMode;
    controls.nextMode = 'success';
    if (mode === 'quota') return json(response, { errorCode: 'LLM_QUOTA_EXCEEDED' }, 429);
    const turnId = randomUUID();
    const common = { ...binding(scanId), epoch: history.epoch, revision: history.revision + 2, mutationId: input.mutationId, turnId };
    const text = mode === 'unfinished' ? unfinishedReply : cleanReply;
    const reply = { ...binding(scanId), kind: 'hypothesis', text, sources: [source(scanId)] };
    // All normal protocol frames come from the real codec; no provider, store, controller or writer is invoked.
    const plan = encodeDelivery(mode === 'error'
      ? { ...common, outcome: 'failed', usage: receipt }
      : { ...common, outcome: 'completed', reply, usage: receipt });
    const frames = plan.lines.map(line => JSON.parse(line));
    if (mode === 'hostile') {
      // Explicit negative mutation, NOT wire a conforming server codec would emit.
      const hostile = '<script>alert(1)</script> [JS](javascript:alert(1))';
      frames.find(frame => frame.type === 'delta').text = hostile;
      frames.at(-1).textBytes = Buffer.byteLength(hostile);
    }
    entry.fixture = { mode, codec: 'actual encodeDelivery v1', adversarialMutation: mode === 'hostile' };
    response.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store, no-transform', 'X-Content-Type-Options': 'nosniff' });
    response.flushHeaders();
    if (mode === 'error') {
      history.revision += 2;
      history.turns.push({ id: turnId, mutationId: input.mutationId, state: 'failed', question: input.question, report: binding(scanId), createdAt: clock });
      await writeFile(`${output}/wire-${owner}-${scanId.slice(-2)}-${requests.length}.ndjson`, wire(frames));
      return response.end(wire(frames));
    }
    if (mode !== 'hostile') {
      history.revision += 2;
      history.turns.push({ id: turnId, mutationId: input.mutationId, state: 'completed', question: input.question, report: binding(scanId), createdAt: clock, reply });
    }
    await writeFile(`${output}/wire-${owner}-${scanId.slice(-2)}-${requests.length}.ndjson`, wire(frames));
    if (mode === 'held' || mode === 'abort') {
      response.write(wire(frames.slice(0, 3)));
      controls.hold = { response, frames, phase: 'partial', mode };
      stages.push({ mode, phase: 'partial', atMs: Math.round(performance.now() - started) });
      response.on('close', () => stages.push({ mode, phase: 'socket-closed', atMs: Math.round(performance.now() - started) }));
      return;
    }
    // Actual TCP chunks, including a JSON/UTF-8 boundary, not a fetch/ReadableStream replacement.
    const bytes = Buffer.from(wire(frames));
    response.write(bytes.subarray(0, 17));
    response.write(bytes.subarray(17, 741));
    response.end(bytes.subarray(741));
  } catch (error) {
    fixtureErrors.push(error.stack);
    if (!response.headersSent) json(response, { errorCode: 'FIXTURE_FAILURE' }, 500);
    else response.destroy();
  }
}
function releaseDone() {
  const hold = controls.hold;
  if (!hold || hold.phase !== 'partial') throw new Error('Missing held partial response');
  hold.response.write(wire(hold.frames.slice(3)));
  hold.phase = 'done-no-eof';
  stages.push({ mode: hold.mode, phase: hold.phase, atMs: Math.round(performance.now() - started) });
}
function releaseEof() {
  const hold = controls.hold;
  if (!hold) throw new Error('Missing held response');
  hold.response.end();
  controls.hold = null;
  stages.push({ mode: hold.mode, phase: 'eof', atMs: Math.round(performance.now() - started) });
}
async function screenshot(page, name) {
  const path = `${output}/${name}.png`;
  await page.screenshot({ path, fullPage: false });
  screenshots.push(path);
}
async function stableReport(page) {
  return Promise.all(['Покрытие проверок', 'Результаты проверок'].map(name => page.getByRole('region', { name, exact: true }).evaluate(node => node.outerHTML)));
}
async function assertPreserved(page, baseline) { expect(await stableReport(page)).toEqual(baseline); }
async function activateKeyboard(page, locator) {
  await locator.focus();
  await expect(locator).toBeFocused();
  const ring = await locator.evaluate(node => ({ outline: getComputedStyle(node).outlineStyle, width: parseFloat(getComputedStyle(node).outlineWidth), shadow: getComputedStyle(node).boxShadow }));
  expect(ring.outline !== 'none' && ring.width > 0 || ring.shadow !== 'none').toBe(true);
  stages.push({ scope: 'keyboard', role: await locator.getAttribute('role'), label: await locator.innerText(), ring });
  await page.keyboard.press('Enter');
}
async function openChat(page, chat) {
  await activateKeyboard(page, chat.getByRole('button', { name: /Открыть чат и прочитать условия|Обновить историю и условия чата/ }));
  await expect(chat.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toBeVisible();
  await expect(chat).toHaveAttribute('aria-busy', 'false');
}
async function submit(page, chat, mode, question) {
  controls.nextMode = mode;
  await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(question);
  const consent = chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ });
  const send = chat.getByRole('button', { name: 'Отправить вопрос', exact: true });
  await expect(consent).not.toBeChecked();
  await expect(send).toBeDisabled();
  await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).focus();
  await page.keyboard.press('Tab');
  await expect(consent).toBeFocused();
  await page.keyboard.press('Space');
  await expect(consent).toBeChecked();
  await expect(send).toBeEnabled();
  const before = requests.filter(r => r.method === 'POST' && r.path.endsWith('/llm/chat')).length;
  await activateKeyboard(page, send);
  await expect.poll(() => requests.filter(r => r.method === 'POST' && r.path.endsWith('/llm/chat')).length).toBe(before + 1);
}
async function createContext(width, owner = 'A') {
  const context = await browser.newContext({ viewport: { width, height: 800 }, reducedMotion: 'reduce', serviceWorkers: 'block', permissions: ['clipboard-read', 'clipboard-write'] });
  await context.addCookies([{ name: 'task16-proof-owner', value: owner, url: origin, httpOnly: true, sameSite: 'Strict' }]);
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) { blockedEgress.push(url.href); return route.abort(); }
    return route.continue();
  });
  return context;
}
async function viewportProof(width) {
  histories.clear(); controls.exhausted = false; controls.usageUnavailable = false;
  const context = await createContext(width);
  const page = await context.newPage();
  page.setDefaultTimeout(6000);
  page.on('pageerror', error => browserErrors.push({ width, message: error.message }));
  page.on('dialog', dialog => { browserErrors.push({ width, message: `Unexpected dialog: ${dialog.message()}` }); void dialog.dismiss(); });
  await page.goto(`${origin}/scans/${scanA}`);
  const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
  const cve = page.getByRole('region', { name: 'Результаты CVE', exact: true });
  await expect(cve.getByText('CVE-2026-10001', { exact: true })).toBeVisible();
  await expect(cve.getByRole('list', { name: 'Находки CVE' }).locator(':scope > li')).toHaveCount(12);
  await expect(chat.getByRole('button', { name: 'Открыть чат и прочитать условия' })).toBeVisible();
  const chatReads = () => requests.filter(r => r.path.includes('/llm/chat/') || r.path.endsWith('/llm/history'));
  expect(chatReads()).toHaveLength(0);
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(0);
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  expect(chatReads()).toHaveLength(0);
  const top = cve.getByRole('navigation', { name: 'Пагинация CVE · сверху' });
  const bottom = cve.getByRole('navigation', { name: 'Пагинация CVE · снизу' });
  await top.scrollIntoViewIfNeeded();
  const topScroll = await page.evaluate(() => window.scrollY);
  await screenshot(page, `${width}-cve-top-page1`);
  await bottom.scrollIntoViewIfNeeded();
  const bottomScroll = await page.evaluate(() => window.scrollY);
  expect(bottomScroll - topScroll).toBeGreaterThan(800);
  await screenshot(page, `${width}-cve-bottom-page1`);
  await activateKeyboard(page, bottom.getByRole('button', { name: 'Далее · CVE', exact: true }));
  await expect(cve.getByText('Строки 13–24', { exact: true })).toBeVisible();
  await expect(cve.getByText('CVE-2026-10013', { exact: true })).toBeVisible();
  await top.scrollIntoViewIfNeeded();
  await screenshot(page, `${width}-cve-top-page2`);
  await activateKeyboard(page, top.getByRole('button', { name: 'Далее · CVE · сверху', exact: true }));
  await expect(cve.getByText('Строки 25–36', { exact: true })).toBeVisible();
  await expect(bottom.getByRole('button', { name: 'Далее · CVE', exact: true })).toBeDisabled();
  await activateKeyboard(page, bottom.getByRole('button', { name: 'Назад · CVE', exact: true }));
  await expect(cve.getByText('Строки 13–24', { exact: true })).toBeVisible();
  await activateKeyboard(page, top.getByRole('button', { name: 'Назад · CVE · сверху', exact: true }));
  await expect(cve.getByText('Строки 1–12', { exact: true })).toBeVisible();
  controls.failVuln = true;
  await activateKeyboard(page, top.getByRole('button', { name: 'Далее · CVE · сверху', exact: true }));
  await expect(cve.getByRole('alert')).toContainText('Показана предыдущая подтверждённая страница');
  await expect(cve.getByText('CVE-2026-10001', { exact: true })).toBeVisible();
  await activateKeyboard(page, cve.getByRole('button', { name: 'Повторить загрузку CVE', exact: true }));
  await expect(cve.getByText('Строки 13–24', { exact: true })).toBeVisible();
  // Other category pagers remain independent of CVE navigation.
  await expect(page.getByRole('region', { name: 'Результаты Secrets' }).getByText('Строки 1–1', { exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Пакеты SBOM' }).getByText('Строки 1–1', { exact: true })).toBeVisible();
  const pagerGeometry = await top.locator('button').evaluateAll(nodes => nodes.map(node => ({ height: node.getBoundingClientRect().height, font: parseFloat(getComputedStyle(node).fontSize) })));
  for (const g of pagerGeometry) { expect(g.height).toBeGreaterThanOrEqual(44); expect(g.font).toBeGreaterThanOrEqual(14); }
  const baseline = await stableReport(page);
  await openChat(page, chat);
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(0);
  await expect(chat.getByText(/Допуск запроса неизвестен/)).toBeVisible();
  await submit(page, chat, 'held', `Синтетический вопрос ${width}`);
  await expect.poll(() => controls.hold?.phase).toBe('partial');
  await expect(chat).toHaveAttribute('aria-busy', 'true');
  await expect(chat.getByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toHaveCount(0);
  await expect(chat.getByRole('button', { name: 'Скопировать текст', exact: true })).toHaveCount(0);
  await screenshot(page, `${width}-chat-partial-no-publication`);
  releaseDone();
  await page.waitForTimeout(150); // Give the actual network reader time to consume done while EOF remains held.
  await expect(chat.getByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toHaveCount(0);
  await expect(chat).toHaveAttribute('aria-busy', 'true');
  releaseEof();
  await expect(chat.getByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toHaveCount(1);
  await expect(chat.getByText('Последний ответ:', { exact: false })).toContainText('input 500, output 32');
  const article = chat.locator('article').first();
  await expect(article.locator('code')).toHaveText('echo synthetic-only\n');
  await expect(article.locator('[data-streamdown="strong"]')).toHaveText('Синтетическая гипотеза');
  await activateKeyboard(page, article.getByRole('button', { name: 'Скопировать код', exact: true }));
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('echo synthetic-only\n');
  const citation = article.getByRole('link', { name: 'Находка secret-0-1', exact: true });
  await activateKeyboard(page, citation);
  const citationTarget = await citation.getAttribute('href');
  expect(await page.evaluate(() => document.activeElement?.id)).toBe(citationTarget.slice(1));
  await expect(article.getByText('Источник текущего отчёта, проверен по scanner results.')).toBeVisible();
  expect(requests.some(r => r.path.endsWith('/results') && r.cursor === '1')).toBe(true);
  const accessibility = await chat.ariaSnapshot();
  await writeFile(`${output}/${width}-chat-accessibility.yaml`, accessibility);
  await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill('Новый вопрос снимает согласие');
  await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).not.toBeChecked();
  await article.scrollIntoViewIfNeeded();
  await screenshot(page, `${width}-chat-confirmed-citation`);
  await assertPreserved(page, baseline);
  await submit(page, chat, 'unfinished', `Незакрытый ответ ${width}`);
  await expect(chat.locator('article')).toHaveCount(2);
  const unfinished = chat.locator('article').last();
  await expect(unfinished.locator('pre')).toHaveText(unfinishedReply);
  await expect(unfinished.locator('code')).toHaveCount(0);
  await activateKeyboard(page, unfinished.getByRole('button', { name: 'Скопировать текст', exact: true }));
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(unfinishedReply);
  await screenshot(page, `${width}-chat-unfinished-exact-copy`);
  await assertPreserved(page, baseline);
  for (const [mode, expected] of [['error', /Не удалось безопасно прочитать ответ/], ['quota', /Достигнут лимит запросов или квоты/], ['hostile', /Не удалось безопасно прочитать ответ/]]) {
    if (mode !== 'error') await openChat(page, chat);
    const before = requests.filter(r => r.method === 'POST' && r.path.endsWith('/llm/chat')).length;
    await submit(page, chat, mode, `Ошибка синтетического запроса ${mode} ${width}`);
    await expect(chat.getByRole('alert')).toContainText(expected);
    await expect(chat).toHaveAttribute('aria-busy', 'false');
    await expect(chat.locator('article')).toHaveCount(0);
    await expect(chat.locator('script, img, a[href^="javascript:"], a[href^="data:"], a[href^="file:"]')).toHaveCount(0);
    expect(requests.filter(r => r.method === 'POST' && r.path.endsWith('/llm/chat'))).toHaveLength(before + 1);
    await assertPreserved(page, baseline);
    await screenshot(page, `${width}-chat-${mode}`);
  }
  controls.exhausted = true;
  await openChat(page, chat);
  await expect(chat.getByRole('region', { name: 'Квоты чата' })).toContainText('Квота исчерпана.');
  await assertPreserved(page, baseline);
  controls.exhausted = false; controls.usageUnavailable = true;
  await openChat(page, chat);
  await expect(chat.getByText(/Учёт недоступен, не ноль/)).toBeVisible();
  controls.usageUnavailable = false;
  await openChat(page, chat);
  await submit(page, chat, 'abort', `Отмена синтетического ожидания ${width}`);
  await expect.poll(() => controls.hold?.phase).toBe('partial');
  await activateKeyboard(page, chat.getByRole('button', { name: 'Отменить ожидание чата', exact: true }));
  await expect(chat.getByRole('alert')).toContainText('Ожидание остановлено');
  await expect(chat.locator('article')).toHaveCount(0);
  releaseEof();
  await expect(chat.locator('article')).toHaveCount(0);
  await assertPreserved(page, baseline);
  await openChat(page, chat);
  await expect(chat.locator('article').getByText(`Отмена синтетического ожидания ${width}`, { exact: true })).toBeVisible();
  await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).not.toBeChecked();
  // Explicit no-provider decision persists through the same real transport/history reread.
  const decisionPosts = requests.filter(r => r.path.endsWith('/llm/chat') && r.method === 'POST').length;
  const decisionText = `Синтетическое решение владельца A ${width}`;
  await chat.getByRole('textbox', { name: 'Текст решения', exact: true }).fill(decisionText);
  await activateKeyboard(page, chat.getByRole('button', { name: 'Сохранить решение', exact: true }));
  await expect(chat.locator('article').getByText(decisionText, { exact: true })).toBeVisible();
  expect(requests.filter(r => r.path.endsWith('/llm/chat') && r.method === 'POST')).toHaveLength(decisionPosts);
  await openChat(page, chat);
  await expect(chat.locator('article').getByText(decisionText, { exact: true })).toBeVisible();
  await assertPreserved(page, baseline);
  const overflow = await page.evaluate(() => ({ viewport: window.innerWidth, document: document.documentElement.scrollWidth }));
  expect(overflow.document).toBeLessThanOrEqual(width);
  results.push({ width, height: 800, status: 'passed', topScroll, bottomScroll, pagerGeometry, overflow,
    criteria: ['actual36CVE/3pages/12rows', 'viewport-scroll-top-bottom', 'keyboard-pagination-back-next-error-retry', 'category-independence', 'manual-read-consent-only-POST', 'real-network-partial+done-withoutEOF-unpublished', 'durable-reread-rich-publication', 'late-page-citation-keyboard-focus', 'real-clipboard-code+unfinished-exact', 'usage-error+quota+hostile-refusal', 'quota-exhausted+unknown-notzero', 'abort-hides+manual-durable-recovery', 'decision-no-generation', 'coverage/findings-outerHTML-identical'] });
  await context.close();
}
async function isolationProof() {
  const context = await createContext(1280);
  const page = await context.newPage(); page.setDefaultTimeout(6000);
  const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
  await page.goto(`${origin}/scans/${scanA}`); await openChat(page, chat);
  await expect(chat.getByText('Синтетическое решение владельца A 375', { exact: true })).toBeVisible();
  await page.goto(`${origin}/scans/${scanB}`); await openChat(page, chat);
  await expect(chat.getByText(/История пока пуста/)).toBeVisible();
  await expect(chat.getByText(/Синтетическое решение владельца A/)).toHaveCount(0);
  await page.goto(`${origin}/scans/${scanA}`); await openChat(page, chat);
  await expect(chat.getByText('Синтетическое решение владельца A 375', { exact: true })).toBeVisible();
  await context.addCookies([{ name: 'task16-proof-owner', value: 'B', url: origin, httpOnly: true, sameSite: 'Strict' }]);
  await page.reload(); await openChat(page, chat);
  await expect(chat.getByText(/История пока пуста/)).toBeVisible();
  await expect(chat.getByText(/Синтетическое решение владельца A/)).toHaveCount(0);
  await chat.getByRole('textbox', { name: 'Текст решения' }).fill('Синтетическое решение владельца B');
  await activateKeyboard(page, chat.getByRole('button', { name: 'Сохранить решение', exact: true }));
  await expect(chat.locator('article').getByText('Синтетическое решение владельца B', { exact: true })).toBeVisible();
  await screenshot(page, '1280-ownerB-separated-history');
  await context.addCookies([{ name: 'task16-proof-owner', value: 'A', url: origin, httpOnly: true, sameSite: 'Strict' }]);
  await page.reload(); await openChat(page, chat);
  await expect(chat.getByText('Синтетическое решение владельца A 375', { exact: true })).toBeVisible();
  await expect(chat.getByText('Синтетическое решение владельца B', { exact: true })).toHaveCount(0);
  results.push({ status: 'passed', scope: 'synthetic owner+scan isolation', scanSwitch: 'A→B→A through actual router reload', ownerSwitch: 'A→B→A via synthetic cookie+actual auth/me+reload', limitation: 'No real backend auth/security proof; no in-flight same-tab session transition tested here.' });
  await context.close();
}
async function staleProof() {
  for (const width of [320, 375, 1280]) {
    histories.clear(); requests.length = 0;
    const context = await createContext(width);
    const page = await context.newPage(); page.setDefaultTimeout(6000);
    const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
    await page.goto(`${origin}/scans/${scanA}`); await openChat(page, chat);
    const navigate = async scanId => page.evaluate(id => {
      window.history.pushState({}, '', `/scans/${id}`);
      window.dispatchEvent(new PopStateEvent('popstate'));
    }, scanId);
    await submit(page, chat, 'held', `STALE SCAN ${width}`);
    await expect.poll(() => controls.hold?.phase).toBe('partial');
    const scanHold = controls.hold;
    await navigate(scanB);
    await expect(chat.getByRole('button', { name: 'Открыть чат и прочитать условия' })).toBeVisible();
    // Old response completes (or is disconnected); neither event may publish into new scope.
    scanHold.response.end(wire(scanHold.frames.slice(3))); controls.hold = null;
    await openChat(page, chat);
    await expect(chat.locator('article')).toHaveCount(0);
    await expect(chat.getByText(`STALE SCAN ${width}`, { exact: true })).toHaveCount(0);
    await navigate(scanA); await openChat(page, chat);
    await expect(chat.locator('article').getByText(`STALE SCAN ${width}`, { exact: true })).toBeVisible();
    // Stored history in this mock was committed before output, as specified; recovering it is explicit.
    await submit(page, chat, 'held', `STALE ACCOUNT ${width}`);
    await expect.poll(() => controls.hold?.phase).toBe('partial');
    const accountHold = controls.hold;
    await context.addCookies([{ name: 'task16-proof-owner', value: 'B', url: origin, httpOnly: true, sameSite: 'Strict' }]);
    await page.evaluate(async () => {
      const { switchSubject } = await import('/tests-e2e/task16-chat-browser.session.ts');
      switchSubject('synthetic-owner-B');
    });
    await expect(chat.getByRole('button', { name: 'Открыть чат и прочитать условия' })).toBeVisible();
    accountHold.response.end(wire(accountHold.frames.slice(3))); controls.hold = null;
    await page.waitForTimeout(150);
    await expect(chat.locator('article')).toHaveCount(0);
    await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).toHaveCount(0);
    // Direct observable injection deliberately does not update the app's auth query/cache.
    // Recovery exercises the real auth/me flow, rather than claiming injected login integration.
    await page.reload(); await openChat(page, chat);
    await expect(chat.locator('article')).toHaveCount(0);
    await expect(chat.getByText(`STALE ACCOUNT ${width}`, { exact: true })).toHaveCount(0);
    await expect(chat.getByRole('checkbox', { name: /Разрешаю один запрос чата/ })).not.toBeChecked();
    await screenshot(page, `${width}-inflight-account-separated`);
    results.push({ width, scope: 'inflight-stale-scan-account', status: 'passed',
      scan: 'same-document pushState/popstate A→B→A, old HTTP completion unpublished',
      account: 'synthetic cookie plus actual transitionScanSession observable; no backend auth claim',
      mutations: requests.filter(r => r.method === 'POST').length });
    await context.close();
  }
}
async function rendererProof(width) {
  const context = await createContext(width);
  const page = await context.newPage(); page.setDefaultTimeout(6000);
  page.on('pageerror', error => browserErrors.push({ scope: 'renderer', message: error.message }));
  page.on('dialog', dialog => { browserErrors.push({ scope: 'renderer', message: dialog.message() }); void dialog.dismiss(); });
  await page.goto(`${origin}/tests-e2e/task16-chat-browser.renderer.html`);
  const html = page.getByTestId('html');
  await expect(html.locator('pre')).toContainText('<script>');
  await expect(html.locator('script,img')).toHaveCount(0);
  const urls = page.getByTestId('urls');
  await expect(urls.locator('a')).toHaveCount(1);
  await expect(urls.locator('a')).toHaveAttribute('href', 'https://example.invalid/synthetic');
  await expect(urls.locator('a')).toHaveAttribute('rel', 'noopener noreferrer nofollow');
  await expect(urls.locator('a[href^="javascript:"], a[href^="data:"], a[href^="file:"]')).toHaveCount(0);
  for (const id of ['html', 'unfinished', 'tilde']) {
    const sample = page.getByTestId(id);
    const text = await sample.locator('pre').textContent();
    await activateKeyboard(page, sample.getByRole('button', { name: 'Скопировать текст', exact: true }));
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(text);
    await expect(sample.locator('code')).toHaveCount(0);
  }
  const closed = page.getByTestId('closed');
  await expect(closed.locator('code')).toHaveText('window.__task16Executed = true\n');
  await activateKeyboard(page, closed.getByRole('button', { name: 'Скопировать код', exact: true }));
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('window.__task16Executed = true\n');
  expect(await page.evaluate(() => window.__task16Executed ?? false)).toBe(false);
  await screenshot(page, `${width}-actual-renderer-adversarial`);
  results.push({ width, scope: 'separate actual SafeMarkdown browser probe', status: 'passed', rawHtml: 'exact inert pre', urls: 'unsafe inert/HTTPS-only', nestedUnfinished: 'exact pre/copy', closedCode: 'inert/plaintext/copy', executionMarker: false, clipboard: 'real Chromium Clipboard API, no stub' });
  await context.close();
}
async function cleanup() {
  controls.hold?.response.destroy(); controls.hold = null;
  await browser?.close();
  for (const socket of sockets) socket.destroy();
  await server?.close();
}
await mkdir(output, { recursive: true });
const before = await hashes(productionPaths);
let failure;
const watchdog = setTimeout(() => {
  timeoutTriggered = true;
  void cleanup().finally(() => process.exit(124));
}, 115000);
// Even a stalled cleanup cannot leave an indefinite owned server/browser command.
const hardStop = setTimeout(() => process.exit(124), 120000);
try {
  const allocator = net.createServer();
  await new Promise(resolve => allocator.listen(0, '127.0.0.1', resolve));
  const plannedPort = allocator.address().port;
  await new Promise(resolve => allocator.close(resolve));
  server = await createServer({ configFile: 'tests-e2e/task16-chat-browser.independent.vite.mjs', envDir: false,
    cacheDir: `${output}/vite-cache`, server: { host: '127.0.0.1', port: plannedPort, strictPort: true, proxy: undefined, hmr: false },
    plugins: [{ name: 'synthetic-task16-loopback-only', configureServer(vite) { vite.middlewares.use((req, res, next) => { void api(req, res, next); }); } }] });
  server.httpServer.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await server.listen();
  const address = server.httpServer.address();
  expect(address.address).toBe('127.0.0.1');
  port = address.port; origin = `http://127.0.0.1:${port}`;
  process.send?.({ origin, port });
  browser = await chromium.launch({ headless: true });
  for (const width of [1280, 320, 375]) {
    requests.length = 0;
    await viewportProof(width);
    await writeFile(`${output}/${width}-requests.json`, JSON.stringify(requests, null, 2));
    console.log(`PASS Chromium ${width}x800: actual ScanDetailPage/HTTP/NDJSON/pagers/chat/copy/keyboard`);
  }
  await isolationProof(); await staleProof();
  for (const width of [320, 375, 1280]) await rendererProof(width);
  expect(browserErrors).toEqual([]); expect(fixtureErrors).toEqual([]); expect(blockedEgress).toEqual([]);
} catch (error) {
  failure = error;
  results.push({ status: 'failed', message: error.stack });
  console.error(error.stack);
  await writeFile(`${output}/failed-requests.json`, JSON.stringify(requests, null, 2));
  for (const context of browser?.contexts() ?? []) for (const page of context.pages()) {
    await screenshot(page, 'failure-current-viewport').catch(() => {});
    await writeFile(`${output}/failure-current-dom.txt`, await page.locator('body').innerText()).catch(() => {});
  }
} finally {
  await cleanup(); clearTimeout(watchdog); clearTimeout(hardStop);
  const after = await hashes(productionPaths);
  const unchanged = JSON.stringify(before) === JSON.stringify(after);
  const listenerClosed = port === undefined ? true : await new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => resolve(true));
    socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
  });
  if (!unchanged || !listenerClosed) { failure ??= new Error('Production source changed during proof or own listener remains open'); }
  const evidence = { synthetic: true, productionBackend: false, providerCalls: 0, LIVE: false, Docker: false,
    mode: 'Vite7 source-transformed compiled React/CSS, not production dist/deployed bundle',
    viewports: [1280, 320, 375].map(width => ({ width, height: 800 })), status: failure ? 'failed' : 'passed',
    durationMs: Math.round(performance.now() - started), timeoutTriggered, maxLifetimeMs: 120000, listener: { host: '127.0.0.1', port, closed: listenerClosed },
    productionSourceUnchanged: unchanged, before, after, results, screenshots, stages, browserErrors, fixtureErrors, blockedEgress,
        protocol: { codec: 'actual server/api/src/llm/history-delivery.ts encodeDelivery', version: 1, nativeProviderStream: false, limits: DELIVERY, adversarialWire: 'hostile mode intentionally mutates valid encoded delta; never claimed backend output' },
    assuranceLimits: ['Synthetic cookie owner/history/API; no selected backend/main/nginx/provider integration', 'No provider-native token streaming', 'No VoiceOver/screen reader/complete WCAG/axe/contrast certification', 'Renderer adversarial page is separate from schema-rejecting mounted chat', 'No production source/config/notices edits; read-only relevant source hashes only, no curated graph writes/commits/taskclose/specapply'] };
  await writeFile(`${output}/results.json`, JSON.stringify(evidence, null, 2));
  const localEvidence = (await readdir(output)).filter(name => /\.(json|ndjson|yaml|png|txt)$/.test(name) && name !== 'manifest.json').map(name => `${output}/${name}`);
  const files = await hashes([...productionPaths, 'tests-e2e/task16-chat-browser.session.ts', 'tests-e2e/task16-chat-browser.independent.mjs',
    'tests-e2e/task16-chat-browser.independent.vite.mjs', 'tests-e2e/task16-chat-browser.managed.mjs', ...localEvidence]);
  await writeFile(`${output}/manifest.json`, JSON.stringify({ synthetic: true, files, codecLimits: DELIVERY, selfExcluded: true }, null, 2));
  console.log(`Evidence: ${output}/results.json; own listener closed=${listenerClosed}; source unchanged=${unchanged}`);
}
if (failure) process.exitCode = 1;
