// Default/import is inert. Coordinator-only VIEW of already owned results.
// No generation, disk output, original-request reconstruction or lock disposition.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import { REVIEW_SOURCE as SHARED_TOOL_SOURCE, browserIo, validateSummary, bounded, SESSION_FILE } from './batch27-final-native.mjs';
import { contracts, fingerprint, policyMatches, readinessMatches, SCAN, ORIGIN, BASE } from './native-h7v3-paid-sol.mjs';
import { privateSnapshot, validateStorage, extraContracts, replyProof, allowedGet, assertNoCaptureEnvironment } from './batch26-native-chat.mjs';
import { diagnosticContracts } from './native-h7v3-finite-diagnostics.mjs';
import { BROWSER_ARGS } from './public-product-live.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
// Historical coordinator report only. This VIEW does NOT attest a deployment,
// container/image identity, shipped bytes, or eligibility for a new generation.
export const HISTORICAL_WIRE = Object.freeze({ summaryHttp: 200, chatHttp: 502, chatFiniteHeaders: 'absent', chatBody: 'unavailable', originalWireResult: 'FAILED_NOT_REPAIRED' });
export const EVIDENCE_SCOPE = Object.freeze({
  toolIdentity: 'CURRENT_REVIEWED_PUBLIC_TOOL_SNAPSHOT_ONLY',
  productIdentity: 'AUTHENTICATED_SAME_ORIGIN_OWNER_REPORT_GET_AND_RENDER',
  deployedBuildIdentity: 'NOT_MEASURED', runtimeEpochIdentity: 'NOT_MEASURED', generationEligibility: 'NOT_ASSESSED',
  historicalWireProvenance: 'COORDINATOR_REPORTED_NOT_REMEASURED_BY_VIEW',
});
export const VIEWPORTS = Object.freeze([375, 1280]);
export const BOUNDS = Object.freeze({ workMs: 105000, closeMs: 5000, sessionCheckMs: 5000, requests: 400 });
const SHA = /^[a-f0-9]{64}$/;
const need = (ok, code) => { if (!ok) throw Error(code); };
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype && equal(Object.keys(v).sort(), [...keys].sort());
const binding = (a, b) => ['scanId', 'digest', 'platform', 'reportVersion'].every(k => a?.[k] === b?.[k]);
// This is a CURRENT tool/validator review, never an original deployment hash.
export const REVIEW_SOURCE = Object.freeze([...new Set([...SHARED_TOOL_SOURCE,
  'tests-e2e/batch33-product-readonly.mjs', 'tests-e2e/batch33-product-readonly.test.mjs',
  'src/pages/scans/ScanReportOverview.tsx', 'src/pages/scans/ScanReportSections.tsx',
  'src/features/scans/ReportRemediation.tsx', 'src/features/scans/LlmFindingDetails.tsx',
  'src/features/scans/reportSourceNavigation.tsx',
])].sort());
export async function reviewFingerprint() {
  const rows = [];
  for (const path of REVIEW_SOURCE) {
    const file = await open(join(ROOT, path), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const s = await file.stat();
      need(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && !(s.mode & 0o022) && s.size <= 1048576, 'SOURCE_CHANGED');
      const bytes = await file.readFile(), after = await file.stat();
      need(equal([s.ino, s.size, s.mtimeMs, s.ctimeMs], [after.ino, after.size, after.mtimeMs, after.ctimeMs]), 'SOURCE_CHANGED');
      rows.push([path, createHash('sha256').update(bytes).digest('hex')]);
    } finally { await file.close(); }
  }
  return fingerprint(rows);
}
export function modeOf(args) {
  if (!args.length) return { mode: 'inert' };
  if (equal(args, ['--fingerprint'])) return { mode: 'fingerprint' };
  need(args.length === 5 && args[0] === '--view-readonly' && args[1] === '--ack-coordinator-get-only' &&
    args[2] === '--ack-retain-native-lock-original-wire-failed' && args[3] === '--review-sha256' && SHA.test(args[4]), 'EXACT_VIEW_GO_REQUIRED');
  return { mode: 'view', review: args[4] };
}
const CODES = Object.freeze(['EXACT_VIEW_GO_REQUIRED', 'SOURCE_CHANGED', 'VIEW_ONLY_FENCE', 'RUNTIME_CHANGED', 'OWNER_CHANGED',
  'REQUEST_BOUND', 'ROUTE_REFUSED', 'TRANSPORT_REFUSED', 'BODY_BOUND', 'PAGE_ERROR', 'GET_FAILED', 'CURRENT_RESULT_INVALID',
  'CURRENT_RESULT_CHANGED', 'UI_UNVERIFIED', 'GEOMETRY_UNVERIFIED', 'SESSION_CHANGED', 'CAPTURE_DEBUG_ENABLED', 'DEADLINE_NO_RETRY',
  'PRIVATE_SESSION_UNSAFE', 'AUTOMATION_NOT_OFF', 'CURRENT_POLICY', 'CORPUS_MISMATCH', 'CORPUS_PAGE_INVALID', 'CORPUS_PAGE_CHANGED',
  'CORPUS_IDENTITY', 'SUMMARY_BINDING', 'SUMMARY_SOURCE_UNKNOWN', 'SUMMARY_FACT_CHANGED', 'SUMMARY_LANGUAGE_OR_GROUNDING',
  'NATIVE_CITATION_MISMATCH', 'RUSSIAN_VALIDATION_FAILED']);
export function failureCode(error) { return CODES.includes(error?.message) ? error.message : 'READONLY_UNVERIFIED'; }
export function createGuard() { return { requests: 0, denied: 0, nonGet: 0, pageErrors: 0, stopped: false, firstFailure: null }; }
function stop(guard, error) { guard.firstFailure ??= failureCode(error); guard.stopped = true; }

export function readPlan(url, method, redirected = false) {
  try {
    const u = new URL(url);
    if (method !== 'GET' || redirected || u.origin !== ORIGIN || u.username || u.password || u.hash ||
      url !== u.href || /[%\\]/.test(u.pathname) || u.pathname.includes('//') || !allowedGet(url)) return false;
    // No runtime-discovery/provider, streaming, translation, auth mutation or list discovery.
    return ['/account', `/scans/${SCAN}`, '/api/v1/auth/me', '/favicon.ico'].includes(u.pathname) && !u.search ||
      /^\/assets\/[A-Za-z0-9._/-]+\.(?:js|css|svg|png|webp|woff2?)$/.test(u.pathname) && !u.search ||
      (u.pathname === BASE || u.pathname.startsWith(BASE + '/')) &&
        !/\/(?:events|translation)(?:\/|$)/.test(u.pathname);
  } catch { return false; }
}
// Actual installed route handler: no continue(), no fallback/retry and no hidden redirect.
export async function installRoutes(context, guard) {
  await context.route('**/*', async route => {
    const request = route.request(); let response;
    const deny = async code => { guard.denied++; stop(guard, Error(code)); await route.abort().catch(() => {}); };
    if (request.method() !== 'GET') guard.nonGet++;
    if (guard.closing && readPlan(request.url(), request.method(), !!request.redirectedFrom())) return route.abort().catch(() => {});
    if (++guard.requests > BOUNDS.requests) return deny('REQUEST_BOUND');
    if (guard.stopped || !readPlan(request.url(), request.method(), !!request.redirectedFrom()) || request.postData() !== null) return deny('ROUTE_REFUSED');
    try {
      response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15000 });
      if (guard.closing) { await route.abort().catch(() => {}); return; }
      const status = response.status(), headers = response.headers();
      need(!guard.stopped && Number.isInteger(status) && status >= 200 && status <= 599 &&
        !(status >= 300 && status < 400) && response.url() === request.url() &&
        !Object.keys(headers).some(k => k.toLowerCase() === 'location' || k.toLowerCase() === 'content-disposition'), 'TRANSPORT_REFUSED');
      const max = new URL(request.url()).pathname.startsWith('/assets/') ? 8 * 1048576 : 1048576;
      const length = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-length')?.[1];
      need(length === undefined || /^\d+$/.test(length) && Number(length) <= max, 'BODY_BOUND');
      const bytes = await response.body();
      if (guard.closing) { await route.abort().catch(() => {}); return; }
      need(bytes.length <= max && !guard.stopped, 'BODY_BOUND');
      await route.fulfill({ response, body: bytes });
    } catch (error) {
      if (guard.closing) await route.abort().catch(() => {});
      else await deny(failureCode(error));
    }
    finally { await response?.dispose().catch(() => {}); }
  });
  await context.routeWebSocket('**/*', socket => { guard.denied++; stop(guard, Error('ROUTE_REFUSED')); socket.close(); });
}

// Code-injected readReview is an OFFLINE test seam, not a CLI attestation input.
// Only today's reviewed tool bytes are checked. Original deployment receipts,
// native lock/audit and local generation-source eligibility are not consulted.
export function toolReview(review, readReview = reviewFingerprint) {
  need(SHA.test(review), 'EXACT_VIEW_GO_REQUIRED');
  return Object.freeze({ async check() { need(await readReview() === review, 'SOURCE_CHANGED'); } });
}

// Current-view validation, NOT attribution to an unrecorded original mutation or
// baseline. All fingerprints stay in memory; none are published as historical pins.
export function validateCurrent(sample, corpus, tools, c) {
  const s = tools.summary.summaryContextSchema.parse(sample.context.s), h = c.chat.chatContextSchema.parse(sample.context.h),
    r = c.chat.chatReadinessSchema.parse(sample.context.r), history = c.chat.chatHistorySchema.parse(sample.history), usage = c.usage.parse(sample.usage);
  need(s.scanId === SCAN && binding(s, h) && policyMatches(s) && policyMatches(h) && readinessMatches(r, h) &&
    !h.pending && h.revision === 6 && binding(history, h) && history.epoch === h.epoch && history.revision === h.revision &&
    !history.pending && history.turns.length === 3 && history.decisions.length === 0 &&
    equal(history.turns.map(t => t.state), ['failed', 'failed', 'completed']) && history.turns.every(t => binding(t.report, h)), 'CURRENT_RESULT_INVALID');
  const summary = validateSummary(sample.summary, s, corpus, tools), last = history.turns[2];
  need(summary.hypotheses.length === 4 && last.reply.sources.length === 3 && binding(last.reply, h) &&
    last.reply.sources.every(source => binding(source, h)), 'CURRENT_RESULT_INVALID');
  replyProof({ reply: last.reply }, corpus, c, tools);
  need(usage.available && usage.integrationEnabled && usage.quotaEnabled && usage.monetaryLimit === 'uncapped' && binding(usage, h), 'CURRENT_RESULT_INVALID');
  return { context: { s, h, r }, summary, history, usage };
}
const currentFlags = () => ({ reportSourcesValidated: true, fourRussianParagraphsValidated: true, chatThreeSourcesValidated: true,
  historyFailedFailedCompletedRev6: true, currentDtoStableAcrossReload: true });
export async function verifyProduct(io, source, tools, c) {
  await source.check();
  const first = await io.preflight(), corpus = await io.corpus();
  const sample = async context => {
    const summary = await io.summaryRead(); need(summary.status === 200, 'GET_FAILED');
    return validateCurrent({ context, summary: summary.value, history: await io.history(), usage: await io.usage() }, corpus, tools, c);
  };
  const initial = await sample({ s: first.s, h: first.h, r: first.r });
  need(equal(c.chat.chatHistorySchema.parse(first.history), initial.history), 'CURRENT_RESULT_CHANGED');
  const seen = [];
  for (const width of VIEWPORTS) {
    await source.check(); await io.viewport(width);
    await io.visible(initial); await io.geometry(width);
    await io.reload();
    const restored = await sample(await io.current());
    need(equal(restored, initial), 'CURRENT_RESULT_CHANGED');
    await io.visible(restored); await io.geometry(width); await source.check();
    seen.push({ width, reportVisible: true, summaryVisible: true, chatVisible: true, reloadVisible: true, noHorizontalOverflow: true });
  }
  return { kind: 'current-owned-product-view-only', evidenceScope: EVIDENCE_SCOPE, ...currentFlags(), viewports: seen,
    historicalWire: HISTORICAL_WIRE, originalRequestCorrelation: 'NOT_ESTABLISHED_NO_HISTORICAL_ANCHORS_INFERRED',
    semanticAccuracy: 'UNVERIFIED_VALIDATORS_AND_RENDER_ARE_NOT_HUMAN_FIDELITY_REVIEW',
    accounting: 'CURRENT_GET_UNCHANGED_NOT_INVOICE_NOT_RECONCILIATION', nativeLock: 'RETAINED_NO_DISPOSITION', paidRetryAuthorized: false };
}

// DOM proof uses actual inline source cards and paragraph-local source regions,
// not obsolete source accordions, copied DTO success booleans or screenshots.
export async function visibleProduct(page, sample) {
  const overview = page.locator('.scan-report-overview'); await overview.waitFor({ state: 'visible' });
  need((await overview.locator('.scan-report-overview__counts').innerText()).includes('440'), 'UI_UNVERIFIED');
  const output = page.getByLabel('ИИ-разбор отчёта', { exact: true }); await output.waitFor({ state: 'visible' });
  const explanation = output.locator('details.scan-summary-explanation');
  if (await explanation.getAttribute('open') === null) await explanation.locator(':scope > summary').click();
  for (const [i, paragraph] of sample.summary.hypotheses.entries()) {
    const region = output.getByLabel(`Источники абзаца ${i + 1}`, { exact: true }); await region.waitFor({ state: 'visible' });
    need((await region.locator('..').innerText()).includes(paragraph.text), 'UI_UNVERIFIED');
    const ids = await region.locator('.report-remediation').evaluateAll(nodes => nodes.map(n => n.getAttribute('data-finding-id')));
    need(equal([...ids].sort(), [...paragraph.citations].sort()), 'UI_UNVERIFIED');
  }
  const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
  await chat.getByRole('heading', { name: 'Ответ · проверьте по источникам', exact: true }).waitFor({ state: 'visible' });
  const articles = chat.locator(':scope > article'); need(await articles.count() === 3, 'UI_UNVERIFIED');
  const normalize = value => value.replace(/\s+/g, ' ').trim();
  for (let i = 0; i < 3; i++) {
    const article = articles.nth(i), turn = sample.history.turns[i], text = await article.innerText();
    need(normalize(text).includes(normalize(turn.question)), 'UI_UNVERIFIED');
    if (i < 2) need(text.includes('Вопрос · ошибка') && text.includes('Подтверждённого ответа нет'), 'UI_UNVERIFIED');
    else {
      // SafeMarkdown may turn line breaks/links into separate DOM nodes.
      need(normalize(text).includes(normalize(turn.reply.text)), 'UI_UNVERIFIED');
      const cards = article.getByLabel('Источники ответа', { exact: true }).locator('.report-remediation');
      const ids = await cards.evaluateAll(nodes => nodes.map(n => n.getAttribute('data-finding-id')));
      need(equal([...ids].sort(), turn.reply.sources.map(s => s.finding.findingId).sort()), 'UI_UNVERIFIED');
      for (const source of turn.reply.sources) {
        const card = article.locator(`.report-remediation[data-finding-id="${source.finding.findingId}"]`);
        const codes = await card.locator('code').allTextContents(), f = source.finding;
        for (const key of ['packageName', 'installedVersion', 'ecosystem', 'fixedVersion', 'ruleId', 'evidenceRef', 'classification', 'location'])
          if (typeof f[key] === 'string') need(codes.includes(f[key]), 'UI_UNVERIFIED');
        if (f.check === 'vuln') need((await card.innerText()).includes(f.cveId), 'UI_UNVERIFIED');
      }
    }
  }
  await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).waitFor({ state: 'visible' });
}
export async function geometry(page, width) {
  const value = await page.evaluate(() => ({ width: window.innerWidth, scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth, body: document.body.scrollWidth }));
  need(value.width === width && value.client === width && value.scroll <= width + 1 && value.body <= width + 1, 'GEOMETRY_UNVERIFIED');
}
export async function closeBrowser(context, browser, milliseconds = BOUNDS.closeMs) {
  let failure;
  // Always attempt BOTH closes, including when context.close rejects or stalls.
  for (const handle of [context, browser]) if (handle) {
    try { await bounded(() => handle.close(), milliseconds, () => {}); } catch (error) { failure ??= error; }
  }
  if (failure) throw failure;
}
export async function runView(options) {
  need(exact(options, ['mode', 'review']) && options.mode === 'view' && SHA.test(options.review), 'EXACT_VIEW_GO_REQUIRED');
  assertNoCaptureEnvironment(process.env);
  const guard = createGuard(); let browser, context, retained, result, error;
  try {
    result = await bounded(async () => {
      const source = toolReview(options.review); await source.check();
      need(!guard.stopped, 'DEADLINE_NO_RETRY');
      // Only explicit future coordinator execution reaches this fixed private read.
      retained = await privateSnapshot(SESSION_FILE); const storage = validateStorage(retained.value);
      need(!guard.stopped, 'DEADLINE_NO_RETRY');
      const tools = await contracts(), c = { ...await diagnosticContracts(), ...await extraContracts() };
      const { chromium } = await import('@playwright/test');
      need(!guard.stopped, 'DEADLINE_NO_RETRY');
      const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
      browser = await chromium.launch({ headless: true, timeout: 20000, env, args: [...BROWSER_ARGS] });
      if (guard.stopped) { await browser.close(); throw Error('DEADLINE_NO_RETRY'); }
      context = await browser.newContext({ storageState: storage, serviceWorkers: 'block', acceptDownloads: false,
        viewport: { width: 375, height: 960 }, reducedMotion: 'reduce' });
      if (guard.stopped) { await context.close(); await browser.close(); throw Error('DEADLINE_NO_RETRY'); }
      await installRoutes(context, guard);
      const page = await context.newPage(); page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(15000);
      page.on('pageerror', () => { guard.pageErrors++; stop(guard, Error('PAGE_ERROR')); });
      page.on('download', download => { stop(guard, Error('ROUTE_REFUSED')); void download.cancel(); });
      page.on('popup', popup => { stop(guard, Error('ROUTE_REFUSED')); void popup.close(); });
      const oldIo = await browserIo(page, tools, c, {}, async () => { throw Error('VIEW_ONLY_FENCE'); });
      // Restrict interface to reads/local disclosure and reload; no consent/save/generate methods.
      let owner;
      const checkOwner = async () => {
        const current = await page.evaluate(async () => {
          const r = await fetch('/api/v1/auth/me', { redirect: 'error', credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
          if (r.status !== 200) throw Error('OWNER_CHANGED');
          const text = await r.text(); if (text.length > 16384) throw Error('OWNER_CHANGED'); return JSON.parse(text);
        });
        const hash = fingerprint(current); need(!owner || hash === owner, 'OWNER_CHANGED'); owner = hash;
      };
      const io = { ...Object.fromEntries(['preflight', 'corpus', 'current', 'summaryRead', 'history', 'usage', 'reload'].map(k => [k, async () => {
        need(!guard.stopped, 'ROUTE_REFUSED'); return oldIo[k]();
      }])),
        viewport: async width => { need(!guard.stopped, 'ROUTE_REFUSED'); await checkOwner(); await page.setViewportSize({ width, height: 960 }); },
        visible: sample => visibleProduct(page, sample), geometry: width => geometry(page, width) };
      const proof = await verifyProduct(io, source, tools, c); await checkOwner();
      need(!guard.stopped && guard.nonGet === 0 && guard.denied === 0 && guard.pageErrors === 0, 'ROUTE_REFUSED'); return proof;
    }, BOUNDS.workMs, () => { stop(guard, Error('DEADLINE_NO_RETRY')); void context?.close().catch(() => {}); void browser?.close().catch(() => {}); });
  } catch (e) { error = e; }
  finally {
    // Quiesce before shutdown; expected cancellation of GETs during close is not
    // new evidence of successful transport. Never touch any native fence here.
    if (guard.firstFailure || guard.denied) error ??= Error(guard.firstFailure ?? 'ROUTE_REFUSED');
    guard.closing = true; guard.stopped = true;
    try { await closeBrowser(context, browser); } catch (e) { error ??= e; }
    if (retained) try {
      const after = await bounded(() => privateSnapshot(SESSION_FILE), BOUNDS.sessionCheckMs, () => {});
      need(after.byteHash === retained.byteHash, 'SESSION_CHANGED');
    } catch (e) { error ??= e; }
  }
  if (guard.nonGet || guard.pageErrors || guard.firstFailure) error ??= Error(guard.firstFailure ?? 'ROUTE_REFUSED');
  return error ? { status: 'UNVERIFIED', code: guard.firstFailure ?? failureCode(error), nativeLock: 'RETAINED_NO_DISPOSITION',
    evidenceScope: EVIDENCE_SCOPE, historicalWire: HISTORICAL_WIRE, paidRetryAuthorized: false } : { status: 'CURRENT_PRODUCT_VIEW_VERIFIED_NOT_WIRE_REPAIRED', ...result,
    network: { requests: guard.requests, denied: 0, nonGet: 0, pageErrors: 0 }, browserClosed: true, sessionFileUnchanged: true };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = modeOf(process.argv.slice(2));
    const result = options.mode === 'inert' ? { status: 'INERT_NO_BROWSER_NO_NETWORK_NO_PRIVATE_READ' } :
      options.mode === 'fingerprint' ? { review: await reviewFingerprint() } : await runView(options);
    console.log(JSON.stringify(result)); if (result.status === 'UNVERIFIED') process.exitCode = 1;
  } catch (error) { console.log(JSON.stringify({ status: 'REFUSED', code: failureCode(error) })); process.exitCode = 1; }
}
