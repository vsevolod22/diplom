// Default/import is inert. Live entry requires a completed normal app receipt,
// reviewed build/source identity and a held, freshly revalidated runtime fence.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { constants } from 'node:fs';
import { open, mkdir, realpath, lstat } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BROWSER_ARGS } from './public-product-live.mjs';
import { SCAN, MODEL, ORIGIN, BASE, QUESTION, contracts, collectVulnCorpus, policyMatches,
  readinessMatches, fingerprint, disableAutomationUi } from './native-h7v3-paid-sol.mjs';
import { REVIEW_FILES, privateSnapshot, validateStorage, initialHistory, completionPreserved,
  captureChatResponse, parseAnswer, replyProof, usageDifference, extraContracts, assertNoCaptureEnvironment,
  allowedGet, openEvidenceJournal, writeAggregate, nativeFinding } from './batch26-native-chat.mjs';
import { diagnosticContracts, captureResponseDiagnostics } from './native-h7v3-finite-diagnostics.mjs';
import { usageProjection } from './native-h7v3-recovery-7f.mjs';
import { openNativeRuntimeAuthority } from '../scripts/native-runtime-authority.mjs';
export { SCAN, MODEL, ORIGIN, BASE };
const ROOT = fileURLToPath(new URL('../', import.meta.url));
// A separately authorized future attempt only; never fall back to or reset old slots.
export const DIRECTORY = join(ROOT, 'test-results/batch31-final-native-20261104');
export const SESSION_FILE = join(ROOT, 'tests-e2e/batch25-browser-final-evidence/private-storage.json');
const need = (ok, code) => { if (!ok) throw Error(code); };
const same = (a, b) => ['scanId', 'digest', 'platform', 'reportVersion'].every(k => a?.[k] === b?.[k]);
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const TARGET_DIGEST = 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55';
export const RUN_PHASES = Object.freeze(['prepare', 'session', 'browser', 'routes', 'preflight', 'corpus', 'usage-before',
  'summary-consent', 'summary-response', 'summary-validate', 'summary-cleanup', 'summary-existing', 'summary-durable', 'summary-visible',
  'summary-accounting', 'chat-preflight', 'chat-consent', 'chat-response', 'chat-capture', 'chat-accounting', 'chat-validate', 'chat-visible',
  'reload', 'complete', 'cleanup', 'runtime-close', 'unknown']);
export const FAILURE_CODES = Object.freeze(['CORPUS_MISMATCH', 'CORPUS_PAGE_INVALID', 'CORPUS_PAGE_CHANGED', 'CORPUS_IDENTITY',
  'CORPUS_PAGE_BOUND', 'CORPUS_COUNT_CHANGED', 'CORPUS_DUPLICATE_OR_INVALID_ID', 'CORPUS_EXTRA_ROWS', 'CORPUS_CURSOR_PROGRESS', 'INCOMPLETE_CORPUS',
  'GET_BOUND', 'GET_FAILED', 'CURRENT_POLICY', 'CURRENT_POLICY_HISTORY', 'AUTOMATION_NOT_OFF', 'USAGE_UNAVAILABLE', 'ARM_REFUSED',
  'SUMMARY_BINDING', 'SUMMARY_SOURCE_UNKNOWN', 'SUMMARY_FACT_CHANGED', 'SUMMARY_LANGUAGE_OR_GROUNDING', 'SUMMARY_FAILED_NO_RETRY',
  'CURRENT_SUMMARY_MISSING_NO_FALLBACK', 'SUMMARY_NOT_DURABLE', 'SUMMARY_NOT_VISIBLE', 'SUMMARY_ACCOUNTING_UNAVAILABLE',
  'BEFORE_CHAT_CHANGED', 'CHAT_FAILED_NO_RETRY', 'CHAT_RECEIPT_ACCOUNTING', 'NATIVE_CITATION_MISMATCH', 'RUSSIAN_VALIDATION_FAILED',
  'HISTORY_CHANGED', 'CHAT_NOT_VISIBLE', 'RELOAD_OR_ROUTE_FAILED', 'RESPONSE_UNKNOWN_NO_RETRY', 'CONSENT_UI',
  'FRESH_PATH_REQUIRES_CURRENT_MISS', 'REQUEST_BOUND', 'GATE_STOPPED', 'ROUTE_REFUSED', 'REQUEST_BODY_INVALID', 'WEBSOCKET_REFUSED',
  'TRANSPORT_REFUSED_NO_RETRY', 'INTENT_UNCERTAIN_NO_RETRY', 'RUNTIME_AUTHORITY_EXPIRED', 'RUNTIME_EPOCH_CHANGED', 'RUNTIME_REFERENCE_CHANGED',
  'DEADLINE_NO_RETRY', 'PAGE_ERROR', 'SESSION_CHANGED', 'UNCLASSIFIED_FAILURE']);
export function recordFailure(log, error) {
  if (log.firstFailure) return;
  log.firstFailure = { phase: RUN_PHASES.includes(log.phase) ? log.phase : 'unknown',
    code: FAILURE_CODES.includes(error?.message) ? error.message : 'UNCLASSIFIED_FAILURE' };
}
let corpusContractsPromise;
export function corpusContracts() {
  return corpusContractsPromise ??= (async () => {
    const require = createRequire(join(ROOT, 'server/api/package.json')), manifest = require('tsx/package.json');
    const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
    const load = path => tsImport(join(ROOT, path), { parentURL: import.meta.url, tsconfig: join(ROOT, 'tsconfig.json') });
    return { ...await load('src/shared/api/scans/scanTransport.ts'), ...await load('src/shared/api/scans/publicVulnerabilityIdentifiers.ts'),
      ...await load('src/shared/api/scans/publicImageProfile.ts') };
  })();
}
export const REVIEW_SOURCE = [...new Set([...REVIEW_FILES,
  'tests-e2e/batch27-final-native.mjs', 'tests-e2e/batch27-final-native.test.mjs',
  'server/api/src/llm/history-store.ts', 'server/api/src/llm/summary-reservation.ts',
  'server/api/src/llm/llm.service.ts', 'server/api/src/llm/llm.controller.ts',
  'src/features/scans/ScanSummaryPanel.tsx', 'src/features/scans/ScanChatPanel.tsx',
  'src/shared/api/preferences/reportPreferences.ts',
  'scripts/native-runtime-authority.mjs', 'scripts/test_native_runtime_authority.mjs',
  'scripts/deploy-adapter.mjs', 'scripts/deploy-authority.mjs',
  'scripts/public-image-stand.mjs', 'scripts/public-llm-stand.mjs',
  'scripts/public-llm-source-build.mjs', 'scripts/deploy-reference-custody.mjs',
    'scripts/deploy-adapter-stores.mjs', 'scripts/deploy-core.mjs', 'scripts/deploy-supervisor.mjs',
    'scripts/public-llm-deployment-catalog.mjs',
    ...['scanTransport.ts', 'publicVulnerabilityIdentifiers.ts', 'publicImageProfile.ts', 'reportView.ts', 'vulnAdvisory.ts',
      'cveDbMetadata.ts', 'imageConfigReport.ts', 'imageFailure.ts', 'types.ts'].map(n => 'src/shared/api/scans/' + n)])].sort();
export async function reviewFingerprint() {
  const rows = [];
  for (const path of REVIEW_SOURCE) {
    const f = await open(join(ROOT, path), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { need((await f.stat()).isFile(), 'SOURCE_UNSAFE'); rows.push([path, createHash('sha256').update(await f.readFile()).digest('hex')]); }
    finally { await f.close(); }
  }
  return fingerprint(rows);
}
export function modeOf(args) {
  if (!args.length) return { mode: 'inert' };
  if (JSON.stringify(args) === '["--fingerprint"]') return { mode: 'fingerprint' };
  need(args.length === 10 && args[0] === '--run-once' && args[1] === '--ack-new-coordinator-postdeploy-go' &&
    args[2] === '--ack-paid-openai-uncapped' && args[3] === '--ack-separate-b0-b1-preservation' &&
    args[4] === '--path' && ['fresh-summary', 'existing-current-summary'].includes(args[5]) &&
    args[6] === '--deployment-id' && /^[a-f0-9]{32}$/.test(args[7]) &&
    args[8] === '--review-sha256' && HASH.test(args[9]), 'EXACT_NEW_GO_REQUIRED');
  return { mode: 'run-once', path: args[5], deployment: args[7], review: args[9] };
}
export async function spend(path, metadata) {
  // O_EXCL plus fsync before side effects. Never unlink, overwrite, or resume a spent slot.
  const f = await open(path, 'wx', 0o600);
  try { await f.writeFile(JSON.stringify({ spent: true, ...metadata })); await f.sync(); }
  finally { await f.close(); }
  const d = await open(dirname(path), constants.O_RDONLY);
  try { await d.sync(); } finally { await d.close(); }
}
export class Gate {
  constructor(persist) { this.persist = persist; this.permit = null; this.stopped = false; this.counts = { summary: 0, chat: 0 }; }
  arm(kind, context, history) {
    need(!this.stopped && !this.permit && ['summary', 'chat'].includes(kind) && this.counts[kind] === 0 &&
      policyMatches(context) && (kind !== 'chat' || initialHistory(history, context)), 'ARM_REFUSED');
    this.permit = { kind, context: structuredClone(context), old: history?.turns.map(t => t.mutationId) ?? [] };
  }
  async consume(kind, body) {
    const p = this.permit, c = p?.context;
    if (this.stopped || !p || p.kind !== kind || this.counts[kind] !== 0 ||
      !exact(body, kind === 'summary' ? ['reportVersion', 'consent'] : ['epoch', 'revision', 'mutationId', 'reportVersion', 'question', 'consent']) ||
      body.reportVersion !== c.reportVersion || !exact(body.consent, ['accepted', 'policyVersion']) ||
      body.consent.accepted !== true || body.consent.policyVersion !== c.policyVersion ||
      kind === 'chat' && (body.epoch !== c.epoch || body.revision !== c.revision || body.question !== QUESTION ||
        !UUID.test(body.mutationId ?? '') || p.old.includes(body.mutationId))) return false;
    this.permit = null; this.counts[kind]++;
    try { await this.persist(kind); } catch { this.stop(); throw Error('INTENT_UNCERTAIN_NO_RETRY'); }
    return !this.stopped;
  }
  stop() { this.stopped = true; this.permit = null; }
}
export function routePlan(url, method, redirected = false) {
  let u; try { u = new URL(url); } catch { return 'deny'; }
  if (redirected || u.origin !== ORIGIN || u.username || u.password || u.hash || u.pathname.includes('//')) return 'deny';
  if (method === 'GET') return allowedGet(url) ? 'read' : 'deny';
  if (method !== 'POST' || u.search) return 'deny';
  return u.pathname === BASE + '/llm/summary' ? 'summary' : u.pathname === BASE + '/llm/chat' ? 'chat' : 'deny';
}
export async function installRoutes(context, gate, log, publish, dispatch = async () => { throw Error('RUNTIME_AUTHORITY_UNAVAILABLE'); }) {
  await context.route('**/*', async route => {
    const r = route.request();
    const deny = async (code = 'ROUTE_REFUSED') => { recordFailure(log, Error(code)); log.denied++; gate.stop(); await route.abort().catch(() => {}); };
    if (++log.requests > 400) return deny('REQUEST_BOUND');
    if (gate.stopped) return deny('GATE_STOPPED');
    const plan = routePlan(r.url(), r.method(), !!r.redirectedFrom());
    const forward = async () => {
      let response;
      try {
        if (gate.stopped) return await deny();
        // Playwright routes only the first redirect URL. Fetch the ORIGINAL
        // request without overrides/follow/retry, then deliver only checked bytes.
        const send = () => route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: plan === 'read' ? 15000 : 150000 });
        if (plan === 'read') response = await send();
        else await dispatch(plan, async () => {
          need(!gate.stopped, 'TRANSPORT_REFUSED_NO_RETRY');
          log.dispatched++; log[plan + 'Posts']++;
          response = await send(); return response;
        });
        const status = response.status();
        need(!gate.stopped && Number.isInteger(status) && status >= 200 && status <= 599 &&
          !(status >= 300 && status < 400) && response.url() === r.url(), 'TRANSPORT_REFUSED_NO_RETRY');
        await route.fulfill({ response });
      } catch (error) { recordFailure(log, error); await deny(); }
      finally { await response?.dispose().catch(() => {}); }
    };
    if (plan === 'read') return forward();
    if (r.method() !== 'GET') log.postAttempts++;
    if (!['summary', 'chat'].includes(plan) ||
      (await r.headerValue('content-type'))?.split(';')[0] !== 'application/json' ||
      plan === 'chat' && await r.headerValue('accept') !== 'application/x-ndjson') return deny();
    let body; try { body = r.postDataJSON(); } catch { return deny('REQUEST_BODY_INVALID'); }
    try {
      if (!await gate.consume(plan, body)) return deny();
      await publish({ event: 'durable-dispatch-intent', operation: plan });
      if (gate.stopped) return deny();
      await forward();
    } catch (error) { recordFailure(log, error); await deny(); }
  });
  await context.routeWebSocket('**/*', socket => { recordFailure(log, Error('WEBSOCKET_REFUSED')); log.denied++; gate.stop(); socket.close(); });
}
export async function bounded(operation, ms, stop) {
  let timer;
  try { return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => {
    timer = setTimeout(() => { stop(); reject(Error('DEADLINE_NO_RETRY')); }, ms);
  })]); } finally { clearTimeout(timer); }
}
export async function paidUi(panel) {
  const d = panel.getByLabel('Условия OpenAI', { exact: true }); await d.waitFor({ state: 'visible' });
  const text = await d.innerText();
  need(text.includes(MODEL) && text.includes('без локального денежного лимита') &&
    text.includes('не бесплатный режим') && text.includes('ZDR'), 'PAID_UI_MISMATCH');
}
export function validateSummary(summary, context, corpus, tools) {
  const value = tools.summary.summaryReplySchema.parse(summary);
  need(same(value, context), 'SUMMARY_BINDING');
  for (const fact of value.scannerFacts) {
    const raw = corpus.get(fact.findingId); need(raw, 'SUMMARY_SOURCE_UNKNOWN');
    const row = nativeFinding(raw);
    for (const key of Object.keys(fact))
      need(Object.hasOwn(row, key) && row[key] !== undefined && fingerprint(fact[key]) === fingerprint(row[key]), 'SUMMARY_FACT_CHANGED');
  }
  for (const p of value.hypotheses) {
    const facts = value.scannerFacts.filter(f => p.citations.includes(f.findingId));
    need(!tools.language.publicReportLanguageFailure(p.text, facts) && !tools.language.remediationGroundingRejection(p.text, facts), 'SUMMARY_LANGUAGE_OR_GROUNDING');
  }
  return value;
}
// The same journey is driven by real Playwright in runOnce and synthetic adapters in tests.
export async function journey(io, gate, path, tools, c, log) {
  try {
  log.phase = 'preflight';
  const first = await io.preflight();
  need(initialHistory(first.history, first.h) && policyMatches(first.s) && policyMatches(first.h) && same(first.s, first.h) &&
    readinessMatches(first.r, first.h), 'CURRENT_POLICY_HISTORY');
  log.phase = 'corpus'; const corpus = await io.corpus();
  log.phase = 'usage-before'; const before = await io.usage(); need(before.available && same(before, first.h), 'USAGE_UNAVAILABLE');
  log.usageBefore = usageProjection(before);
  let summary;
  if (path === 'fresh-summary') {
    log.phase = 'summary-consent'; await io.paidSummary(); gate.arm('summary', first.s);
    log.phase = 'summary-response'; const response = await io.generate('summary');
    gate.permit = null;
    const observed = await captureResponseDiagnostics(response, c, io.publish);
    need(response.status() === 200, 'SUMMARY_FAILED_NO_RETRY');
    log.phase = 'summary-validate'; summary = validateSummary(JSON.parse(observed.raw), first.s, corpus, tools);
    // No reload or chat on any failed/unknown summary. Disable only local UI automation.
    log.phase = 'summary-cleanup'; await io.disableAutomation();
  } else {
    need(path === 'existing-current-summary', 'PATH_REFUSED');
    log.phase = 'summary-existing'; const result = await io.summaryRead();
    need(result.status === 200, 'CURRENT_SUMMARY_MISSING_NO_FALLBACK');
    summary = validateSummary(result.value, first.s, corpus, tools);
  }
  log.phase = 'summary-durable'; const durable = await io.summaryRead();
  need(durable.status === 200 && fingerprint(tools.summary.summaryReplySchema.parse(durable.value)) === fingerprint(summary), 'SUMMARY_NOT_DURABLE');
  log.phase = 'summary-visible'; await io.summaryVisible(summary);
  log.phase = 'summary-accounting'; const middle = await io.usage();
  log.summaryAccounting = usageDifference(before, middle);
  need(log.summaryAccounting.valid && ['user', 'scan'].every(scope =>
      ['held', 'carried'].every(group => fingerprint(before[scope][group]) === fingerprint(middle[scope][group])) &&
      ['input', 'output', 'costMicros'].every(key => Number.isSafeInteger(middle[scope].used[key] - before[scope].used[key]) &&
        middle[scope].used[key] >= before[scope].used[key])), 'SUMMARY_ACCOUNTING_UNAVAILABLE');
  // Summary wire has no receipt. Record aggregate delta honestly, never invent a receipt or zero liability.
  log.summaryAccounting.receipt = 'NOT_EXPOSED_BY_SUMMARY_DTO';
  log.phase = 'chat-preflight'; const fresh = await io.current(), history = await io.history();
  need(fingerprint(history) === fingerprint(first.history) && fingerprint(fresh.h) === fingerprint(first.h) &&
    fingerprint(fresh.s) === fingerprint(first.s) && readinessMatches(fresh.r, fresh.h), 'BEFORE_CHAT_CHANGED');
  log.phase = 'chat-consent'; await io.paidChat(); gate.arm('chat', fresh.h, history);
  log.phase = 'chat-response'; const response = await io.generate('chat'); gate.permit = null;
  const mutation = response.request().postDataJSON().mutationId;
  log.phase = 'chat-capture'; const captured = await captureChatResponse(response, c, fresh.h, mutation, io.publish);
  log.phase = 'chat-accounting'; const afterUsage = await io.usage(), after = await io.history();
  log.usageAfter = usageProjection(afterUsage);
  log.chatAccounting = usageDifference(middle, afterUsage, captured.diagnostics.currentUsageReceipt);
  need(response.status() === 200 && !captured.diagnostics.currentTerminal, 'CHAT_FAILED_NO_RETRY');
  log.phase = 'chat-validate'; const answer = parseAnswer(captured.raw, c, fresh.h, mutation);
  need(captured.diagnostics.currentReceiptCaptured && fingerprint(answer.usage) === fingerprint(captured.diagnostics.currentUsageReceipt) &&
    log.chatAccounting.valid && log.chatAccounting.receiptMatched !== false, 'CHAT_RECEIPT_ACCOUNTING');
  log.reply = replyProof(answer, corpus, c, tools);
  need(completionPreserved(first.history, after, answer), 'HISTORY_CHANGED');
  log.phase = 'chat-visible'; await io.chatVisible(answer);
  log.phase = 'reload'; const count = log.postAttempts;
  await io.reload();
  const reloaded = await io.history(), restoredSummary = await io.summaryRead();
  need(fingerprint(reloaded) === fingerprint(after) && restoredSummary.status === 200 &&
    fingerprint(tools.summary.summaryReplySchema.parse(restoredSummary.value)) === fingerprint(summary) &&
    log.postAttempts === count && log.denied === 0 && log.pageErrors === 0 &&
    log.summaryPosts === (path === 'fresh-summary' ? 1 : 0) && log.chatPosts === 1, 'RELOAD_OR_ROUTE_FAILED');
  await io.chatVisible(answer); await io.summaryVisible(summary);
  log.status = 'NATIVE_WIRE_HISTORY_RELOAD_VERIFIED_SEMANTICS_PENDING';
  log.reload = { repeatedPosts: 0, exactSummary: true, exactHistory: true, priorTwoFailedUnchanged: true };
  log.summaryHash = fingerprint(summary); log.historyHash = fingerprint(after);
  log.preservation = 'B0_B1_SEPARATE_COORDINATOR_EVIDENCE_NOT_MEASURED_HERE';
  log.summaryStorage = 'NORMAL_SAME_OWNER_SCAN_REPLACEMENT_NOT_OLD_POLICY_ROW_RETENTION';
  log.unknownHistoricalLiabilities = 'PRESERVED_NOT_REFUNDED_OR_PROVEN_ZERO';
  log.phase = 'complete';
  } catch (error) { recordFailure(log, error); throw error; }
}
export async function browserIo(page, tools, c, log, publish) {
  let gets = 0;
  const read = async suffix => {
    need(++gets <= 44, 'GET_BOUND');
    return page.evaluate(async path => {
      const r = await fetch(path, { signal: AbortSignal.timeout(15000), redirect: 'error', cache: 'no-store', credentials: 'same-origin' });
      const text = await r.text(); if (new TextEncoder().encode(text).length > 1048576) throw Error('GET_BOUND');
      return { status: r.status, value: JSON.parse(text) };
    }, BASE + suffix);
  };
  const get = async suffix => { const r = await read(suffix); need(r.status === 200, 'GET_FAILED'); return r.value; };
  const current = async () => {
    const s = tools.summary.summaryContextSchema.parse(await get('/llm/context')),
      h = c.chat.chatContextSchema.parse(await get('/llm/chat/context')),
      r = c.chat.chatReadinessSchema.parse(await get('/llm/readiness'));
    need(s.scanId === SCAN && s.digest === TARGET_DIGEST &&
      policyMatches(s) && policyMatches(h) && same(s, h) && !h.pending, 'CURRENT_POLICY');
    return { s, h, r };
  };
  const summaryPanel = () => page.locator('.scan-a1__ai');
  const chatPanel = () => page.getByRole('region', { name: 'Чат по отчёту', exact: true });
  return {
    publish, current, summaryRead: () => read('/llm/summary'),
    history: async () => c.chat.chatHistorySchema.parse(await get('/llm/history')),
    usage: async () => c.usage.parse(await get('/llm/usage')),
    async preflight() {
      await page.goto(ORIGIN + '/account');
      const details = page.locator('details.demo-auth__preferences'); await details.waitFor({ state: 'visible' });
      if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
      const prefs = details.getByRole('region', { name: 'Настройки отчётов', exact: true });
      need(await prefs.getByLabel('ИИ-разбор', { exact: true }).inputValue() === 'off' &&
        await prefs.getByLabel('Язык исходных описаний уязвимостей', { exact: true }).inputValue() === 'original', 'AUTOMATION_NOT_OFF');
      await page.goto(`${ORIGIN}/scans/${SCAN}`); await page.locator('.scan-report-overview').waitFor();
      return { ...await current(), history: c.chat.chatHistorySchema.parse(await get('/llm/history')) };
    },
    async corpus() {
      const snapshot = await get('');
      need(snapshot.state === 'completed' && snapshot.perCheck?.secret?.findingCount === 0 && snapshot.perCheck?.vuln?.findingCount === 440, 'CORPUS_MISMATCH');
      const corpus = new Map((snapshot.config?.findings ?? []).map(f => [f.findingId, f]));
      const parsers = await corpusContracts(); let identity;
      const native = await collectVulnCorpus(async suffix => {
        const raw = await get(suffix); let page;
        try { page = parsers.parseCurrentVuln(raw); } catch { throw Error('CORPUS_PAGE_INVALID'); }
        need(page.outcome === 'checked' && page.profile === parsers.PUBLIC_IMAGE_PROFILE && page.platform === 'linux/amd64' &&
          page.image.endsWith('@' + TARGET_DIGEST), 'CORPUS_IDENTITY');
        const { findings, nextCursor, ...metadata } = page, currentIdentity = fingerprint(metadata);
        if (identity !== undefined) need(identity === currentIdentity, 'CORPUS_PAGE_CHANGED');
        identity = currentIdentity;
        return { ...page, nextCursor: nextCursor === null ? null : Number(nextCursor), findings: findings.map(row => {
          const kind = parsers.vulnerabilityIdentifierKind(row.cveId);
          need(kind && parsers.validVulnerabilityId(row.cveId, row.ecosystem, page.profile), 'CORPUS_MISMATCH');
          return { ...row, check: 'vuln', identifierKind: kind };
        }) };
      }, 440), counts = { cve: 0, 'debian-temp': 0, 'debian-dla': 0 };
      for (const [id, f] of native.findings) { need(!corpus.has(id), 'CORPUS_DUPLICATE_OR_INVALID_ID'); counts[f.identifierKind]++; corpus.set(id, f); }
      need(counts.cve === 431 && counts['debian-temp'] === 6 && counts['debian-dla'] === 3, 'CORPUS_MISMATCH');
      log.corpus = { vulnerabilities: 440, identifiers: counts, pages: native.pages }; return corpus;
    },
    async paidSummary() {
      await paidUi(summaryPanel());
      need((await summaryPanel().locator('#scan-summary-send-help').innerText()).includes('Старое бесплатное согласие не применяется'), 'CONSENT_UI');
      // Current-policy miss is expected, but NEVER automatically authorizes generation.
      const existing = await read('/llm/summary');
      need(existing.status === 404 && exact(existing.value, ['errorCode']) && existing.value.errorCode === 'LLM_SUMMARY_MISSING', 'FRESH_PATH_REQUIRES_CURRENT_MISS');
    },
    async paidChat() {
      await paidUi(chatPanel()); need((await chatPanel().locator('#scan-chat-send-help').innerText()).includes('платный запрос OpenAI'), 'CONSENT_UI');
      await chatPanel().getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(QUESTION);
    },
    async generate(kind) {
      const pending = page.waitForResponse(r => r.request().method() === 'POST' && r.url() === ORIGIN + BASE + '/llm/' + kind, { timeout: 150000 });
      // Attach rejection immediately; click failure or deadline never creates a retry.
      const response = pending.catch(() => null);
      await (kind === 'summary' ? summaryPanel().getByRole('button', { name: 'Включить платный авторазбор OpenAI', exact: true }) :
        chatPanel().getByRole('button', { name: 'Отправить вопрос', exact: true })).click();
      const result = await response; need(result, 'RESPONSE_UNKNOWN_NO_RETRY'); return result;
    },
    async disableAutomation() { await disableAutomationUi(page); await page.goto(`${ORIGIN}/scans/${SCAN}`); await page.locator('.scan-report-overview').waitFor(); },
    async summaryVisible(summary) {
      const output = page.getByLabel('ИИ-разбор отчёта', { exact: true }); await output.waitFor({ state: 'visible' });
      const details = output.locator('details.scan-summary-explanation');
      if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
      const text = await output.innerText(); need(summary.hypotheses.every(p => text.includes(p.text)), 'SUMMARY_NOT_VISIBLE');
    },
    async chatVisible(answer) {
      await chatPanel().getByRole('heading', { name: 'Ответ · проверьте по источникам', exact: true }).waitFor({ state: 'visible' });
      need((await chatPanel().innerText()).includes(answer.reply.text), 'CHAT_NOT_VISIBLE');
    },
    async reload() { await page.reload(); await page.locator('.scan-report-overview').waitFor(); },
  };
}
export async function closeRuntimeFence(authority, log) {
  log.phase = 'runtime-close';
  try {
    const disposition = await authority.close(log.status !== 'BLOCKED_OR_PARTIAL');
    log.runtimeFenceReleased = disposition.released;
  } catch (error) {
    recordFailure(log, error); log.status = 'BLOCKED_OR_PARTIAL'; log.runtimeFenceReleased = false;
    log.failure = 'NO_RETRY_REQUIRES_NEW_COORDINATOR_DISPOSITION';
  }
}
async function requireRuntimeAuthority(options) {
  return openNativeRuntimeAuthority({ deployment: options.deployment, review: options.review, origin: ORIGIN }, reviewFingerprint);
}
export async function runOnce(options) {
  // Serialized caller assertions or alternative authority/transport factories are not inputs.
  need(exact(options, ['mode', 'path', 'review', 'deployment']) && options.mode === 'run-once' && ['fresh-summary', 'existing-current-summary'].includes(options.path) &&
    HASH.test(options.review) && /^[a-f0-9]{32}$/.test(options.deployment), 'EXACT_NEW_GO_REQUIRED');
  assertNoCaptureEnvironment(process.env);
  const authority = await requireRuntimeAuthority(options);
  try {
  need(await reviewFingerprint() === options.review, 'SOURCE_CHANGED');
  process.umask(0o077); await mkdir(DIRECTORY, { recursive: true, mode: 0o700 });
  const stat = await lstat(DIRECTORY);
  need(await realpath(DIRECTORY) === DIRECTORY && stat.isDirectory() && (stat.mode & 0o077) === 0 && stat.uid === process.getuid(), 'DIRECTORY_UNSAFE');
  await spend(join(DIRECTORY, 'attempt.spent.json'), { deployment: options.deployment, review: options.review, path: options.path });
  // Fixed retained session is read ONLY here, after explicit CLI GO and irreversible spend.
  let browser, context, events, sessionHash;
  const log = { status: 'BLOCKED_OR_PARTIAL', requests: 0, postAttempts: 0, dispatched: 0, summaryPosts: 0, chatPosts: 0,
    denied: 0, pageErrors: 0, phase: 'prepare', deployment: options.deployment, review: options.review, path: options.path, liveExecuted: false, runtimeQualification: authority.qualification };
  const gate = new Gate(kind => spend(join(DIRECTORY, kind + '.spent.json'), { operation: kind }));
  try {
    events = await openEvidenceJournal(join(DIRECTORY, 'diagnostics.ndjson'));
    log.phase = 'session'; const retained = await privateSnapshot(SESSION_FILE); sessionHash = retained.byteHash;
    const storage = validateStorage(retained.value), tools = await contracts(), c = { ...await diagnosticContracts(), ...await extraContracts() };
    log.phase = 'browser'; const { chromium } = await import('@playwright/test');
    const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
    browser = await chromium.launch({ headless: true, timeout: 20000, env, args: [...BROWSER_ARGS] });
    context = await browser.newContext({ storageState: storage, serviceWorkers: 'block', acceptDownloads: false, viewport: { width: 1280, height: 960 }, reducedMotion: 'reduce' });
    log.phase = 'routes'; await installRoutes(context, gate, log, value => events.publish(value), authority.dispatch);
    const page = await context.newPage(); page.setDefaultTimeout(20000); page.setDefaultNavigationTimeout(20000);
    page.on('pageerror', () => { recordFailure(log, Error('PAGE_ERROR')); log.pageErrors++; gate.stop(); });
    const io = await browserIo(page, tools, c, log, value => events.publish(value));
    log.liveExecuted = true;
    await bounded(() => journey(io, gate, options.path, tools, c, log), 360000, () => { recordFailure(log, Error('DEADLINE_NO_RETRY')); gate.stop(); void context.close().catch(() => {}); });
  } catch (error) { recordFailure(log, error); log.status = 'BLOCKED_OR_PARTIAL'; log.failure = 'NO_RETRY_REQUIRES_NEW_COORDINATOR_DISPOSITION'; }
  finally {
    log.phase = 'cleanup'; gate.stop(); await context?.close().catch(() => {}); await browser?.close().catch(() => {});
    log.browserClosed = true;
    if (sessionHash) {
      try { log.retainedSessionUnchanged = (await privateSnapshot(SESSION_FILE)).byteHash === sessionHash; }
      catch { log.retainedSessionUnchanged = false; }
      if (!log.retainedSessionUnchanged) { recordFailure(log, Error('SESSION_CHANGED')); log.status = 'BLOCKED_OR_PARTIAL'; }
    }
    try { await events?.close(); } catch (error) { recordFailure(log, error); }
    if (log.firstFailure || log.denied || log.pageErrors) log.status = 'BLOCKED_OR_PARTIAL';
    // Keep a durable pre-release result, but never overwrite an append-only file.
    await writeAggregate(join(DIRECTORY, 'journey-aggregate.json'), log);
  }
  // Only a dispatched/uncertain journey retains a diagnosable operator fence.
  // A side-effect-free refusal releases its own known admission, never old HOLDs
  // or spent markers, and never changes accounting or authorizes another attempt.
  await closeRuntimeFence(authority, log);
  // Append-only aggregate is created ONCE, after the owned-fence disposition.
  await writeAggregate(join(DIRECTORY, 'aggregate.json'), log);
  return log;
  } catch (error) { await authority.close(false).catch(() => {}); throw error; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = modeOf(process.argv.slice(2));
    if (options.mode === 'inert') console.log('INERT_NO_PRIVATE_READS_NO_BROWSER_NO_NETWORK');
    else if (options.mode === 'fingerprint') console.log(await reviewFingerprint());
    else { const log = await runOnce(options); console.log(JSON.stringify(log)); if (log.status === 'BLOCKED_OR_PARTIAL') process.exitCode = 1; }
  } catch (error) {
    console.log(error?.message === 'RUNTIME_AUTHORITY_UNAVAILABLE' ? 'REFUSED_RUNTIME_AUTHORITY_UNAVAILABLE' : 'REFUSED_NO_RETRY');
    process.exitCode = 1;
  }
}
