// PREPARED ONLY: no browser/runtime/provider contact without coordinator READYGO.
// Offline: node --test tests-e2e/public-automation-live.test.mjs
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { lstat, open, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  ORIGIN, CHECKS, TARGETS, SCANS, WORKER_MS, BROWSER_ARGS, fixedUrl, safeReadRequest,
  allowedApiGet, safeMutationRequest, consumePermit, validIntent, eligibilityReady,
  EligibilityFence, awaitEligibility, awaitStableUiEligibility, readLaunchForm, uiLaunchReady,
  assertAuthUser, assertDeniedReply, assertChatUsage, readAllPages, partition,
  trackBrowserReadPage, readBrowserJson, settleAuthNavigation, runtimeProbeRead, assertRuntimeOffReply, BrowserReadError,
} from './public-product-live.mjs';
import {
  GLOBAL_MS, MODEL, ENDPOINT, GuardLedger, guardAbortReason, projectMeta, diagnosticFromHeaders,
  llmFailureMeta, assertLlmSuccess, assertFixedPolicy, assertReady, chatBodyMatches, translationBody,
  eligibleAssessment, renderedReplyMatches, historyMetadata, loadTranslationContracts,
  settleAcceptedScan, completeFreshOwnerLogin, Fault as BaseFault,
} from './public-ai-translation-live.mjs';

export { GLOBAL_MS, WORKER_MS };
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);
const QUESTIONS = ['Кратко назови одно ограничение покрытия отчёта.', 'Кратко укажи один безопасный следующий шаг проверки.'];
export const CASES = Object.freeze(['tooling', 'owner_registration', 'preferences_original', 'native_scan',
  'estimate', 'coverage_click', 'report', 'always_open_chat', 'summary_initial_missing', 'summary', 'chat_1', 'chat_2',
  'history_reload', 'summary_reload_no_post', 'summary_reload_restore', 'preferences_ru',
  'translation', 'translation_toggle', 'preferences_fresh_context', 'fresh_login', 'history_fresh_login', 'summary_fresh_login_restore',
  'anonymous_denial', 'settings_owner_isolation', 'preservation', 'safety']);
const CODES = new Set(['NOT_RUN', 'VERIFIED', 'INVALID_ARGUMENTS', 'EVIDENCE_ALREADY_EXISTS', 'EVIDENCE_WRITE_FAILED',
  'NOT_ACTUALLY_RUN', 'UNSAFE_DEBUG_ENVIRONMENT', 'BROWSER_UNAVAILABLE', 'PREREQUISITE_UNAVAILABLE',
  'REQUEST_GUARD', 'GLOBAL_DEADLINE', 'INTERRUPTED', 'ASSERTION_FAILED', 'LLM_HTTP_ERROR',
  'DELIVERY_UNCONFIRMED_NO_RETRY', 'LAUNCH_UNCONFIRMED_NO_RETRY', 'WORKER_DEADLINE_NO_RELAUNCH',
  'REQUIRED_CHECK_NOT_CHECKED', 'UI_NOT_DEPLOYED', 'READINESS_BLOCKED', 'RUNTIME_NOT_OFF', 'PAGE_ERRORS',
  'CLEANUP_FAILED', 'BROWSER_READ_FAILED', 'SUMMARY_NOT_RESTORED', 'SECOND_OWNER_NOT_AUTHORIZED',
  'NO_ELIGIBLE_ASSESSMENT', 'PROVIDER_STOP_NO_RETRY', 'CONTEXT_CHANGED', 'SUMMARY_READ_FAILED']);
export const FAILURE_PREDICATES = Object.freeze(['vuln-http-status', 'vuln-decode', 'vuln-target-image', 'vuln-target-platform',
  'vuln-profile', 'vuln-outcome', 'vuln-scanner-version', 'vuln-checked-at', 'vuln-identifiers',
  'secret-http-status', 'secret-decode', 'secret-outcome', 'secret-count', 'secret-scanner-version', 'secret-checked-at',
  'secret-decoded-coverage', 'report-partition']);
export const SUMMARY_DRAIN_MS = 45_000;
export function automationMeta(input = {}) {
  const out = projectMeta(input);
  if (!Number.isInteger(out.runnerLine) || out.runnerLine < 1 || out.runnerLine > 100_000) delete out.runnerLine;
  if (FAILURE_PREDICATES.includes(input.predicate)) out.predicate = input.predicate;
  return out;
}
export function failureMetadata(error) {
  const line = error?.stack?.match(/^\s+at [^\n]*\/public-automation-live\.mjs:([0-9]+):[0-9]+(?:\)|$)/m);
  return automationMeta({ ...error?.meta, ...(line ? { runnerLine: Number(line[1]) } : {}) });
}
export class Fault extends BaseFault {
  constructor(code, meta = {}, failure = false) {
      super(code, meta, failure); this.meta = automationMeta(meta); Error.captureStackTrace(this, Fault);
    }
}
export function checkPredicate(condition, predicate) {
  assert.ok(FAILURE_PREDICATES.includes(predicate));
  if (condition) return;
  const error = new Fault('ASSERTION_FAILED', { predicate }, true);
  Error.captureStackTrace(error, checkPredicate);
  throw error;
}
// The Secrets wire contract has coverage, not top-level image/platform. Preserve
// its own scanner/count/stamp fences rather than inventing an image field.
export function parseBoundReport(kind, wire, snapshot, query, cursor, decoder) {
  assert.ok(['secret', 'vuln'].includes(kind));
  let value;
  try { value = kind === 'secret' ? decoder.parseCurrentResults(wire, query, cursor) : decoder.parseCurrentVuln(wire, query, cursor); }
  catch { checkPredicate(false, `${kind}-decode`); }
  const expected = snapshot.perCheck?.[kind];
  if (kind === 'secret') {
    const coverage = wire?.coverage, decoded = value.coverage.find(item => item.check === 'Secrets');
    checkPredicate(coverage?.check === 'secret' && coverage.coverage === 'image' && coverage.outcome === 'checked' && coverage.errorCode === null && expected?.outcome === 'checked', 'secret-outcome');
    checkPredicate(coverage.findingCount === expected.findingCount, 'secret-count');
    checkPredicate(coverage.scannerVersion === expected.scannerVersion, 'secret-scanner-version');
    checkPredicate(coverage.checkedAt === expected.checkedAt, 'secret-checked-at');
    checkPredicate(decoded?.status === 'checked' && decoded.findingCount === expected.findingCount &&
      decoded.scannerVersion === expected.scannerVersion && decoded.checkedAt === expected.checkedAt, 'secret-decoded-coverage');
  } else {
    checkPredicate(value.image === snapshot.imageReference, 'vuln-target-image');
    checkPredicate(value.platform === snapshot.platform, 'vuln-target-platform');
    checkPredicate(value.profile === snapshot.profile, 'vuln-profile');
    checkPredicate(value.outcome === 'checked' && expected?.outcome === 'checked', 'vuln-outcome');
    checkPredicate(value.scannerVersion === expected.scannerVersion, 'vuln-scanner-version');
    checkPredicate(value.checkedAt === expected.checkedAt, 'vuln-checked-at');
    checkPredicate(isDeepStrictEqual(value.identifierCounts, snapshot.identifierCounts), 'vuln-identifiers');
  }
  return value;
}
const SUMMARY_CAPTURES = new Set(['NOT_ADMITTED', 'NOT_CAPTURED', 'RESPONSE_RECEIVED', 'ERROR_CAPTURED', 'DELIVERY_UNKNOWN']);
export function summaryObservationMeta(input = {}) {
  return { admitted: input.admitted === true, consumption: 'UNKNOWN',
    capture: SUMMARY_CAPTURES.has(input.capture) ? input.capture : 'NOT_CAPTURED',
    ...(CODES.has(input.code) ? { code: input.code } : {}), ...automationMeta(input) };
}
// Only observe a promise already installed by the guarded POST handler. There is
// no page/client/request/permit argument, so cleanup cannot initiate a retry or GET.
export async function collectAdmittedSummary(book, gate, pending, timeoutMs = SUMMARY_DRAIN_MS) {
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 0 && timeoutMs <= SUMMARY_DRAIN_MS);
  const admitted = gate.counts.summary === 1;
  if (!admitted || !pending || typeof pending.then !== 'function') {
    book.summaryObservation = summaryObservationMeta({ admitted, capture: admitted ? 'DELIVERY_UNKNOWN' : 'NOT_ADMITTED' });
    return;
  }
  try {
    await bounded(pending, timeoutMs);
    book.summaryObservation = summaryObservationMeta({ admitted, capture: 'RESPONSE_RECEIVED', httpStatus: 200 });
  } catch (error) {
    const meta = failureMetadata(error);
    book.summaryObservation = summaryObservationMeta({ admitted, capture: meta.httpStatus ? 'ERROR_CAPTURED' : 'DELIVERY_UNKNOWN',
      code: CODES.has(error?.message) ? error.message : 'DELIVERY_UNCONFIRMED_NO_RETRY', ...meta });
  }
  // A received response is NOT a summary qualification or a verified consumption
  // receipt. Leave every case (especially the first FAIL) unchanged.
}
export function parseMode(args) {
  if (!args.length) return 'not-run';
  if (isDeepStrictEqual(args, ['--preflight'])) return 'offline';
  if (args.length === 6 && isDeepStrictEqual(args.slice(0, 4),
    ['--run', '--ack-coordinator-readygo', '--ack-four-generation-posts', '--ack-source-deployed']) &&
    args[4] === '--attempt-id' && UUID.test(args[5])) return 'live';
  throw new Fault('INVALID_ARGUMENTS');
}
export function assertFreshAttempt(id, filenames) {
  evidencePaths(id);
  if (filenames.some(name => name.includes(id))) throw new Fault('EVIDENCE_ALREADY_EXISTS');
}
export function browserGetAllowed(input, ids) {
  if (!fixedUrl(input)) return false;
  const url = new URL(input);
  if (url.pathname.startsWith('/api/')) return allowedApiGet(input, ids);
  return !url.search && (['/', '/account', '/login', '/register', '/scans', '/scans/new', '/favicon.ico'].includes(url.pathname) ||
    [...ids].some(id => UUID.test(id) && url.pathname === `/scans/${id}`) ||
    /^\/assets\/[A-Za-z0-9._-]+\.(?:js|css|svg|png|webp|woff2?)$/.test(url.pathname));
}
export function evidencePaths(id) {
  if (!UUID.test(id)) throw new Fault('INVALID_ARGUMENTS');
  return ['json', 'md'].map(ext => join(ROOT, `docs/public-automation-${id}.${ext}`));
}
export function generationMetadata(gate) {
  const out = {};
  for (const [key, value] of Object.entries({ total: gate?.total, summaryPosts: gate?.counts?.summary,
    chatPosts: gate?.counts?.chat, translationPosts: gate?.counts?.translation }))
    if (Number.isSafeInteger(value) && value >= 0 && value <= 10_000_000) out[key] = value;
  if (typeof gate?.halted === 'boolean') out.halted = gate.halted;
  return out;
}
export class ResultBook {
  constructor(id) {
    evidencePaths(id); this.id = id; this.runId = randomUUID(); this.actual = false;
    this.startedAt = new Date().toISOString(); this.finishedAt = null; this.guard = new GuardLedger(); this.passiveSummaryReads = 0;
    this.cases = Object.fromEntries(CASES.map(name => [name, { status: 'BLOCKED', code: 'NOT_RUN' }]));
  }
  record(name, status, code = 'VERIFIED', meta = {}) {
    assert.ok(CASES.includes(name) && ['PASS', 'FAIL', 'BLOCKED'].includes(status) && CODES.has(code));
    if (this.cases[name].status !== 'FAIL') this.cases[name] = { status, code, ...automationMeta(meta) };
  }
  recordScanReceipt(status, value) {
    assert.ok(status === 202 && UUID.test(value?.scanId));
    assert.ok(!this.scanReceipt || this.scanReceipt.scanId === value.scanId);
    this.scanReceipt = { scanId: value.scanId, launchHttpStatus: 202, receiptAccepted: true };
    return value.scanId;
  }
  evidence() {
    return { schemaVersion: 1, scope: 'native-public8081-report-automation', attemptId: this.id,
      runId: this.runId, origin: ORIGIN, actuallyRun: this.actual, startedAt: this.startedAt, finishedAt: this.finishedAt,
      ...(this.scanReceipt ? { scanReceipt: projectMeta(this.scanReceipt) } : {}), guard: this.guard.evidence(),
      maxAccounts: 1, maxScans: 1, maxGenerationPosts: 4, requiredChecks: [...CHECKS],
            generationAdmissions: generationMetadata(this.generation), requiredCases: [...CASES],
                  passiveSummaryReads: Number.isSafeInteger(this.passiveSummaryReads) && this.passiveSummaryReads >= 0 && this.passiveSummaryReads <= 1000 ? this.passiveSummaryReads : 0,
                  summaryRetention: 'process-lifetime-not-durable',
                        admittedSummaryObservation: summaryObservationMeta(this.summaryObservation ?? {
                          admitted: this.generation?.counts?.summary === 1, capture: this.generation?.counts?.summary === 1 ? 'NOT_CAPTURED' : 'NOT_ADMITTED' }),
      policy: { model: MODEL, endpoint: ENDPOINT, freeOnly: true, noFallback: true },
      serverEgressIndependentlyObserved: false, billingIndependentlyVerified: false,
      semanticAccuracy: 'unverified-requires-memory-only-human-review',
      ownershipScope: 'fresh-owner-login-and-anonymous-denial-not-foreign-owner',
      preferenceScope: 'same-owner-browser-local-and-empty-context-not-foreign-owner',
      payloadArtifacts: false, credentialsPersisted: false, screenshots: false, har: false, storageState: false,
      createdRuntimeDataAutomaticallyDeleted: false,
      cases: Object.fromEntries(CASES.map(name => [name, { status: this.cases[name].status,
        code: this.cases[name].code, ...automationMeta(this.cases[name]) }])) };
  }
}
export function exitCode(book) {
  return CASES.some(name => book.cases[name].status === 'FAIL') ? 1 :
    CASES.every(name => book.cases[name].status === 'PASS') ? 0 : 2;
}
export function evidenceDocuments(book) {
  const value = book.evidence();
  return [JSON.stringify(value, null, 2) + '\n', ['# Native public automation qualification — 2026-10-26', '',
    `Attempt: ${book.id}. Actually run: ${book.actual}. Origin: ${ORIGIN}.`,
    'Maximum one disposable account, one native Node four-check scan, four generation POSTs. No retries/fallback.',
    'Metadata only: no answers, selected source text, conversations, credentials, screenshots, HAR or storage state.',
    'Already-admitted summary transport may be observed during bounded cleanup; consumption remains UNKNOWN and this cannot qualify a failed/skipped case.',
    `Already-admitted summary capture: ${value.admittedSummaryObservation.capture}; consumption: UNKNOWN.`,
    'Russian/schema/citation checks do not establish semantic accuracy or translation fidelity. Review only in memory.',
    'No foreign-owner isolation claim: only one account is authorized. Summary reload/fresh-login restoration requires passive GET, never another POST.',
    'Source changes and offline tests are not deployment or live acceptance; 412 remains the stand source until coordinator deployment.',
    '', '| Case | Result | Code |', '| --- | --- | --- |',
    ...CASES.map(name => `| ${name} | ${value.cases[name].status} | ${value.cases[name].code} |`), ''].join('\n')];
}
export async function writeEvidence(book, openFile = open) {
  if (!book.actual) throw new Fault('NOT_ACTUALLY_RUN');
  const handles = [], documents = evidenceDocuments(book);
  try {
    for (const path of evidencePaths(book.id)) handles.push(await openFile(path, 'wx', 0o600));
    for (const index of [1, 0]) { await handles[index].writeFile(documents[index]); await handles[index].sync(); }
  } finally { await Promise.all(handles.map(handle => handle.close())); }
}
export function summaryBody(context) {
  return { reportVersion: context.reportVersion, consent: { accepted: true, policyVersion: context.policyVersion } };
}
export function automationDisclosureMatches(disclosure, kind) {
  if (!['summary', 'translation'].includes(kind)) return false;
  const expected = { provider: 'OpenRouter', model: MODEL, providers: [ENDPOINT], region: 'global', retention: 'no-storage',
    operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, requestBudgetUsd: 0, freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 }, data: kind === 'summary'
      ? 'Sanitized scanner findings and coverage; no raw evidence or credentials.'
      : 'Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.',
    ...(kind === 'translation' ? { targetLanguage: 'ru', machineTranslation: true, automaticDispatch: 'account-preference', persistentTranslationCache: false } : {}) };
  return isDeepStrictEqual(disclosure, expected);
}
export function summaryMissing(result) {
  return result?.status === 404 && exact(result.value, ['errorCode']) && result.value.errorCode === 'LLM_SUMMARY_MISSING';
}
export function passiveSummaryValue(result, context) {
  const headers = result?.headers ?? {};
  // The API and exact nginx location both add no-store. Accept only repetitions
  // of that directive, never public/max-age or arbitrary cache policy tokens.
  const controls = typeof headers['cache-control'] === 'string' ? headers['cache-control'].split(',').map(value => value.trim().toLowerCase()) : [];
  if (!controls.length || !controls.every(value => value === 'no-store') || !/^application\/json(?:;|$)/i.test(headers['content-type'] ?? ''))
    throw new Fault('SUMMARY_READ_FAILED', { httpStatus: result?.status });
  if (summaryMissing(result)) return null;
  if (result?.status !== 200) throw new Fault('SUMMARY_READ_FAILED', llmFailureMeta(result?.status, result?.value, 'http-error'));
  assertFixedPolicy(context);
  if (headers['x-llm-summary-retention'] !== 'process-lifetime' || result.value?.errorCode || !automationDisclosureMatches(context.disclosure, 'summary'))
    throw new Fault('SUMMARY_READ_FAILED', { httpStatus: result.status });
  for (const key of ['scanId', 'digest', 'platform', 'reportVersion'])
    if (result.value?.[key] !== context[key]) throw new Fault('CONTEXT_CHANGED');
  return result.value;
}
export function assertSummaryRestored(result, context, generated) {
  const value = passiveSummaryValue(result, context);
  if (value === null) throw new Fault('SUMMARY_NOT_RESTORED', { httpStatus: 404, errorCode: 'LLM_SUMMARY_MISSING', noAdditionalPosts: true });
  assert.deepEqual(value, generated); // Same retained enriched DTO, not a cache wrapper or regenerated answer.
  return value;
}
// Exact operation paths; GET on the summary path is passive, never generation.
export function generationKind(path, scanId, method = 'POST') {
  if (method !== 'POST' || !UUID.test(scanId)) return undefined;
  return ({ [`${SCANS}/${scanId}/llm/summary`]: 'summary', [`${SCANS}/${scanId}/llm/chat`]: 'chat',
    [`${SCANS}/${scanId}/llm/translation`]: 'translation' })[path];
}
export class GenerationGate {
  constructor() { this.counts = { summary: 0, chat: 0, translation: 0 }; this.total = 0; this.busy = false; this.halted = false; this.chatSuccesses = 0; }
  admit({ owner, path, scanId, body, permit, context, completed, report, preferences, readiness, passiveSummary }) {
    const kind = generationKind(path, scanId);
    if (!kind || !owner || this.halted || this.busy || this.total >= 4 || !permit || permit.used ||
      permit.path !== path || permit.kind !== kind || !completed || !context || context.scanId !== scanId ||
            report?.scanId !== scanId || report.state !== 'completed' || !CHECKS.every(check => report.perCheck?.[check]?.outcome === 'checked') ||
            context.digest !== report.digest || context.platform !== report.platform || !/^[a-f0-9]{64}$/.test(context.reportVersion ?? '')) return false;
    try { assertReady(readiness, context); } catch { return false; }
    if (readiness.provider.status !== 'catalog-listed-unprobed') return false;
    if (kind !== 'chat' && !automationDisclosureMatches(context.disclosure, kind)) return false;
    if (kind === 'summary') {
      try { if (!summaryMissing(passiveSummary) || passiveSummaryValue(passiveSummary, context) !== null) return false; }
      catch { return false; }
    }
    const allowed = kind === 'summary' ? this.counts.summary === 0 && summaryMissing(passiveSummary) && preferences?.language === 'original' &&
      preferences.autoSummary === true && isDeepStrictEqual(body, summaryBody(context)) :
      kind === 'chat' ? this.counts.chat < 2 && this.counts.chat === this.chatSuccesses &&
        chatBodyMatches(body, context, permit.question) : this.counts.translation === 0 &&
        preferences?.language === 'ru' && isDeepStrictEqual(body, translationBody(context));
    if (!allowed || !consumePermit(permit, 'POST', path, body)) return false;
    this.counts[kind]++; this.total++; this.busy = true; return true;
  }
  observe(status, value) {
    // Fail closed even if a malformed providerFailure cannot enter sanitized evidence.
    if ([429, 503].includes(status) || [429, 503].includes(value?.providerFailure?.status) ||
      value?.errorCode === 'LLM_PROVIDER_RATE_LIMITED') this.halted = true;
  }
  finish() { this.busy = false; }
}
export async function bounded(promise, ms = 45_000, code = 'DELIVERY_UNCONFIRMED_NO_RETRY') {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Fault(code)), ms); })]); }
  finally { clearTimeout(timer); }
}
export async function readGeneration(response, gate, chat, context) {
  if (!response) { gate.halted = true; throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY'); }
  const status = response.status(), headers = response.headers(); gate.observe(status);
  try {
    const bytes = await bounded(response.body()); assert.ok(bytes.length <= 4 * 1024 * 1024);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    let value;
    const ndjson = /^application\/x-ndjson(?:;|$)/i.test(headers['content-type'] ?? '');
    if (status === 200 && ndjson) {
      assert.ok(bytes.length <= chat.CHAT_DELIVERY.totalBytes && text.endsWith('\n'));
      const parser = chat.createChatFrameParser(context, response.request().postDataJSON().mutationId);
      for (const line of text.slice(0, -1).split('\n')) {
        assert.ok(Buffer.byteLength(line) < chat.CHAT_DELIVERY.lineBytes);
        const frame = JSON.parse(line); gate.observe(status, frame); parser.accept(frame);
      }
      value = parser.finish();
    } else value = JSON.parse(text);
    gate.observe(status, value);
    if (status !== 200 || value?.errorCode) throw new Fault('LLM_HTTP_ERROR',
      llmFailureMeta(status, value, ndjson ? 'ndjson-error' : 'http-error', diagnosticFromHeaders(headers)));
    return value;
  } catch (error) { gate.halted = true; throw error; }
  finally { gate.finish(); }
}
export function estimateSample(sample) {
  return sample?.state === 'running' && Number.isFinite(sample.value) && sample.value >= 0 && sample.value < 100 &&
    /Оценка прогресса: ≈\d+%/.test(sample.text) && /Точное оставшееся время неизвестно/.test(sample.text);
}
export async function savePreferences(page, expect, language, autoSummary) {
  const panel = page.getByRole('region', { name: 'Язык и сводка отчётов', exact: true });
  if (!await panel.count()) throw new Fault('UI_NOT_DEPLOYED');
  await expect(panel).toBeVisible();
  await expect(panel.locator('#report-preferences-disclosure')).toContainText('До сохранения выбора внешняя отправка не разрешена.');
  await panel.getByLabel('Язык отчёта', { exact: true }).selectOption(language);
  await panel.getByLabel('Краткая ИИ-сводка', { exact: true }).selectOption(autoSummary ? 'on' : 'off');
  await panel.getByRole('button', { name: 'Сохранить настройки отчётов', exact: true }).click();
  await expect(panel.getByRole('status')).toHaveText('Настройки сохранены для аккаунта в этом браузере.');
  return { language, autoSummary };
}

async function runLive(id) {
  evidencePaths(id);
  if (['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'PLAYWRIGHT_TRACE_DIR', 'PLAYWRIGHT_BROWSERS_PATH'].some(key => process.env[key])) throw new Fault('UNSAFE_DEBUG_ENVIRONMENT');
  assertFreshAttempt(id, await readdir(join(ROOT, 'docs')));
  for (const path of evidencePaths(id)) {
    try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') continue; throw new Fault('EVIDENCE_WRITE_FAILED'); }
    throw new Fault('EVIDENCE_ALREADY_EXISTS');
  }
  const book = new ResultBook(id), gate = new GenerationGate(), handles = [], knownIds = new Set();
  const stats = { accountsCreated: 0, scanLaunches: 0, chatPosts: 0, translationPosts: 0, pageErrors: 0, blockedRequests: 0 };
  const owner = { email: `automation-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const target = TARGETS[0];
  let browser, expect, tools, own, scanId, snapshot, rows, selected, baseline, savedHistory, summaryReply;
    const evidenceChecks = new Map();
  let stopped = false, fatal, currentCase = 'tooling', activeLaunch, pendingCreation = Promise.resolve();
  let interrupt;
  const interrupted = new Promise((_, reject) => { interrupt = code => { stopped = true; fatal = code; gate.halted = true; reject(new Fault(code)); }; });
  const deadlineAt = Date.now() + GLOBAL_MS;
  const timer = setTimeout(() => interrupt('GLOBAL_DEADLINE'), GLOBAL_MS);
  const signal = () => interrupt('INTERRUPTED');
  process.once('SIGINT', signal); process.once('SIGTERM', signal); process.once('SIGHUP', signal);
  const live = () => { if (stopped) throw new Fault(fatal ?? 'INTERRUPTED'); };
  const step = async (name, task) => {
    live(); currentCase = name;
    try { const value = await task(); book.record(name, 'PASS', 'VERIFIED', value?.meta); return value?.value ?? true; }
    catch (error) {
      const code = CODES.has(error?.message) ? error.message : error instanceof BrowserReadError ? 'BROWSER_READ_FAILED' : 'ASSERTION_FAILED';
      if (['summary', 'chat_1', 'chat_2', 'translation'].includes(name)) gate.halted = true;
      book.record(name, error instanceof BaseFault && !error.failure || code === 'BROWSER_READ_FAILED' ? 'BLOCKED' : 'FAIL', code, failureMetadata(error));
      if (fatal || stats.blockedRequests) throw error;
      return false;
    }
  };
  const http = (page, path) => { live(); return readBrowserJson(page, path, knownIds); };
  const responseFor = (page, path) => page.waitForResponse(response => fixedUrl(response.url()) &&
    new URL(response.url()).pathname === path && response.request().method() === 'POST', { timeout: 45_000 }).catch(() => null);
  const readResponse = async response => {
    if (!response) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
    const bytes = await bounded(response.body()); assert.ok(bytes.length <= 4 * 1024 * 1024);
    let value; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { value = null; }
    return { status: response.status(), value, headers: response.headers(), providerDiagnostic: diagnosticFromHeaders(response.headers()) };
  };
  const arm = (handle, path, matches, extra = {}) => {
    live(); assert.ok(!handle.permit || handle.permit.used);
    handle.permit = { path, matches, used: false, ...extra };
  };
  const newPage = async (aiOwner = false) => {
    live();
    const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
    const state = { context, aiOwner, closing: false, permit: null, readSession: 0, fence: new EligibilityFence(),
      eligibilityPending: Promise.resolve(), observations: new Set(), observed: new Map(), generations: new Map(), summaryReads: [], preferences: null };
    handles.push(state);
    const rejected = new WeakSet();
    const denyNote = (request, reason) => {
      if (rejected.has(request)) return; rejected.add(request); book.guard.record(reason, request.url(), request.method());
      stats.blockedRequests = book.guard.blockedRequests;
      if (!['controlled-shutdown-read', 'cancelled-local-read'].includes(reason)) interrupt('REQUEST_GUARD');
    };
    const observeGet = async (route, request, path) => {
      await route.continue();
      if (!scanId || ![`${SCANS}/${scanId}`, `${SCANS}/${scanId}/llm/context`, `${SCANS}/${scanId}/llm/readiness`, `${SCANS}/${scanId}/llm/summary`].includes(path)) return;
      const response = await request.response(), result = await readResponse(response);
      if (path === `${SCANS}/${scanId}/llm/summary`) {
        if (state.summaryReads.length >= 64) throw new Fault('SUMMARY_READ_FAILED');
        state.summaryReads.push(result); book.passiveSummaryReads++;
        // Read failures are not provider calls, but 429/503 still close every generation lane.
        gate.observe(result.status, result.value);
        // This is an observed read only: never consume a generation permit or count a provider call.
        return;
      }
      if (result.status === 200) state.observed.set(path, result.value);
      else state.observed.delete(path); // Failed/current metadata can never leave an old readiness grant active.
    };
    await context.route('**/*', async route => {
      const request = route.request(), input = request.url(), method = request.method(); let approvedRead = false;
      const deny = async reason => { denyNote(request, reason); await route.abort('blockedbyclient').catch(() => {}); };
      try {
        if (!fixedUrl(input)) return deny('external-request');
        const path = new URL(input).pathname;
        if (method === 'GET') {
          if (!safeReadRequest(input, await request.allHeaders())) return deny('mutation-shape');
          approvedRead = browserGetAllowed(input, knownIds);
          if (!approvedRead && activeLaunch) { await bounded(pendingCreation); approvedRead = browserGetAllowed(input, knownIds); }
          if (!approvedRead) return deny('api-get-not-allowed');
          if (stopped || state.closing) return deny('controlled-shutdown-read');
          const pending = observeGet(route, request, path); state.observations.add(pending);
          try { await pending; } finally { state.observations.delete(pending); }
          return;
        }
        if (stopped || state.closing) return deny('shutdown-request');
        if (method !== 'POST') return deny('method-not-allowed');
        if (!safeMutationRequest(input, await request.allHeaders()) || new URL(input).search) return deny('mutation-shape');
        let body; try { body = request.postDataJSON(); } catch { return deny('mutation-shape'); }
        if (path === `${SCANS}/images/eligibility`) {
          if (!state.scanTarget || body?.imageReference !== target.reference) return route.abort();
          if (!exact(body, ['imageReference', 'checks']) || !Array.isArray(body.checks) || !body.checks.length ||
            !body.checks.every((check, index) => CHECKS.includes(check) && (!index || CHECKS.indexOf(body.checks[index - 1]) < CHECKS.indexOf(check)))) return deny('eligibility-shape');
          approvedRead = true; const sequence = state.fence.start();
          state.eligibilityPending = (async () => {
            await route.continue(); const response = await request.response();
            const value = response?.status() === 200 ? (await readResponse(response)).value : null;
            if (response?.status() === 200) state.fence.accept(sequence, body, value, target);
            if (sequence === state.fence.sequence) state.eligibilityResult = { sequence, httpStatus: response?.status() ?? null,
              refused: isDeepStrictEqual(body.checks, CHECKS) && (response?.status() !== 200 || !eligibilityReady(value, target)) };
          })(); await state.eligibilityPending; return;
        }
        if (path === SCANS) {
          if (!state.aiOwner || activeLaunch?.state !== state || !activeLaunch.armed || stats.scanLaunches !== 0 || !validIntent(body, target)) return deny('scan-not-authorized');
          const launch = activeLaunch;
          if (!await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending, () => !stopped && activeLaunch === launch && launch.armed && stats.scanLaunches === 0)) return deny('scan-not-authorized');
          launch.armed = false; stats.scanLaunches++;
          pendingCreation = (async () => {
            await route.continue(); const response = await request.response();
            if (response?.status() === 202) {
              scanId = book.recordScanReceipt(202, (await readResponse(response)).value); knownIds.add(scanId);
              // Arm before native report navigation/completion, not after its automatic effect.
              arm(state, `${SCANS}/${scanId}/llm/summary`, value => isDeepStrictEqual(value, summaryBody(state.observed.get(`${SCANS}/${scanId}/llm/context`))), { kind: 'summary' });
            }
          })(); await pendingCreation; return;
        }
        const kind = generationKind(path, scanId);
        if (kind) {
          await bounded(Promise.all([...state.observations]));
          const permit = state.permit;
          const binding = kind === 'summary' ? state.observed.get(`${SCANS}/${scanId}/llm/context`) : permit?.context;
          const status = state.observed.get(`${SCANS}/${scanId}`);
          const readiness = tools.chat.chatReadinessSchema.safeParse(state.observed.get(`${SCANS}/${scanId}/llm/readiness`));
          if (!readiness.success) return deny('ai-permit-or-limit');
          if (!gate.admit({ owner: state.aiOwner, path, scanId, body, permit, context: binding,
            completed: status?.state === 'completed' && CHECKS.every(check => status.perCheck?.[check]?.outcome === 'checked'), report: status, preferences: state.preferences,
                        readiness: readiness.data, passiveSummary: state.summaryReads.at(-1) })) return deny('ai-permit-or-limit');
          stats.chatPosts = gate.counts.chat; stats.translationPosts = gate.counts.translation;
          const pending = (async () => {
            await route.continue(); const response = await request.response();
            return readGeneration(response, gate, tools.chat, binding);
          })();
          const key = kind === 'chat' ? `chat_${gate.counts.chat}` : kind;
          state.generations.set(key, pending);
          // Preserve finite diagnostics even if a queued hidden POST ends the workflow first.
          pending.catch(error => { gate.halted = true;
            book.record(key, 'BLOCKED', CODES.has(error?.message) ? error.message : 'ASSERTION_FAILED', failureMetadata(error));
          });
          await pending.catch(() => {}); return;
        }
        if (!['/api/v1/auth/register', '/api/v1/auth/login'].includes(path) ||
          path === '/api/v1/auth/register' && stats.accountsCreated !== 0 ||
          !consumePermit(state.permit, method, path, body)) return deny('mutation-not-permitted');
        await route.continue();
      } catch (error) {
        await deny(guardAbortReason({ approvedRead, closing: state.closing, aborted: request.failure()?.errorText === 'net::ERR_ABORTED' || error?.name === 'AbortError' }));
      }
    });
    context.on('request', request => { if (!fixedUrl(request.url())) denyNote(request, 'external-request'); });
    context.on('response', response => {
      if (fixedUrl(response.url())) book.actual = true;
      if (generationKind(new URL(response.url()).pathname, scanId, response.request().method())) gate.observe(response.status());
      if (runtimeProbeRead(response.url(), response.request().method())) {
        try { assertRuntimeOffReply(response.url(), response.request().method(), response.status()); }
        catch { interrupt('RUNTIME_NOT_OFF'); }
      }
      if (response.status() >= 300 && response.status() < 400) denyNote(response.request(), 'redirect');
    });
    await context.routeWebSocket('**/*', socket => { book.guard.record('websocket', socket.url(), 'OTHER'); stats.blockedRequests++; interrupt('REQUEST_GUARD'); socket.close(); });
    context.on('page', page => {
      page.on('pageerror', () => { stats.pageErrors++; });
      page.on('download', download => { book.guard.record('download', page.url(), 'GET'); stats.blockedRequests++; interrupt('REQUEST_GUARD'); void download.cancel().catch(() => {}); });
    });
    state.page = await context.newPage(); state.page.setDefaultTimeout(15_000); state.page.setDefaultNavigationTimeout(20_000);
    trackBrowserReadPage(state.page, { active: () => !stopped && !state.closing, sessionVersion: () => state.readSession });
    return state;
  };
  const auth = async (handle, action) => {
    handle.readSession++; await handle.page.goto(`${ORIGIN}/${action}`);
    await handle.page.getByLabel('Email', { exact: true }).fill(owner.email);
    await handle.page.getByLabel('Пароль', { exact: true }).fill(owner.password);
    arm(handle, `/api/v1/auth/${action}`, body => exact(body, ['email', 'password']) && body.email === owner.email && body.password === owner.password);
    const pending = responseFor(handle.page, `/api/v1/auth/${action}`);
    await handle.page.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти', exact: true }).click();
    assert.equal((await pending)?.status(), action === 'register' ? 201 : 200);
    if (action === 'register') stats.accountsCreated++;
    await settleAuthNavigation(handle.page, () => !stopped && !handle.closing);
    const me = await http(handle.page, '/api/v1/auth/me'); assert.equal(me.status, 200);
    owner.subject = assertAuthUser(me.value, owner.email, owner.subject); return owner.subject;
  };
  const readStatus = async page => {
    const response = await http(page, `${SCANS}/${scanId}`); assert.equal(response.status, 200);
    const value = tools.decoder.parseCurrentStatus(response.value);
    assert.equal(value.scanId, scanId); assert.equal(value.profile, 'public-hub-amd64-v1'); assert.deepEqual(value.checks, CHECKS);
    return value;
  };
  const readFindings = async page => {
    const query = { view: 'report-v1', limit: 50, sort: 'severity:desc' };
    return readAllPages('vuln', { whole: snapshot.perCheck.vuln.findingCount, matched: snapshot.perCheck.vuln.findingCount }, async cursor => {
      const response = await http(page, `${SCANS}/${scanId}/vuln?${tools.view.reportViewSearch('vuln', query, cursor)}`);
      checkPredicate(response.status === 200, 'vuln-http-status');
      return parseBoundReport('vuln', response.value, snapshot, query, cursor, tools.decoder);
    });
  };
  const openChat = async page => {
    const region = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
    await expect(region).toBeVisible();
    await expect(region.getByRole('button', { name: 'Открыть чат', exact: true })).toHaveCount(0);
    await expect(region.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toBeVisible();
    await expect(region.locator('#scan-chat-send-help')).toBeVisible(); return region;
  };
  const readChat = async page => {
    const context = tools.chat.chatContextSchema.parse(assertLlmSuccess(await http(page, `${SCANS}/${scanId}/llm/chat/context`)));
    const history = tools.chat.chatHistorySchema.parse(assertLlmSuccess(await http(page, `${SCANS}/${scanId}/llm/history`)));
    for (const key of ['scanId', 'digest', 'platform']) assert.equal(context[key], snapshot[key]);
    assert.equal(history.epoch, context.epoch); assert.equal(history.revision, context.revision); return { context, history };
  };
  const readyFor = async (page, context) => {
    const ready = tools.chat.chatReadinessSchema.parse(assertLlmSuccess(await http(page, `${SCANS}/${scanId}/llm/readiness`)));
    if (!ready.localReady) throw new Fault('READINESS_BLOCKED'); assertReady(ready, context);
  };
  const historyUi = async (page, history) => {
    const region = await openChat(page);
    for (const turn of history.turns) {
      const article = region.locator('article').filter({ has: region.getByText(turn.question, { exact: true }) });
      await expect(article).toHaveCount(1); assert.equal(turn.state, 'completed');
      await expect(article.getByRole('heading', { name: 'Ответ ИИ · требует проверки', exact: true })).toBeVisible();
      assert.ok(renderedReplyMatches(turn.reply.text, await article.innerText()));
      for (const source of turn.reply.sources) await expect(article.getByRole('link', { name: `Находка ${source.finding.findingId}`, exact: true })).toBeVisible();
    }
  };
  const delivered = async (handle, key) => {
    const end = Date.now() + 45_000;
    while (!handle.generations.has(key) && Date.now() < end) {
      live(); if (gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY'); await pause(25);
    }
    if (!handle.generations.has(key)) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
    return bounded(handle.generations.get(key));
  };
  const waitSummaryRead = async (handle, after = 0) => {
    const end = Date.now() + 45_000;
    while (handle.summaryReads.length <= after && Date.now() < end) { live(); await pause(25); }
    if (handle.summaryReads.length <= after) throw new Fault('SUMMARY_READ_FAILED');
    return handle.summaryReads[after];
  };
  const summaryUi = async (page, value) => {
    const output = page.locator('[aria-label="Сводка ИИ · требует проверки"]');
    await expect(output).toBeVisible();
    await expect(output).toContainText('Сводка восстановлена из кэша процесса сервера; это не долговечная история.');
    for (const hypothesis of value.hypotheses) await expect(output).toContainText(hypothesis.text);
  };
  const originalVisible = async () => {
    const source = own.page.locator('li.scan-vuln-row').filter({ hasText: `ID находки: ${selected.row.findingId}` }).locator('div[aria-label^="Источник "]').nth(selected.index);
    for (const field of ['title', 'description']) if (selected.item[field].value !== null) await expect(source).toContainText(selected.item[field].value);
    await expect(source).toContainText(selected.item.provenanceRef);
  };
  try {
    await Promise.race([interrupted, (async () => {
      if (!await step('tooling', async () => {
        tools = await loadTranslationContracts();
        const { chromium, expect: baseExpect } = await import('@playwright/test'); expect = baseExpect.configure({ timeout: 15_000 });
        const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
        try { browser = await chromium.launch({ headless: true, timeout: 20_000, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false, env, args: [...BROWSER_ARGS] }); }
        catch { throw new Fault('BROWSER_UNAVAILABLE'); }
      })) return;
      own = await newPage(true);
      if (!await step('owner_registration', () => auth(own, 'register'))) return;
      if (!await step('preferences_original', async () => {
        own.preferences = await savePreferences(own.page, expect, 'original', true);
        await own.page.reload();
        await expect(own.page.getByLabel('Язык отчёта', { exact: true })).toHaveValue('original');
        await expect(own.page.getByLabel('Краткая ИИ-сводка', { exact: true })).toHaveValue('on'); assert.equal(gate.total, 0);
        return { meta: { explicitConsent: true, noAdditionalPosts: true } };
      })) return;
      if (!await step('native_scan', async () => {
        own.scanTarget = target; const after = own.fence.sequence;
        await own.page.goto(`${ORIGIN}/scans/new`);
        const form = own.page.getByRole('form', { name: 'Параметры скана', exact: true }); await expect(form).toBeVisible();
        await own.page.getByRole('textbox', { name: 'Canonical reference Docker Hub', exact: true }).fill(target.reference);
        for (const check of CHECKS) await own.page.locator(`input[name="checks"][value="${check}"]`).check();
        const read = () => readLaunchForm(form, target);
        const authority = () => !stopped && !own.closing && own.page.url() === `${ORIGIN}/scans/new`;
        const stable = await awaitStableUiEligibility(own, after, read, authority);
        assert.ok(uiLaunchReady(await read()) && authority() && own.fence.sequence === stable.sequence && own.fence.fresh(after));
        const consent = own.page.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
        const submit = own.page.getByRole('button', { name: 'Запустить скан', exact: true });
        await expect(consent).not.toBeChecked(); await expect(submit).toBeDisabled(); await consent.check(); await expect(submit).toBeEnabled();
        assert.ok(uiLaunchReady(await read(), true) && authority() && own.fence.sequence === stable.sequence);
        activeLaunch = { state: own, armed: true, sequence: own.fence.sequence };
        const pending = responseFor(own.page, SCANS); await submit.click(); const response = await pending; await pendingCreation;
        if (response?.status() !== 202) throw new Fault('LAUNCH_UNCONFIRMED_NO_RETRY'); activeLaunch = null;
        scanId = await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        const end = Date.now() + WORKER_MS; const samples = [];
        do {
          const status = await readStatus(own.page);
          if (TERMINAL.has(status.state)) { snapshot = status; break; }
          const panel = own.page.getByRole('group', { name: `Ход сканирования ${scanId}`, exact: true });
          const sample = await panel.evaluate(element => ({ state: element.getAttribute('data-state'), text: element.textContent,
            value: Number(element.querySelector('progress')?.getAttribute('value')) }));
          if (estimateSample(sample)) samples.push(sample.value);
          live(); await pause(1500);
        } while (Date.now() < end);
        const increased = samples.length >= 2 && samples.at(-1) > samples[0] && samples.every((value, index) => !index || value >= samples[index - 1]);
                book.record('estimate', increased ? 'PASS' : 'BLOCKED', increased ? 'VERIFIED' : 'PREREQUISITE_UNAVAILABLE');
        if (!snapshot) throw new Fault('WORKER_DEADLINE_NO_RELAUNCH', { scanId });
        if (snapshot.state !== 'completed' || !CHECKS.every(check => snapshot.perCheck?.[check]?.outcome === 'checked')) throw new Fault('REQUIRED_CHECK_NOT_CHECKED', { scanId, state: snapshot.state });
        const terminalPanel = own.page.getByRole('group', { name: `Ход сканирования ${scanId}`, exact: true });
                await expect(terminalPanel).toHaveAttribute('data-state', 'completed');
                await expect(terminalPanel).toContainText('Прогресс: 100% — завершение подтверждено сервером.');
                await expect(terminalPanel.locator('progress')).toHaveCount(0);
                return { meta: { scanId, digest: snapshot.digest, platform: snapshot.platform, state: snapshot.state } };
      })) return;
      await step('coverage_click', async () => {
        const region = own.page.getByRole('region', { name: 'Покрытие проверок', exact: true }); const before = gate.total;
        const outcomes = region.getByRole('list', { name: 'Исходы проверок', exact: true });
        for (const check of CHECKS) {
          const label = { secret: 'Secrets', sbom: 'SBOM', vuln: 'Уязвимости', config: 'Image config' }[check];
          const tile = outcomes.locator(':scope > li').filter({ has: own.page.getByText(label, { exact: true }) });
          await expect(tile).toHaveAttribute('data-outcome', 'checked');
          const details = tile.locator('details');
          if (!await details.count()) throw new Fault('UI_NOT_DEPLOYED');
          await details.locator('summary').click(); await expect(details).toHaveAttribute('open', '');
          await expect(details.locator('p').first()).toBeVisible(); await details.locator('summary').click();
          await expect(details).not.toHaveAttribute('open', '');
        }
        const help = region.getByRole('button', { name: 'Что означает неполный отчёт?', exact: true });
        await help.click(); await expect(help).toHaveAttribute('aria-expanded', 'true');
        await expect(region.getByText('Нельзя считать непроверенные категории безопасными.', { exact: false })).toBeVisible();
        await help.click(); await expect(help).toHaveAttribute('aria-expanded', 'false');
        assert.equal(gate.total, before); return { meta: { noAdditionalPosts: true } };
      });
      if (!await step('report', async () => {
        const result = await readFindings(own.page); rows = result.rows;
                checkPredicate(isDeepStrictEqual(partition(rows), snapshot.identifierCounts), 'report-partition');
        baseline = hash({ snapshot, rows });
        for (const row of rows) evidenceChecks.set(row.findingId, 'vuln');
        for (const finding of snapshot.config?.findings ?? []) evidenceChecks.set(finding.findingId, 'config');
        const query = { view: 'report-v1', limit: 50, sort: 'ruleId:asc' };
        const secrets = await readAllPages('secret', { whole: snapshot.perCheck.secret.findingCount, matched: snapshot.perCheck.secret.findingCount }, async cursor => {
          const response = await http(own.page, `${SCANS}/${scanId}/results?${tools.view.reportViewSearch('secret', query, cursor)}`);
          checkPredicate(response.status === 200, 'secret-http-status');
          return parseBoundReport('secret', response.value, snapshot, query, cursor, tools.decoder);
        });
        for (const finding of secrets.rows) evidenceChecks.set(finding.findingId, 'secret');
        // Opening a card mounts ALL its assessments: authorize only a single-assessment card.
        for (const row of rows.slice(0, 25)) if (!selected && row.advisory?.assessments?.length === 1 && eligibleAssessment(row.advisory.assessments[0]) &&
                  ['title', 'description'].every(field => row.advisory.assessments[0][field].value === null ||
                    tools.translation.translatableField(row.advisory.assessments[0][field], field === 'title' ? 512 : 4096))) selected = { row, index: 0, item: row.advisory.assessments[0] };
        return { meta: { pages: result.pages, vulnerabilities: rows.length } };
      })) return;
      await step('always_open_chat', async () => { await openChat(own.page); });
      await step('summary_initial_missing', async () => {
        const first = await waitSummaryRead(own);
        assert.equal(passiveSummaryValue(first, own.observed.get(`${SCANS}/${scanId}/llm/context`)), null);
        return { meta: { httpStatus: 404, errorCode: 'LLM_SUMMARY_MISSING' } };
      });
      const summaryOk = await step('summary', async () => {
        summaryReply = await delivered(own, 'summary'); const context = own.observed.get(`${SCANS}/${scanId}/llm/context`); assertFixedPolicy(context);
        for (const key of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(summaryReply[key], context[key]);
        assert.ok(Array.isArray(summaryReply.hypotheses) && summaryReply.hypotheses.length > 0 && summaryReply.hypotheses.length <= 12);
        const facts = new Map(summaryReply.scannerFacts.map(fact => [fact.findingId, fact.check]));
                assert.equal(facts.size, summaryReply.scannerFacts.length);
        const output = own.page.locator('[aria-label="Сводка ИИ · требует проверки"]'); await expect(output).toBeVisible();
        for (const hypothesis of summaryReply.hypotheses) {
          assert.equal(hypothesis.kind, 'hypothesis');
                    assert.ok(tools.chat.validChatText(hypothesis.text, 8000));
                    assert.ok(hypothesis.citations.length && hypothesis.citations.every(id => evidenceChecks.has(id) && evidenceChecks.get(id) === facts.get(id)));
                    assert.ok(/[А-Яа-яЁё]{3}/u.test(hypothesis.text)); // Not a fidelity/grounding verdict.
          await expect(output).toContainText(hypothesis.text);
        }
        assert.equal(gate.counts.summary, 1); return { meta: { explicitConsent: true, transferNoteVisible: true } };
      });
      for (const [index, question] of QUESTIONS.entries()) await step(`chat_${index + 1}`, async () => {
        if (!summaryOk || gate.halted || index === 1 && book.cases.chat_1.status !== 'PASS') throw new Fault(gate.halted ? 'PROVIDER_STOP_NO_RETRY' : 'PREREQUISITE_UNAVAILABLE');
        const panel = await openChat(own.page), before = await readChat(own.page); await readyFor(own.page, before.context);
        assert.equal(before.history.turns.length, index);
        const usage = assertChatUsage(assertLlmSuccess(await http(own.page, `${SCANS}/${scanId}/llm/chat/usage`)), before.context);
        for (const scope of ['user', 'scan']) assert.equal(usage[scope].used.costMicros, 0);
        await panel.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(question);
        const submit = panel.getByRole('button', { name: 'Отправить вопрос', exact: true });
        await expect(submit).toHaveAttribute('aria-describedby', 'scan-chat-send-help'); await expect(submit).toBeEnabled();
        arm(own, `${SCANS}/${scanId}/llm/chat`, body => chatBodyMatches(body, before.context, question), { kind: 'chat', context: before.context, question });
        await submit.click(); const value = await delivered(own, `chat_${index + 1}`); const after = await readChat(own.page);
        assert.equal(after.history.turns.length, index + 1); const turn = after.history.turns.at(-1);
        assert.equal(turn.state, 'completed'); assert.equal(turn.question, question); assert.deepEqual(turn.reply, value.reply);
                assert.ok(/[А-Яа-яЁё]{3}/u.test(turn.reply.text)); // Script plausibility only, NOT semantic accuracy.
                        assert.equal(turn.reply.kind, 'hypothesis');
                        assert.ok(turn.reply.sources.length && turn.reply.sources.every(source => tools.chat.sameChatBinding(source, before.context) &&
                          evidenceChecks.get(source.finding.findingId) === source.finding.check));
                assert.equal(value.usage.costMicros, 0);
        await historyUi(own.page, after.history); savedHistory = after.history; gate.chatSuccesses++;
        return { meta: { ...historyMetadata(savedHistory), turnId: turn.id, costMicros: value.usage.costMicros, explicitConsent: true } };
      });
      const beforeReload = gate.total, beforeReloadReads = own.summaryReads.length; let reloadRead;
      await step('summary_reload_no_post', async () => {
        if (!summaryOk) throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.reload(); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        reloadRead = await waitSummaryRead(own, beforeReloadReads);
        passiveSummaryValue(reloadRead, own.observed.get(`${SCANS}/${scanId}/llm/context`));
        await expect(own.page.getByRole('region', { name: 'Сводка отчёта', exact: true })).toHaveAttribute('aria-busy', 'false');
        assert.equal(gate.total, beforeReload); return { meta: { httpStatus: reloadRead.status, noAdditionalPosts: true } };
      });
      await step('summary_reload_restore', async () => {
        if (!summaryOk || !reloadRead) throw new Fault('PREREQUISITE_UNAVAILABLE');
        assertSummaryRestored(reloadRead, own.observed.get(`${SCANS}/${scanId}/llm/context`), summaryReply);
        await summaryUi(own.page, summaryReply); assert.equal(gate.total, beforeReload);
        return { meta: { httpStatus: 200, noAdditionalPosts: true } };
      });
      await step('history_reload', async () => {
        if (!savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        const current = await readChat(own.page); assert.deepEqual(current.history, savedHistory); await historyUi(own.page, savedHistory);
        assert.equal(gate.total, beforeReload); return { meta: { ...historyMetadata(savedHistory), historyUnchanged: true, noAdditionalPosts: true } };
      });
      const prefsRu = await step('preferences_ru', async () => {
        if (gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY');
        await own.page.goto(`${ORIGIN}/account`); own.preferences = await savePreferences(own.page, expect, 'ru', true);
        return { meta: { explicitConsent: true } };
      });
      let translated, region;
      const translatedOk = await step('translation', async () => {
        if (!prefsRu || gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY');
        if (!selected) throw new Fault('NO_ELIGIBLE_ASSESSMENT');
        await own.page.goto(`${ORIGIN}/scans/${scanId}`); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        const path = `${SCANS}/${scanId}/llm/translation/context?findingId=${selected.row.findingId}&assessmentIndex=${selected.index}`;
        const context = tools.translation.translationContextSchema.parse(assertLlmSuccess(await http(own.page, path))); await readyFor(own.page, context);
        assert.equal(context.sourceVersion, hash(['selected-advisory-ru-v1', selected.row.cveId, selected.item]));
        const post = `${SCANS}/${scanId}/llm/translation`;
        arm(own, post, body => isDeepStrictEqual(body, translationBody(context)), { kind: 'translation', context });
        const row = own.page.locator('li.scan-vuln-row').filter({ hasText: `ID находки: ${selected.row.findingId}` });
        await expect(row.locator('details.scan-vuln-row__details')).not.toHaveAttribute('open', '');
        await row.locator('details.scan-vuln-row__details > summary').click();
        region = row.getByRole('region', { name: `Перевод ${selected.row.cveId}, источник ${selected.item.source}, оценка 1`, exact: true });
        translated = tools.translation.translationReplySchema.parse(await delivered(own, 'translation'));
        assert.ok(tools.translation.sameTranslationBinding(translated, context)); assert.equal(translated.model, MODEL); assert.equal(translated.provider, 'OpenRouter');
                assert.ok(tools.translation.matchesTranslationFields(translated, selected.item));
                        for (const field of ['title', 'description']) {
                          const original = selected.item[field].value, result = translated.translation[field];
                          assert.equal(result === null, original === null);
                          const ids = text => [...new Set(text?.match(/\b(?:CVE|TEMP)-[A-Za-z0-9-]+/gi) ?? [])].sort();
                          assert.deepEqual(ids(result), ids(original)); // Identifier retention, not semantic fidelity.
                        }
                assert.ok(/[А-Яа-яЁё]{3}/u.test(Object.values(translated.translation).filter(Boolean).join(' '))); // Not semantic fidelity.
        await expect(region).toContainText('Машинный перевод на русский · не официальный текст NVD или БДУ');
        for (const text of Object.values(translated.translation).filter(value => value !== null)) await expect(region).toContainText(text);
        await originalVisible(); assert.equal(gate.counts.translation, 1); return { meta: { findingId: context.findingId, assessmentIndex: 0, sourceVersion: context.sourceVersion, originalUnchanged: true, explicitConsent: true } };
      });
      await step('translation_toggle', async () => {
        if (!translatedOk) throw new Fault('PREREQUISITE_UNAVAILABLE'); const before = gate.total;
        await region.getByRole('button', { name: 'Оригинал', exact: true }).click(); await expect(region).toContainText('Показан оригинальный текст источника выше.'); await originalVisible();
        await region.getByRole('button', { name: 'Перевод', exact: true }).click();
        for (const text of Object.values(translated.translation).filter(value => value !== null)) await expect(region).toContainText(text);
        assert.equal(gate.total, before); return { meta: { noAdditionalPosts: true, originalUnchanged: true } };
      });
      // A fresh empty context also supplies anonymous denial; no second account is created.
      const fresh = await newPage(true);
      await step('anonymous_denial', async () => {
        await fresh.page.goto(`${ORIGIN}/login`); await expect(fresh.page.getByLabel('Email', { exact: true })).toBeVisible();
        for (const suffix of ['', '/llm/history', '/llm/chat/context', '/llm/context', '/llm/readiness', '/llm/summary']) assertDeniedReply(await http(fresh.page, `${SCANS}/${scanId}${suffix}`), 401);
        return { meta: { httpStatus: 401, noAdditionalPosts: true } };
      });
      // completeFreshOwnerLogin requires a NEW about:blank context, not the anonymous probe page.
      fresh.closing = true; await fresh.context.close();
      await step('fresh_login', async () => {
        if (!savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        own.closing = true; await own.context.close(); own = await newPage(true);
        return completeFreshOwnerLogin(book, own, owner.subject, () => auth(own, 'login'), () => !stopped && !own.closing);
      });
      await step('preferences_fresh_context', async () => {
        if (book.cases.fresh_login.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.goto(`${ORIGIN}/account`);
        await expect(own.page.getByLabel('Язык отчёта', { exact: true })).toHaveValue('original');
        await expect(own.page.getByLabel('Краткая ИИ-сводка', { exact: true })).toHaveValue('off');
        await expect(own.page.getByText('Автоматика отключена: сохраните выбор, чтобы подтвердить текущие условия.', { exact: true })).toBeVisible();
      });
      let freshSummaryRead;
      await step('history_fresh_login', async () => {
        if (book.cases.fresh_login.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE'); const before = gate.total, reads = own.summaryReads.length;
        await own.page.goto(`${ORIGIN}/scans/${scanId}`); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        freshSummaryRead = await waitSummaryRead(own, reads);
        assert.deepEqual((await readChat(own.page)).history, savedHistory); await historyUi(own.page, savedHistory);
        assert.equal(gate.total, before); return { meta: { ...historyMetadata(savedHistory), historyUnchanged: true, noAdditionalPosts: true } };
      });
      await step('summary_fresh_login_restore', async () => {
        if (!summaryOk || !freshSummaryRead || book.cases.fresh_login.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = gate.total;
        assertSummaryRestored(freshSummaryRead, own.observed.get(`${SCANS}/${scanId}/llm/context`), summaryReply);
        await summaryUi(own.page, summaryReply); assert.equal(gate.total, before);
        return { meta: { httpStatus: 200, noAdditionalPosts: true } };
      });
      book.record('settings_owner_isolation', 'BLOCKED', 'SECOND_OWNER_NOT_AUTHORIZED');
      await step('preservation', async () => {
        const current = await readStatus(own.page); assert.deepEqual(current, snapshot);
        const result = await readFindings(own.page); assert.equal(hash({ snapshot: current, rows: result.rows }), baseline);
        if (savedHistory) assert.deepEqual((await readChat(own.page)).history, savedHistory);
        const context = (await readChat(own.page)).context;
        const usage = assertChatUsage(assertLlmSuccess(await http(own.page, `${SCANS}/${scanId}/llm/chat/usage`)), context);
        for (const scope of ['user', 'scan']) assert.equal(usage[scope].used.costMicros, 0);
        return { meta: { countsUnchanged: true, originalUnchanged: true, costMicros: 0 } };
      });
    })()]);
  } catch (error) {
    book.record(currentCase, fatal ? 'FAIL' : 'BLOCKED', CODES.has(fatal ?? error?.message) ? fatal ?? error.message : 'ASSERTION_FAILED', failureMetadata(error));
  } finally {
    stopped = true; gate.halted = true; clearTimeout(timer); for (const handle of handles) handle.closing = true;
    process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); process.removeListener('SIGHUP', signal);
    // Admission is already closed above. Observe only the existing POST promise,
    // before closing the browser; never wait for/arm a not-yet-admitted operation.
    const pendingSummary = handles.map(handle => handle.generations.get('summary')).find(Boolean);
    await collectAdmittedSummary(book, gate, pendingSummary, Math.max(0, Math.min(SUMMARY_DRAIN_MS, deadlineAt - Date.now())));
    let browserClosed = false;
    try { await bounded(Promise.allSettled(handles.map(handle => handle.context.close())), 10_000); if (browser) await bounded(browser.close(), 10_000); browserClosed = !browser || !browser.isConnected(); } catch { /* Finite cleanup result only. */ }
    const bad = !browserClosed || stats.blockedRequests || stats.pageErrors || stats.accountsCreated > 1 || stats.scanLaunches > 1 || gate.total > 4;
    book.record('safety', bad ? 'FAIL' : 'PASS', !browserClosed ? 'CLEANUP_FAILED' : stats.blockedRequests ? 'REQUEST_GUARD' : stats.pageErrors ? 'PAGE_ERRORS' : bad ? 'ASSERTION_FAILED' : 'VERIFIED',
      { ...stats, browserClosed, nativeScanMayRemainActive: stats.scanLaunches > 0 && !snapshot });
    book.generation = gate; book.finishedAt = new Date().toISOString();
    if (book.actual) { try { await writeEvidence(book); } catch { book.record('safety', 'FAIL', 'EVIDENCE_WRITE_FAILED'); } }
    console.log(JSON.stringify(book.evidence(), null, 2));
  }
  return exitCode(book);
}
async function main() {
  let mode;
  try { mode = parseMode(process.argv.slice(2)); } catch { console.log(JSON.stringify({ status: 'BLOCKED', code: 'INVALID_ARGUMENTS', actuallyRun: false })); return 2; }
  if (mode === 'not-run') { console.log(JSON.stringify({ status: 'BLOCKED', code: 'NOT_RUN', actuallyRun: false, requiresCoordinatorReadyGo: true })); return 2; }
  if (mode === 'offline') {
    const contracts = await loadTranslationContracts();
    const { DIAGNOSTIC_PHASES, DIAGNOSTIC_REASONS } = await import('./public-ai-translation-live.mjs');
    assert.deepEqual(DIAGNOSTIC_PHASES, [...contracts.diagnostics.FAILURE_PHASES]); assert.deepEqual(DIAGNOSTIC_REASONS, [...contracts.diagnostics.FAILURE_REASONS]);
    assert.equal(allowedApiGet('http://127.0.0.1:8080/api/v1/auth/me', []), false);
    console.log(JSON.stringify({ status: 'PASS', scope: 'OFFLINE_PREFLIGHT_ONLY', actuallyRun: false, browserLaunched: false, networkRequests: 0, evidenceWritten: false })); return 0;
  }
  try { return await runLive(process.argv.at(-1)); }
  catch { console.log(JSON.stringify({ status: 'BLOCKED', code: 'PREFLIGHT_FAILED', actuallyRun: false, rawDiagnosticsSuppressed: true })); return 2; }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main();
