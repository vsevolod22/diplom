// PREPARED ONLY: no browser/runtime/provider contact without coordinator READYGO.
// Offline: node --test tests-e2e/public-automation-live.test.mjs
// Isolated (READYGO only): --run --chat-translation-only --ack-coordinator-readygo --ack-three-generation-posts --ack-source-deployed --attempt-id NEW_UUID
// Translation only: --run --translation-only --ack-coordinator-readygo --ack-one-generation-post --ack-source-deployed --attempt-id NEW_UUID
// Fresh account + one fresh completed native scan; isolated summary POST forbidden, never resume an old attempt.
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
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
  GLOBAL_MS, MODEL, ENDPOINT, GuardLedger, guardAbortReason, projectMeta, diagnosticFromHeaders as baseDiagnosticFromHeaders,
  llmFailureMeta, assertLlmSuccess, assertFixedPolicy, assertReady, chatBodyMatches, translationBody,
  eligibleAssessment, renderedReplyMatches, historyMetadata, loadTranslationContracts,
  settleAcceptedScan, completeFreshOwnerLogin, Fault as BaseFault,
} from './public-ai-translation-live.mjs';

export { GLOBAL_MS, WORKER_MS };
export const AUTOMATION_REVISION = 'report-automation-v4-remediation';
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
  'secret-decoded-coverage', 'report-partition', 'generation-body-read', 'generation-body-limit', 'generation-utf8', 'generation-json', 'generation-frames']);
// Metadata remains short and read-only. A generation observation must outlive
// the 90s API operation (+5s metadata allowance) and the 120s browser client.
export const METADATA_MS = 45_000;
export const GENERATION_MS = 135_000;
export const SUMMARY_DRAIN_MS = GENERATION_MS;
export const SUMMARY_CASES = Object.freeze(['tooling', 'owner_registration', 'preferences_original', 'native_scan',
  'report', 'summary_initial_missing', 'summary', 'summary_reload_no_post', 'summary_reload_restore', 'preservation', 'safety']);
export const TRANSLATION_CASES = Object.freeze(CASES.filter(name => ['tooling', 'owner_registration', 'preferences_original', 'native_scan', 'estimate', 'coverage_click', 'report', 'preferences_ru', 'translation', 'translation_toggle', 'anonymous_denial', 'settings_owner_isolation', 'preservation', 'safety'].includes(name)));
export const CHAT_TRANSLATION_CASES = Object.freeze(CASES.filter(name => ![
  'summary_initial_missing', 'summary', 'summary_reload_no_post', 'summary_reload_restore', 'summary_fresh_login_restore',
].includes(name)));
export async function loadCoverageLabels() {
  const require = createRequire(join(ROOT, 'server/api/package.json'));
  const manifest = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
  const { scanCheckLabels } = await tsImport(join(ROOT, 'src/features/scans/scanProgressPresentation.ts'), { parentURL: import.meta.url, tsconfig: false });
  assert.ok(exact(scanCheckLabels, CHECKS) && CHECKS.every(check => typeof scanCheckLabels[check] === 'string' && scanCheckLabels[check].length > 0));
  return Object.freeze({ ...scanCheckLabels });
}
export function coverageTile(outcomes, page, labels, check) {
  assert.ok(CHECKS.includes(check) && exact(labels, CHECKS));
  return outcomes.locator(':scope > li').filter({ has: page.getByText(labels[check], { exact: true }) });
}
export const COVERAGE_WARNING = '«Выполнено» означает завершение проверки, а не гарантию безопасности. Пропущенные проверки не означают отсутствие проблем.';
export async function assertCoverageWarning(region, expect) {
  await expect(region.getByText(COVERAGE_WARNING, { exact: true })).toBeVisible();
}
export const GROUNDING_PREDICATES = Object.freeze(['cvss_version', 'package_label', 'version_label', 'update_target', 'score_parentheses', 'score_value', 'score_boundary', 'unmasked_tilde', 'unmasked_dotted_number', 'advisory_identifier']);
export const GROUNDING_SOURCE_RELATIONS = Object.freeze(['cited_value_match', 'no_cited_value_match', 'indeterminate']);
export const GROUNDING_LEXICAL_CLASSES = Object.freeze(['unsigned_decimal', 'signed_decimal', 'dotted_numeric', 'ascii_identity', 'tilde', 'indeterminate']);
export const GROUNDING_BOUNDARY_CLASSES = Object.freeze(['end', 'whitespace', 'sentence_punctuation', 'typography', 'identity_continuation', 'other', 'indeterminate']);
export const LANGUAGE_REASONS = Object.freeze(['insufficient_russian', 'residual_latin', 'residual_other_script', 'mixed']);
export const LANGUAGE_TOKEN_CLASSES = Object.freeze(['cited_identity', 'cited_ecosystem', 'conventional_report_term', 'unknown', 'indeterminate']);
function finiteLanguage(value) {
  if (!value || typeof value !== 'object') return undefined;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || !['reason', 'index', 'tokenClass'].every(key => keys.includes(key))) return undefined;
  const reason = Object.getOwnPropertyDescriptor(value, 'reason')?.value;
  const index = Object.getOwnPropertyDescriptor(value, 'index')?.value;
  const tokenClass = Object.getOwnPropertyDescriptor(value, 'tokenClass')?.value;
  return LANGUAGE_REASONS.includes(reason) && Number.isInteger(index) && index >= 0 && index <= 11 && LANGUAGE_TOKEN_CLASSES.includes(tokenClass)
    ? { reason, index, tokenClass } : undefined;
}
function finiteWitness(value) {
  if (!value || typeof value !== 'object') return undefined;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || !['sourceRelation', 'lexicalClass', 'boundaryClass'].every(key => keys.includes(key))) return undefined;
  const sourceRelation = Object.getOwnPropertyDescriptor(value, 'sourceRelation')?.value;
  const lexicalClass = Object.getOwnPropertyDescriptor(value, 'lexicalClass')?.value;
  const boundaryClass = Object.getOwnPropertyDescriptor(value, 'boundaryClass')?.value;
  return GROUNDING_SOURCE_RELATIONS.includes(sourceRelation) && GROUNDING_LEXICAL_CLASSES.includes(lexicalClass) && GROUNDING_BOUNDARY_CLASSES.includes(boundaryClass)
    ? { sourceRelation, lexicalClass, boundaryClass } : undefined;
}
export function diagnosticFromHeaders(headers) {
  const base = baseDiagnosticFromHeaders(headers);
  if (!base) return undefined;
  const get = name => typeof headers?.get === 'function' ? headers.get(name) :
    Object.hasOwn(headers ?? {}, name.toLowerCase()) ? headers[name.toLowerCase()] :
      Object.hasOwn(headers ?? {}, name) ? headers[name] : undefined;
  if (base.phase === 'language' && base.reason === 'not_russian') {
      const index = get('X-LLM-Language-Index');
      const language = typeof index === 'string' && /^(?:[0-9]|1[01])$/.test(index) ? finiteLanguage({
        reason: get('X-LLM-Language-Reason'), index: Number(index), tokenClass: get('X-LLM-Language-Token-Class'),
      }) : undefined;
      return { ...base, ...(language ? { languageRejection: language } : {}) };
    }
    const predicate = get('X-LLM-Grounding-Predicate'), index = get('X-LLM-Grounding-Index');
  if (base.phase !== 'grounding' || base.reason !== 'unknown_identifier' ||
    !GROUNDING_PREDICATES.includes(predicate) || typeof index !== 'string' || !/^(?:[0-9]|1[01])$/.test(index)) return base;
  const witness = finiteWitness({ sourceRelation: get('X-LLM-Grounding-Source-Relation'),
    lexicalClass: get('X-LLM-Grounding-Lexical-Class'), boundaryClass: get('X-LLM-Grounding-Boundary-Class') });
  return { ...base, groundingPredicate: predicate, groundingIndex: Number(index), ...(witness ? { groundingWitness: witness } : {}) };
}
export function automationMeta(input = {}) {
  const diagnostic = input.providerDiagnostic;
  const out = projectMeta({ ...input, providerDiagnostic: diagnostic ? { phase: diagnostic.phase, reason: diagnostic.reason } : undefined });
  if (out.providerDiagnostic?.phase === 'grounding' && out.providerDiagnostic?.reason === 'unknown_identifier' &&
    GROUNDING_PREDICATES.includes(diagnostic?.groundingPredicate) && Number.isInteger(diagnostic?.groundingIndex) && diagnostic.groundingIndex >= 0 && diagnostic.groundingIndex <= 11) {
        const witness = finiteWitness(diagnostic.groundingWitness);
        out.providerDiagnostic = { ...out.providerDiagnostic, groundingPredicate: diagnostic.groundingPredicate, groundingIndex: diagnostic.groundingIndex,
          ...(witness ? { groundingWitness: witness } : {}) };
      }
  if (out.providerDiagnostic?.phase === 'language' && out.providerDiagnostic?.reason === 'not_russian') {
      const language = finiteLanguage(diagnostic?.languageRejection);
      if (language) out.providerDiagnostic = { ...out.providerDiagnostic, languageRejection: language };
    }
    if (!Number.isInteger(out.runnerLine) || out.runnerLine < 1 || out.runnerLine > 100_000) delete out.runnerLine;
  if (FAILURE_PREDICATES.includes(input.predicate)) out.predicate = input.predicate;
  for (const key of ['findingCount', 'selectedFindings', 'omittedFindings'])
    if (Number.isSafeInteger(input[key]) && input[key] >= 0 && input[key] <= 10_000_000) out[key] = input[key];
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
  if (args.length === 7 && isDeepStrictEqual(args.slice(0, 5),
    ['--run', '--summary-only', '--ack-coordinator-readygo', '--ack-one-generation-post', '--ack-source-deployed']) &&
    args[5] === '--attempt-id' && UUID.test(args[6])) return 'summary-only';
  if (args.length === 7 && isDeepStrictEqual(args.slice(0, 5),
    ['--run', '--chat-translation-only', '--ack-coordinator-readygo', '--ack-three-generation-posts', '--ack-source-deployed']) &&
    args[5] === '--attempt-id' && UUID.test(args[6])) return 'chat-translation-only';
  if (args.length === 7 && isDeepStrictEqual(args.slice(0, 5),
    ['--run', '--translation-only', '--ack-coordinator-readygo', '--ack-one-generation-post', '--ack-source-deployed']) &&
    args[5] === '--attempt-id' && UUID.test(args[6])) return 'translation-only';
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
  constructor(id, mode = 'full') {
    assert.ok(['full', 'summary-only', 'chat-translation-only', 'translation-only'].includes(mode));
    this.mode = mode; this.requiredCases = mode === 'translation-only' ? TRANSLATION_CASES : mode === 'summary-only' ? SUMMARY_CASES : mode === 'chat-translation-only' ? CHAT_TRANSLATION_CASES : CASES;
    evidencePaths(id); this.id = id; this.runId = randomUUID(); this.actual = false;
    this.startedAt = new Date().toISOString(); this.finishedAt = null; this.guard = new GuardLedger(); this.passiveSummaryReads = 0;
    this.cases = Object.fromEntries(CASES.map(name => [name, { status: !this.requiredCases.includes(name) ? 'NOT_RUN' : 'BLOCKED', code: 'NOT_RUN' }]));
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
      mode: this.mode, maxAccounts: 1, maxScans: 1, maxGenerationPosts: ['summary-only', 'translation-only'].includes(this.mode) ? 1 : this.mode === 'chat-translation-only' ? 3 : 4, requiredChecks: [...CHECKS],
      generationWaitMs: GENERATION_MS, metadataWaitMs: METADATA_MS,
      generationAdmissions: generationMetadata(this.generation), requiredCases: [...this.requiredCases],
                  passiveSummaryReads: Number.isSafeInteger(this.passiveSummaryReads) && this.passiveSummaryReads >= 0 && this.passiveSummaryReads <= 1000 ? this.passiveSummaryReads : 0,
                  summaryRetention: 'durable-owner-scan',
                        admittedSummaryObservation: summaryObservationMeta(this.summaryObservation ?? {
                          admitted: this.generation?.counts?.summary === 1, capture: this.generation?.counts?.summary === 1 ? 'NOT_CAPTURED' : 'NOT_ADMITTED' }),
      policy: { model: MODEL, endpoint: ENDPOINT, retention: 'no-training', freeOnly: true, noFallback: true,
              automationRevision: AUTOMATION_REVISION },
      serverEgressIndependentlyObserved: false, billingIndependentlyVerified: false,
      semanticAccuracy: 'unverified-requires-memory-only-human-review',
      ownershipScope: this.mode === 'translation-only' ? 'fresh-owner-and-anonymous-denial-no-relogin-or-foreign-owner' : this.mode === 'summary-only' ? 'same-owner-reload-only-no-isolation-claim' : 'fresh-owner-login-and-anonymous-denial-not-foreign-owner',
      preferenceScope: this.mode === 'translation-only' ? 'same-owner-browser-local-original-to-ru-auto-summary-off' : this.mode === 'summary-only' ? 'same-owner-browser-local-saved-original-auto-summary' : 'same-owner-browser-local-and-empty-context-not-foreign-owner',
      payloadArtifacts: false, credentialsPersisted: false, screenshots: false, har: false, storageState: false,
      createdRuntimeDataAutomaticallyDeleted: false,
      cases: Object.fromEntries(CASES.map(name => [name, { status: this.cases[name].status,
        code: this.cases[name].code, ...automationMeta(this.cases[name]) }])) };
  }
}
export function exitCode(book) {
  return CASES.some(name => book.cases[name].status === 'FAIL') ? 1 :
    book.requiredCases.every(name => book.cases[name].status === 'PASS') ? 0 : 2;
}
export function evidenceDocuments(book) {
  const value = book.evidence();
  return [JSON.stringify(value, null, 2) + '\n', ['# Native public automation qualification — 2026-10-26', '',
    `Attempt: ${book.id}. Actually run: ${book.actual}. Origin: ${ORIGIN}.`,
    `Maximum one disposable account, one native Node four-check scan, ${value.maxGenerationPosts} generation POST(s). Mode: ${value.mode}. No retries/fallback.`,
    ...(book.mode === 'summary-only' ? ['Chat and translation are NOT_RUN, not diagnosed as current root causes. Fresh login/isolation are not exercised.'] : []),
    ...(book.mode === 'translation-only' ? ['Translation-only: summary/chat POSTs forbidden; both auto-summary and chat are not prerequisites. One fresh report, at most one translation POST, no retry. Summary/chat/history/relogin are NOT_RUN.'] : []),
    ...(book.mode === 'chat-translation-only' ? ['Isolated chat/translation scope: summary POSTs are forbidden, auto-summary stays off; summary generation/restore cases are NOT_RUN, not accepted or diagnosed. Fresh account and native completed report are required; this is not resume of any previous attempt.'] : []),
    'Metadata only: no answers, selected source text, conversations, credentials, screenshots, HAR or storage state.',
    'Already-admitted summary transport may be observed during bounded cleanup; consumption remains UNKNOWN and this cannot qualify a failed/skipped case.',
    `Already-admitted summary capture: ${value.admittedSummaryObservation.capture}; consumption: UNKNOWN.`,
    'Russian/schema/citation checks do not establish semantic accuracy or translation fidelity. Review only in memory.',
    'No foreign-owner isolation claim: only one account is authorized. Summary reload/fresh-login restoration requires passive GET, never another POST.',
        'Require the durable-owner-scan retention header. API restart/backup/restore durability is not exercised by this browser run.',
    'Source changes and offline tests are not deployment or live acceptance. Only the coordinator may execute after confirming the actual source rollout.',
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
  const expected = { provider: 'OpenRouter', model: MODEL, providers: [ENDPOINT], region: 'global', retention: 'no-training',
    operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, requestBudgetUsd: 0, freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 }, data: kind === 'summary'
      ? 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.'
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
  if (headers['x-llm-summary-retention'] !== 'durable-owner-scan' || result.value?.errorCode || !automationDisclosureMatches(context.disclosure, 'summary'))
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
  constructor(mode = 'full') {
    assert.ok(['full', 'summary-only', 'chat-translation-only', 'translation-only'].includes(mode));
    Object.defineProperty(this, 'mode', { value: mode, enumerable: true });
    Object.defineProperty(this, 'maxPosts', { value: ['summary-only', 'translation-only'].includes(mode) ? 1 : mode === 'chat-translation-only' ? 3 : 4, enumerable: true });
    this.counts = { summary: 0, chat: 0, translation: 0 }; this.total = 0; this.busy = false; this.halted = false; this.chatSuccesses = 0;
  }
  admit({ owner, path, scanId, body, permit, context, completed, report, preferences, readiness, passiveSummary }) {
    const kind = generationKind(path, scanId);
    if (!kind || this.mode === 'translation-only' && (kind !== 'translation' || preferences?.autoSummary !== false) || this.mode === 'summary-only' && kind !== 'summary' ||
        this.mode === 'chat-translation-only' && (kind === 'summary' || this.counts.summary !== 0 || preferences?.autoSummary !== false ||
          kind === 'translation' && this.chatSuccesses !== 2) || !owner || this.halted || this.busy || this.total >= this.maxPosts || !permit || permit.used ||
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
export async function bounded(promise, ms = METADATA_MS, code = 'DELIVERY_UNCONFIRMED_NO_RETRY') {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Fault(code)), ms); })]); }
  finally { clearTimeout(timer); }
}
export async function receiveGeneration(request, gate, chat, context, deadlineAt = Date.now() + GENERATION_MS) {
  try {
    const response = await bounded(request.response(), Math.max(0, deadlineAt - Date.now()));
    return await readGeneration(response, gate, chat, context, deadlineAt);
  } catch (error) { gate.halted = true; gate.finish(); throw error; }
}
export async function readGeneration(response, gate, chat, context, deadlineAt = Date.now() + GENERATION_MS) {
  if (!response) { gate.halted = true; throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY'); }
  const status = response.status(), headers = response.headers(); gate.observe(status);
  gate.responseMeta = automationMeta({ httpStatus: status, providerDiagnostic: diagnosticFromHeaders(headers) });
  let predicate = 'generation-body-read';
  try {
    const bytes = await bounded(response.body(), Math.max(0, deadlineAt - Date.now()));
    predicate = 'generation-body-limit'; assert.ok(bytes.length <= 4 * 1024 * 1024);
    predicate = 'generation-utf8'; const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    predicate = 'generation-json';
    let value;
    const ndjson = /^application\/x-ndjson(?:;|$)/i.test(headers['content-type'] ?? '');
    if (status === 200 && ndjson) {
      predicate = 'generation-frames';
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
      { ...llmFailureMeta(status, value, ndjson ? 'ndjson-error' : 'http-error', diagnosticFromHeaders(headers)), providerDiagnostic: diagnosticFromHeaders(headers) });
    return value;
  } catch (error) {
    gate.halted = true;
    throw new Fault(error instanceof BaseFault ? error.message : 'ASSERTION_FAILED',
      { httpStatus: status, ...(!(error instanceof BaseFault) ? { predicate } : {}), ...automationMeta(error?.meta), providerDiagnostic: diagnosticFromHeaders(headers) },
      !(error instanceof BaseFault) || error.failure);
  }
  finally { gate.finish(); }
}
export function assertOneSummary(gate) {
  assert.equal(gate.total, 1); assert.deepEqual(gate.counts, { summary: 1, chat: 0, translation: 0 });
}
export function assertSummaryQualification(reply, context, snapshot, evidenceChecks, validText) {
  assertFixedPolicy(context); assert.ok(automationDisclosureMatches(context.disclosure, 'summary'));
  for (const key of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(reply?.[key], context[key]);
  for (const key of ['scanId', 'digest', 'platform']) assert.equal(context[key], snapshot[key]);
  const counts = Object.fromEntries(CHECKS.map(check => [check, check === 'sbom' ? 0 : snapshot.perCheck[check].findingCount]));
  for (const count of Object.values(counts)) assert.ok(Number.isSafeInteger(count) && count >= 0);
  assert.equal(context.findingCount, evidenceChecks.size);
  assert.equal(Object.values(counts).reduce((sum, count) => sum + count, 0), evidenceChecks.size);
  assert.deepEqual(context.findingCounts?.byCheck, counts);
  assert.ok(exact(context.findingCounts?.bySeverity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']));
  assert.ok(Object.values(context.findingCounts.bySeverity).every(count => Number.isSafeInteger(count) && count >= 0));
  assert.equal(Object.values(context.findingCounts.bySeverity).reduce((sum, count) => sum + count, 0), context.findingCount);
  assert.deepEqual(context.identifierCounts, snapshot.identifierCounts);
  for (const key of ['findingCount', 'findingCounts', 'identifierCounts', 'coverage']) assert.deepEqual(reply[key], context[key]);
  assert.ok(exact(context.coverage, CHECKS));
  for (const check of CHECKS) {
    const coverage = context.coverage[check], original = snapshot.perCheck[check];
    assert.equal(coverage.outcome, 'checked'); assert.equal(original.outcome, 'checked');
    for (const key of [check === 'sbom' ? 'componentCount' : 'findingCount', 'scannerVersion', 'checkedAt'])
      assert.equal(coverage[key], original[key]);
  }
  const selection = reply.contextSelection;
  assert.ok(exact(selection, ['totalFindings', 'selectedFindings', 'omittedFindings', 'strategy', 'selectedFindingIds']));
  assert.equal(selection.strategy, 'all-critical-and-unknown-then-severity');
  assert.equal(selection.totalFindings, context.findingCount);
  assert.ok(Number.isSafeInteger(selection.selectedFindings) && selection.selectedFindings > 0 && selection.selectedFindings <= selection.totalFindings);
  assert.equal(selection.omittedFindings, selection.totalFindings - selection.selectedFindings);
  assert.ok(Array.isArray(selection.selectedFindingIds));
  assert.equal(selection.selectedFindingIds.length, selection.selectedFindings);
  const selected = new Set(selection.selectedFindingIds);
  assert.equal(selected.size, selection.selectedFindings);
  assert.ok([...selected].every(id => evidenceChecks.has(id)));
  assert.ok(Array.isArray(reply.scannerFacts) && reply.scannerFacts.length <= 1000);
  const facts = new Map(reply.scannerFacts.map(fact => [fact.findingId, fact.check]));
  assert.equal(facts.size, reply.scannerFacts.length); assert.ok(facts.size > 0 && facts.size <= selected.size);
  assert.ok([...facts].every(([id, check]) => selected.has(id) && evidenceChecks.get(id) === check));
  assert.ok(Array.isArray(reply.hypotheses) && reply.hypotheses.length > 0 && reply.hypotheses.length <= 12);
  for (const item of reply.hypotheses) {
    assert.ok(exact(item, ['kind', 'text', 'citations'])); assert.equal(item.kind, 'hypothesis');
    assert.ok(validText(item.text, 2000) && /[А-Яа-яЁё]{3}/u.test(item.text));
    assert.ok(Array.isArray(item.citations) && item.citations.length > 0 && item.citations.length <= 20);
    assert.equal(new Set(item.citations).size, item.citations.length);
    assert.ok(item.citations.every(id => selected.has(id) && facts.get(id) === evidenceChecks.get(id)));
  }
  // The backend returns only cited facts, not every selected finding sent to the model.
  const cited = new Set(reply.hypotheses.flatMap(item => item.citations));
  assert.equal(cited.size, facts.size); assert.ok([...facts.keys()].every(id => cited.has(id)));
}
export function assertZeroSummaryUsage(usage, context) {
  assert.ok(usage?.available === true && usage.integrationEnabled === true && usage.quotaEnabled === true);
  for (const key of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(usage[key], context[key]);
  for (const scope of ['user', 'scan']) for (const vector of ['used', 'held', 'carried']) {
    assert.ok(exact(usage[scope]?.[vector], ['input', 'output', 'costMicros']));
    assert.ok(Object.values(usage[scope][vector]).every(value => Number.isSafeInteger(value) && value >= 0));
    assert.equal(usage[scope][vector].costMicros, 0);
  }
}
export function estimateSample(sample) {
  return sample?.state === 'running' && Number.isFinite(sample.value) && sample.value >= 0 && sample.value < 100 &&
    /Оценка прогресса: ≈\d+%/.test(sample.text) && /Точное оставшееся время неизвестно/.test(sample.text);
}
export function selectTranslationCandidate(rows, translation) {
  for (const row of rows) {
    if (row.advisory?.state !== 'available') continue;
    const assessments = row.advisory.assessments;
    // Opening one card mounts every assessment. Exactly one may auto-translate;
    // metadata-only siblings do not justify rejecting an otherwise safe card.
    const eligible = assessments.map((item, index) => ({ item, index })).filter(({ item }) => translation.hasTranslationText(item));
    if (eligible.length !== 1) continue;
    const { item, index } = eligible[0];
    if (eligibleAssessment(item) && ['title', 'description'].every(field => item[field].value === null ||
      translation.translatableField(item[field], field === 'title' ? 512 : 4096))) return { row, index, item };
  }
  return undefined;
}
export async function locateTranslationRow(page, expect, selected, rows) {
  const ordinal = rows.findIndex(row => row.findingId === selected.row.findingId);
  assert.ok(ordinal >= 0);
  const report = page.getByRole('region', { name: 'Результаты Уязвимости', exact: true });
  // Match actual UI paging (25); API inventory uses50 and must not be confused with it.
  // Navigation is read-only with every card closed: no translation is armed yet.
  for (let offset = 0; offset <= ordinal; offset += 25) {
    await expect(report.locator('li.scan-vuln-row').first()).toContainText(`ID находки: ${rows[offset].findingId}`);
    if (ordinal < offset + 25) break;
    const next = report.getByRole('button', { name: 'Далее · Уязвимости', exact: true });
    await expect(next).toBeEnabled(); await next.click();
  }
  const row = report.locator('li.scan-vuln-row').filter({ hasText: `ID находки: ${selected.row.findingId}` });
  await expect(row).toBeVisible();
  await expect(row.locator('details.scan-vuln-row__details')).not.toHaveAttribute('open', '');
  return row;
}
export async function savePreferences(page, expect, language, autoSummary) {
  const panel = page.getByRole('region', { name: 'Настройки отчётов', exact: true });
  // Navigation can finish before React mounts the account region; count() does not wait.
  try { await expect(panel).toBeVisible({ timeout: 15_000 }); }
  catch { throw new Fault('UI_NOT_DEPLOYED'); }
  const disclosure = panel.locator('#report-preferences-disclosure');
  await expect(disclosure).toHaveAttribute('data-automation-revision', AUTOMATION_REVISION);
  for (const text of ['До сохранения выбора внешняя отправка не разрешена.', MODEL, 'провайдеру Atlas Cloud', ENDPOINT,
    'отсутствие обучения (no-training)', 'но не отсутствие хранения', 'могут сохраняться', 'не Zero Data Retention (ZDR)'])
    await expect(disclosure).toContainText(text);
  await panel.getByLabel('Язык исходных описаний уязвимостей', { exact: true }).selectOption(language);
  await panel.getByLabel('ИИ-разбор', { exact: true }).selectOption(autoSummary ? 'on' : 'off');
  await panel.getByRole('button', { name: 'Сохранить настройки отчётов', exact: true }).click();
  await expect(panel.getByRole('status')).toHaveText('Настройки сохранены для аккаунта в этом браузере.');
  return { language, autoSummary };
}

async function runLive(id, mode = 'full') {
  const summaryOnly = mode === 'summary-only';
  const translationOnly = mode === 'translation-only';
  const chatTranslationOnly = mode === 'chat-translation-only' || translationOnly;
  evidencePaths(id);
  if (['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'PLAYWRIGHT_TRACE_DIR', 'PLAYWRIGHT_BROWSERS_PATH'].some(key => process.env[key])) throw new Fault('UNSAFE_DEBUG_ENVIRONMENT');
  assertFreshAttempt(id, await readdir(join(ROOT, 'docs')));
  for (const path of evidencePaths(id)) {
    try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') continue; throw new Fault('EVIDENCE_WRITE_FAILED'); }
    throw new Fault('EVIDENCE_ALREADY_EXISTS');
  }
  const book = new ResultBook(id, mode), gate = new GenerationGate(mode), handles = [], knownIds = new Set();
  const stats = { accountsCreated: 0, scanLaunches: 0, chatPosts: 0, translationPosts: 0, pageErrors: 0, blockedRequests: 0 };
  const owner = { email: `automation-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const target = TARGETS[0];
  let browser, expect, tools, own, scanId, snapshot, rows, selected, baseline, savedHistory, summaryReply;
    const evidenceChecks = new Map();
  let stopped = false, fatal, currentCase = 'tooling', activeLaunch, pendingCreation = Promise.resolve();
  let interrupt;
  const interrupted = new Promise((_, reject) => { interrupt = (code, meta = {}) => { stopped = true; fatal = code; gate.halted = true; reject(new Fault(code, meta)); }; });
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
      book.record(name, error instanceof BaseFault && !error.failure || code === 'BROWSER_READ_FAILED' ? 'BLOCKED' : 'FAIL', code,
              { ...(['summary', 'chat_1', 'chat_2', 'translation'].includes(name) ? gate.responseMeta : {}), ...failureMetadata(error) });
      if (fatal || stats.blockedRequests) throw error;
      return false;
    }
  };
  const http = (page, path) => { live(); return readBrowserJson(page, path, knownIds); };
  const responseFor = (page, path) => page.waitForResponse(response => fixedUrl(response.url()) &&
    new URL(response.url()).pathname === path && response.request().method() === 'POST', { timeout: generationKind(path, scanId) ? GENERATION_MS : METADATA_MS }).catch(() => null);
  const readResponse = async response => {
    if (!response) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
    const bytes = await bounded(response.body(), METADATA_MS); assert.ok(bytes.length <= 4 * 1024 * 1024);
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
      eligibilityPending: Promise.resolve(), observations: new Set(), observed: new Map(), generations: new Map(), generationDeadlines: new Map(), summaryReads: [], preferences: null };
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
          if (!approvedRead && activeLaunch) { await bounded(pendingCreation, METADATA_MS); approvedRead = browserGetAllowed(input, knownIds); }
          if (!approvedRead) return deny('api-get-not-allowed');
          if (stopped || state.closing) return deny('controlled-shutdown-read');
          const pending = observeGet(route, request, path); state.observations.add(pending);
          try { await pending; } finally { state.observations.delete(pending); }
          return;
        }
        if (stopped || state.closing) return deny('shutdown-request');
        if (method !== 'POST') return deny('method-not-allowed');
        // This route fence precedes every permit, metadata wait and continue().
        // Reject even malformed/other-scan chat or translation POST paths.
        if (summaryOnly && /\/llm\/(?:chat|translation)(?:\/|$)/.test(path)) return deny('ai-permit-or-limit');
        if (chatTranslationOnly && /\/llm\/summary(?:\/|$)/.test(path)) return deny('ai-permit-or-limit');
                if (translationOnly && /\/llm\/chat(?:\/|$)/.test(path)) return deny('ai-permit-or-limit');
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
              if (!chatTranslationOnly) arm(state, `${SCANS}/${scanId}/llm/summary`, value => isDeepStrictEqual(value, summaryBody(state.observed.get(`${SCANS}/${scanId}/llm/context`))), { kind: 'summary' });
            }
          })(); await pendingCreation; return;
        }
        const kind = generationKind(path, scanId);
        if (kind) {
          if (translationOnly && kind !== 'translation' || summaryOnly && kind !== 'summary' || chatTranslationOnly && kind === 'summary') return deny('ai-permit-or-limit');
          await bounded(Promise.all([...state.observations]), METADATA_MS);
          const permit = state.permit;
          const binding = kind === 'summary' ? state.observed.get(`${SCANS}/${scanId}/llm/context`) : permit?.context;
          const status = state.observed.get(`${SCANS}/${scanId}`);
          const readiness = tools.chat.chatReadinessSchema.safeParse(state.observed.get(`${SCANS}/${scanId}/llm/readiness`));
          if (!readiness.success || deadlineAt - Date.now() < GENERATION_MS) return deny('ai-permit-or-limit');
          if (!gate.admit({ owner: state.aiOwner, path, scanId, body, permit, context: binding,
            completed: status?.state === 'completed' && CHECKS.every(check => status.perCheck?.[check]?.outcome === 'checked'), report: status, preferences: state.preferences,
                        readiness: readiness.data, passiveSummary: state.summaryReads.at(-1) })) return deny('ai-permit-or-limit');
          stats.chatPosts = gate.counts.chat; stats.translationPosts = gate.counts.translation;
          const generationDeadlineAt = Date.now() + GENERATION_MS;
          const pending = (async () => {
            await route.continue();
            return receiveGeneration(request, gate, tools.chat, binding, generationDeadlineAt);
          })();
          const key = kind === 'chat' ? `chat_${gate.counts.chat}` : kind;
          state.generationDeadlines.set(key, generationDeadlineAt); state.generations.set(key, pending);
          // Preserve finite diagnostics even if a queued hidden POST ends the workflow first.
          pending.catch(error => { gate.halted = true;
            const code = CODES.has(error?.message) ? error.message : 'ASSERTION_FAILED';
            book.record(key, 'BLOCKED', code, failureMetadata(error));
            if (summaryOnly && !stopped) { currentCase = 'summary'; interrupt(code, failureMetadata(error)); }
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
    const end = Date.now() + GENERATION_MS;
    while (!handle.generations.has(key) && Date.now() < end) {
      live(); if (gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY'); await pause(25);
    }
    if (!handle.generations.has(key)) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
    return bounded(handle.generations.get(key), Math.max(0, handle.generationDeadlines.get(key) - Date.now()));
  };
  const waitSummaryRead = async (handle, after = 0) => {
    const end = Date.now() + METADATA_MS;
    while (handle.summaryReads.length <= after && Date.now() < end) { live(); await pause(25); }
    if (handle.summaryReads.length <= after) throw new Fault('SUMMARY_READ_FAILED');
    return handle.summaryReads[after];
  };
  const summaryUi = async (page, value) => {
    const output = page.locator('[aria-label="ИИ-разбор отчёта"]');
    await expect(output).toBeVisible();
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
        tools.coverageLabels = await loadCoverageLabels();
        const { chromium, expect: baseExpect } = await import('@playwright/test'); expect = baseExpect.configure({ timeout: 15_000 });
        const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
        try { browser = await chromium.launch({ headless: true, timeout: 20_000, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false, env, args: [...BROWSER_ARGS] }); }
        catch { throw new Fault('BROWSER_UNAVAILABLE'); }
      })) return;
      own = await newPage(true);
      if (!await step('owner_registration', () => auth(own, 'register'))) return;
      if (!await step('preferences_original', async () => {
        own.preferences = await savePreferences(own.page, expect, 'original', !chatTranslationOnly);
        await own.page.reload();
        await expect(own.page.getByLabel('Язык исходных описаний уязвимостей', { exact: true })).toHaveValue('original');
        await expect(own.page.getByLabel('ИИ-разбор', { exact: true })).toHaveValue(chatTranslationOnly ? 'off' : 'on'); assert.equal(gate.total, 0);
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
      if (!summaryOnly) await step('coverage_click', async () => {
        const region = own.page.getByRole('region', { name: 'Проверки', exact: true }); const before = gate.total;
        const outcomes = region.getByRole('list', { name: 'Исходы проверок', exact: true });
        for (const check of CHECKS) {
          const tile = coverageTile(outcomes, own.page, tools.coverageLabels, check);
          await expect(tile).toHaveAttribute('data-outcome', 'checked');
          const details = tile.locator('details');
          if (!await details.count()) throw new Fault('UI_NOT_DEPLOYED');
          await details.locator('summary').click(); await expect(details).toHaveAttribute('open', '');
          await expect(details.locator('p').first()).toBeVisible(); await details.locator('summary').click();
          await expect(details).not.toHaveAttribute('open', '');
        }
        await assertCoverageWarning(region, expect);
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
        selected = summaryOnly ? undefined : selectTranslationCandidate(rows, tools.translation);
        return { meta: { pages: result.pages, vulnerabilities: rows.length } };
      })) return;
      if (!summaryOnly && !translationOnly) await step('always_open_chat', async () => { await openChat(own.page); });
      let summaryOk = false;
      if (!chatTranslationOnly) {
      const initialMissing = await step('summary_initial_missing', async () => {
        const first = await waitSummaryRead(own);
        assert.equal(passiveSummaryValue(first, own.observed.get(`${SCANS}/${scanId}/llm/context`)), null);
        return { meta: { httpStatus: 404, errorCode: 'LLM_SUMMARY_MISSING' } };
      });
      if (summaryOnly && !initialMissing) return;
      summaryOk = await step('summary', async () => {
        summaryReply = await delivered(own, 'summary'); const context = own.observed.get(`${SCANS}/${scanId}/llm/context`); assertFixedPolicy(context);
        if (summaryOnly) assertSummaryQualification(summaryReply, context, snapshot, evidenceChecks, tools.chat.validChatText);
        for (const key of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(summaryReply[key], context[key]);
        assert.ok(Array.isArray(summaryReply.hypotheses) && summaryReply.hypotheses.length > 0 && summaryReply.hypotheses.length <= 12);
        const facts = new Map(summaryReply.scannerFacts.map(fact => [fact.findingId, fact.check]));
                assert.equal(facts.size, summaryReply.scannerFacts.length);
        const output = own.page.locator('[aria-label="ИИ-разбор отчёта"]'); await expect(output).toBeVisible();
        for (const hypothesis of summaryReply.hypotheses) {
          assert.equal(hypothesis.kind, 'hypothesis');
                    assert.ok(tools.chat.validChatText(hypothesis.text, 8000));
                    assert.ok(hypothesis.citations.length && hypothesis.citations.every(id => evidenceChecks.has(id) && evidenceChecks.get(id) === facts.get(id)));
                    assert.ok(/[А-Яа-яЁё]{3}/u.test(hypothesis.text)); // Not a fidelity/grounding verdict.
          await expect(output).toContainText(hypothesis.text);
        }
        assert.equal(gate.counts.summary, 1); return { meta: { explicitConsent: true, transferNoteVisible: true,
          ...(summaryOnly ? { httpStatus: 200, reportVersion: context.reportVersion, findingCount: summaryReply.findingCount,
            selectedFindings: summaryReply.contextSelection.selectedFindings, omittedFindings: summaryReply.contextSelection.omittedFindings,
            cve: summaryReply.identifierCounts.cve, debianTemp: summaryReply.identifierCounts.debianTemp } : {}) } };
      });
      }
      if (summaryOnly) {
        // No chat questions, translation preferences/cards or fresh-login workflow
        // is reachable here, on success OR failure. Close admissions before reads.
        gate.halted = true;
        if (!summaryOk) return;
        assertOneSummary(gate);
        const reads = own.summaryReads.length;
        let restored;
        if (!await step('summary_reload_no_post', async () => {
          await own.page.reload(); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
          restored = await waitSummaryRead(own, reads);
          passiveSummaryValue(restored, own.observed.get(`${SCANS}/${scanId}/llm/context`));
          await expect(own.page.getByRole('region', { name: 'ИИ-отчёт', exact: true })).toHaveAttribute('aria-busy', 'false');
          assertOneSummary(gate); return { meta: { httpStatus: restored.status, noAdditionalPosts: true } };
        })) return;
        if (!await step('summary_reload_restore', async () => {
          assertSummaryRestored(restored, own.observed.get(`${SCANS}/${scanId}/llm/context`), summaryReply);
          await summaryUi(own.page, summaryReply); assertOneSummary(gate);
          return { meta: { httpStatus: 200, noAdditionalPosts: true } };
        })) return;
        await step('preservation', async () => {
          const current = await readStatus(own.page); assert.deepEqual(current, snapshot);
          const result = await readFindings(own.page); assert.equal(hash({ snapshot: current, rows: result.rows }), baseline);
          const context = assertLlmSuccess(await http(own.page, `${SCANS}/${scanId}/llm/context`));
          assertFixedPolicy(context); assert.ok(automationDisclosureMatches(context.disclosure, 'summary'));
          assertSummaryQualification(summaryReply, context, current, evidenceChecks, tools.chat.validChatText);
          assertZeroSummaryUsage(assertLlmSuccess(await http(own.page, `${SCANS}/${scanId}/llm/usage`)), context);
          assertOneSummary(gate); return { meta: { countsUnchanged: true, originalUnchanged: true, costMicros: 0, noAdditionalPosts: true } };
        });
        return;
      }
      for (const [index, question] of (translationOnly ? [] : QUESTIONS).entries()) await step(`chat_${index + 1}`, async () => {
        if (!chatTranslationOnly && !summaryOk || gate.halted || index === 1 && book.cases.chat_1.status !== 'PASS') throw new Fault(gate.halted ? 'PROVIDER_STOP_NO_RETRY' : 'PREREQUISITE_UNAVAILABLE');
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
      if (!chatTranslationOnly) await step('summary_reload_no_post', async () => {
        if (!summaryOk) throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.reload(); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        reloadRead = await waitSummaryRead(own, beforeReloadReads);
        passiveSummaryValue(reloadRead, own.observed.get(`${SCANS}/${scanId}/llm/context`));
        await expect(own.page.getByRole('region', { name: 'ИИ-отчёт', exact: true })).toHaveAttribute('aria-busy', 'false');
        assert.equal(gate.total, beforeReload); return { meta: { httpStatus: reloadRead.status, noAdditionalPosts: true } };
      });
      if (!chatTranslationOnly) await step('summary_reload_restore', async () => {
        if (!summaryOk || !reloadRead) throw new Fault('PREREQUISITE_UNAVAILABLE');
        assertSummaryRestored(reloadRead, own.observed.get(`${SCANS}/${scanId}/llm/context`), summaryReply);
        await summaryUi(own.page, summaryReply); assert.equal(gate.total, beforeReload);
        return { meta: { httpStatus: 200, noAdditionalPosts: true } };
      });
      if (!translationOnly) await step('history_reload', async () => {
        if (!savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        if (chatTranslationOnly) { await own.page.reload(); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing); }
        const current = await readChat(own.page); assert.deepEqual(current.history, savedHistory); await historyUi(own.page, savedHistory);
        assert.equal(gate.total, beforeReload); return { meta: { ...historyMetadata(savedHistory), historyUnchanged: true, noAdditionalPosts: true } };
      });
      const prefsRu = await step('preferences_ru', async () => {
        if (gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY');
        await own.page.goto(`${ORIGIN}/account`); own.preferences = await savePreferences(own.page, expect, 'ru', !chatTranslationOnly);
        return { meta: { explicitConsent: true } };
      });
      let translated, region;
      const translatedOk = await step('translation', async () => {
        if (!prefsRu || gate.halted) throw new Fault('PROVIDER_STOP_NO_RETRY');
        if (!selected) throw new Fault('NO_ELIGIBLE_ASSESSMENT');
        await own.page.goto(`${ORIGIN}/scans/${scanId}`); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        const row = await locateTranslationRow(own.page, expect, selected, rows);
                const path = `${SCANS}/${scanId}/llm/translation/context?findingId=${selected.row.findingId}&assessmentIndex=${selected.index}`;
        const context = tools.translation.translationContextSchema.parse(assertLlmSuccess(await http(own.page, path))); await readyFor(own.page, context);
        assert.equal(context.sourceVersion, hash(['selected-advisory-ru-v1', selected.row.cveId, selected.item]));
        const post = `${SCANS}/${scanId}/llm/translation`;
        arm(own, post, body => isDeepStrictEqual(body, translationBody(context)), { kind: 'translation', context });
        await row.locator('details.scan-vuln-row__details > summary').click();
        region = row.getByRole('region', { name: `Перевод ${selected.row.cveId}, источник ${selected.item.source}, оценка ${selected.index + 1}`, exact: true });
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
        await originalVisible(); assert.equal(gate.counts.translation, 1); return { meta: { findingId: context.findingId, assessmentIndex: selected.index, sourceVersion: context.sourceVersion, originalUnchanged: true, explicitConsent: true } };
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
      if (translationOnly) {
        book.record('settings_owner_isolation', 'BLOCKED', 'SECOND_OWNER_NOT_AUTHORIZED');
        await step('preservation', async () => {
          const current = await readStatus(own.page); assert.deepEqual(current, snapshot);
          const result = await readFindings(own.page); assert.equal(hash({ snapshot: current, rows: result.rows }), baseline);
          assert.equal(gate.counts.summary, 0); assert.equal(gate.counts.chat, 0);
          assert.ok(gate.counts.translation <= 1);
          return { meta: { countsUnchanged: true, originalUnchanged: true, noAdditionalPosts: true } };
        });
        return;
      }
      await step('fresh_login', async () => {
        if (!savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        own.closing = true; await own.context.close(); own = await newPage(true);
        return completeFreshOwnerLogin(book, own, owner.subject, () => auth(own, 'login'), () => !stopped && !own.closing);
      });
      await step('preferences_fresh_context', async () => {
        if (book.cases.fresh_login.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.goto(`${ORIGIN}/account`);
        await expect(own.page.getByLabel('Язык исходных описаний уязвимостей', { exact: true })).toHaveValue('original');
        await expect(own.page.getByLabel('ИИ-разбор', { exact: true })).toHaveValue('off');
        await expect(own.page.getByText('Автоматические функции отключены: сохраните выбор, чтобы подтвердить текущие условия.', { exact: true })).toBeVisible();
      });
      let freshSummaryRead;
      await step('history_fresh_login', async () => {
        if (book.cases.fresh_login.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE'); const before = gate.total, reads = own.summaryReads.length;
        await own.page.goto(`${ORIGIN}/scans/${scanId}`); await settleAcceptedScan(book, own.page, () => !stopped && !own.closing);
        if (!chatTranslationOnly) freshSummaryRead = await waitSummaryRead(own, reads);
        assert.deepEqual((await readChat(own.page)).history, savedHistory); await historyUi(own.page, savedHistory);
        assert.equal(gate.total, before); return { meta: { ...historyMetadata(savedHistory), historyUnchanged: true, noAdditionalPosts: true } };
      });
      if (!chatTranslationOnly) await step('summary_fresh_login_restore', async () => {
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
    const bad = !browserClosed || stats.blockedRequests || stats.pageErrors || stats.accountsCreated > 1 || stats.scanLaunches > 1 || gate.total > gate.maxPosts || translationOnly && gate.counts.chat !== 0 || chatTranslationOnly && gate.counts.summary !== 0 || summaryOnly && (gate.counts.chat !== 0 || gate.counts.translation !== 0);
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
    await loadCoverageLabels();
    const { DIAGNOSTIC_PHASES, DIAGNOSTIC_REASONS } = await import('./public-ai-translation-live.mjs');
    assert.deepEqual(DIAGNOSTIC_PHASES, [...contracts.diagnostics.FAILURE_PHASES]); assert.deepEqual(DIAGNOSTIC_REASONS, [...contracts.diagnostics.FAILURE_REASONS]);
    assert.equal(allowedApiGet('http://127.0.0.1:8080/api/v1/auth/me', []), false);
    console.log(JSON.stringify({ status: 'PASS', scope: 'OFFLINE_PREFLIGHT_ONLY', actuallyRun: false, browserLaunched: false, networkRequests: 0, evidenceWritten: false })); return 0;
  }
  try { return await runLive(process.argv.at(-1), mode === 'live' ? 'full' : mode); }
  catch { console.log(JSON.stringify({ status: 'BLOCKED', code: 'PREFLIGHT_FAILED', actuallyRun: false, rawDiagnosticsSuppressed: true })); return 2; }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main();
