// PREPARED ONLY. Run only after an explicit coordinator READYGO for the deployed source.
// Full: --run --ack-coordinator-readygo --ack-three-provider-requests --attempt-id <new UUID>
// Independent: --run --translation-only --ack-coordinator-readygo --ack-one-translation-request --attempt-id <new UUID>
// Offline: node --test tests-e2e/public-ai-translation-live.test.mjs
// No runtime lifecycle, key/config reads, saved credentials, cookie injection, mocks or debug artifacts.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { lstat, open } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  ORIGIN, CHECKS, TARGETS, SCANS, WORKER_MS, BROWSER_ARGS, fixedUrl, validIntent,
  eligibilityReady, EligibilityFence, awaitEligibility, consumePermit, safeMutationRequest,
  assertAuthUser, assertDeniedReply, assertChatUsage, readAllPages, partition, loadContracts,
    allowedApiGet, runtimeProbeRead, assertRuntimeOffReply, safeReadRequest,
} from './public-product-live.mjs';

export { ORIGIN, WORKER_MS, allowedApiGet, runtimeProbeRead, assertRuntimeOffReply };
export const GLOBAL_MS = 20 * 60_000;
export const MODEL = 'xingchen-agi/xing4.0-29b-a4b:free';
export const ENDPOINT = 'phala';
export const CASES = Object.freeze(['tooling', 'owner_registration', 'native_scan', 'report', 'deployed_ui',
  'readiness', 'chat_1', 'chat_2', 'history_reload', 'fresh_login', 'history_fresh_login',
  'foreign_registration', 'foreign_denial', 'translation_context', 'translation', 'translation_toggle', 'preservation', 'safety']);
  export function qualificationCases(scope = 'full') {
    assert.ok(['full', 'translation'].includes(scope));
    return scope === 'full' ? CASES : CASES.filter(name => !['readiness', 'chat_1', 'chat_2', 'history_reload', 'history_fresh_login'].includes(name));
  }
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const EVIDENCE_PATHS = Object.freeze(['json', 'md'].map(ext => join(ROOT, `docs/public-ai-live-20261022.${ext}`)));
export function evidencePaths(attemptSuffix = null) {
  if (attemptSuffix === null) return EVIDENCE_PATHS;
  if (UUID.test(attemptSuffix)) return ['json', 'md'].map(ext => join(ROOT, `docs/public-final-${attemptSuffix}-ai-translation.${ext}`));
    if (!['attempt2', 'attempt3'].includes(attemptSuffix)) throw new Fault('INVALID_ARGUMENTS');
  return ['json', 'md'].map(ext => join(ROOT, `docs/public-ai-live-20261022.${attemptSuffix}.${ext}`));
}
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const FINDING = /^vuln-[a-f0-9]{64}$/;
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);
const QUESTIONS = Object.freeze(['Кратко назови одно ограничение покрытия отчёта.', 'Кратко укажи один безопасный следующий шаг проверки.']);
const CODES = new Set(['NOT_RUN', 'VERIFIED', 'INVALID_ARGUMENTS', 'PREREQUISITE_UNAVAILABLE', 'UNSAFE_DEBUG_ENVIRONMENT',
  'BROWSER_UNAVAILABLE', 'ELIGIBILITY_NOT_READY', 'LAUNCH_UNCONFIRMED_NO_RETRY', 'WORKER_DEADLINE_NO_RELAUNCH', 'REQUIRED_CHECK_NOT_CHECKED',
  'UI_NOT_DEPLOYED', 'READINESS_BLOCKED', 'FIXED_POLICY_REQUIRED', 'CONTEXT_CHANGED', 'NO_ELIGIBLE_ASSESSMENT', 'LLM_HTTP_ERROR',
  'DELIVERY_UNCONFIRMED_NO_RETRY', 'ASSERTION_FAILED', 'REQUEST_GUARD', 'GLOBAL_DEADLINE', 'INTERRUPTED', 'CLEANUP_FAILED',
  'PAGE_ERRORS', 'EVIDENCE_ALREADY_EXISTS', 'EVIDENCE_WRITE_FAILED', 'NOT_ACTUALLY_RUN', 'RUNTIME_NOT_OFF']);
const HTTP_CODES = new Set(['LLM_CONFIGURATION_UNAVAILABLE', 'LLM_PROVIDER_UNAVAILABLE', 'LLM_PROVIDER_RATE_LIMITED', 'LLM_PROVIDER_AUTH_FAILED', 'LLM_PROVIDER_TIMEOUT', 'LLM_UNAVAILABLE', 'LLM_INVALID_RESPONSE',
  'LLM_QUOTA_EXCEEDED', 'LLM_BUDGET_EXCEEDED', 'LLM_CAPACITY', 'LLM_CONTEXT_LIMIT', 'LLM_NO_EVIDENCE', 'LLM_HISTORY_CAPACITY',
  'LLM_HISTORY_UNAVAILABLE', 'LLM_HISTORY_CONFLICT', 'LLM_STALE_REPORT', 'LLM_STALE_SOURCE', 'LLM_STALE_POLICY',
  'LLM_TRANSLATION_UNAVAILABLE', 'LLM_RESPONSE_LIMIT', 'LLM_REQUEST_ABORTED', 'SCAN_NOT_FOUND', 'SCAN_ACCESS_DENIED', 'UNAUTHORIZED']);
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export class Fault extends Error {
  constructor(code, meta = {}, failure = false) { super(code); this.meta = projectMeta(meta); this.failure = failure; }
}
export function parseMode(args) {
  if (!args.length) return 'not-run';
  if (isDeepStrictEqual(args, ['--self-test'])) return 'offline';
  if (args.at(-2) === '--attempt-id' && UUID.test(args.at(-1))) {
    const flags = args.slice(0, -2);
    if (isDeepStrictEqual(flags, ['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests'])) return 'live-final';
    if (isDeepStrictEqual(flags, ['--run', '--translation-only', '--ack-coordinator-readygo', '--ack-one-translation-request'])) return 'translation-final';
  }
  throw new Fault('INVALID_ARGUMENTS');
}
// Match the finite public provider-failure wire contract; never copy an upstream object.
function providerFailureMeta(errorCode, failure) {
  const hasRetry = failure !== null && typeof failure === 'object' && Object.hasOwn(failure, 'retryAfterSeconds');
  if (!exact(failure, ['kind', 'status', ...(hasRetry ? ['retryAfterSeconds'] : [])])) return undefined;
  const { status, kind, retryAfterSeconds } = failure;
  if (!Number.isInteger(status) || status < 300 || status > 599) return undefined;
  const expectedKind = status === 429 || status === 503 ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable';
  const expectedCode = { rate_limited: 'LLM_PROVIDER_RATE_LIMITED', auth_failed: 'LLM_PROVIDER_AUTH_FAILED', unavailable: 'LLM_PROVIDER_UNAVAILABLE' }[expectedKind];
  if (kind !== expectedKind || errorCode !== expectedCode) return undefined;
  if (retryAfterSeconds !== undefined && (kind !== 'rate_limited' || !Number.isSafeInteger(retryAfterSeconds) || retryAfterSeconds < 0 || retryAfterSeconds > 86400)) return undefined;
  return { kind, status, ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }) };
}
export function llmFailureMeta(httpStatus, value, deliveryKind) {
  return projectMeta({ httpStatus, errorCode: value?.errorCode, deliveryKind, providerFailure: value?.providerFailure });
}
export function assertLlmSuccess(result) {
  if (result.status !== 200) throw new Fault('LLM_HTTP_ERROR', llmFailureMeta(result.status, result.value, 'http-error'));
  return result.value;
}
export function projectMeta(input = {}) {
  const out = {};
  for (const key of ['scanId', 'turnId']) if (UUID.test(input[key])) out[key] = input[key];
  if (FINDING.test(input.findingId)) out.findingId = input.findingId;
  for (const key of ['reportVersion', 'sourceVersion', 'policyVersion', 'historyFingerprint']) if (HASH.test(input[key])) out[key] = input[key];
  if (/^sha256:[a-f0-9]{64}$/.test(input.digest)) out.digest = input.digest;
  if (input.platform === 'linux/amd64') out.platform = input.platform;
  if (TERMINAL.has(input.state)) out.state = input.state;
  if (Number.isInteger(input.httpStatus) && input.httpStatus >= 100 && input.httpStatus <= 599) out.httpStatus = input.httpStatus;
  if (HTTP_CODES.has(input.errorCode)) out.errorCode = input.errorCode;
  const providerFailure = providerFailureMeta(out.errorCode, input.providerFailure);
  if (providerFailure) out.providerFailure = providerFailure;
  if (['http-error', 'ndjson-error'].includes(input.deliveryKind)) out.deliveryKind = input.deliveryKind;
  for (const key of ['accountsCreated', 'scanLaunches', 'chatPosts', 'translationPosts', 'blockedRequests', 'pageErrors', 'ignoredEligibility',
    'completedTurns', 'pages', 'cve', 'debianTemp', 'vulnerabilities', 'assessmentIndex', 'input', 'output', 'costMicros', 'runnerLine', 'runtimeOffReads'])
    if (Number.isSafeInteger(input[key]) && input[key] >= 0 && input[key] <= 10_000_000) out[key] = input[key];
  for (const key of ['browserClosed', 'nativeScanMayRemainActive', 'historyUnchanged', 'countsUnchanged', 'originalUnchanged', 'explicitConsent', 'noAdditionalPosts', 'initialUsageZero'])
    if (typeof input[key] === 'boolean') out[key] = input[key];
  if (input.credential === 'metadata-valid') out.credential = input.credential;
  return out;
}
const GUARD_REASONS = new Set(['external-request', 'local-url-shape', 'api-get-not-allowed', 'method-not-allowed',
  'mutation-shape', 'eligibility-shape', 'scan-not-authorized', 'ai-permit-or-limit', 'mutation-not-permitted',
  'redirect', 'websocket', 'download', 'handler-error', 'shutdown-request', 'controlled-shutdown-read', 'cancelled-local-read']);
const BENIGN_GUARD_REASONS = new Set(['controlled-shutdown-read', 'cancelled-local-read']);
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
export function routeCategory(input) {
  let url;
  try { url = new URL(input); } catch { return 'external'; }
  if (url.origin !== ORIGIN) return 'external';
  if (url.username || url.password || url.hash) return 'otherlocal';
  const path = url.pathname;
  if (['/', '/login', '/register', '/scans', '/scans/new'].includes(path) || /^\/scans\/[a-f0-9-]{36}$/.test(path)) return 'navigation';
  if (/^\/assets\/[A-Za-z0-9._-]+\.(?:js|css|svg|png|webp|woff2?)$/.test(path) || path === '/favicon.ico') return 'asset';
  if (['/api/v1/auth/register', '/api/v1/auth/login', '/api/v1/auth/me'].includes(path)) return 'auth';
  if (path === '/api/v1/browser/runtime/capabilities') return 'runtime-capabilities';
  if (path === '/api/v1/browser/runtime/targets') return 'runtime-targets';
  if (path === '/api/v1/browser/runtime/captures') return 'runtime-captures';
  if (path === SCANS) return 'scan-list';
  if (path === `${SCANS}/images/eligibility`) return 'eligibility';
  const match = path.match(/^\/api\/v1\/browser\/scans\/([a-f0-9-]{36})(.*)$/);
  if (!match || !UUID.test(match[1])) return 'otherlocal';
  return ({ '': 'scan-status', '/events': 'scan-events', '/results': 'scan-results', '/sbom': 'scan-sbom', '/vuln': 'scan-vuln',
    '/llm/context': 'llm-context', '/llm/usage': 'llm-usage', '/llm/readiness': 'llm-readiness', '/llm/history': 'llm-history',
    '/llm/chat/context': 'llm-chat-context', '/llm/chat/usage': 'llm-chat-usage', '/llm/chat': 'llm-chat',
    '/llm/translation/context': 'translation-context', '/llm/translation': 'translation' })[match[2]] ?? 'otherlocal';
}
export function guardAbortReason({ closing, approvedRead, aborted }) {
  if (approvedRead && closing) return 'controlled-shutdown-read';
  if (approvedRead && aborted) return 'cancelled-local-read';
  return 'handler-error';
}
export class GuardLedger {
  constructor() { this.records = new Map(); this.blockedRequests = 0; this.benignAborts = 0; this.overflow = 0; }
  record(reason, input, method) {
    assert.ok(GUARD_REASONS.has(reason));
    const event = { reason, routeCategory: routeCategory(input), method: METHODS.has(method) ? method : 'OTHER' };
    if (BENIGN_GUARD_REASONS.has(reason)) this.benignAborts++;
    else this.blockedRequests++;
    const key = JSON.stringify(event), previous = this.records.get(key);
    if (previous) previous.count = Math.min(previous.count + 1, 10_000_000);
    else if (this.records.size < 32) this.records.set(key, { ...event, count: 1 });
    else this.overflow++;
  }
  evidence() {
    return { blockedRequests: this.blockedRequests, benignAborts: this.benignAborts, overflow: this.overflow,
      events: [...this.records.values()].map(({ reason, routeCategory, method, count }) => ({ reason, routeCategory, method, count })) };
  }
}
export function recordFailure(book, name, error, fatal = null) {
  const previous = book.cases[name];
  const preserve = previous.code !== 'NOT_RUN' && previous.status !== 'PASS';
  book.record(name, preserve ? previous.status : error instanceof Fault && !error.failure ? 'BLOCKED' : 'FAIL',
    preserve ? previous.code : fatal ?? (error instanceof Fault ? error.message : 'ASSERTION_FAILED'),
    { ...failureMeta(error), ...(error instanceof Fault ? error.meta : {}) });
}
export function canRunTranslation(book) {
  return ['native_scan', 'report', 'deployed_ui', 'fresh_login'].every(name => book.cases[name].status === 'PASS') &&
    !['chat_1', 'chat_2'].some(name => book.cases[name].status === 'FAIL') && book.guard.blockedRequests === 0;
}
export class ResultBook {
  constructor(attemptSuffix = null, qualification = 'full') {
    evidencePaths(attemptSuffix);
    this.qualification = qualification;
    this.requiredCases = qualificationCases(qualification);
    this.attemptSuffix = attemptSuffix;
    this.guard = new GuardLedger();
    this.runId = randomUUID(); this.startedAt = new Date().toISOString(); this.finishedAt = null; this.actual = false;
    this.cases = Object.fromEntries(CASES.map(name => [name, { status: 'BLOCKED', code: 'NOT_RUN' }]));
  }
  record(name, status, code, meta = {}) {
    assert.ok(CASES.includes(name) && ['PASS', 'BLOCKED', 'FAIL'].includes(status) && CODES.has(code));
    if (this.cases[name].status === 'FAIL') return;
    this.cases[name] = { status, code, ...projectMeta(this.cases[name]), ...projectMeta(meta) };
  }
  evidence() {
    return { schemaVersion: 1, scope: 'native-public8081-ai-translation', origin: ORIGIN, runId: this.runId,
      startedAt: this.startedAt, finishedAt: this.finishedAt, actuallyRun: this.actual, attempt: this.attemptSuffix ?? 'original', qualification: this.qualification, requiredCases: this.requiredCases,
      guard: this.guard.evidence(),
      requiredPolicy: { provider: 'OpenRouter', model: MODEL, endpoint: ENDPOINT, freeOnly: true, noFallback: true },
      serverEgressIndependentlyObserved: false, billingIndependentlyVerified: false, semanticAccuracy: 'unverified',
      createdRuntimeDataAutomaticallyDeleted: false, credentialsPersisted: false, payloadArtifacts: false,
      cases: Object.fromEntries(CASES.map(name => [name, { status: this.cases[name].status, code: this.cases[name].code, ...projectMeta(this.cases[name]) }])) };
  }
}
export function exitCode(book) {
  return CASES.some(name => book.cases[name].status === 'FAIL') ? 1 : book.requiredCases.every(name => book.cases[name].status === 'PASS') ? 0 : 2;
}
export function evidenceDocuments(book) {
  const evidence = book.evidence();
  return [JSON.stringify(evidence, null, 2) + '\n', ['# Public AI + advisory translation live acceptance — 2026-10-22', '',
    `Origin: ${ORIGIN}`, `Run: ${book.runId}`, `Actually attempted: ${book.actual}`, '',
    'Only a completed native browser attempt may produce these documents. Require the matching JSON; this summary alone is not acceptance.',
    'Any created disposable accounts/scan are retained (maximum two accounts and one native Node four-check scan). Credentials exist only in process/browser memory.',
    `Qualification: ${book.qualification}. Required cases: ${book.requiredCases.join(', ')}.`,
        book.qualification === 'translation' ? 'Chat generation is NOT qualified or attempted. At most one separately consented translation POST.' : 'Maximum two sequential manual chat POSTs and one separately consented translation POST.',
        'No retry, alternate model, paid fallback, or lifecycle action.',
    'The browser is restricted to loopback 8081. Server egress and billing are NOT independently observed; fixed free policy and server-validated receipts are checked.',
    'Semantic accuracy is unverified by this runner; schema/render/Cyrillic checks are not fidelity proof. Native semantic review is memory-only, without conversation artifacts.',
        'Provider failure status/kind/bounded retry hints are metadata only, not permission to retry or refund unknown liability.',
        'No conversations, provider payloads, raw diagnostics, auth data, HAR, screenshots, traces or storage state are artifacts.', '',
    '| Case | Result | Code |', '| --- | --- | --- |', ...CASES.map(name => `| ${name} | ${evidence.cases[name].status} | ${evidence.cases[name].code} |`), ''].join('\n')];
}
export async function writeEvidence(book, openFile = open) {
  if (!book.actual) throw new Fault('NOT_ACTUALLY_RUN');
  const handles = [], documents = evidenceDocuments(book);
  try {
    for (const path of evidencePaths(book.attemptSuffix)) handles.push(await openFile(path, 'wx', 0o600));
    for (const index of [1, 0]) { await handles[index].writeFile(documents[index]); await handles[index].sync(); }
  } finally { await Promise.all(handles.map(handle => handle.close())); }
}
export function assertFixedPolicy(context) {
  const d = context?.disclosure;
  assert.ok(context?.enabled === true && HASH.test(context.policyVersion));
  assert.ok(d?.provider === 'OpenRouter' && d.model === MODEL && isDeepStrictEqual(d.providers, [ENDPOINT]));
  assert.ok(d.freeOnly === true && d.requestBudgetUsd === 0 && d.retention === 'no-storage' && d.region === 'global');
  assert.ok(d.maxPrice?.prompt === 0 && d.maxPrice.completion === 0 && d.maxPrice.request === 0);
  assert.ok(d.operatorApprovedRouting === true && d.providerComplianceNotProvenByDeclaration === true);
}
export function assertReady(ready, context) {
  assertFixedPolicy(context);
  for (const key of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(ready[key], context[key]);
  assert.ok(ready.localReady === true && ready.credential === 'metadata-valid' && ready.blockers.length === 0);
  assert.ok(ready.requiresConsent === true && ready.acceptsCredentials === false && ready.generationVerified === false);
  assert.ok(ready.provider.model === MODEL && ready.provider.endpoint === ENDPOINT && ready.provider.liveVerified === false);
}
export function chatBodyMatches(body, context, question) {
  return exact(body, ['epoch', 'revision', 'mutationId', 'reportVersion', 'question', 'consent']) &&
    body.epoch === context.epoch && body.revision === context.revision && UUID.test(body.mutationId) &&
    body.reportVersion === context.reportVersion && body.question === question &&
    exact(body.consent, ['accepted', 'policyVersion']) && body.consent.accepted === true && body.consent.policyVersion === context.policyVersion;
}
export function translationBody(context) {
  return { reportVersion: context.reportVersion, findingId: context.findingId, assessmentIndex: context.assessmentIndex,
    sourceVersion: context.sourceVersion, targetLanguage: 'ru', consent: { accepted: true, policyVersion: context.policyVersion } };
}
export function canDispatch(state, path, body, qualification = 'full') {
  if (!['full', 'translation'].includes(qualification) || qualification === 'translation' && path.endsWith('/llm/chat')) return false;
  if (!state.aiOwner || !state.permit || state.permit.used || !state.permit.context) return false;
  if (path.endsWith('/llm/chat')) return state.chatPosts < 2 && chatBodyMatches(body, state.permit.context, state.permit.question);
  if (path.endsWith('/llm/translation')) return state.translationPosts < 1 && isDeepStrictEqual(body, translationBody(state.permit.context));
  return false;
}

export function eligibleAssessment(item) {
  const allowed = (field, ceiling) => field && ['available', 'truncated'].includes(field.state) && !field.redacted &&
    typeof field.value === 'string' && field.value.trim() && Buffer.byteLength(field.value, 'utf8') <= ceiling &&
    !/https?:|mailto:|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/iu.test(field.value);
  return !!(item && (allowed(item.title, 512) || allowed(item.description, 4096)));
}
export function assertInitialUsage(value, binding) {
  const usage = assertChatUsage(value, binding);
  for (const scope of ['user', 'scan']) for (const vector of ['used', 'held', 'carried'])
    assert.deepEqual(usage[scope][vector], { input: 0, output: 0, costMicros: 0 });
  return usage;
}
export function renderedReplyMatches(expected, rendered) {
  const plain = expected.replace(/^\s*```[^\n]*$/gm, '').replace(/^\s*(?:\d+[.)]|[-+])\s+/gm, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
  const words = value => value.normalize('NFC').match(/[\p{L}\p{N}]+/gu) ?? [];
  const wanted = words(plain), visible = words(rendered);
  let index = 0;
  for (const word of visible) if (word === wanted[index]) index++;
  return wanted.length > 0 && index === wanted.length;
}
export function historyMetadata(history) {
  return projectMeta({ historyFingerprint: hash(history), completedTurns: history.turns.filter(turn => turn.state === 'completed').length });
}
export async function loadTranslationContracts() {
  const base = await loadContracts();
  const require = createRequire(join(ROOT, 'server/api/package.json'));
  const manifest = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
  const translation = await tsImport(join(ROOT, 'src/shared/api/scans/advisoryTranslationContract.ts'), { parentURL: import.meta.url, tsconfig: false });
  return { ...base, translation };
}
async function bounded(promise, ms, code = 'GLOBAL_DEADLINE') {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Fault(code)), ms); })]); }
  finally { clearTimeout(timer); }
}
function failureMeta(error) {
  const line = error?.stack?.match(/public-ai-translation-live\.mjs:([0-9]+):[0-9]+/);
  return line ? projectMeta({ runnerLine: Number(line[1]) }) : {};
}
async function runLive(attemptSuffix, qualification = 'full') {
  if (!UUID.test(attemptSuffix)) throw new Fault('INVALID_ARGUMENTS');
  if (['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'PLAYWRIGHT_TRACE_DIR', 'PLAYWRIGHT_BROWSERS_PATH'].some(name => process.env[name])) throw new Fault('UNSAFE_DEBUG_ENVIRONMENT');
  for (const path of evidencePaths(attemptSuffix)) {
    try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') continue; throw new Fault('EVIDENCE_WRITE_FAILED'); }
    throw new Fault('EVIDENCE_ALREADY_EXISTS');
  }
  const book = new ResultBook(attemptSuffix, qualification), handles = [], knownIds = new Set();
  const stats = { accountsCreated: 0, scanLaunches: 0, chatPosts: 0, translationPosts: 0, blockedRequests: 0, pageErrors: 0, ignoredEligibility: 0, runtimeOffReads: 0 };
  const owner = { email: `ai-live-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const foreign = { email: `ai-live-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const target = TARGETS[0];
  let browser, tools, expect, stopped = false, fatal = null, currentCase = 'tooling', browserClosed = false;
  let pendingCreation = Promise.resolve(), activeLaunch = null, snapshot, scanId, rows, selected, baseline, savedHistory, panel;
  let stop;
  const interrupted = new Promise((_, reject) => { stop = code => { fatal = code; stopped = true; reject(new Fault(code)); }; });
  const deadline = setTimeout(() => stop('GLOBAL_DEADLINE'), GLOBAL_MS);
  const signal = () => stop('INTERRUPTED');
  process.once('SIGINT', signal); process.once('SIGTERM', signal); process.once('SIGHUP', signal);
  const live = () => { if (stopped || fatal) throw new Fault(fatal ?? 'INTERRUPTED'); };
  const step = async (name, operation) => {
    live(); currentCase = name;
    try { const result = await operation(); book.record(name, 'PASS', 'VERIFIED', result?.meta); return result?.value ?? true; }
    catch (error) {
      recordFailure(book, name, error);
      if (fatal || stats.blockedRequests) throw error;
      return undefined;
    }
  };
  const arm = (handle, path, matches, extra = {}) => {
    live(); assert.ok(!handle.permit || handle.permit.used);
    handle.permit = { path, used: false, matches, ...extra };
  };
  const responseFor = (page, path, method = 'POST') => page.waitForResponse(response => {
    const u = new URL(response.url()); return fixedUrl(response.url()) && u.pathname === path && response.request().method() === method;
  }, { timeout: 45_000 }).catch(() => null);
  const readResponse = async response => {
    if (!response) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
    const bytes = await bounded(response.body(), 45_000, 'DELIVERY_UNCONFIRMED_NO_RETRY');
    if (bytes.byteLength > 4 * 1024 * 1024) throw new Fault('ASSERTION_FAILED', {}, true);
    let value = null;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { /* Raw body is never emitted. */ }
    return { status: response.status(), value };
  };
  const http = async (page, path) => {
    live(); assert.ok(allowedApiGet(`${ORIGIN}${path}`, knownIds));
    return page.evaluate(async path => {
      const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(40_000) });
      if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) return { status: response.status, value: null };
      const reader = response.body?.getReader(), chunks = []; let size = 0;
      if (!reader) return { status: response.status, value: null };
      try {
        for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
          if (size > 4 * 1024 * 1024) return { status: response.status, value: null }; chunks.push(part.value); }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const part of chunks) { bytes.set(part, offset); offset += part.byteLength; }
        let value = null; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { /* No diagnostics. */ }
        return { status: response.status, value };
      } finally { await reader.cancel().catch(() => {}); }
    }, path);
  };
  const successful = assertLlmSuccess;
  const newPage = async (aiOwner = false) => {
    live();
    const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
    const state = { context, aiOwner, closing: false, permit: null, chatPosts: 0, translationPosts: 0, fence: new EligibilityFence(), eligibilityPending: Promise.resolve(), scanTarget: null };
    handles.push(state);
    const observedRejections = new WeakSet();
    const note = (request, reason) => {
      if (observedRejections.has(request)) return;
      observedRejections.add(request);
      book.guard.record(reason, request.url(), request.method());
      stats.blockedRequests = book.guard.blockedRequests;
      if (!BENIGN_GUARD_REASONS.has(reason)) stop('REQUEST_GUARD');
    };
    await context.route('**/*', async route => {
      const request = route.request(), input = request.url(), method = request.method();
      let approvedRead = false;
      const deny = async reason => { note(request, reason); await route.abort('blockedbyclient').catch(() => {}); };
      try {
        if (!fixedUrl(input)) return deny(routeCategory(input) === 'external' ? 'external-request' : 'local-url-shape');
        const u = new URL(input);
        if (['GET', 'HEAD'].includes(method)) {
          if (method !== 'GET' || !safeReadRequest(input, await request.allHeaders())) return deny('mutation-shape');
          approvedRead = !u.pathname.startsWith('/api/') || allowedApiGet(input, knownIds, method);
          // A just-created scan may navigate before the observed create receipt is decoded.
          if (!approvedRead && activeLaunch && u.pathname.startsWith(`${SCANS}/`)) {
            await bounded(pendingCreation, 45_000).catch(() => {});
            approvedRead = allowedApiGet(input, knownIds, method);
          }
          if (!approvedRead) return deny('api-get-not-allowed');
          if (stopped || state.closing) return deny('controlled-shutdown-read');
          return await route.continue();
        }
        if (stopped || state.closing) return deny('shutdown-request');
        if (method !== 'POST') return deny('method-not-allowed');
        if (!safeMutationRequest(input, await request.allHeaders())) return deny('mutation-shape');
        let body; try { body = request.postDataJSON(); } catch { return deny('mutation-shape'); }
        if (u.pathname === `${SCANS}/images/eligibility`) {
          if (!state.scanTarget || body?.imageReference !== target.reference) { stats.ignoredEligibility++; return await route.abort(); }
          if (!exact(body, ['imageReference', 'checks']) || !Array.isArray(body.checks) || !body.checks.length ||
            !body.checks.every((check, index) => CHECKS.includes(check) && (!index || CHECKS.indexOf(body.checks[index - 1]) < CHECKS.indexOf(check)))) return deny('eligibility-shape');
          // This exact validated POST is a read, not an AI/scan mutation. UI check changes can abort it.
          approvedRead = true;
          const sequence = state.fence.start();
          state.eligibilityPending = (async () => { await route.continue(); const response = await request.response();
            if (response?.status() === 200) state.fence.accept(sequence, body, (await readResponse(response)).value, target); })();
          await state.eligibilityPending; return;
        }
        if (u.pathname === SCANS) {
          if (!state.aiOwner || activeLaunch?.state !== state || !activeLaunch.armed || stats.scanLaunches !== 0 || !validIntent(body, target)) return deny('scan-not-authorized');
          const launch = activeLaunch;
          if (!await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending, () => !stopped && activeLaunch === launch && launch.armed && stats.scanLaunches === 0)) return deny('scan-not-authorized');
          launch.armed = false; stats.scanLaunches++;
          pendingCreation = (async () => { await route.continue(); const response = await request.response();
            if (response?.status() === 202) { const result = await readResponse(response); if (UUID.test(result.value?.scanId)) knownIds.add(result.value.scanId); } })();
          await pendingCreation; return;
        }
        const ai = u.pathname.endsWith('/llm/chat') || u.pathname.endsWith('/llm/translation');
        const auth = ['/api/v1/auth/register', '/api/v1/auth/login'].includes(u.pathname);
        if (!ai && !auth) return deny('mutation-not-permitted');
        if ((qualification === 'translation' && u.pathname.endsWith('/llm/chat')) ||
                  (ai && !canDispatch(state, u.pathname, body, qualification)) ||
          (u.pathname.endsWith('/llm/chat') && stats.chatPosts >= 2) || (u.pathname.endsWith('/llm/translation') && stats.translationPosts >= 1)) return deny('ai-permit-or-limit');
        if (!consumePermit(state.permit, method, u.pathname, body)) return deny('mutation-not-permitted');
        if (u.pathname.endsWith('/llm/chat')) { state.chatPosts++; stats.chatPosts++; }
        if (u.pathname.endsWith('/llm/translation')) { state.translationPosts++; stats.translationPosts++; }
        await route.continue();
      } catch (error) {
        const aborted = request.failure()?.errorText === 'net::ERR_ABORTED' || error?.name === 'AbortError';
        await deny(guardAbortReason({ approvedRead, closing: state.closing, aborted }));
      }
    });
    context.on('request', request => { if (!fixedUrl(request.url())) note(request, routeCategory(request.url()) === 'external' ? 'external-request' : 'local-url-shape'); });
    context.on('response', response => { if (fixedUrl(response.url())) book.actual = true;
      if (runtimeProbeRead(response.url(), response.request().method())) {
        try { assertRuntimeOffReply(response.url(), response.request().method(), response.status()); stats.runtimeOffReads++; }
        catch { book.record('safety', 'FAIL', 'RUNTIME_NOT_OFF', { httpStatus: response.status() }); stop('RUNTIME_NOT_OFF'); }
      }
      if (response.status() >= 300 && response.status() < 400) note(response.request(), 'redirect'); });
    await context.routeWebSocket('**/*', socket => { book.guard.record('websocket', socket.url(), 'OTHER'); stats.blockedRequests = book.guard.blockedRequests; stop('REQUEST_GUARD'); socket.close(); });
    context.on('page', page => { page.on('pageerror', () => { stats.pageErrors++; }); page.on('download', download => { book.guard.record('download', page.url(), 'GET'); stats.blockedRequests = book.guard.blockedRequests; stop('REQUEST_GUARD'); void download.cancel().catch(() => {}); }); });
    state.page = await context.newPage(); state.page.setDefaultTimeout(15_000); state.page.setDefaultNavigationTimeout(20_000);
    return state;
  };
  const auth = async (handle, account, action) => {
    await handle.page.goto(`${ORIGIN}/${action}`);
    await handle.page.getByLabel('Email', { exact: true }).fill(account.email);
    await handle.page.getByLabel('Пароль', { exact: true }).fill(account.password);
    if (action === 'register') assert.ok(stats.accountsCreated < 2);
    arm(handle, `/api/v1/auth/${action}`, value => exact(value, ['email', 'password']) && value.email === account.email && value.password === account.password);
    const pending = responseFor(handle.page, `/api/v1/auth/${action}`);
    await handle.page.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти', exact: true }).click();
    const response = await pending;
    assert.equal(response?.status(), action === 'register' ? 201 : 200);
    if (action === 'register') stats.accountsCreated++;
    const me = await http(handle.page, '/api/v1/auth/me'); assert.equal(me.status, 200);
    account.subject = assertAuthUser(me.value, account.email, account.subject);
  };
  const readStatus = async page => {
    const response = await http(page, `${SCANS}/${scanId}`); assert.equal(response.status, 200);
    const value = tools.decoder.parseCurrentStatus(response.value);
    assert.equal(value.scanId, scanId); assert.equal(value.profile, 'public-hub-amd64-v1'); assert.deepEqual(value.checks, CHECKS);
    if (TERMINAL.has(value.state)) snapshot = value;
    return value;
  };
  const readFindings = async page => {
    const query = { view: 'report-v1', limit: 50, sort: 'severity:desc' };
    return readAllPages('vuln', { whole: snapshot.perCheck.vuln.findingCount, matched: snapshot.perCheck.vuln.findingCount }, async cursor => {
      const response = await http(page, `${SCANS}/${scanId}/vuln?${tools.view.reportViewSearch('vuln', query, cursor)}`); assert.equal(response.status, 200);
      const value = tools.decoder.parseCurrentVuln(response.value, query, cursor);
      assert.equal(value.image, snapshot.imageReference); assert.equal(value.platform, snapshot.platform);
      assert.deepEqual(value.identifierCounts, snapshot.identifierCounts);
      return value;
    });
  };
  const readChat = async page => {
    const context = tools.chat.chatContextSchema.parse(successful(await http(page, `${SCANS}/${scanId}/llm/chat/context`)));
    const history = tools.chat.chatHistorySchema.parse(successful(await http(page, `${SCANS}/${scanId}/llm/history`)));
    assert.equal(context.scanId, scanId); assert.equal(context.digest, snapshot.digest); assert.equal(context.platform, snapshot.platform);
    assert.equal(history.epoch, context.epoch); assert.equal(history.revision, context.revision);
    return { context, history };
  };
  const usageFor = async (page, context) => {
      const value = successful(await http(page, `${SCANS}/${scanId}/llm/chat/usage`));
      if (value?.available !== true) throw new Fault('READINESS_BLOCKED');
      return assertChatUsage(value, context);
    };
    const readyFor = async (page, context) => {
    const ready = tools.chat.chatReadinessSchema.parse(successful(await http(page, `${SCANS}/${scanId}/llm/readiness`)));
    if (!ready.localReady) throw new Fault('READINESS_BLOCKED');
    try { assertReady(ready, context); } catch { throw new Fault('FIXED_POLICY_REQUIRED'); }
    return ready;
  };
  const openChat = async page => {
    const region = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
    await region.getByRole('button', { name: 'Открыть чат и прочитать условия', exact: true }).click();
    await expect(region.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toBeVisible();
    await expect(region.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ })).not.toBeChecked();
    return region;
  };
  const assertHistoryUi = async (region, history) => {
    for (const turn of history.turns) {
      const article = region.locator('article').filter({ has: region.getByText(turn.question, { exact: true }) });
      await expect(article).toHaveCount(1);
      if (turn.state === 'completed') {
        await expect(article.getByRole('heading', { name: 'Гипотеза · не доказанный факт', exact: true })).toBeVisible();
        // The copy control is inside the rendered SafeMarkdown message, not inside citations.
        const message = article.getByRole('button', { name: 'Скопировать текст', exact: true }).locator('..');
        assert.ok(renderedReplyMatches(turn.reply.text, await message.innerText()));
        for (const source of turn.reply.sources) await expect(article.getByRole('link', { name: `Находка ${source.finding.findingId}`, exact: true })).toBeVisible();
      }
    }
    await expect(region.getByRole('heading', { name: 'Гипотеза · не доказанный факт', exact: true })).toHaveCount(history.turns.filter(turn => turn.state === 'completed').length);
  };
  const translationPath = () => `${SCANS}/${scanId}/llm/translation/context?findingId=${selected.row.findingId}&assessmentIndex=${selected.index}`;
  const translationPanel = async page => {
    const row = page.locator('li.scan-vuln-row').filter({ hasText: `ID находки: ${selected.row.findingId}` });
    if (!await row.count()) throw new Fault('NO_ELIGIBLE_ASSESSMENT');
    await row.locator('details.scan-vuln-row__details > summary').click();
    return row.getByRole('region', { name: `Перевод ${selected.row.cveId}, источник ${selected.item.source}, оценка ${selected.index + 1}`, exact: true });
  };
  let own, chatPin;
  try {
    await Promise.race([interrupted, (async () => {
      if (!await step('tooling', async () => {
        tools = await loadTranslationContracts();
        const { chromium, expect: baseExpect } = await import('@playwright/test'); expect = baseExpect.configure({ timeout: 15_000 });
        const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
        try { browser = await chromium.launch({ headless: true, timeout: 20_000, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false, env, args: [...BROWSER_ARGS] }); }
        catch { throw new Fault('BROWSER_UNAVAILABLE'); }
      })) return;
      own = await newPage(true);
      if (!await step('owner_registration', () => auth(own, owner, 'register'))) return;
      const scanOk = await step('native_scan', async () => {
        own.scanTarget = target;
        await own.page.goto(`${ORIGIN}/scans/new`);
        await own.page.getByRole('textbox', { name: 'Canonical reference Docker Hub', exact: true }).fill(target.reference);
        for (const check of CHECKS) await own.page.locator(`input[name="checks"][value="${check}"]`).check();
        await bounded(own.eligibilityPending, 35_000);
        const consent = own.page.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
        await expect(consent).not.toBeChecked(); await consent.check();
        const submit = own.page.getByRole('button', { name: 'Запустить скан', exact: true });
        await expect(submit).toBeEnabled();
        activeLaunch = { state: own, armed: true, sequence: own.fence.sequence };
        const pending = responseFor(own.page, SCANS); await submit.click();
        const response = await pending; await pendingCreation.catch(() => {});
        if (response?.status() !== 202) throw new Fault('LAUNCH_UNCONFIRMED_NO_RETRY');
        const receipt = await readResponse(response); scanId = receipt.value?.scanId;
        assert.ok(UUID.test(scanId) && knownIds.has(scanId)); activeLaunch = null;
        const end = Date.now() + WORKER_MS;
        do { live(); const value = await readStatus(own.page); if (TERMINAL.has(value.state)) break; await pause(1500); } while (Date.now() < end);
        if (!snapshot) throw new Fault('WORKER_DEADLINE_NO_RELAUNCH', { scanId });
        if (snapshot.state !== 'completed' || !CHECKS.every(check => snapshot.perCheck?.[check]?.outcome === 'checked'))
          throw new Fault('REQUIRED_CHECK_NOT_CHECKED', { scanId, state: snapshot.state });
        return { meta: { scanId, digest: snapshot.digest, platform: snapshot.platform, state: snapshot.state } };
      });
      if (!scanOk) return;
      const reportOk = await step('report', async () => {
        const result = await readFindings(own.page); rows = result.rows;
        const counts = partition(rows); assert.deepEqual(counts, snapshot.identifierCounts);
        baseline = hash({ snapshot, rows });
        // Match the UI's initial report page; do not dispatch an invisible/off-page assessment.
        for (const row of rows.slice(0, 25)) for (const [index, item] of (row.advisory?.assessments ?? []).entries())
          if (!selected && eligibleAssessment(item)) selected = { row, index, item };
        return { meta: { cve: counts.cve, debianTemp: counts.debianTemp, vulnerabilities: rows.length, pages: result.pages } };
      });
      if (!reportOk) return;
      if (!await step('deployed_ui', async () => {
        if (!selected) throw new Fault('NO_ELIGIBLE_ASSESSMENT');
        const region = await translationPanel(own.page);
        if (!await region.getByRole('button', { name: 'Прочитать условия перевода', exact: true }).count()) throw new Fault('UI_NOT_DEPLOYED');
        await expect(region.getByRole('button', { name: 'Перевести на русский', exact: true })).toBeDisabled();
        await selectedOriginalVisible(own.page, selected, expect);
      })) return;
      if (qualification === 'full') {
            const readyOk = await step('readiness', async () => {
        panel = await openChat(own.page);
        const before = await readChat(own.page); await readyFor(own.page, before.context);
        assert.equal(before.history.turns.length, 0); assert.equal(before.history.decisions.length, 0);
        chatPin = before.context.policyVersion;
        await expect(panel.getByRole('button', { name: 'Отправить вопрос', exact: true })).toBeDisabled();
        return { meta: { credential: 'metadata-valid', reportVersion: before.context.reportVersion, policyVersion: chatPin } };
      });
      for (const [index, question] of QUESTIONS.entries()) await step(`chat_${index + 1}`, async () => {
        if (!readyOk || (index === 1 && book.cases.chat_1.status !== 'PASS')) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = await readChat(own.page); await readyFor(own.page, before.context);
        if (before.context.policyVersion !== chatPin || before.context.pending) throw new Fault('CONTEXT_CHANGED');
        assert.equal(before.history.turns.length, index);
        const usageBefore = await usageFor(own.page, before.context);
        if (index === 0) {
          assertInitialUsage(usageBefore, before.context);
          book.record('readiness', 'PASS', 'VERIFIED', { ...book.cases.readiness, initialUsageZero: true });
        }
        await panel.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(question);
        const consent = panel.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ });
        const submit = panel.getByRole('button', { name: 'Отправить вопрос', exact: true });
        await expect(consent).not.toBeChecked(); await expect(submit).toBeDisabled(); await consent.check(); await expect(submit).toBeEnabled();
        const path = `${SCANS}/${scanId}/llm/chat`;
        arm(own, path, body => chatBodyMatches(body, before.context, question), { context: before.context, question });
        const pending = responseFor(own.page, path); await submit.click(); const response = await pending;
        if (!response) throw new Fault('DELIVERY_UNCONFIRMED_NO_RETRY');
        if (response.status() !== 200) { successful(await readResponse(response)); }
        const request = response.request().postDataJSON();
        assert.match(response.headers()['content-type'] ?? '', /^application\/x-ndjson(?:;|$)/i);
                const data = await bounded(response.body(), 45_000, 'DELIVERY_UNCONFIRMED_NO_RETRY');
        assert.ok(data.length <= tools.chat.CHAT_DELIVERY.totalBytes);
        const parser = tools.chat.createChatFrameParser(before.context, request.mutationId);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(data); assert.ok(text.endsWith('\n'));
        for (const line of text.slice(0, -1).split('\n')) { assert.ok(Buffer.byteLength(line) < tools.chat.CHAT_DELIVERY.lineBytes); parser.accept(JSON.parse(line)); }
        const delivered = parser.finish();
        if ('errorCode' in delivered) throw new Fault('LLM_HTTP_ERROR', llmFailureMeta(200, delivered, 'ndjson-error'));
        const after = await readChat(own.page);
        const turn = after.history.turns.find(turn => turn.mutationId === request.mutationId);
        assert.ok(turn?.state === 'completed' && turn.question === question); assert.deepEqual(turn.reply, delivered.reply);
        assert.equal(after.context.policyVersion, chatPin); assert.equal(after.history.turns.length, index + 1);
        await expect(panel.getByRole('heading', { name: 'Гипотеза · не доказанный факт', exact: true })).toHaveCount(index + 1, { timeout: 45_000 });
        await assertHistoryUi(panel, after.history); await expect(consent).not.toBeChecked(); await expect(submit).toBeDisabled();
        const usageAfter = await usageFor(own.page, after.context);
        for (const scope of ['user', 'scan']) { assert.equal(usageBefore[scope].used.costMicros, 0); assert.equal(usageAfter[scope].used.costMicros, 0); }
        savedHistory = after.history;
        return { meta: { ...historyMetadata(savedHistory), turnId: turn.id, input: delivered.usage.input, output: delivered.usage.output,
          costMicros: delivered.usage.costMicros, explicitConsent: true } };
      });
      await step('history_reload', async () => {
        if (!savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = stats.chatPosts; await own.page.reload(); panel = await openChat(own.page);
        const current = await readChat(own.page); assert.deepEqual(current.history, savedHistory); await assertHistoryUi(panel, current.history);
        assert.equal(stats.chatPosts, before); return { meta: { ...historyMetadata(current.history), historyUnchanged: true, noAdditionalPosts: true } };
      });
      }
            const loginOk = await step('fresh_login', async () => {
        own.closing = true; await own.context.close(); own = await newPage(true);
        assert.equal((await own.context.cookies()).length, 0);
        await own.page.goto(`${ORIGIN}/login`);
        assert.equal((await http(own.page, `${SCANS}/${scanId}`)).status, 401);
        await auth(own, owner, 'login'); await own.page.goto(`${ORIGIN}/scans/${scanId}`);
      });
      if (qualification === 'full') await step('history_fresh_login', async () => {
        if (!loginOk || !savedHistory || book.cases.chat_2.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
        panel = await openChat(own.page);
        const current = await readChat(own.page); assert.deepEqual(current.history, savedHistory); await assertHistoryUi(panel, current.history);
        await expect(panel.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ })).not.toBeChecked();
        return { meta: { ...historyMetadata(current.history), historyUnchanged: true, noAdditionalPosts: true } };
      });
      const other = await newPage(false);
      const foreignOk = await step('foreign_registration', () => auth(other, foreign, 'register'));
      await step('foreign_denial', async () => {
        if (!foreignOk) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = stats.chatPosts + stats.translationPosts;
        for (const suffix of ['', '/llm/history', '/llm/chat/context', '/llm/readiness']) assertDeniedReply(await http(other.page, `${SCANS}/${scanId}${suffix}`), 404);
        assertDeniedReply(await http(other.page, translationPath()), 404);
        await other.page.goto(`${ORIGIN}/scans/${scanId}`);
        await expect(other.page.getByRole('region', { name: 'Чат по отчёту', exact: true })).toHaveCount(0);
        await expect(other.page.locator('li.scan-vuln-row')).toHaveCount(0);
        assert.equal(stats.chatPosts + stats.translationPosts, before);
        return { meta: { httpStatus: 404, noAdditionalPosts: true } };
      });
      let translationContext, translationRegion, translated;
      const contextOk = await step('translation_context', async () => {
        if (!loginOk || !selected || !canRunTranslation(book)) throw new Fault('PREREQUISITE_UNAVAILABLE');
        // Translation has its own context/readiness and never retries or depends on chat delivery.
        translationRegion = await translationPanel(own.page);
        await translationRegion.getByRole('button', { name: 'Прочитать условия перевода', exact: true }).click();
        translationContext = tools.translation.translationContextSchema.parse(successful(await http(own.page, translationPath())));
        await readyFor(own.page, translationContext);
        assert.equal(translationContext.findingId, selected.row.findingId); assert.equal(translationContext.assessmentIndex, selected.index);
        assert.deepEqual(translationContext.source, { source: selected.item.source, provenanceRef: selected.item.provenanceRef, language: selected.item.language });
        if (chatPin) assert.notEqual(translationContext.policyVersion, chatPin);
        const digest = hash(['selected-advisory-ru-v1', selected.row.cveId, selected.item]);
        assert.equal(translationContext.sourceVersion, digest);
        const consent = translationRegion.getByRole('checkbox', { name: /Разрешаю один запрос перевода:/ });
        await expect(consent).toBeEnabled(); await expect(consent).not.toBeChecked();
        await expect(translationRegion.getByRole('button', { name: 'Перевести на русский', exact: true })).toBeDisabled();
        return { meta: { findingId: selected.row.findingId, assessmentIndex: selected.index, sourceVersion: digest,
          reportVersion: translationContext.reportVersion, policyVersion: translationContext.policyVersion } };
      });
      const translatedOk = await step('translation', async () => {
        if (!contextOk) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = tools.translation.translationContextSchema.parse(successful(await http(own.page, translationPath())));
        assert.deepEqual(before, translationContext); await readyFor(own.page, before);
                const usageBefore = await usageFor(own.page, before);
        const consent = translationRegion.getByRole('checkbox', { name: /Разрешаю один запрос перевода:/ });
        await expect(consent).not.toBeChecked(); await consent.check();
        const path = `${SCANS}/${scanId}/llm/translation`;
        arm(own, path, body => isDeepStrictEqual(body, translationBody(before)), { context: before });
        const pending = responseFor(own.page, path);
        await translationRegion.getByRole('button', { name: 'Перевести на русский', exact: true }).click();
        translated = tools.translation.translationReplySchema.parse(successful(await readResponse(await pending)));
        assert.ok(tools.translation.sameTranslationBinding(translated, before)); assert.equal(translated.model, MODEL); assert.equal(translated.provider, 'OpenRouter');
        assert.ok(/[А-Яа-яЁё]{3}/u.test([translated.translation.title, translated.translation.description].filter(Boolean).join(' ')));
        await expect(translationRegion).toContainText('Машинный перевод на русский · не официальный текст NVD или БДУ', { timeout: 45_000 });
        for (const text of Object.values(translated.translation).filter(value => value !== null)) await expect(translationRegion).toContainText(text);
        await selectedOriginalVisible(own.page, selected, expect);
        await expect(consent).not.toBeChecked();
        const usageAfter = await usageFor(own.page, before);
        for (const scope of ['user', 'scan']) { assert.equal(usageBefore[scope].used.costMicros, 0); assert.equal(usageAfter[scope].used.costMicros, 0); }
        return { meta: { findingId: before.findingId, assessmentIndex: before.assessmentIndex, sourceVersion: before.sourceVersion, explicitConsent: true, originalUnchanged: true } };
      });
      await step('translation_toggle', async () => {
        if (!translatedOk) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const before = stats.translationPosts;
        await translationRegion.getByRole('button', { name: 'Оригинал', exact: true }).click();
        await expect(translationRegion).toContainText('Показан оригинальный текст источника выше.');
        await selectedOriginalVisible(own.page, selected, expect);
        await translationRegion.getByRole('button', { name: 'Перевод', exact: true }).click();
        for (const text of Object.values(translated.translation).filter(value => value !== null)) await expect(translationRegion).toContainText(text);
        assert.equal(stats.translationPosts, before); return { meta: { originalUnchanged: true, noAdditionalPosts: true } };
      });
      await step('preservation', async () => {
        if (!loginOk || !baseline) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const original = snapshot; const current = await readStatus(own.page); assert.deepEqual(current, original);
        const result = await readFindings(own.page); assert.equal(hash({ snapshot: current, rows: result.rows }), baseline);
        const counts = partition(result.rows); assert.deepEqual(counts, original.identifierCounts);
        if (savedHistory) assert.deepEqual((await readChat(own.page)).history, savedHistory);
        return { meta: { cve: counts.cve, debianTemp: counts.debianTemp, countsUnchanged: true, originalUnchanged: true } };
      });
    })()]);
  } catch (error) {
    recordFailure(book, currentCase, error, fatal);
  } finally {
    stopped = true; for (const handle of handles) handle.closing = true; clearTimeout(deadline); process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); process.removeListener('SIGHUP', signal);
    try { await bounded(Promise.allSettled(handles.map(handle => handle.context.close())), 10_000); if (browser) await bounded(browser.close(), 10_000); browserClosed = !browser || !browser.isConnected(); }
    catch { browserClosed = false; }
    const bad = !browserClosed || stats.blockedRequests || stats.pageErrors || stats.accountsCreated > 2 || stats.scanLaunches > 1 || stats.chatPosts > (qualification === 'translation' ? 0 : 2) || stats.translationPosts > 1;
    book.record('safety', bad ? 'FAIL' : 'PASS', !browserClosed ? 'CLEANUP_FAILED' : stats.blockedRequests ? 'REQUEST_GUARD' : stats.pageErrors ? 'PAGE_ERRORS' : bad ? 'ASSERTION_FAILED' : 'VERIFIED',
      { ...stats, browserClosed, nativeScanMayRemainActive: stats.scanLaunches > 0 && !snapshot });
    book.finishedAt = new Date().toISOString();
    if (book.actual) { try { await writeEvidence(book); } catch { book.record('safety', 'FAIL', 'EVIDENCE_WRITE_FAILED'); } }
    console.log(JSON.stringify(book.evidence(), null, 2));
  }
  return exitCode(book);
}
async function selectedOriginalVisible(page, selected, expect) {
  const row = page.locator('li.scan-vuln-row').filter({ hasText: `ID находки: ${selected.row.findingId}` });
  const source = row.locator('div[aria-label^="Источник "]').nth(selected.index);
    await expect(source).toContainText(selected.item.provenanceRef);
  for (const field of ['title', 'description']) if (selected.item[field].value !== null) await expect(source).toContainText(selected.item[field].value);
  await expect(source).toContainText(`Язык источника: ${selected.item.language ?? 'не указан'}`);
}
async function main() {
  let mode;
  try { mode = parseMode(process.argv.slice(2)); } catch { console.log(JSON.stringify({ status: 'BLOCKED', code: 'INVALID_ARGUMENTS', actuallyRun: false })); return 2; }
  if (mode === 'not-run') { console.log(JSON.stringify({ status: 'BLOCKED', code: 'NOT_RUN', actuallyRun: false, requiresCoordinatorReadyGo: true })); return 2; }
  if (mode === 'offline') {
    assert.equal(parseMode([]), 'not-run'); assert.throws(() => parseMode(['--run']));
    assert.equal(allowedApiGet('http://127.0.0.1:8080/api/v1/auth/me', []), false);
    assert.deepEqual(projectMeta({ password: 'synthetic', text: 'synthetic', apiKey: 'synthetic' }), {});
    console.log(JSON.stringify({ status: 'PASS', scope: 'OFFLINE_GUARDS_ONLY', actuallyRun: false, networkRequests: 0, evidenceWritten: false })); return 0;
  }
  try { return await runLive(process.argv.at(-1), mode === 'translation-final' ? 'translation' : 'full'); }
  catch (error) { console.log(JSON.stringify({ status: 'BLOCKED', code: error instanceof Fault ? error.message : 'ASSERTION_FAILED', actuallyRun: false, rawDiagnosticsSuppressed: true })); return 2; }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main();
