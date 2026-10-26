// Native acceptance only. No stand lifecycle, fixture server, mock response or saved credentials.
// LIVE (only after coordinator GO; key activation must stay fenced throughout this run):
// node tests-e2e/public-product-live.mjs --run --ack-coordinator-go --ack-no-key-activation --attempt-id <new UUID>
// ONE-SCAN SMOKE (same GO fence, no LLM mutations):
// node tests-e2e/public-product-live.mjs --run --smoke-only --ack-coordinator-go --ack-no-key-activation --attempt-id <new UUID>
// CANCEL ONLY (one scan, all LLM POSTs denied; supplied key presence is irrelevant):
// node tests-e2e/public-product-live.mjs --run --cancel-only --ack-coordinator-go --ack-no-key-activation --attempt-id <new UUID>
// OFFLINE: node tests-e2e/public-product-live.mjs --self-test
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { lstat, open } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

export const ORIGIN = 'http://127.0.0.1:8081';
export const CHECKS = Object.freeze(['secret', 'sbom', 'vuln', 'config']);
export const TARGETS = Object.freeze([
  Object.freeze({ name: 'node', reference: 'registry-1.docker.io/library/node:22.14.0-alpine3.21', os: 'alpine' }),
  Object.freeze({ name: 'debian', reference: 'registry-1.docker.io/library/debian:bookworm-slim', os: 'debian' }),
]);
export const SCANS = '/api/v1/browser/scans';
export const WORKER_MS = 660_000;
export const GLOBAL_MS = 2_520_000; // 42 min: two full attempts, one cancel attempt, bounded UI/HTTP.
export const SMOKE_MS = 900_000; // One full native attempt plus bounded browser/report checks.
export const CANCEL_MS = 900_000; // First-subset observation, one UI cancel, durable reads; never relaunch.
// The browser proxy is a second fence for redirects, which Playwright routing does not
// reliably intercept on every hop. No other loopback port is implicitly bypassed.
export const BROWSER_ARGS = Object.freeze(['--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--no-first-run',
  '--proxy-server=http://public-product-denied.invalid:1', '--proxy-bypass-list=<-loopback>;127.0.0.1:8081',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);
const OUTCOMES = new Set(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']);
const BLOCKERS = new Set(['configuration-required', 'public-key-required', 'public-key-unsafe', 'quota-store-unavailable', 'history-store-unavailable', 'provider-profile-unavailable']);
const CODES = new Set(['NOT_RUN', 'VERIFIED', 'INVALID_ARGUMENTS', 'STAND_OR_BROWSER_UNAVAILABLE', 'ELIGIBILITY_NOT_READY', 'LAUNCH_UNCONFIRMED_NO_RETRY', 'WORKER_DEADLINE_NO_RELAUNCH', 'REQUIRED_CHECK_NOT_CHECKED', 'PREREQUISITE_UNAVAILABLE', 'ASSERTION_FAILED', 'REQUEST_GUARD', 'GLOBAL_DEADLINE', 'INTERRUPTED', 'CLEANUP_FAILED', 'PAGE_ERRORS', 'EVIDENCE_ALREADY_EXISTS', 'EVIDENCE_WRITE_FAILED', 'NO_SECOND_PAGE', 'SSE_NOT_OBSERVED', 'CANCEL_RACE', 'NO_COMPLETED_SUBSET_OBSERVED', 'SUBSET_CAPTURE_CHANGED', 'UNSAFE_DEBUG_ENVIRONMENT', 'KEY_ABSENT', 'KEY_NOT_ABSENT_NO_POST', 'LLM_STORES_OR_CONTEXT_UNAVAILABLE', 'NO_EVIDENCE', 'CONTEXT_LIMIT', 'GENERATION_NOT_AUTHORIZED', 'QUOTA_WINDOW_CHANGED', 'QUOTA_UNAVAILABLE', 'INCOMPLETE_PAGINATION_COVERAGE', 'RUNTIME_NOT_OFF', 'PROGRESS_NOT_OBSERVED', 'BROWSER_READ_FAILED']);
const CASES = ['tooling', 'registration', ...TARGETS.flatMap(t => ['scan', 'report', 'pagination', 'filters', 'events', 'reload'].map(s => `${t.name}.${s}`)), 'scan_history', 'foreign_registration', 'ownership', 'anonymous', 'ownership_mutations', 'anonymous_mutations', 'llm_readiness', 'llm_no_consent', 'llm_missing_key', 'llm_manual_history', 'llm_reload', 'fresh_login', 'llm_fresh_login', 'llm_generation', 'cancel', 'cancel_preservation', 'cancel_history', 'cancel_fresh_login', 'safety'];
const SMOKE_CASES = ['tooling', 'registration', 'node.scan', 'node.report', 'node.filters', 'node.reload', 'scan_history', 'llm_readiness', 'llm_reload', 'fresh_login', 'llm_fresh_login', 'llm_generation', 'safety'];
const CANCEL_CASES = ['tooling', 'registration', 'cancel', 'cancel_progress', 'cancel_report', 'cancel_preservation', 'cancel_reload', 'cancel_history', 'cancel_fresh_login', 'safety'];
const EVIDENCE = ['public-product-browser-20261021.json', 'public-product-browser-20261021.md'].map(name => join(ROOT, 'docs', name));
const SMOKE_EVIDENCE_ROOT = 'docs/public8081launch-20261022.attempt2';
const SMOKE_EVIDENCE = ['json', 'md'].map(extension => join(ROOT, `${SMOKE_EVIDENCE_ROOT}.${extension}`));
export function nativePlan(mode = 'native', attemptId = null) {
  assert.ok(['native', 'smoke', 'cancel'].includes(mode));
  const smokeOnly = mode === 'smoke', cancelOnly = mode === 'cancel';
  if (cancelOnly && attemptId === null) throw new Error('INVALID_ARGUMENTS');
  if (attemptId !== null && !UUID.test(attemptId)) throw new Error('INVALID_ARGUMENTS');
  const finalRoot = attemptId === null ? null : `docs/public-final-${attemptId}-${mode}`;
  return Object.freeze({ mode, smokeOnly, cancelOnly, targets: Object.freeze(smokeOnly || cancelOnly ? [TARGETS[0]] : [...TARGETS]),
    maxScans: smokeOnly || cancelOnly ? 1 : 3, globalMs: cancelOnly ? CANCEL_MS : smokeOnly ? SMOKE_MS : GLOBAL_MS,
    attemptId, evidenceRoot: finalRoot ?? (smokeOnly ? SMOKE_EVIDENCE_ROOT : 'docs/public-product-browser-20261021'),
    cases: Object.freeze([...(cancelOnly ? CANCEL_CASES : smokeOnly ? SMOKE_CASES : CASES)]), evidencePaths: Object.freeze(finalRoot ? ['json', 'md'].map(ext => join(ROOT, `${finalRoot}.${ext}`)) : [...(smokeOnly ? SMOKE_EVIDENCE : EVIDENCE)]) });
}
export function scanLaunchAllowed(plan, target, launches) {
  return plan.targets.includes(target) && Number.isSafeInteger(launches) && launches >= 0 && launches < plan.maxScans;
}
export function smokeMutationAllowed(path) {
  return ['/api/v1/auth/register', '/api/v1/auth/login', SCANS, `${SCANS}/images/eligibility`].includes(path);
}
export function cancelMutationAllowed(path, ids) {
  if (smokeMutationAllowed(path)) return true;
  for (const id of ids) if (UUID.test(id) && path === `${SCANS}/${id}/cancel`) return true;
  return false;
}
export function completedChecks(snapshot) {
  return CHECKS.filter(key => snapshot?.perCheck?.[key]?.outcome === 'checked');
}
export function durableProgress(value) {
  assert.ok(exact(value, ['basis', 'requestedChecks', 'outcomes', 'resolvedChecks', 'checkedChecks']));
  assert.equal(value.basis, 'durable-outcomes-v1'); assert.ok(sameChecks(value.requestedChecks));
  assert.ok(value.outcomes && typeof value.outcomes === 'object' && !Array.isArray(value.outcomes));
  assert.ok(Object.keys(value.outcomes).every(key => CHECKS.includes(key) && (value.outcomes[key] === null || OUTCOMES.has(value.outcomes[key]))));
  const outcomes = Object.fromEntries(CHECKS.filter(key => Object.hasOwn(value.outcomes, key)).map(key => [key, value.outcomes[key]]));
  assert.equal(value.resolvedChecks, Object.values(outcomes).filter(outcome => outcome !== null).length);
  assert.equal(value.checkedChecks, Object.values(outcomes).filter(outcome => outcome === 'checked').length);
  return { basis: 'durable-outcomes-v1', requestedChecks: [...CHECKS], outcomes, resolvedChecks: value.resolvedChecks, checkedChecks: value.checkedChecks };
}
export function checkpointChecks(snapshot) {
  const progress = snapshot?.progress ? durableProgress(snapshot.progress) : null;
  return progress ? CHECKS.filter(key => progress.outcomes[key] === 'checked') : [];
}
export function cancelObservation(snapshot) {
  return TERMINAL.has(snapshot?.state) ? 'terminal' : checkpointChecks(snapshot).length ? 'ready' : 'waiting';
}
export function assertCancelOutcomePreservation(before, after) {
  assert.equal(before.state, 'running'); assert.equal(after.state, 'cancelled');
  for (const key of ['scanId', 'imageReference', 'digest', 'platform']) assert.equal(after[key], before[key]);
  assert.ok(Object.values(before.perCheck ?? {}).every(value => value == null));
  assert.equal(before.config, undefined);
  const earlier = durableProgress(before.progress), published = durableProgress(after.progress);
  assert.ok(earlier.checkedChecks > 0);
  for (const key of CHECKS) {
    if (earlier.outcomes[key] != null) assert.equal(published.outcomes[key], earlier.outcomes[key]);
    assert.equal(published.outcomes[key] ?? null, after.perCheck?.[key]?.outcome ?? null);
  }
}
const QUESTION = 'Какие ограничения покрытия этого отчёта нужно учесть при ручной проверке?';
const DECISION = 'Проверить приоритеты находок вручную; это решение пользователя, не вывод сканера.';

export function parseMode(args) {
  if (isDeepStrictEqual(args, ['--self-test'])) return 'offline';
  if (args.length >= 2 && args.at(-2) === '--attempt-id' && UUID.test(args.at(-1))) {
    const flags = args.slice(0, -2);
    if (isDeepStrictEqual(flags, ['--run', '--ack-coordinator-go', '--ack-no-key-activation'])) return 'native';
    if (isDeepStrictEqual(flags, ['--run', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation'])) return 'smoke';
        if (isDeepStrictEqual(flags, ['--run', '--cancel-only', '--ack-coordinator-go', '--ack-no-key-activation'])) return 'cancel';
  }
  if (!args.length) return 'not-run';
  throw new Error('INVALID_ARGUMENTS');
}
export function fixedUrl(input) {
  try { const u = new URL(input); return input.startsWith(`${ORIGIN}/`) && u.origin === ORIGIN && !u.username && !u.password && !u.hash; }
  catch { return false; }
}
export function runtimeProbeRead(input, method = 'GET') {
  if (method !== 'GET' || !fixedUrl(input)) return false;
  const url = new URL(input);
  return !input.includes('?') && !url.search && ['/api/v1/browser/runtime/capabilities', '/api/v1/browser/runtime/targets', '/api/v1/browser/runtime/captures'].includes(url.pathname);
}
export function assertRuntimeOffReply(input, method, status) {
  assert.ok(runtimeProbeRead(input, method));
  assert.equal(status, 404);
}
// Derived from httpScanTransport/reportView/advisoryTranslationClient, not a route-prefix bypass.
export function allowedApiGet(input, ids, method = 'GET') {
  if (!fixedUrl(input) || method !== 'GET') return false;
  const url = new URL(input), path = url.pathname, params = url.searchParams;
  const keys = [...params.keys()];
  if (new Set(keys).size !== keys.length) return false;
  const cursor = params.get('cursor');
  if (cursor !== null && (!cursor.length || cursor.length > 512 || /[\x00-\x20\x7f]/.test(cursor))) return false;
  if (path.startsWith('/api/v1/browser/runtime')) return runtimeProbeRead(input, method);
  if (path === '/api/v1/auth/me') return !url.search;
  if (path === SCANS) return !url.search || params.get('limit') === '100' && keys.every(key => ['limit', 'cursor'].includes(key));
  for (const id of ids) {
    if (!UUID.test(id)) continue;
    const base = `${SCANS}/${id}`;
    if (path === `${base}/llm/summary`) return !url.search && !input.includes('?');
    if (['', '/events', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage'].some(suffix => path === base + suffix)) return !url.search;
    if (path === `${base}/llm/translation/context`) return keys.length === 2 &&
      /^vuln-[a-f0-9]{64}$/.test(params.get('findingId') ?? '') && /^(?:[0-9]|1[0-5])$/.test(params.get('assessmentIndex') ?? '');
    const kind = ({ [`${base}/results`]: 'secret', [`${base}/sbom`]: 'sbom', [`${base}/vuln`]: 'vuln' })[path];
    if (!kind) continue;
    if (!url.search) return true;
    if (!params.has('view')) return params.get('limit') === '50' && keys.every(key => ['limit', 'cursor'].includes(key)) && (cursor === null || /^(0|[1-9]\d{0,5})$/.test(cursor));
    const fields = { secret: ['ruleId', 'linePresence'], sbom: ['ecosystem', 'name'], vuln: ['severity'] }[kind];
    if (!keys.every(key => ['view', 'limit', 'sort', 'cursor', ...fields].includes(key)) || params.get('view') !== 'report-v1' ||
      !['5', '10', '25', '50'].includes(params.get('limit'))) return false;
    if (!({ secret: ['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc'], sbom: ['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc'], vuln: ['severity:asc', 'severity:desc'] })[kind].includes(params.get('sort'))) return false;
    if (params.has('ruleId') && !/^[A-Za-z0-9._-]{1,80}$/.test(params.get('ruleId'))) return false;
    if (params.has('linePresence') && !['known', 'unknown'].includes(params.get('linePresence'))) return false;
    if (params.has('name') && !/^[A-Za-z0-9@._+:/-]{1,128}$/.test(params.get('name'))) return false;
    if (params.has('ecosystem') && !['apk', 'deb', 'rpm', 'npm', 'pypi', 'gem', 'gomod', 'cargo', 'maven', 'composer', 'nuget'].includes(params.get('ecosystem'))) return false;
    if (params.has('severity')) {
      const selected = params.get('severity').split(',');
      if (selected.length > 5 || new Set(selected).size !== selected.length || !selected.every(value => ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(value))) return false;
    }
    return true;
  }
  return false;
}
export function allowedGet(path, ids, method = 'GET') {
  return path.startsWith('/') && !path.startsWith('//') && allowedApiGet(`${ORIGIN}${path}`, ids, method);
}
export function safeReadRequest(input, headers = {}) {
  if (!fixedUrl(input)) return false;
  const values = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return !['authorization', 'proxy-authorization', 'x-api-key'].some(key => key in values) &&
    (!('origin' in values) || values.origin === ORIGIN);
}
export const BROWSER_READ_STAGES = Object.freeze(['authority', 'auth-navigation', 'report-navigation', 'evaluate', 'fetch', 'headers', 'body', 'decode', 'json']);
export const BROWSER_READ_CAUSES = Object.freeze(['navigation', 'execution-context-destroyed', 'page-closed', 'authority-changed', 'origin-mismatch', 'request-not-approved', 'caller-abort', 'timeout', 'network', 'content-type', 'missing-body', 'body-limit', 'invalid-utf8', 'invalid-json', 'unknown']);
const READ_TARGETS = new Set(['auth', 'scan-list', 'scan-status', 'report', 'llm-read', 'runtime', 'other-approved']);
export function browserReadFailureMeta(input = {}) {
  if (!BROWSER_READ_STAGES.includes(input.readStage) || !BROWSER_READ_CAUSES.includes(input.readCause)) return {};
  const out = { readStage: input.readStage, readCause: input.readCause };
  if (READ_TARGETS.has(input.readTarget)) out.readTarget = input.readTarget;
  if (UUID.test(input.scanId)) out.scanId = input.scanId;
  if (Number.isInteger(input.httpStatus) && input.httpStatus >= 100 && input.httpStatus <= 599) out.httpStatus = input.httpStatus;
  return out;
}
export function classifyBrowserReadFailure(error) {
  // Known browser/DOM signatures are inspected only in memory. Never emit text,
  // stacks, errno, URLs, response bodies or arbitrary Error.name values.
  const text = typeof error?.message === 'string' ? error.message.slice(0, 2048) : '';
  if (/Execution context was destroyed|Cannot find context with specified id/.test(text)) return 'execution-context-destroyed';
  if (/Target page, context or browser has been closed|Page closed/.test(text)) return 'page-closed';
  if (/Frame was detached|Navigation interrupted by another one/.test(text)) return 'navigation';
  if (error?.name === 'TimeoutError') return 'timeout';
  if (error?.name === 'AbortError') return 'caller-abort';
  if (/Failed to fetch|NetworkError when attempting to fetch resource/.test(text)) return 'network';
  return 'unknown';
}
export class BrowserReadError extends Error {
  constructor(meta) { super('BROWSER_READ_FAILED'); this.meta = browserReadFailureMeta(meta); }
}
const readPages = new WeakMap();
export function trackBrowserReadPage(page, { active, sessionVersion }) {
  const scope = { active, sessionVersion, epoch: 0, pending: false };
  const mainRequest = request => request.isNavigationRequest() && request.frame() === page.mainFrame();
  page.on('request', request => { if (mainRequest(request)) { scope.pending = true; scope.epoch++; } });
  page.on('framenavigated', frame => { if (frame === page.mainFrame()) { scope.pending = false; scope.epoch++; } });
  page.on('requestfailed', request => { if (mainRequest(request)) { scope.pending = false; scope.epoch++; } });
  readPages.set(page, scope);
}
function captureReadPage(page, meta) {
  const scope = readPages.get(page);
  if (page.isClosed()) throw new BrowserReadError({ ...meta, readStage: 'authority', readCause: 'page-closed' });
  if (!scope || !scope.active()) throw new BrowserReadError({ ...meta, readStage: 'authority', readCause: 'authority-changed' });
  if (!fixedUrl(page.url().split('#')[0])) throw new BrowserReadError({ ...meta, readStage: 'authority', readCause: 'origin-mismatch' });
  if (scope.pending) throw new BrowserReadError({ ...meta, readStage: 'authority', readCause: 'navigation' });
  const epoch = scope.epoch, session = scope.sessionVersion(), url = page.url();
  return () => page.isClosed() ? 'page-closed' : !scope.active() || scope.sessionVersion() !== session ? 'authority-changed' :
    scope.pending || scope.epoch !== epoch || page.url() !== url ? 'navigation' : null;
}
async function settleNavigation(page, url, active, meta, waitForUi) {
  const scope = readPages.get(page), session = scope?.sessionVersion();
  if (!scope || !active()) throw new BrowserReadError({ ...meta, readCause: 'authority-changed' });
  try {
    // Wait for the SPA commit AND UI before evaluating in its execution context.
    // This orders the first read; it never resends a failed read or mutation.
    await page.waitForURL(url, { timeout: 20_000, waitUntil: 'domcontentloaded' });
    if (!active() || scope.sessionVersion() !== session || page.url() !== url) throw new BrowserReadError({ ...meta, readCause: 'authority-changed' });
    await waitForUi();
    const current = captureReadPage(page, meta), changed = current();
    if (!active() || scope.sessionVersion() !== session || changed) throw new BrowserReadError({ ...meta, readCause: changed ?? 'authority-changed' });
  } catch (error) {
    if (error instanceof BrowserReadError) throw error;
    throw new BrowserReadError({ ...meta, readCause: classifyBrowserReadFailure(error) });
  }
}
export async function settleReportNavigation(page, scanId, active) {
  const meta = { scanId, readTarget: 'scan-status', readStage: 'report-navigation' };
  if (!UUID.test(scanId)) throw new BrowserReadError({ ...meta, readCause: 'authority-changed' });
  await settleNavigation(page, `${ORIGIN}/scans/${scanId}`, active, meta,
    () => page.getByRole('group', { name: `Ход сканирования ${scanId}`, exact: true }).waitFor({ state: 'visible', timeout: 15_000 }));
}
export async function settleAuthNavigation(page, active) {
  await settleNavigation(page, `${ORIGIN}/account`, active, { readTarget: 'auth', readStage: 'auth-navigation' },
    () => page.getByRole('heading', { name: 'Вы вошли', exact: true }).waitFor({ state: 'visible', timeout: 15_000 }));
}
export async function readBrowserJson(page, path, knownIds) {
  const ids = [...knownIds], match = path.match(/^\/api\/v1\/browser\/scans\/([a-f0-9-]{36})(?:\/|$)/);
  const scanId = match && ids.includes(match[1]) && UUID.test(match[1]) ? match[1] : undefined;
  const clean = path.split('?')[0];
  const readTarget = clean === '/api/v1/auth/me' ? 'auth' : clean === SCANS ? 'scan-list' :
    scanId && clean === `${SCANS}/${scanId}` ? 'scan-status' : clean.includes('/llm/') ? 'llm-read' :
      /\/(results|sbom|vuln)$/.test(clean) ? 'report' : clean.startsWith('/api/v1/browser/runtime/') ? 'runtime' : 'other-approved';
  const meta = { scanId, readTarget };
  if (!allowedGet(path, ids)) throw new BrowserReadError({ ...meta, readStage: 'authority', readCause: 'request-not-approved' });
  const current = captureReadPage(page, meta);
  let result;
  try {
    result = await page.evaluate(async path => {
      let stage = 'fetch', status;
      const signal = AbortSignal.timeout(40_000);
      const failed = cause => ({ readFailure: { readStage: stage, readCause: cause, ...(status ? { httpStatus: status } : {}) } });
      try {
        const response = await fetch(path, { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal });
        status = response.status; stage = 'headers';
        if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) return failed('content-type');
        stage = 'body'; const reader = response.body?.getReader();
        if (!reader) return failed('missing-body');
        const chunks = []; let size = 0;
        try {
          for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
            if (size > 4 * 1024 * 1024) return failed('body-limit'); chunks.push(part.value); }
        } finally { await reader.cancel().catch(() => {}); }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const part of chunks) { bytes.set(part, offset); offset += part.byteLength; }
        stage = 'decode'; let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return failed('invalid-utf8'); }
        stage = 'json';
        try { return { status, value: JSON.parse(text) }; } catch { return failed('invalid-json'); }
      } catch (error) {
        return failed(signal.aborted || error?.name === 'TimeoutError' ? 'timeout' : error?.name === 'AbortError' ? 'caller-abort' :
          typeof error?.message === 'string' && /Failed to fetch|NetworkError when attempting to fetch resource/.test(error.message.slice(0, 2048)) ? 'network' : 'unknown');
      }
    }, path);
  } catch (error) {
    throw new BrowserReadError({ ...meta, readStage: 'evaluate', readCause: current() ?? classifyBrowserReadFailure(error) });
  }
  const changed = current();
  if (changed) throw new BrowserReadError({ ...meta, readStage: 'evaluate', readCause: changed });
  if (result?.readFailure) throw new BrowserReadError({ ...meta, ...browserReadFailureMeta(result.readFailure) });
  return result;
}
const exact = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
export const sameChecks = value => isDeepStrictEqual(value, CHECKS);
export function validIntent(body, target) {
  return exact(body, ['imageReference', 'scope', 'checks', 'idempotencyKey']) && body.imageReference === target.reference && body.scope === 'image' && sameChecks(body.checks) && typeof body.idempotencyKey === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(body.idempotencyKey);
}
export function eligibilityReady(value, target) {
  return value?.imageReference === target.reference && value.eligible === true && value.reason === 'READY' && value.eligibility === 'public-hub-profile' && Array.isArray(value.allowedCheckSets) && value.allowedCheckSets.some(sameChecks);
}
export function consumePermit(permit, method, path, body) {
  if (method !== 'POST' || path.includes('?') || !permit || permit.used || permit.path !== path || !permit.matches(body)) return false;
  permit.used = true;
  return true;
}
export class EligibilityFence {
  sequence = 0;
  grant = null;
  start() { this.grant = null; return ++this.sequence; }
  accept(sequence, body, value, target, now = Date.now()) {
    if (sequence === this.sequence && sameChecks(body.checks) && body.imageReference === target.reference && eligibilityReady(value, target)) this.grant = { sequence, at: now };
  }
  fresh(after, now = Date.now()) { return !!this.grant && this.grant.sequence > after && now >= this.grant.at && now - this.grant.at <= 30_000; }
}
export async function awaitEligibility(fence, after, pending, active, timeoutMs = 35_000) {
  await bounded(pending, timeoutMs);
  return active() && fence.fresh(after);
}
// A network grant is necessary, not sufficient: React must have committed the same
// full-check target. Two matching observations fence debounce/render scheduling;
// create still requires a distinct fresh post-arm eligibility response below.
export function uiLaunchReady(value, confirmed = false) {
  return ['formPresent', 'referenceMatches', 'inputEnabled', 'inputValid', 'checksMatch', 'checksEnabled', 'consentEnabled', 'uiEligibilityReady'].every(key => value?.[key] === true) &&
    value.consentChecked === confirmed && value.submitEnabled === confirmed && value.hasAlert === false && value.waitActive === false;
}
export function readLaunchForm(form, target) {
  return form.evaluate((element, { reference, checks }) => {
    const input = element.querySelector('#image-reference');
    const selected = [...element.querySelectorAll('input[name="checks"]:checked')].map(item => item.value);
    const inputs = [...element.querySelectorAll('input[name="checks"]')];
    const confirmation = [...element.querySelectorAll('label')].find(label => label.textContent.includes('Подтверждаю выбранную цель и область'))?.querySelector('input');
    const button = element.querySelector('button[type="submit"]');
    const statuses = [...element.querySelectorAll('[role="status"]')];
    return { formPresent: element.isConnected, referenceMatches: input?.value === reference,
      inputEnabled: !!input && !input.disabled, inputValid: input?.validity.valid === true,
      checksMatch: JSON.stringify(selected) === JSON.stringify(checks), checksEnabled: inputs.length === checks.length && inputs.every(item => !item.disabled),
      consentEnabled: !!confirmation && !confirmation.disabled, consentChecked: confirmation?.checked === true,
      submitEnabled: !!button && !button.disabled,
      uiEligibilityReady: statuses.some(item => item.textContent.trim() === 'Серверный допуск подтверждён; перед новым запуском проверяется повторно.'),
      hasAlert: !!element.querySelector('[role="alert"]'),
      waitActive: !!element.querySelector('[role="status"][aria-label="Ожидание сервера"]') };
  }, { reference: target.reference, checks: CHECKS });
}
export async function awaitStableUiEligibility(state, after, read, active, observe = () => {}, options = {}) {
  const { timeoutMs = 35_000, now = Date.now, pause = () => wait(50) } = options;
  const deadline = now() + timeoutMs;
  let previousSequence = null;
  while (now() < deadline) {
    if (!active()) throw new Fault('ELIGIBILITY_NOT_READY');
    const sequence = state.fence.sequence;
    const snapshot = await bounded(read(), Math.max(1, deadline - now()));
    observe(snapshot);
    if (!active()) throw new Fault('ELIGIBILITY_NOT_READY');
    if (sequence === state.fence.sequence && state.eligibilityResult?.sequence === sequence && state.eligibilityResult.refused) throw new Fault('ELIGIBILITY_NOT_READY');
    const current = sequence === state.fence.sequence && state.fence.fresh(after, now()) && uiLaunchReady(snapshot);
    if (current && previousSequence === sequence) return { sequence, snapshot };
    previousSequence = current ? sequence : null;
    await bounded(pause(), Math.max(1, deadline - now()));
  }
  throw new Fault('ELIGIBILITY_NOT_READY');
}
const PHASES = new Set(['progress-snapshot', 'form-navigation', 'target-fill', 'checks-select', 'ui-eligibility', 'consent-fresh', 'consent-check', 'submit-enabled', 'launch-arm', 'launch-click', 'launch-receipt', 'report-navigation', 'subset-observation', 'subset-capture', 'cancel-available', 'cancel-click', 'cancel-receipt', 'cancel-terminal', 'cancel-report', 'cancel-preservation', 'cancel-reload', 'cancel-history', 'cancel-fresh-login']);
// Completed-check counts are NOT elapsed-work percent or an ETA. The public
// decoder currently supplies percent:null, including after SSE reconnect.
export function progressExpectation(snapshot) {
  assert.ok(snapshot && sameChecks(snapshot.checks) && ['queued', 'running', 'cancelling', ...TERMINAL].includes(snapshot.state));
  const active = ['queued', 'running', 'cancelling'].includes(snapshot.state);
  const progress = snapshot.progress ? durableProgress(snapshot.progress) : null;
  const resolved = progress ? progress.resolvedChecks : active ? 0 : CHECKS.filter(key => snapshot.perCheck?.[key]?.check === key).length;
  const checked = progress ? progress.checkedChecks : active ? 0 : completedChecks(snapshot).length;
  return { active, hasCheckSnapshot: !!progress || !active && snapshot.perCheck !== undefined, total: CHECKS.length, resolved, checked,
    remaining: CHECKS.length - resolved,
    percent: active && typeof snapshot.percent === 'number' && Number.isFinite(snapshot.percent) && snapshot.percent >= 0 && snapshot.percent <= 100 ? snapshot.percent : null };
}
// Self-contained for page.evaluate: check current JSX's bounded estimate, never turn
// completed-check counts into elapsed percent or claim an estimated ETA.
export function progressDomSample(element, { expected, state }) {
  const text = element.textContent ?? '', progress = element.querySelector('progress');
  const raw = progress?.getAttribute('value'), value = raw === null || raw === undefined || raw === '' ? null : Number(raw);
  const bounded = Number.isFinite(value) && value >= 0 && value < 100;
  const approximate = bounded && text.includes(`Оценка прогресса: ≈${Math.floor(value)}%${expected.active ? '' : ' на момент остановки'}.`);
  const server = bounded && expected.percent === value && text.includes(`Прогресс: ${value}% по данным сервера.`);
  const unknown = text.includes('Выполнение не подтверждено; оценка до остановки отсутствует.');
  const stoppedEstimate = !expected.active && /Оценка прогресса: ≈(?:[0-9]|[1-9][0-9])% на момент остановки\./u.test(text);
  const completed = state === 'completed' && text.includes('Прогресс: 100% — завершение подтверждено сервером.');
  const counts = expected.hasCheckSnapshot ? `Получены итоги: ${expected.resolved} из ${expected.total}. Успешно выполнено: ${expected.checked}.` : 'Счётчики проверок не предоставлены сервером.';
  return { stateMatches: element.getAttribute('data-state') === state,
    barMatches: expected.active ? !!progress && progress.getAttribute('max') === '100' && bounded && (state !== 'queued' || value === 0) : !progress,
    countsMatch: text.includes(counts),
    remainingMatch: !expected.hasCheckSnapshot || text.includes(`${expected.active ? 'Без подтверждённого итога' : 'Без сохранённого итога'}: ${expected.remaining}.`),
    percentMatches: expected.active ? approximate || server || unknown && value === 0 : state === 'completed' ? completed : stoppedEstimate || unknown,
    timeHonest: text.includes(expected.active ? 'Точное оставшееся время неизвестно.' : 'Скан больше не выполняется. Отсутствующие итоги не считаются успешными проверками.'),
    indeterminate: unknown };
}
export function progressSampleMatches(sample) {
  return ['stateMatches', 'barMatches', 'countsMatch', 'remainingMatch', 'percentMatches', 'timeHonest'].every(key => sample?.[key] === true);
}
export class PhaseEvidence {
  constructor(now = Date.now) { this.now = now; this.reset(); }
  reset() { this.phase = null; this.at = this.now(); this.observation = {}; }
  enter(phase) { assert.ok(PHASES.has(phase)); this.phase = phase; this.at = this.now(); this.observation = {}; }
  observe(value) { this.observation = safeMeta(value); }
  meta() { return this.phase ? safeMeta({ ...this.observation, phase: this.phase, phaseElapsedMs: Math.max(0, this.now() - this.at) }) : {}; }
}
export function partition(rows) {
  const counts = { cve: 0, debianTemp: 0 };
  for (const row of rows) {
    if (/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(row.cveId)) counts.cve++;
    else if (row.ecosystem === 'deb' && /^TEMP-[0-9]{7}-[A-F0-9]{6}$/.test(row.cveId) && !row.advisory?.references?.length) counts.debianTemp++;
    else throw new Error('ASSERTION_FAILED');
  }
  return counts;
}
export function cancelVerdict(state, httpStatus) {
  if (state === 'cancelled' && httpStatus === 200) return { status: 'PASS', code: 'VERIFIED' };
  if (['completed', 'partial', 'failed'].includes(state) && (httpStatus === null || httpStatus === 409)) return { status: 'INCONCLUSIVE', code: 'CANCEL_RACE' };
  return { status: 'BLOCKED', code: 'ASSERTION_FAILED' };
}
export function keyBoundaryAllowed(ready, context) {
  return ready?.credential === 'missing' && ready.localReady === false && ready.generationVerified === false && ready.requiresConsent === true && ready.acceptsCredentials === false && Array.isArray(ready.blockers) && ready.blockers.includes('public-key-required') && ready.quota === 'available' && ready.history === 'available' && context?.enabled === true && HASH.test(context.policyVersion) && context.pending === false && ready.scanId === context.scanId && ready.reportVersion === context.reportVersion && ready.digest === context.digest && ready.platform === context.platform;
}
export function safeMutationRequest(url, headers = {}) {
  if (!fixedUrl(url) || new URL(url).search) return false;
  const values = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return !('authorization' in values) && !('proxy-authorization' in values) && !('x-api-key' in values) &&
    values.origin === ORIGIN && /^application\/json(?:;|$)/i.test(values['content-type'] ?? '');
}
export function assertAuthUser(value, email, subject) {
  assert.ok(exact(value, ['id', 'email']));
  assert.ok(typeof value.id === 'string' && /^[a-f0-9]{32}$/.test(value.id));
  assert.equal(value.email, email);
  if (subject !== undefined) assert.equal(value.id, subject);
  return value.id;
}
export function assertDeniedReply(response, expected) {
  assert.equal(response.status, expected);
  const value = response.value;
  if (exact(value, ['errorCode'])) {
    assert.ok(['UNAUTHORIZED', 'SCAN_NOT_FOUND', 'SCAN_ACCESS_DENIED', 'SCAN_ACCESS_DISABLED', 'LLM_UNAVAILABLE', 'LLM_REPORT_UNAVAILABLE'].includes(value.errorCode));
    return;
  }
  if (expected === 404 && exact(value, ['statusCode', 'message'])) {
    assert.equal(value.statusCode, 404);
    assert.equal(value.message, 'Not Found');
    return;
  }
  assert.ok(exact(value, ['statusCode', 'message', 'error']));
  assert.equal(value.statusCode, expected);
  assert.equal(value.message, expected === 401 ? 'Unauthorized' : 'Not Found');
  assert.equal(value.error, value.message);
}
export function assertChatUsage(value, binding) {
  assert.ok(value && value.available === true);
  for (const field of ['scanId', 'digest', 'platform', 'reportVersion']) assert.equal(value[field], binding[field]);
  assert.ok(exact(value.window, ['start', 'end']));
  assert.ok(Number.isSafeInteger(value.window.start) && value.window.start >= 0 && value.window.start % 86400000 === 0);
  assert.equal(value.window.end, value.window.start + 86400000);
  assert.ok(exact(value.admission, ['status']) && value.admission.status === 'unavailable');
  for (const name of ['user', 'scan']) {
    const scope = value[name]; assert.ok(scope);
    for (const field of ['limits', 'used', 'held', 'carried', 'remaining']) {
      assert.ok(exact(scope[field], ['input', 'output', 'costMicros']));
      for (const n of Object.values(scope[field])) assert.ok(Number.isSafeInteger(n) && n >= 0);
    }
    for (const dimension of ['input', 'output', 'costMicros']) {
      const total = scope.used[dimension] + scope.held[dimension] + scope.carried[dimension];
      assert.ok(Number.isSafeInteger(total));
      assert.equal(scope.remaining[dimension], Math.max(0, scope.limits[dimension] - total));
    }
  }
  return value;
}
export function renderedRowParts(kind, row) {
  if (kind === 'sbom') return [row.name, `${row.ecosystem} · версия ${row.version}`];
  if (kind === 'secret') return [row.ruleId, `ID: ${row.findingId}`, row.line == null ? 'Номер строки неизвестен' : `Строка ${row.line}`];
  return [row.cveId, `ID находки: ${row.findingId}`, row.packageName, row.installedVersion, row.severity];
}
export function preservationVerdict(before, observed, subsets, changed) {
  const checked = observed.filter(key => before.perCheck[key].outcome === 'checked');
  const captured = checked.length > 0 && checked.every(key => key === 'config' || subsets[key]);
  return { status: captured && !changed ? 'PASS' : 'INCONCLUSIVE', code: changed ? 'SUBSET_CAPTURE_CHANGED' : captured ? 'VERIFIED' : 'NO_COMPLETED_SUBSET_OBSERVED' };
}
export function paginationVerdict(exercised, eligible) {
  if (exercised === eligible && eligible > 0) return { status: 'PASS', code: 'VERIFIED' };
  return { status: 'INCONCLUSIVE', code: exercised ? 'INCOMPLETE_PAGINATION_COVERAGE' : 'NO_SECOND_PAGE' };
}
function count(n) { assert.ok(Number.isSafeInteger(n) && n >= 0 && n <= 1000); return n; }
function rowsOf(kind, page) { return kind === 'sbom' ? page.components : page.findings; }
function rowId(kind, row) { return kind === 'sbom' ? JSON.stringify([row.ecosystem, row.name, row.version]) : row.findingId; }
export function checkPage(kind, page, expected, offset, seen) {
  const rows = rowsOf(kind, page);
  assert.equal(page.page.totalCount, expected.whole);
  assert.equal(page.page.matchedCount, expected.matched);
  assert.equal(page.page.offset, offset);
  assert.equal(page.page.returnedCount, rows.length);
  for (const row of rows) { const id = rowId(kind, row); assert.equal(seen.has(id), false); seen.add(id); }
  if (page.nextCursor !== null) assert.ok(rows.length > 0);
  return rows;
}

export async function readAllPages(kind, expected, read) {
  count(expected.whole); count(expected.matched); assert.ok(expected.matched <= expected.whole);
  const rows = [], seen = new Set(), cursors = new Set(); let cursor;
  for (let pages = 1; pages <= 200; pages++) {
    const value = await read(cursor);
    rows.push(...checkPage(kind, value, expected, rows.length, seen));
    assert.ok(rows.length <= expected.matched);
    if (value.nextCursor === null) { assert.equal(rows.length, expected.matched); return { rows, pages }; }
    assert.ok(typeof value.nextCursor === 'string' && value.nextCursor.length > 0 && !cursors.has(value.nextCursor));
    cursors.add(value.nextCursor); cursor = value.nextCursor;
  }
  throw new Error('ASSERTION_FAILED'); // Exhaustion is never silently accepted as EOF.
}

// Error text/stack never leaves the runner; retain only a bounded first-party line number.
export function failureMeta(error) {
  const match = typeof error?.stack === 'string' ? error.stack.match(/public-product-live\.mjs:([0-9]+):[0-9]+/) : null;
  return match ? safeMeta({ runnerLine: Number(match[1]) }) : {};
}
// Closed projection: no free-form strings from HTTP/errors/DOM are emitted.
export function safeMeta(input = {}) {
  const out = { ...browserReadFailureMeta(input) };
  if (UUID.test(input.scanId)) out.scanId = input.scanId;
  if (DIGEST.test(input.digest)) out.digest = input.digest;
  if (input.platform === 'linux/amd64') out.platform = input.platform;
  if (['queued', 'running', ...TERMINAL].includes(input.state)) out.state = input.state;
  if (PHASES.has(input.phase)) out.phase = input.phase;
  for (const key of ['progress', 'preCancelProgress']) if (input[key] !== undefined) {
    try { out[key] = durableProgress(input[key]); } catch { /* Unknown/malformed metadata is not a progress receipt. */ }
  }
  if (input.preservationBasis === 'post-cancel-published-baseline-v1') out.preservationBasis = input.preservationBasis;
  if (Number.isSafeInteger(input.phaseElapsedMs) && input.phaseElapsedMs >= 0 && input.phaseElapsedMs <= 2_520_000) out.phaseElapsedMs = input.phaseElapsedMs;
  if (Number.isInteger(input.httpStatus) && input.httpStatus >= 100 && input.httpStatus <= 599) out.httpStatus = input.httpStatus;
  if (input.launchHttpStatus === 202) out.launchHttpStatus = 202;
  for (const key of ['pages', 'checkedSets', 'observedEvents', 'scanLaunches', 'cancelPosts', 'accountsCreated', 'pageErrors', 'blockedRequests', 'ignoredEligibility', 'runnerLine']) if (Number.isSafeInteger(input[key]) && input[key] >= 0 && input[key] <= 100000) out[key] = input[key];
  for (const key of ['allChecksChecked', 'noGenerationPosts', 'historyUnchanged', 'quotaUnchanged', 'browserClosed', 'nativeScanMayRemainActive', 'formPresent', 'referenceMatches', 'inputEnabled', 'inputValid', 'checksMatch', 'checksEnabled', 'consentEnabled', 'consentChecked', 'submitEnabled', 'uiEligibilityReady', 'hasAlert', 'waitActive', 'progressObserved', 'progressIndeterminate', 'progressActive', 'preCancelReportUiEmpty', 'preCancelFindingsRead', 'preCancelByteComparison', 'postCancelBaselineVerified', 'receiptAccepted']) if (typeof input[key] === 'boolean') out[key] = input[key];
  if (['unconfigured', 'missing', 'unsafe', 'metadata-valid'].includes(input.credential)) out.credential = input.credential;
  if (Array.isArray(input.blockers)) out.blockers = [...new Set(input.blockers.filter(x => BLOCKERS.has(x)))];
  if (Array.isArray(input.observedCompletedChecks)) out.observedCompletedChecks = CHECKS.filter(x => input.observedCompletedChecks.includes(x));
  for (const field of ['counts', 'checks']) if (input[field] && typeof input[field] === 'object') {
    out[field] = {};
    for (const key of field === 'counts' ? [...CHECKS, 'cve', 'debianTemp'] : CHECKS) {
      const value = input[field][key];
      if (field === 'counts' && (value === null || Number.isSafeInteger(value) && value >= 0 && value <= 1000)) out[field][key] = value;
      if (field === 'checks' && (value === null || OUTCOMES.has(value))) out[field][key] = value;
    }
  }
  return out;
}
export class ResultBook {
  constructor(mode = 'native', attemptId = null) { this.plan = nativePlan(mode, attemptId); this.actual = false; this.runId = randomUUID(); this.startedAt = new Date().toISOString(); this.finishedAt = null; this.cases = Object.fromEntries(this.plan.cases.map(id => [id, { status: 'BLOCKED', code: 'NOT_RUN', failure: false }])); }
  record(id, status, code, meta = {}, failure = code === 'ASSERTION_FAILED') {
    assert.ok(this.plan.cases.includes(id) && ['PASS', 'BLOCKED', 'INCONCLUSIVE'].includes(status) && CODES.has(code));
    if (this.cases[id].failure && !failure) return; // A later successful probe must not hide an earlier violation.
    this.cases[id] = { status, code, failure: !!failure, ...safeMeta(this.cases[id]), ...safeMeta(meta) };
  }
  recordScanReceipt(id, status, value) {
    assert.ok(this.plan.cases.includes(id) && status === 202 && UUID.test(value?.scanId));
    this.cases[id] = { ...this.cases[id], ...safeMeta({ scanId: value.scanId, launchHttpStatus: 202, receiptAccepted: true }) };
  }
  evidence() {
    return { schema: 1, actuallyRun: this.actual, mode: this.plan.mode, attemptId: this.plan.attemptId, evidenceRoot: this.plan.evidenceRoot, runId: this.runId, startedAt: this.startedAt, finishedAt: this.finishedAt, scope: this.plan.cancelOnly ? 'native-public8081-one-scan-cancel' : this.plan.smokeOnly ? 'native-public8081-one-scan-smoke' : 'native-public8081-browser-only', origin: ORIGIN, providerGenerationQualified: false, generationPolicy: this.plan.cancelOnly ? 'all-llm-posts-denied' : this.plan.smokeOnly ? 'readiness-only-no-llm-posts' : 'negative-boundary-only',
      providerDispatchIndependentlyObserved: false, credentialPersistence: false, screenshots: false, har: false, trace: false,
      lifecycleOperations: 0, syntheticResponses: false, cases: structuredClone(this.cases) };
  }
}
class Fault extends Error {
  constructor(code, failure = false) { super(CODES.has(code) ? code : 'ASSERTION_FAILED'); this.failure = failure; }
}
const ok = (value, meta = {}) => ({ value, meta });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Fault('GLOBAL_DEADLINE')), ms); })]); }
  finally { clearTimeout(timer); }
}
async function absentEvidence(plan) {
  for (const path of plan.evidencePaths) {
    try { await lstat(path); } catch (e) { if (e.code === 'ENOENT') continue; throw new Fault('EVIDENCE_WRITE_FAILED'); }
    throw new Fault('EVIDENCE_ALREADY_EXISTS');
  }
}
export function evidenceDocuments(evidence) {
  const smokeOnly = evidence.mode === 'smoke', cancelOnly = evidence.mode === 'cancel';
  const markdown = [cancelOnly ? '# Public 8081 one-scan cancel qualification' : smokeOnly ? '# Public 8081 one-scan browser smoke — 2026-10-22' : '# Public product browser qualification — 2026-10-21', '', `Origin: ${ORIGIN}`, `Evidence root: ${evidence.evidenceRoot}`, '',
    `Run: ${evidence.runId}. Provisional summary only: require the matching complete JSON and a successful evidence write; this Markdown alone is not acceptance.`,
        'Native generation is NOT qualified. No key is sought or persisted. Provider dispatch is not independently observed.',
    cancelOnly ? 'One account and at most one native four-check scan are retained. All LLM POSTs are denied, including manual history; key presence is irrelevant and no key-absent/readiness probe is required. Terminal races and absent checked durable-outcome metadata never qualify cancellation. Pre-cancel findings are not read or byte-compared; published post-cancel datasets form the baseline for late-write/reload/fresh-login checks. No relaunch.' : smokeOnly ? 'One account and at most one scan are retained; no LLM POST or manual decision is authorized. Credentials exist only in runner/browser memory.' : 'Accounts/scans/decisions are retained in the public stand; credentials exist only in runner/browser memory.',
    'PASS is per assertion; BLOCKED is not success; cancel races and unavailable pagination/subset observations are INCONCLUSIVE.', '',
    '| Case | Result | Code |', '| --- | --- | --- |', ...Object.entries(evidence.cases).map(([id, item]) => `| ${id} | ${item.status} | ${item.code} |`), ''].join('\n');
  return [JSON.stringify(evidence, null, 2) + '\n', markdown];
}
export async function writeEvidence(evidence, openFile = open) {
  const files = [], documents = evidenceDocuments(evidence);
  try {
    // Acquire both exclusive destinations before writing anything. A second-path
    // collision must not leave a valid-looking JSON receipt from a failed run.
    for (const path of nativePlan(evidence.mode ?? 'native', evidence.attemptId ?? null).evidencePaths) files.push(await openFile(path, 'wx', 0o600));
    for (const index of [1, 0]) { await files[index].writeFile(documents[index]); await files[index].sync(); }
  } finally { await Promise.all(files.map(file => file.close())); }
}

export async function loadContracts() {
  process.env.TSX_DISABLE_CACHE = '1';
  const require = createRequire(join(ROOT, 'server/api/package.json'));
  // require.resolve selects the CJS API; choose the installed package's actual ESM export.
  const manifest = require('tsx/package.json');
  const entry = manifest.exports['./esm/api'].import.default;
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), entry)).href);
  const source = path => tsImport(join(ROOT, path), { parentURL: import.meta.url, tsconfig: false });
  const decoder = await source('src/shared/api/scans/scanTransport.ts');
  const view = await source('src/shared/api/scans/reportView.ts');
  const metadata = await source('src/shared/api/scans/cveDbMetadata.ts');
  const chat = await source('src/shared/api/scans/llmChatContract.ts');
  return { decoder, view, metadata, chat };
}

async function runNative(mode = 'native', attemptId) {
  if (!UUID.test(attemptId)) throw new Fault('INVALID_ARGUMENTS');
  const plan = nativePlan(mode, attemptId);
  await absentEvidence(plan); // Refuse before registration/browser launch; never replace earlier evidence.
  if (['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'PLAYWRIGHT_TRACE_DIR', 'PLAYWRIGHT_BROWSERS_PATH'].some(key => process.env[key])) throw new Fault('UNSAFE_DEBUG_ENVIRONMENT');
  process.env.TSX_DISABLE_CACHE = '1'; // Transpile in memory, not into a new disk cache.
  const book = new ResultBook(mode, attemptId);
  if (!plan.cancelOnly) book.record('llm_generation', 'BLOCKED', 'GENERATION_NOT_AUTHORIZED');
  const contexts = [], contextStates = new Map(), scans = new Map();
  const stats = { scanLaunches: 0, cancelPosts: 0, accountsCreated: 0, pageErrors: 0, blockedRequests: 0, ignoredEligibility: 0 };
  const owner = { email: `public-product-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const foreign = { email: `public-product-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  let browser, stopped = false, browserClosed = false, activeLaunch = null, pendingCreation = Promise.resolve();
  let currentCase = 'tooling', fatalCode = null, interrupt;
  const interrupted = new Promise((_, reject) => { interrupt = code => { fatalCode = code; reject(new Fault(code)); }; });
  const globalTimer = setTimeout(() => interrupt('GLOBAL_DEADLINE'), plan.globalMs);
  const signal = () => interrupt('INTERRUPTED');
  process.once('SIGINT', signal); process.once('SIGTERM', signal); process.once('SIGHUP', signal);
  const ensureLive = () => { if (stopped || fatalCode) throw new Fault(fatalCode ?? 'INTERRUPTED'); };
  const phase = new PhaseEvidence();
  const step = async (id, operation) => {
    ensureLive(); currentCase = id; phase.reset();
    try {
      const result = await operation();
      assert.ok(result && typeof result === 'object');
      book.record(id, result?.status ?? 'PASS', result?.code ?? 'VERIFIED', { ...phase.meta(), ...result?.meta });
      return result?.value;
    } catch (e) {
      book.record(id, 'BLOCKED', e instanceof BrowserReadError ? 'BROWSER_READ_FAILED' : e instanceof Fault ? e.message : 'ASSERTION_FAILED',
        { ...phase.meta(), ...failureMeta(e), ...(e instanceof BrowserReadError ? e.meta : {}) }, e instanceof BrowserReadError ? false : e instanceof Fault ? e.failure : true);
      if (fatalCode || stats.blockedRequests) throw e;
      return undefined;
    }
  };
  const permit = (state, path, matches) => { assert.ok(!state.permit || state.permit.used); state.permit = { path, matches, used: false }; };
  const waitResponse = (page, path, method, predicate = () => true) => page.waitForResponse(response => {
    const u = new URL(response.url());
    return fixedUrl(response.url()) && u.pathname === path && response.request().method() === method && predicate(u);
  }, { timeout: 45_000 }).catch(() => null);
  // Only real page-origin fetches. SSE probes cancel the reader rather than waiting for EOF.
  const http = async (page, path, body, event = false) => {
    ensureLive(); assert.ok(fixedUrl(`${ORIGIN}${path}`));
    if (body === undefined && !event) return readBrowserJson(page, path, scans.keys());
    return page.evaluate(async ({ path, body, event }) => {
      const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(event ? 12_000 : 40_000),
        ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) });
      const reader = response.body?.getReader();
      if (event && response.ok) {
        let hint = false;
        if (reader && response.ok) {
          const decoder = new TextDecoder(); let text = '';
          try {
            while (text.length < 65536) {
              const part = await reader.read(); if (part.done) break;
              text += decoder.decode(part.value, { stream: true });
              if (text.includes('\n\n')) {
                for (const line of text.split('\n')) if (line.startsWith('data: ')) {
                  try { const value = JSON.parse(line.slice(6)); hint = value.scanId === path.split('/').at(-2) && ['queued', 'running', 'completed', 'partial', 'failed', 'cancelled'].includes(value.state); } catch { /* No event payload leaves the probe. */ }
                }
                if (hint) break;
              }
            }
          } catch { /* Missing stream evidence is not a successful SSE assertion. */ }
        }
        await reader?.cancel().catch(() => {});
        return { status: response.status, hint };
      }
      const chunks = []; let size = 0;
      if (reader) for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 4 * 1024 * 1024) { await reader.cancel(); return { status: response.status, value: null }; } chunks.push(part.value); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      let value = null; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { /* No raw errors are returned or printed. */ }
      return { status: response.status, value };
    }, { path, body, event });
  };
  const newPage = async () => {
    ensureLive();
    const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
    contexts.push(context);
    const state = { context, closing: false, permit: null, generationPosts: 0, fence: new EligibilityFence(), eligibilityPending: Promise.resolve(), target: null };
    contextStates.set(context, state);
    await context.route('**/*', async route => {
      const request = route.request();
      let approvedRead = false;
      try {
        const u = new URL(request.url()), method = request.method();
        const deny = async () => { stats.blockedRequests++; await route.abort(); };
        if (!fixedUrl(request.url())) return deny();
        if (['GET', 'HEAD'].includes(method)) {
          if (method !== 'GET' || !safeReadRequest(request.url(), await request.allHeaders())) return deny();
          if (u.pathname.startsWith(`${SCANS}/`) && activeLaunch && !scans.has(u.pathname.split('/')[5])) await bounded(pendingCreation, 45_000).catch(() => {});
          approvedRead = !u.pathname.startsWith('/api/') || allowedGet(u.pathname + u.search, scans.keys(), method);
          if (!approvedRead) return deny();
          if (stopped || state.closing) return route.abort();
          return await route.continue();
        }
        if (stopped || state.closing || method !== 'POST') return deny();
        const headers = await request.allHeaders();
        if (stopped || fatalCode || !safeMutationRequest(request.url(), headers)) return deny();
        if (plan.smokeOnly && !smokeMutationAllowed(u.pathname)) return deny();
                if (plan.cancelOnly && (!cancelMutationAllowed(u.pathname, scans.keys()) ||
                          u.pathname.endsWith('/cancel') && stats.cancelPosts >= 1 ||
                          u.pathname === '/api/v1/auth/register' && stats.accountsCreated >= 1)) return deny();
        let body; try { body = request.postDataJSON(); } catch { return deny(); }
        if (method === 'POST' && u.pathname === `${SCANS}/images/eligibility`) {
          const target = state.target;
          if (!target || body?.imageReference !== target.reference) { stats.ignoredEligibility++; return route.abort(); }
          if (!exact(body, ['checks', 'imageReference']) || !Array.isArray(body.checks) || !body.checks.length || !body.checks.every((x, i) => CHECKS.includes(x) && (i === 0 || CHECKS.indexOf(body.checks[i - 1]) < CHECKS.indexOf(x)))) return deny();
          approvedRead = true;
          const sequence = state.fence.start();
          state.eligibilityPending = (async () => {
            await route.continue();
            const response = await request.response();
            const value = response?.status() === 200 ? await response.json() : null;
            if (response?.status() === 200) state.fence.accept(sequence, body, value, target);
            if (sequence === state.fence.sequence) state.eligibilityResult = { sequence, httpStatus: response?.status() ?? null,
              refused: sameChecks(body.checks) && (response?.status() !== 200 || !eligibilityReady(value, target)) };
          })();
          await state.eligibilityPending;
          return;
        }
        if (method === 'POST' && u.pathname === SCANS && activeLaunch?.state === state && activeLaunch.armed && validIntent(body, activeLaunch.target) && scanLaunchAllowed(plan, activeLaunch.target, stats.scanLaunches)) {
          const launch = activeLaunch;
          // The UI can receive an eligibility response before our response.json()
          // finishes. Await that genuine check, then recheck cancellation/authority.
          const ready = await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending,
            () => !stopped && !fatalCode && activeLaunch === launch && launch.armed && scanLaunchAllowed(plan, launch.target, stats.scanLaunches));
          if (!ready) return deny();
          launch.armed = false; stats.scanLaunches++;
          pendingCreation = (async () => {
            await route.continue(); const response = await request.response();
            if (response?.status() === 202) {
              const value = await response.json();
              if (UUID.test(value?.scanId)) {
                              scans.set(value.scanId, { target: state.target, launchAt: Date.now(), terminal: false });
                              book.recordScanReceipt(currentCase, response.status(), value);
                            }
            }
          })();
          await pendingCreation; return;
        }
        if (consumePermit(state.permit, method, u.pathname, body)) {
          if (u.pathname.endsWith('/cancel')) stats.cancelPosts++;
          if (u.pathname.endsWith('/llm/chat') || u.pathname.endsWith('/llm/summary') || u.pathname.endsWith('/llm/translation')) state.generationPosts++;
          await route.continue(); return;
        }
        return deny();
      } catch (error) {
              const aborted = request.failure()?.errorText === 'net::ERR_ABORTED' || error?.name === 'AbortError';
              if (!approvedRead || !(state.closing || aborted)) stats.blockedRequests++;
              await route.abort().catch(() => {});
            }
    });
    context.on('request', request => { if (!fixedUrl(request.url())) { stats.blockedRequests++; interrupt('REQUEST_GUARD'); } });
    context.on('response', response => {
      if (fixedUrl(response.url())) book.actual = true;
      if (runtimeProbeRead(response.url(), response.request().method())) {
            try { assertRuntimeOffReply(response.url(), response.request().method(), response.status()); }
            catch { book.record('safety', 'BLOCKED', 'RUNTIME_NOT_OFF', { httpStatus: response.status() }, true); interrupt('RUNTIME_NOT_OFF'); }
          }
          if (response.status() >= 300 && response.status() < 400) { stats.blockedRequests++; interrupt('REQUEST_GUARD'); }
        });
    await context.routeWebSocket('**/*', socket => { stats.blockedRequests++; socket.close(); });
    const page = await context.newPage();
    state.readSession = 0;
    trackBrowserReadPage(page, { active: () => !stopped && !fatalCode && !state.closing, sessionVersion: () => state.readSession });
    page.setDefaultTimeout(15_000); page.setDefaultNavigationTimeout(20_000);
    page.on('pageerror', () => { stats.pageErrors++; });
    return { ...state, page, state };
  };
  let decoder, reportViewSearch, validateCveMetadata, cveMetadataIdentity, chat;
  const auth = async (handle, account, action) => {
    const { page, state } = handle;
    state.readSession++;
    await page.goto(`${ORIGIN}/${action}`);
    await page.getByLabel('Email', { exact: true }).fill(account.email);
    await page.getByLabel('Пароль', { exact: true }).fill(account.password);
    permit(state, `/api/v1/auth/${action}`, body => exact(body, ['email', 'password']) && body.email === account.email && body.password === account.password);
    const pending = waitResponse(page, `/api/v1/auth/${action}`, 'POST');
    await page.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти', exact: true }).click();
    assert.equal((await pending)?.status(), action === 'register' ? 201 : 200);
    if (action === 'register') stats.accountsCreated++;
    await settleAuthNavigation(page, () => !stopped && !fatalCode && !state.closing);
    const me = await http(page, '/api/v1/auth/me'); assert.equal(me.status, 200);
    account.subject = assertAuthUser(me.value, account.email, account.subject);
    const session = (await handle.context.cookies(ORIGIN)).find(item => item.name === 'demo_session');
    assert.ok(session?.httpOnly && session.sameSite === 'Lax');
  };
  const launch = async (handle, target) => {
    const { page, state } = handle;
    state.target = target;
    const after = state.fence.sequence;
    phase.enter('form-navigation');
    await page.goto(`${ORIGIN}/scans/new`);
    const form = page.getByRole('form', { name: 'Параметры скана', exact: true });
    // Require the mounted form; the gate below also catches later mount-effect resets.
    await expect(form).toBeVisible();
    phase.enter('target-fill');
    await page.getByRole('textbox', { name: 'Canonical reference Docker Hub' }).fill(target.reference);
    phase.enter('checks-select');
    for (const check of CHECKS) await page.locator(`input[name="checks"][value="${check}"]`).check();
    const consent = page.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
    const submit = page.getByRole('button', { name: 'Запустить скан', exact: true });
    const read = () => readLaunchForm(form, target);
    const authority = () => !stopped && !fatalCode && !state.closing && state.target === target && page.url() === `${ORIGIN}/scans/new`;
    const observe = snapshot => phase.observe({ ...snapshot, httpStatus: state.eligibilityResult?.httpStatus });
    phase.enter('ui-eligibility');
    const stable = await awaitStableUiEligibility(state, after, read, authority, observe);
    phase.enter('consent-fresh');
    const fresh = await read(); observe(fresh);
    assert.ok(uiLaunchReady(fresh) && authority() && state.fence.sequence === stable.sequence && state.fence.fresh(after));
    await expect(consent).not.toBeChecked();
    await expect(submit).toBeDisabled();
    phase.enter('consent-check');
    observe(await read());
    await consent.check();
    phase.enter('submit-enabled');
    observe(await read());
    await expect(submit).toBeEnabled();
    const confirmed = await read(); observe(confirmed);
    assert.ok(uiLaunchReady(confirmed, true) && authority() && state.fence.sequence === stable.sequence && state.fence.fresh(after));
    phase.enter('launch-arm');
    activeLaunch = { state, target, sequence: state.fence.sequence, armed: true };
    const pending = waitResponse(page, SCANS, 'POST');
    phase.enter('launch-click');
    await submit.click();
    phase.enter('launch-receipt');
    const response = await pending;
    await pendingCreation.catch(() => {});
    phase.observe({ httpStatus: response?.status() });
    if (!response || response.status() !== 202) throw new Fault('LAUNCH_UNCONFIRMED_NO_RETRY');
    const body = await response.json(); assert.ok(UUID.test(body.scanId) && scans.has(body.scanId));
    activeLaunch = null;
    phase.enter('report-navigation');
    await settleReportNavigation(page, body.scanId, () => !stopped && !fatalCode && !state.closing);
    return body.scanId;
  };
  const status = async (page, id) => {
    const response = await http(page, `${SCANS}/${id}`); assert.equal(response.status, 200);
    const value = decoder.parseCurrentStatus(response.value), record = scans.get(id);
    assert.equal(value.scanId, id); assert.equal(value.profile, 'public-hub-amd64-v1'); assert.ok(sameChecks(value.checks));
    assert.equal(value.platform, 'linux/amd64'); assert.ok(DIGEST.test(value.digest));
    const repository = record.target.reference.split(':')[0];
    assert.equal(value.imageReference, `${repository}@${value.digest}`);
    const identity = [value.imageReference, value.digest, value.platform];
    if (record.identity) assert.deepEqual(identity, record.identity); else record.identity = identity;
    record.terminal = TERMINAL.has(value.state);
    for (const key of ['secret', 'sbom', 'vuln']) if (value.perCheck?.[key]) {
      const check = value.perCheck[key];
      assert.equal(check.scannerVersion, '0.69.3'); assert.equal(check.checksVersion, 'trivy-0.69.3-public-archive-v1');
      assert.ok(Date.parse(check.checkedAt) >= record.launchAt - 300_000 && Date.parse(check.checkedAt) <= Date.now() + 300_000);
    }
    if (value.state === 'completed') {
      const profile = response.value.imageProfile;
      assert.ok(exact(profile, ['version', 'configDigest', 'resourcePolicyVersion', 'qualified']));
      assert.equal(profile.version, 'public-hub-amd64-v1'); assert.equal(profile.resourcePolicyVersion, 'public-hub-resources-v1');
      assert.equal(profile.qualified, false); assert.ok(DIGEST.test(profile.configDigest));
      if (record.profile) assert.deepEqual(profile, record.profile); else record.profile = profile;
    }
    return value;
  };
  const observeProgress = async (page, id, requireActive = false) => {
    const deadline = Date.now() + 5000;
    let last;
    do {
      ensureLive();
      const before = await status(page, id), expected = progressExpectation(before);
      if (requireActive && !expected.active) return { status: 'INCONCLUSIVE', code: 'PROGRESS_NOT_OBSERVED' };
      const group = page.getByRole('group', { name: `Ход сканирования ${id}`, exact: true });
      if (await group.count() === 1) {
        const sample = await group.evaluate(progressDomSample, { expected, state: before.state });
        const after = await status(page, id);
        // A changed snapshot is not a UI mismatch. Observe boundedly, never freeze a worker.
        if (isDeepStrictEqual(before, after)) {
          last = sample;
          if (progressSampleMatches(sample)) return { status: 'PASS', code: 'VERIFIED', meta: { progressObserved: true, progressIndeterminate: sample.indeterminate, progressActive: expected.active } };
        }
      }
      await wait(100);
    } while (Date.now() < deadline);
    return last ? { status: 'BLOCKED', code: 'ASSERTION_FAILED', failure: true } : { status: 'INCONCLUSIVE', code: 'PROGRESS_NOT_OBSERVED' };
  };
  const statusMeta = snapshot => ({ scanId: snapshot.scanId, state: snapshot.state, digest: snapshot.digest, platform: snapshot.platform, ...(snapshot.progress ? { progress: snapshot.progress } : {}),
    checks: Object.fromEntries(CHECKS.map(key => [key, snapshot.perCheck?.[key]?.outcome ?? null])),
    counts: { ...Object.fromEntries(CHECKS.map(key => [key, snapshot.perCheck?.[key]?.outcome === 'checked' ? count(key === 'sbom' ? snapshot.perCheck[key].componentCount : snapshot.perCheck[key].findingCount) : null])), ...(snapshot.identifierCounts ? { cve: count(snapshot.identifierCounts.cve), debianTemp: count(snapshot.identifierCounts.debianTemp) } : {}) } });
  const terminalStatus = async (page, id) => {
    const deadline = Date.now() + WORKER_MS;
    do { ensureLive(); const value = await status(page, id); if (TERMINAL.has(value.state)) return value; await wait(1500); } while (Date.now() < deadline);
    throw new Fault('WORKER_DEADLINE_NO_RELAUNCH');
  };
  const config = {
    secret: { suffix: 'results', label: 'Secrets', region: 'Результаты Secrets', selector: 'ul.scan-report-inventory > li', sort: 'ruleId:asc', parse: (...args) => decoder.parseCurrentResults(...args) },
    sbom: { suffix: 'sbom', label: 'SBOM', region: 'Пакеты SBOM', selector: 'ul.scan-report-inventory > li', sort: 'name:asc', parse: (...args) => decoder.parseCurrentSbom(...args) },
    vuln: { suffix: 'vuln', label: 'Уязвимости', region: 'Результаты Уязвимости', selector: 'ul.scan-vuln-list > li', sort: 'severity:desc', parse: (...args) => decoder.parseCurrentVuln(...args) },
  };
  const wholeCount = (snapshot, kind) => count(kind === 'sbom' ? snapshot.perCheck[kind].componentCount : snapshot.perCheck[kind].findingCount);
  const collect = async (page, snapshot, kind, filter = {}, matched = wholeCount(snapshot, kind)) => {
    const cfg = config[kind], query = { view: 'report-v1', limit: 50, sort: cfg.sort, ...filter };
    let baseline;
    const result = await readAllPages(kind, { whole: wholeCount(snapshot, kind), matched }, async cursor => {
      const response = await http(page, `${SCANS}/${snapshot.scanId}/${cfg.suffix}?${reportViewSearch(kind, query, cursor)}`); assert.equal(response.status, 200);
      const value = cfg.parse(response.value, query, cursor);
      const coverage = kind === 'secret' ? response.value.coverage : value;
      assert.equal(coverage.outcome, 'checked'); assert.equal(coverage.scannerVersion, snapshot.perCheck[kind].scannerVersion); assert.equal(coverage.checkedAt, snapshot.perCheck[kind].checkedAt);
      if (kind !== 'secret') { assert.equal(value.image, snapshot.imageReference); assert.equal(value.platform, snapshot.platform); assert.equal(value.profile, snapshot.profile); }
      if (kind === 'sbom') assert.equal(value.os.name, scans.get(snapshot.scanId).target.os);
      if (kind === 'vuln') {
        assert.equal(value.resultContractVersion, 2); assert.ok(validateCveMetadata(value)); assert.ok(validateCveMetadata(snapshot.perCheck.vuln));
        assert.equal(cveMetadataIdentity(value), cveMetadataIdentity(snapshot.perCheck.vuln));
        assert.deepEqual(value.identifierCounts, snapshot.identifierCounts);
      }
      const identity = kind === 'secret' ? coverage : { image: value.image, platform: value.platform, scannerVersion: value.scannerVersion, checkedAt: value.checkedAt, os: value.os, node: value.node, ...(kind === 'vuln' ? { db: cveMetadataIdentity(value) } : {}) };
      if (baseline) assert.deepEqual(identity, baseline); else baseline = identity;
      return value;
    });
    if (kind === 'vuln' && !Object.keys(filter).length) assert.deepEqual(partition(result.rows), snapshot.identifierCounts);
    return { ...result, baseline };
  };
  const assertRenderedRows = async (region, kind, expectedRows) => {
    const rows = region.locator(config[kind].selector);
    await expect(rows).toHaveCount(expectedRows.length);
    for (const [index, row] of expectedRows.entries()) for (const part of renderedRowParts(kind, row)) await expect(rows.nth(index)).toContainText(part);
  };
  const verifyReport = async (page, snapshot) => {
    const reports = {};
    for (const kind of Object.keys(config)) {
      if (snapshot.perCheck?.[kind]?.outcome !== 'checked') {
        const region = page.getByRole('region', { name: config[kind].region, exact: true });
        await expect(region.locator(config[kind].selector)).toHaveCount(0);
        if (snapshot.state === 'cancelled' && !snapshot.perCheck?.[kind]) await expect(region).toContainText('неизвестно');
        continue;
      }
      reports[kind] = await collect(page, snapshot, kind);
      const region = page.getByRole('region', { name: config[kind].region, exact: true });
      await expect(region.getByRole('alert')).toHaveCount(0);
      await assertRenderedRows(region, kind, reports[kind].rows.slice(0, 25));
      if (kind === 'sbom') for (const row of reports[kind].rows.slice(0, 3)) await expect(region).toContainText(row.name);
      if (kind === 'vuln') await expect(region).toContainText(`Весь сохранённый отчёт (до фильтров): ${snapshot.identifierCounts.cve} CVE, ${snapshot.identifierCounts.debianTemp} Debian advisories`);
    }
    if (snapshot.perCheck?.config?.outcome === 'checked') await expect(page.getByRole('heading', { name: 'Image config · только метаданные образа', exact: true })).toBeVisible();
    return reports;
  };
  const uiReply = async (page, snapshot, kind, query, action, cursor) => {
    const pending = waitResponse(page, `${SCANS}/${snapshot.scanId}/${config[kind].suffix}`, 'GET', u => u.searchParams.toString() === reportViewSearch(kind, query, cursor));
    await action(); const response = await pending; assert.equal(response?.status(), 200);
    const value = config[kind].parse(await response.json(), query, cursor);
    const region = page.getByRole('region', { name: config[kind].region, exact: true });
    await assertRenderedRows(region, kind, rowsOf(kind, value));
    await expect(region.getByRole('alert')).toHaveCount(0);
    return value;
  };
  const pagination = async (page, snapshot, reports) => {
    if (!Object.keys(reports).length) throw new Fault('PREREQUISITE_UNAVAILABLE');
    let exercised = 0;
    for (const kind of Object.keys(reports)) {
      const cfg = config[kind], region = page.getByRole('region', { name: cfg.region, exact: true });
      const query = { view: 'report-v1', limit: 5, sort: cfg.sort };
      const first = await uiReply(page, snapshot, kind, query, () => region.getByLabel(`Строк на странице · ${cfg.label}`).selectOption('5'));
      assert.deepEqual(rowsOf(kind, first), reports[kind].rows.slice(0, 5));
      if (first.nextCursor !== null) {
        const second = await uiReply(page, snapshot, kind, query, () => region.getByRole('button', { name: `Далее · ${cfg.label} · сверху`, exact: true }).click(), first.nextCursor);
        assert.equal(second.page.offset, 5); assert.deepEqual(rowsOf(kind, second), reports[kind].rows.slice(5, 10));
        const back = await uiReply(page, snapshot, kind, query, () => region.getByRole('button', { name: `Назад · ${cfg.label} · сверху`, exact: true }).click());
        assert.deepEqual(rowsOf(kind, back), rowsOf(kind, first)); exercised++;
      }
      await uiReply(page, snapshot, kind, { ...query, limit: 25 }, () => region.getByLabel(`Строк на странице · ${cfg.label}`).selectOption('25'));
    }
    return { ...paginationVerdict(exercised, Object.keys(reports).length), meta: { checkedSets: exercised } };
  };
  const filters = async (page, snapshot, reports) => {
    if (!Object.keys(reports).length) throw new Fault('PREREQUISITE_UNAVAILABLE');
    for (const kind of Object.keys(reports)) {
      const cfg = config[kind], rows = reports[kind].rows, region = page.getByRole('region', { name: cfg.region, exact: true });
      const selected = kind === 'sbom' ? rows[0]?.ecosystem ?? 'npm' : kind === 'vuln' ? rows[0]?.severity ?? 'HIGH' : 'known';
      const filter = kind === 'sbom' ? { ecosystem: selected } : kind === 'vuln' ? { severity: [selected] } : { linePresence: selected };
      const expected = rows.filter(row => kind === 'sbom' ? row.ecosystem === selected : kind === 'vuln' ? row.severity === selected : row.line !== null);
      const filtered = await collect(page, snapshot, kind, filter, expected.length);
      assert.deepEqual(filtered.rows, expected);
      const label = kind === 'sbom' ? 'Экосистема · SBOM' : kind === 'vuln' ? 'Уровень опасности (severity) · Уязвимости' : 'Номер строки · Secrets';
      const query = { view: 'report-v1', limit: 25, sort: cfg.sort, ...filter };
      const value = await uiReply(page, snapshot, kind, query, () => region.getByLabel(label).selectOption(selected));
      assert.equal(value.page.totalCount, rows.length); assert.equal(value.page.matchedCount, expected.length); assert.equal(value.page.offset, 0);
      assert.deepEqual(rowsOf(kind, value), expected.slice(0, 25));
      await uiReply(page, snapshot, kind, { view: 'report-v1', limit: 25, sort: cfg.sort }, () => region.getByLabel(label).selectOption(''));
    }
    return ok(undefined, { checkedSets: Object.keys(reports).length });
  };
  const list = async page => {
    const rows = [], seen = new Set(); let cursor = null;
    for (let index = 0; index < 100; index++) {
      const response = await http(page, `${SCANS}?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`); assert.equal(response.status, 200);
      const value = decoder.parseCurrentList(response.value);
      for (const row of value.scans) { assert.ok(!seen.has(row.scanId)); seen.add(row.scanId); rows.push(row); }
      if (value.nextCursor === null) return rows;
      assert.ok(value.scans.length && value.nextCursor !== cursor); cursor = value.nextCursor;
    }
    throw new Fault('ASSERTION_FAILED', true);
  };
  const history = async (page, snapshots) => {
    const rows = await list(page); await page.goto(`${ORIGIN}/scans`);
    for (const snapshot of snapshots) {
      const row = rows.find(item => item.scanId === snapshot.scanId); assert.ok(row); assert.equal(row.state, snapshot.state); assert.equal(row.digest, snapshot.digest); assert.equal(row.platform, 'linux/amd64');
      await expect(page.locator(`a[href="/scans/${snapshot.scanId}"]`)).toBeVisible();
    }
    return ok(undefined, { checkedSets: snapshots.length });
  };
  const deny = async (handle, id, expected) => {
    for (const suffix of ['', '/events', '/results?view=report-v1', '/sbom?view=report-v1', '/vuln?view=report-v1', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage']) {
      assertDeniedReply(await http(handle.page, `${SCANS}/${id}${suffix}`, undefined, suffix === '/events'), expected);
    }
    const path = `${SCANS}/${id}/cancel`; permit(handle.state, path, body => exact(body, []));
    assertDeniedReply(await http(handle.page, path, {}), expected);
    await handle.page.goto(`${ORIGIN}/scans/${id}`);
    await expect(handle.page.locator('ul.scan-report-inventory > li, ul.scan-vuln-list > li')).toHaveCount(0);
    await expect(handle.page.getByRole('region', { name: 'Чат по отчёту', exact: true })).toHaveCount(0);
    if (expected === 404) { await expect(handle.page.getByRole('alert')).toContainText('Не удалось получить данные скана'); assert.equal((await list(handle.page)).some(row => row.scanId === id), false); }
    else await expect(handle.page.getByRole('link', { name: 'войдите', exact: true })).toBeVisible();
    return ok(undefined, { httpStatus: expected });
  };
  const denyMutations = async (handle, id, expected, ownerContext, ownPage) => {
    const response = await http(ownPage, `${SCANS}/${id}/llm/readiness`); assert.equal(response.status, 200);
    const readiness = chat.chatReadinessSchema.parse(response.value);
    if (!keyBoundaryAllowed(readiness, ownerContext)) throw new Fault('KEY_NOT_ABSENT_NO_POST');
    {
      const base = { epoch: ownerContext.epoch, revision: ownerContext.revision, reportVersion: ownerContext.reportVersion };
      const mutations = [
        ['chat', { ...base, mutationId: randomUUID(), question: QUESTION, consent: { accepted: true, policyVersion: ownerContext.policyVersion } }],
        ['history/decision', { ...base, mutationId: randomUUID(), text: DECISION, findingIds: [] }],
      ];
      for (const [suffix, body] of mutations) {
        const mutationPath = `${SCANS}/${id}/llm/${suffix}`;
        permit(handle.state, mutationPath, value => isDeepStrictEqual(value, body));
        assertDeniedReply(await http(handle.page, mutationPath, body), expected);
      }
    }
    return ok(undefined, { httpStatus: expected });
  };
  let expect;
  try {
    await Promise.race([interrupted, (async () => {
      const tools = await step('tooling', async () => {
        const contracts = await loadContracts();
        ({ decoder, chat } = contracts);
        ({ reportViewSearch } = contracts.view);
        ({ validateCveMetadata, cveMetadataIdentity } = contracts.metadata);
        const { chromium, expect: baseExpect } = await import('@playwright/test'); expect = baseExpect.configure({ timeout: 15_000 });
        const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
        browser = await chromium.launch({ headless: true, timeout: 20_000, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false, env, args: [...BROWSER_ARGS] });
        return ok(true);
      });
      if (!tools) return;
      let own = await newPage();
      if (!await step('registration', async () => { await auth(own, owner, 'register'); return ok(true); })) return;
      const completed = [];
      if (plan.cancelOnly) {
        await runCancellation();
        return;
      }
      for (const target of plan.targets) {
        const snapshot = await step(`${target.name}.scan`, async () => {
          const id = await launch(own, target), value = await terminalStatus(own.page, id);
          const all = value.state === 'completed' && CHECKS.every(key => value.perCheck?.[key]?.outcome === 'checked');
          return { value, status: all ? 'PASS' : 'BLOCKED', code: all ? 'VERIFIED' : 'REQUIRED_CHECK_NOT_CHECKED', meta: { ...statusMeta(value), allChecksChecked: all } };
        });
        if (!snapshot) break;
        completed.push(snapshot);
        const reports = await step(`${target.name}.report`, async () => {
          const value = await verifyReport(own.page, snapshot);
          return { value, status: Object.keys(value).length === 3 && snapshot.perCheck.config?.outcome === 'checked' ? 'PASS' : 'BLOCKED', code: Object.keys(value).length === 3 && snapshot.perCheck.config?.outcome === 'checked' ? 'VERIFIED' : 'REQUIRED_CHECK_NOT_CHECKED', meta: { ...statusMeta(snapshot), pages: Object.values(value).reduce((sum, item) => sum + item.pages, 0) } };
        });
        if (reports) {
          if (!plan.smokeOnly) await step(`${target.name}.pagination`, () => pagination(own.page, snapshot, reports));
          await step(`${target.name}.filters`, () => filters(own.page, snapshot, reports));
          await step(`${target.name}.reload`, async () => {
            await own.page.reload(); assert.deepEqual(await status(own.page, snapshot.scanId), snapshot);
            assert.deepEqual(await verifyReport(own.page, snapshot), reports); return ok();
          });
        }
        if (!plan.smokeOnly) await step(`${target.name}.events`, async () => {
          const response = await http(own.page, `${SCANS}/${snapshot.scanId}/events`, undefined, true); assert.equal(response.status, 200);
          return { status: response.hint ? 'PASS' : 'INCONCLUSIVE', code: response.hint ? 'VERIFIED' : 'SSE_NOT_OBSERVED', meta: { observedEvents: response.hint ? 1 : 0 } };
        });
      }
      if (!completed.length) return;
      await step('scan_history', () => history(own.page, completed));
      let other, foreignRegistered, anonymous;
      if (!plan.smokeOnly) {
        other = await newPage();
        foreignRegistered = await step('foreign_registration', async () => { await auth(other, foreign, 'register'); return ok(true); });
        if (foreignRegistered) await step('ownership', () => deny(other, completed[0].scanId, 404));
        anonymous = await newPage(); await anonymous.page.goto(`${ORIGIN}/login`);
        await step('anonymous', () => deny(anonymous, completed[0].scanId, 401));
      }
      const report = completed.find(s => CHECKS.some(key => key !== 'sbom' && s.perCheck?.[key]?.outcome === 'checked' && s.perCheck[key].findingCount > 0)) ?? completed[0];
      const llmPath = `${SCANS}/${report.scanId}/llm`;
      const openChat = async page => {
        const panel = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
        await expect(panel).toBeVisible();
        await expect(panel.getByRole('button', { name: 'Открыть чат', exact: true })).toHaveCount(0);
        await expect(panel.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toBeVisible();
        await expect(panel.getByRole('region', { name: 'Готовность генерации', exact: true })).toContainText('Генерация не проверена.');
        return panel;
      };
      const readChat = async page => {
        const r = await http(page, `${llmPath}/chat/context`), h = await http(page, `${llmPath}/history`);
        if (r.status !== 200 || h.status !== 200) throw new Fault('LLM_STORES_OR_CONTEXT_UNAVAILABLE');
        const context = chat.chatContextSchema.parse(r.value), saved = chat.chatHistorySchema.parse(h.value);
        assert.equal(context.scanId, report.scanId); assert.equal(context.digest, report.digest); assert.equal(context.platform, report.platform);
        assert.equal(saved.scanId, context.scanId); assert.equal(saved.epoch, context.epoch); assert.equal(saved.revision, context.revision);
        return { context, saved };
      };
      // Shared fresh-login proof; neither mode injects cookies or inherits storage.
      const freshLogin = async () => {
        own.state.closing = true; await own.context.close(); own = await newPage(); await own.page.goto(`${ORIGIN}/login`);
        return step('fresh_login', async () => {
          assert.equal((await http(own.page, `${SCANS}/${completed[0].scanId}`)).status, 401);
          await auth(own, owner, 'login'); await history(own.page, completed);
          for (const snapshot of completed) { await own.page.goto(`${ORIGIN}/scans/${snapshot.scanId}`); assert.deepEqual(await status(own.page, snapshot.scanId), snapshot); await verifyReport(own.page, snapshot); }
          return ok(true, { checkedSets: completed.length });
        });
      };
      let panel, ready, head, savedHistory;
      await own.page.goto(`${ORIGIN}/scans/${report.scanId}`);
      await step('llm_readiness', async () => {
        const before = own.state.generationPosts;
        panel = await openChat(own.page);
        const response = await http(own.page, `${llmPath}/readiness`); assert.equal(response.status, 200);
        ready = chat.chatReadinessSchema.parse(response.value);
        assert.equal(ready.scanId, report.scanId); assert.equal(ready.digest, report.digest); assert.equal(ready.platform, report.platform);
        assert.equal(ready.generationVerified, false); assert.equal(ready.requiresConsent, true); assert.equal(ready.acceptsCredentials, false);
        assert.equal(own.state.generationPosts, before);
        if (ready.credential !== 'missing') return { status: 'BLOCKED', code: 'KEY_NOT_ABSENT_NO_POST', meta: { credential: ready.credential, blockers: ready.blockers } };
        assert.equal(ready.localReady, false); assert.ok(ready.blockers.includes('public-key-required'));
        if (ready.history === 'available') {
          await expect(panel.getByLabel('Вопрос чату', { exact: true })).toBeVisible();
          await panel.getByLabel('Вопрос чату', { exact: true }).fill(QUESTION);
          await expect(panel.locator('#scan-chat-send-help')).toBeVisible();
          await expect(panel.getByRole('button', { name: 'Отправить вопрос', exact: true })).toBeDisabled();
        }
        await expect(own.page.getByRole('heading', { name: 'Image config · только метаданные образа', exact: true })).toBeVisible();
        return ok(undefined, { credential: ready.credential, blockers: ready.blockers, noGenerationPosts: true });
      });
      if (plan.smokeOnly) {
        const saved = await step('llm_reload', async () => {
          if (book.cases.llm_readiness.status !== 'PASS') throw new Fault('PREREQUISITE_UNAVAILABLE');
          const before = await readChat(own.page);
          if (!keyBoundaryAllowed(ready, before.context)) throw new Fault('LLM_STORES_OR_CONTEXT_UNAVAILABLE');
          await own.page.reload(); panel = await openChat(own.page);
          assert.deepEqual((await readChat(own.page)).saved, before.saved);
          assert.equal(own.state.generationPosts, 0);
          return ok(before.saved, { historyUnchanged: true, noGenerationPosts: true });
        });
        if (!await freshLogin()) return;
        await step('llm_fresh_login', async () => {
          if (!saved) throw new Fault('PREREQUISITE_UNAVAILABLE');
          panel = await openChat(own.page);
          const current = await readChat(own.page), response = await http(own.page, `${llmPath}/readiness`);
          assert.equal(response.status, 200);
          const fresh = chat.chatReadinessSchema.parse(response.value);
          if (!keyBoundaryAllowed(fresh, current.context)) throw new Fault(fresh.credential !== 'missing' ? 'KEY_NOT_ABSENT_NO_POST' : 'LLM_STORES_OR_CONTEXT_UNAVAILABLE');
          assert.deepEqual(current.saved, saved);
          await expect(panel.locator('#scan-chat-send-help')).toBeVisible();
          await expect(panel.getByRole('button', { name: 'Отправить вопрос', exact: true })).toBeDisabled();
          assert.equal(own.state.generationPosts, 0);
          return ok(undefined, { credential: fresh.credential, historyUnchanged: true, noGenerationPosts: true });
        });
        return; // No negative-generation, decision, foreign-account or cancel mutations in smoke mode.
      }
      head = await step('llm_no_consent', async () => {
        const { context, saved } = await readChat(own.page);
        const body = { epoch: context.epoch, revision: context.revision, mutationId: randomUUID(), reportVersion: context.reportVersion, question: QUESTION, consent: { accepted: false, policyVersion: context.policyVersion } };
        permit(own.state, `${llmPath}/chat`, value => isDeepStrictEqual(value, body));
        const response = await http(own.page, `${llmPath}/chat`, body);
        assert.equal(response.status, 403); assert.deepEqual(response.value, { errorCode: 'LLM_CONSENT_REQUIRED' });
        assert.deepEqual((await readChat(own.page)).saved, saved);
        return ok(context, { httpStatus: 403, historyUnchanged: true });
      });
      await step('llm_missing_key', async () => {
        const before = await readChat(own.page), response = await http(own.page, `${llmPath}/readiness`);
        if (response.status !== 200) throw new Fault('LLM_STORES_OR_CONTEXT_UNAVAILABLE');
        const fresh = chat.chatReadinessSchema.parse(response.value);
        if (!keyBoundaryAllowed(fresh, before.context)) throw new Fault(fresh.credential !== 'missing' ? 'KEY_NOT_ABSENT_NO_POST' : 'LLM_STORES_OR_CONTEXT_UNAVAILABLE');
        if (!before.context.findingCount) throw new Fault('NO_EVIDENCE');
        const usage = await http(own.page, `${llmPath}/chat/usage`); assert.equal(usage.status, 200);
        if (usage.value?.available === false) throw new Fault('QUOTA_UNAVAILABLE');
        assertChatUsage(usage.value, before.context);
        // Operator ack forbids concurrent key activation. Metadata is not a key-content proof.
        const body = { epoch: before.context.epoch, revision: before.context.revision, mutationId: randomUUID(), reportVersion: before.context.reportVersion, question: QUESTION, consent: { accepted: true, policyVersion: before.context.policyVersion } };
        permit(own.state, `${llmPath}/chat`, value => isDeepStrictEqual(value, body));
        const result = await http(own.page, `${llmPath}/chat`, body);
        if (result.status === 409 && result.value?.errorCode === 'LLM_CONTEXT_LIMIT') throw new Fault('CONTEXT_LIMIT');
        assert.equal(result.status, 503); assert.deepEqual(result.value, { errorCode: 'LLM_CONFIGURATION_UNAVAILABLE' });
        assert.deepEqual((await readChat(own.page)).saved, before.saved);
        const after = await http(own.page, `${llmPath}/chat/usage`); assert.equal(after.status, 200);
        assertChatUsage(after.value, before.context);
        if (!isDeepStrictEqual(after.value.window, usage.value.window)) return { status: 'INCONCLUSIVE', code: 'QUOTA_WINDOW_CHANGED', meta: { httpStatus: 503, historyUnchanged: true } };
        for (const scope of ['user', 'scan']) for (const vector of ['used', 'held', 'carried']) assert.deepEqual(after.value[scope]?.[vector], usage.value[scope]?.[vector]);
        book.record('llm_generation', 'BLOCKED', 'KEY_ABSENT');
        return ok(undefined, { httpStatus: 503, credential: 'missing', historyUnchanged: true, quotaUnchanged: true });
      });
      savedHistory = await step('llm_manual_history', async () => {
        if (!head || !panel) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const beforePosts = own.state.generationPosts;
        await panel.getByRole('button', { name: 'Обновить историю и условия чата', exact: true }).click();
        await panel.getByLabel('Текст решения', { exact: true }).fill(DECISION);
        const current = await readChat(own.page);
        permit(own.state, `${llmPath}/history/decision`, body => exact(body, ['epoch', 'revision', 'mutationId', 'reportVersion', 'text', 'findingIds']) && UUID.test(body.mutationId) && body.epoch === current.context.epoch && body.revision === current.context.revision && body.reportVersion === current.context.reportVersion && body.text === DECISION && isDeepStrictEqual(body.findingIds, []));
        const pending = waitResponse(own.page, `${llmPath}/history/decision`, 'POST');
        await panel.getByRole('button', { name: 'Сохранить решение', exact: true }).click(); assert.equal((await pending)?.status(), 200);
        await expect(panel.getByText(DECISION, { exact: true })).toBeVisible();
        const after = await readChat(own.page); assert.equal(after.saved.decisions.length, current.saved.decisions.length + 1); assert.equal(after.saved.decisions.at(-1).text, DECISION);
        assert.equal(own.state.generationPosts, beforePosts);
        return ok(after.saved, { noGenerationPosts: true });
      });
      await step('llm_reload', async () => {
        if (!savedHistory) throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.reload(); panel = await openChat(own.page);
        assert.deepEqual((await readChat(own.page)).saved, savedHistory); await expect(panel.getByText(DECISION, { exact: true })).toBeVisible();
        return ok(undefined, { historyUnchanged: true });
      });
      const loggedIn = await freshLogin();
      if (!loggedIn) return;
      await step('llm_fresh_login', async () => {
        if (!savedHistory) throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.goto(`${ORIGIN}/scans/${report.scanId}`); panel = await openChat(own.page);
        assert.deepEqual((await readChat(own.page)).saved, savedHistory); await expect(panel.getByText(DECISION, { exact: true })).toBeVisible();
        await expect(panel.locator('#scan-chat-send-help')).toBeVisible();
        assert.equal(own.state.generationPosts, 0); return ok(undefined, { historyUnchanged: true, noGenerationPosts: true });
      });
      // Repeat denial after a real durable decision exists, not only against an empty history.
      if (savedHistory) {
        const ownerContext = (await readChat(own.page)).context;
        if (foreignRegistered) {
          await step('ownership', () => deny(other, report.scanId, 404));
          await step('ownership_mutations', () => denyMutations(other, report.scanId, 404, ownerContext, own.page));
        }
        await step('anonymous', () => deny(anonymous, report.scanId, 401));
        await step('anonymous_mutations', () => denyMutations(anonymous, report.scanId, 401, ownerContext, own.page));
        assert.deepEqual((await readChat(own.page)).saved, savedHistory);
      }
      async function runCancellation() {
      const cancelled = await step('cancel', async () => {
        if (stats.scanLaunches !== scans.size || [...scans.values()].some(record => !record.terminal)) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const id = await launch(own, TARGETS[0]);
        // Observation never dispatches/cancels; failure must not prevent the one
        // authorized cancellation from proceeding to its durable checks.
        if (plan.cancelOnly) {
          phase.enter('progress-snapshot');
          let progress;
          try { progress = await observeProgress(own.page, id, true); }
          catch (error) { progress = { status: 'BLOCKED', code: 'ASSERTION_FAILED', failure: true, meta: failureMeta(error) }; }
          book.record('cancel_progress', progress.status, progress.code, { ...phase.meta(), ...progress.meta }, progress.failure);
        }
        phase.enter('subset-observation');
        let before = await status(own.page, id);
        phase.observe(statusMeta(before));
        // Only durable outcome metadata is public while running. Never collect
        // private checkpoint findings/datasets, even when checkedChecks is positive.
        const observationDeadline = Date.now() + (plan.cancelOnly ? WORKER_MS : 20_000);
        while (cancelObservation(before) === 'waiting' && Date.now() < observationDeadline) {
          ensureLive(); await wait(500); before = await status(own.page, id); phase.observe(statusMeta(before));
        }
        if (cancelObservation(before) === 'waiting') return { status: 'INCONCLUSIVE', code: 'NO_COMPLETED_SUBSET_OBSERVED', meta: statusMeta(before) };
        const observed = checkpointChecks(before);
        if (!TERMINAL.has(before.state)) {
          assert.ok(Object.values(before.perCheck ?? {}).every(value => value == null));
          assert.equal(before.config, undefined);
          const visibleRows = await own.page.locator('ul.scan-report-inventory > li, li.scan-vuln-row').count();
          if (visibleRows > 0) {
            const current = await status(own.page, id);
            if (TERMINAL.has(current.state)) before = current; // Legitimate terminal publication won the race.
            else assert.equal(visibleRows, 0); // No private row content is read, even on this violation.
          }
        }
        phase.enter('cancel-available');
        let httpStatus = null;
        const stillActive = !TERMINAL.has(before.state) && !TERMINAL.has((await status(own.page, id)).state);
        if (stillActive) {
          const button = own.page.getByRole('button', { name: 'Отменить скан', exact: true });
          if (await button.isVisible()) {
            const path = `${SCANS}/${id}/cancel`; permit(own.state, path, body => exact(body, []));
            const pending = waitResponse(own.page, path, 'POST');
            own.page.once('dialog', dialog => dialog.type() === 'confirm' && dialog.message() === 'Отменить скан? Сохранённые результаты завершённых проверок останутся доступны. Остальные проверки не будут завершены.' ? dialog.accept() : dialog.dismiss());
            phase.enter('cancel-click');
            try { await button.click({ timeout: 2000 }); }
            catch (error) { if (!TERMINAL.has((await status(own.page, id)).state)) throw error; }
            phase.enter('cancel-receipt');
            const response = await pending; httpStatus = response?.status() ?? null;
            phase.observe({ httpStatus });
            if (httpStatus === 200) assert.deepEqual(await response.json(), { scanId: id, state: 'cancelled' });
          }
        }
        phase.enter('cancel-terminal');
        const after = await terminalStatus(own.page, id), verdict = cancelVerdict(after.state, httpStatus);
        return { ...verdict, value: { before, after, observed }, meta: { ...statusMeta(after), ...(httpStatus ? { httpStatus } : {}), observedCompletedChecks: observed,
          preCancelProgress: before.progress, preCancelFindingsRead: false, preCancelByteComparison: false, ...(!TERMINAL.has(before.state) ? { preCancelReportUiEmpty: true } : {}) } };
      });
      if (cancelled) {
        let focusedReports;
        if (plan.cancelOnly) focusedReports = await step('cancel_report', async () => {
          phase.enter('cancel-report');
          if (cancelled.after.state !== 'cancelled') return { status: 'INCONCLUSIVE', code: 'CANCEL_RACE' };
          await own.page.goto(`${ORIGIN}/scans/${cancelled.after.scanId}`);
          const reports = await verifyReport(own.page, cancelled.after);
          const progress = await observeProgress(own.page, cancelled.after.scanId);
          return { ...progress, value: reports, meta: { ...statusMeta(cancelled.after), checkedSets: Object.keys(reports).length, ...progress.meta } };
        });
        await step('cancel_preservation', async () => {
          phase.enter('cancel-preservation');
          const { before, after, observed } = cancelled;
          if (after.state !== 'cancelled') return { status: 'INCONCLUSIVE', code: 'CANCEL_RACE' };
          assertCancelOutcomePreservation(before, after);
          if (plan.cancelOnly && !focusedReports) throw new Fault('PREREQUISITE_UNAVAILABLE');
          const persisted = plan.cancelOnly ? focusedReports : await verifyReport(own.page, after);
          await wait(2000); // Bounded observation, not a guarantee about all future writes.
          assert.deepEqual(await status(own.page, after.scanId), after);
          assert.deepEqual(await verifyReport(own.page, after), persisted);
          return { status: 'PASS', code: 'VERIFIED', meta: { observedCompletedChecks: observed,
            preCancelProgress: before.progress, preCancelFindingsRead: false, preCancelByteComparison: false,
            postCancelBaselineVerified: true, preservationBasis: 'post-cancel-published-baseline-v1' } };
        });
        if (plan.cancelOnly) await step('cancel_reload', async () => {
          phase.enter('cancel-reload');
          const { after } = cancelled;
          if (after.state !== 'cancelled') return { status: 'INCONCLUSIVE', code: 'CANCEL_RACE' };
          if (!focusedReports) throw new Fault('PREREQUISITE_UNAVAILABLE');
          await own.page.reload(); assert.deepEqual(await status(own.page, after.scanId), after);
          assert.deepEqual(await verifyReport(own.page, after), focusedReports);
          const progress = await observeProgress(own.page, after.scanId);
          await wait(2000);
          const final = await status(own.page, after.scanId);
          assert.deepEqual(final, after);
          assert.deepEqual(await verifyReport(own.page, final), focusedReports);
          return { ...progress, meta: { ...statusMeta(final), historyUnchanged: true, ...progress.meta } };
        });
        await step('cancel_history', () => { phase.enter('cancel-history'); return history(own.page, [...completed, cancelled.after]); });
        await step('cancel_fresh_login', async () => {
          phase.enter('cancel-fresh-login');
          own.state.closing = true; await own.context.close(); own = await newPage();
          assert.equal((await own.context.cookies()).length, 0);
          await own.page.goto(`${ORIGIN}/login`);
          assert.equal((await http(own.page, `${SCANS}/${cancelled.after.scanId}`)).status, 401);
          await auth(own, owner, 'login'); await history(own.page, [...completed, cancelled.after]);
          await own.page.goto(`${ORIGIN}/scans/${cancelled.after.scanId}`);
          assert.deepEqual(await status(own.page, cancelled.after.scanId), cancelled.after);
          const reports = await verifyReport(own.page, cancelled.after);
          if (plan.cancelOnly && focusedReports) assert.deepEqual(reports, focusedReports);
          const progress = plan.cancelOnly ? await observeProgress(own.page, cancelled.after.scanId) : { status: 'PASS', code: 'VERIFIED' };
          return { ...progress, meta: { state: cancelled.after.state, historyUnchanged: true, ...progress.meta } };
        });
      }
      }
      await runCancellation();
    })()]);
  } catch (e) {
    const code = fatalCode ?? (e instanceof BrowserReadError ? 'BROWSER_READ_FAILED' : e instanceof Fault ? e.message : 'ASSERTION_FAILED');
    book.record(currentCase, 'BLOCKED', code, { ...phase.meta(), ...failureMeta(e), ...(e instanceof BrowserReadError ? e.meta : {}) }, e instanceof BrowserReadError ? false : !(e instanceof Fault) || e.failure);
  } finally {
    stopped = true; for (const state of contextStates.values()) state.closing = true; clearTimeout(globalTimer); process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); process.removeListener('SIGHUP', signal);
    try { await bounded(Promise.allSettled(contexts.map(context => context.close())), 10_000); if (browser) await bounded(browser.close(), 10_000); browserClosed = !browser || !browser.isConnected(); }
    catch { browserClosed = false; }
    const smokeMutationViolation = (plan.smokeOnly || plan.cancelOnly) && (stats.scanLaunches > 1 || stats.accountsCreated > 1 || contexts.some(context => contextStates.get(context)?.generationPosts > 0) || plan.cancelOnly && stats.cancelPosts > 1);
    const failure = !browserClosed || stats.blockedRequests > 0 || stats.pageErrors > 0 || smokeMutationViolation;
    book.record('safety', failure ? 'BLOCKED' : 'PASS', !browserClosed ? 'CLEANUP_FAILED' : stats.blockedRequests || smokeMutationViolation ? 'REQUEST_GUARD' : stats.pageErrors ? 'PAGE_ERRORS' : 'VERIFIED', { ...stats, noGenerationPosts: contexts.every(context => contextStates.get(context)?.generationPosts === 0), browserClosed, nativeScanMayRemainActive: stats.scanLaunches !== scans.size || [...scans.values()].some(record => !record.terminal) }, failure);
    book.finishedAt = new Date().toISOString();
    const evidence = book.evidence();
    // Only our projected cases go to stdout/disk, never caught exceptions or Playwright diagnostics.
    if (book.actual) { try { await writeEvidence(evidence); } catch { book.record('safety', 'BLOCKED', 'EVIDENCE_WRITE_FAILED', {}, true); } }
    console.log(JSON.stringify(book.evidence(), null, 2));
  }
  return resultExitCode(book);
}

export function resultExitCode(book) {
  const results = Object.entries(book.cases);
  if (results.some(([, item]) => item.failure)) return 1;
  return results.some(([id, item]) => id !== 'llm_generation' && (book.plan.smokeOnly || book.plan.cancelOnly ? item.status !== 'PASS' : item.status === 'BLOCKED')) ? 2 : 0;
}

export function offlineSelfTest() {
  assert.equal(parseMode([]), 'not-run'); assert.equal(parseMode(['--self-test']), 'offline');
  assert.throws(() => parseMode(['--run']));
  assert.equal(parseMode(['--run', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', randomUUID()]), 'native');
  assert.equal(parseMode(['--run', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', randomUUID()]), 'smoke');
    assert.equal(parseMode(['--run', '--cancel-only', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', randomUUID()]), 'cancel');
  assert.throws(() => parseMode(['--run', '--smoke-only']));
  assert.ok(scanLaunchAllowed(nativePlan('smoke'), TARGETS[0], 0));
  assert.ok(!scanLaunchAllowed(nativePlan('smoke'), TARGETS[0], 1));
  assert.ok(!smokeMutationAllowed(`${SCANS}/example/llm/chat`));
  assert.ok(fixedUrl(`${ORIGIN}/scans`)); assert.ok(!fixedUrl('http://127.0.0.1:8080/scans'));
  assert.ok(!fixedUrl('http://localhost:8081/scans'));
  const fence = new EligibilityFence(); const seq = fence.start();
  fence.accept(seq, { checks: CHECKS, imageReference: TARGETS[0].reference }, { imageReference: TARGETS[0].reference, eligible: true, reason: 'READY', eligibility: 'public-hub-profile', allowedCheckSets: [CHECKS] }, TARGETS[0], 100);
  assert.ok(fence.fresh(0, 101)); assert.ok(!fence.fresh(seq, 101)); assert.ok(!fence.fresh(0, 30101));
  assert.deepEqual(safeMeta({ password: 'synthetic', token: 'synthetic', payload: { raw: true }, counts: { secret: 0, vuln: null, raw: 22 } }), { counts: { secret: 0, vuln: null } });
  assert.equal(cancelVerdict('completed', 409).status, 'INCONCLUSIVE');
  console.log(JSON.stringify({ status: 'PASS', scope: 'OFFLINE_GUARDS_ONLY', browserLaunched: false, networkRequests: 0, accountsCreated: 0, evidenceWritten: false }));
}
async function main() {
  let mode;
  try { mode = parseMode(process.argv.slice(2)); } catch { console.log(JSON.stringify({ status: 'BLOCKED', code: 'INVALID_ARGUMENTS', browserLaunched: false })); return 2; }
  if (mode === 'offline') { offlineSelfTest(); return 0; }
  if (mode === 'not-run') { console.log(JSON.stringify({ status: 'BLOCKED', code: 'NOT_RUN', browserLaunched: false, requiresCoordinatorGo: true, requiresNoConcurrentKeyActivation: true })); return 2; }
  try { return await runNative(mode, process.argv.at(-1)); }
  catch (e) { console.log(JSON.stringify({ status: 'BLOCKED', code: e instanceof Fault ? e.message : 'ASSERTION_FAILED', rawDiagnosticsSuppressed: true })); return 1; }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main();
