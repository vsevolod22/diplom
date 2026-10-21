// Native acceptance only. No stand lifecycle, fixture server, mock response or saved credentials.
// LIVE (only after coordinator GO; key activation must stay fenced throughout this run):
// node tests-e2e/public-product-live.mjs --run --ack-coordinator-go --ack-no-key-activation
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
const CODES = new Set(['NOT_RUN', 'VERIFIED', 'INVALID_ARGUMENTS', 'STAND_OR_BROWSER_UNAVAILABLE', 'ELIGIBILITY_NOT_READY', 'LAUNCH_UNCONFIRMED_NO_RETRY', 'WORKER_DEADLINE_NO_RELAUNCH', 'REQUIRED_CHECK_NOT_CHECKED', 'PREREQUISITE_UNAVAILABLE', 'ASSERTION_FAILED', 'REQUEST_GUARD', 'GLOBAL_DEADLINE', 'INTERRUPTED', 'CLEANUP_FAILED', 'PAGE_ERRORS', 'EVIDENCE_ALREADY_EXISTS', 'EVIDENCE_WRITE_FAILED', 'NO_SECOND_PAGE', 'SSE_NOT_OBSERVED', 'CANCEL_RACE', 'NO_COMPLETED_SUBSET_OBSERVED', 'SUBSET_CAPTURE_CHANGED', 'UNSAFE_DEBUG_ENVIRONMENT', 'KEY_ABSENT', 'KEY_NOT_ABSENT_NO_POST', 'LLM_STORES_OR_CONTEXT_UNAVAILABLE', 'NO_EVIDENCE', 'CONTEXT_LIMIT', 'GENERATION_NOT_AUTHORIZED', 'QUOTA_WINDOW_CHANGED', 'QUOTA_UNAVAILABLE', 'INCOMPLETE_PAGINATION_COVERAGE']);
const CASES = ['tooling', 'registration', ...TARGETS.flatMap(t => ['scan', 'report', 'pagination', 'filters', 'events', 'reload'].map(s => `${t.name}.${s}`)), 'scan_history', 'foreign_registration', 'ownership', 'anonymous', 'ownership_mutations', 'anonymous_mutations', 'llm_readiness', 'llm_no_consent', 'llm_missing_key', 'llm_manual_history', 'llm_reload', 'fresh_login', 'llm_fresh_login', 'llm_generation', 'cancel', 'cancel_preservation', 'cancel_history', 'cancel_fresh_login', 'safety'];
const EVIDENCE = ['public-product-browser-20261021.json', 'public-product-browser-20261021.md'].map(name => join(ROOT, 'docs', name));
const QUESTION = 'Какие ограничения покрытия этого отчёта нужно учесть при ручной проверке?';
const DECISION = 'Проверить приоритеты находок вручную; это решение пользователя, не вывод сканера.';

export function parseMode(args) {
  if (isDeepStrictEqual(args, ['--self-test'])) return 'offline';
  if (isDeepStrictEqual(args, ['--run', '--ack-coordinator-go', '--ack-no-key-activation'])) return 'native';
  if (!args.length) return 'not-run';
  throw new Error('INVALID_ARGUMENTS');
}
export function fixedUrl(input) {
  try { const u = new URL(input); return input.startsWith(`${ORIGIN}/`) && u.origin === ORIGIN && !u.username && !u.password && !u.hash; }
  catch { return false; }
}
export function allowedGet(path, ids) {
  if (path === '/api/v1/auth/me' || path === SCANS) return true;
  for (const id of ids) if (UUID.test(id) && ['', '/events', '/results', '/sbom', '/vuln', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage'].some(suffix => path === `${SCANS}/${id}${suffix}`)) return true;
  return false;
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
export function assertDeniedReply(response, expected) {
  assert.equal(response.status, expected);
  const value = response.value;
  if (exact(value, ['errorCode'])) {
    assert.ok(['UNAUTHORIZED', 'SCAN_NOT_FOUND', 'SCAN_ACCESS_DENIED', 'SCAN_ACCESS_DISABLED', 'LLM_UNAVAILABLE', 'LLM_REPORT_UNAVAILABLE'].includes(value.errorCode));
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

// This is a projection, not a blacklist/redactor. No strings from HTTP/errors/DOM are emitted.
export function safeMeta(input = {}) {
  const out = {};
  if (UUID.test(input.scanId)) out.scanId = input.scanId;
  if (['queued', 'running', ...TERMINAL].includes(input.state)) out.state = input.state;
  if (Number.isInteger(input.httpStatus) && input.httpStatus >= 100 && input.httpStatus <= 599) out.httpStatus = input.httpStatus;
  for (const key of ['pages', 'checkedSets', 'observedEvents', 'scanLaunches', 'accountsCreated', 'pageErrors', 'blockedRequests', 'ignoredEligibility']) if (Number.isSafeInteger(input[key]) && input[key] >= 0 && input[key] <= 100000) out[key] = input[key];
  for (const key of ['allChecksChecked', 'noGenerationPosts', 'historyUnchanged', 'quotaUnchanged', 'browserClosed', 'nativeScanMayRemainActive']) if (typeof input[key] === 'boolean') out[key] = input[key];
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
  constructor() { this.runId = randomUUID(); this.startedAt = new Date().toISOString(); this.finishedAt = null; this.cases = Object.fromEntries(CASES.map(id => [id, { status: 'BLOCKED', code: 'NOT_RUN', failure: false }])); }
  record(id, status, code, meta = {}, failure = code === 'ASSERTION_FAILED') {
    assert.ok(CASES.includes(id) && ['PASS', 'BLOCKED', 'INCONCLUSIVE'].includes(status) && CODES.has(code));
    if (this.cases[id].failure && !failure) return; // A later successful probe must not hide an earlier violation.
    this.cases[id] = { status, code, failure: !!failure, ...safeMeta(meta) };
  }
  evidence() {
    return { schema: 1, runId: this.runId, startedAt: this.startedAt, finishedAt: this.finishedAt, scope: 'native-public8081-browser-only', origin: ORIGIN, providerGenerationQualified: false, generationPolicy: 'negative-boundary-only',
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
async function absentEvidence() {
  for (const path of EVIDENCE) {
    try { await lstat(path); } catch (e) { if (e.code === 'ENOENT') continue; throw new Fault('EVIDENCE_WRITE_FAILED'); }
    throw new Fault('EVIDENCE_ALREADY_EXISTS');
  }
}
export function evidenceDocuments(evidence) {
  const markdown = ['# Public product browser qualification — 2026-10-21', '', `Origin: ${ORIGIN}`, '',
    `Run: ${evidence.runId}. Provisional summary only: require the matching complete JSON and a successful evidence write; this Markdown alone is not acceptance.`,
        'Native generation is NOT qualified. No key is sought or persisted. Provider dispatch is not independently observed.',
    'Accounts/scans/decisions are retained in the public stand; credentials exist only in runner/browser memory.',
    'PASS is per assertion; BLOCKED is not success; cancel races and unavailable pagination/subset observations are INCONCLUSIVE.', '',
    '| Case | Result | Code |', '| --- | --- | --- |', ...Object.entries(evidence.cases).map(([id, item]) => `| ${id} | ${item.status} | ${item.code} |`), ''].join('\n');
  return [JSON.stringify(evidence, null, 2) + '\n', markdown];
}
export async function writeEvidence(evidence, openFile = open) {
  const files = [], documents = evidenceDocuments(evidence);
  try {
    // Acquire both exclusive destinations before writing anything. A second-path
    // collision must not leave a valid-looking JSON receipt from a failed run.
    for (const path of EVIDENCE) files.push(await openFile(path, 'wx', 0o600));
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

async function runNative() {
  await absentEvidence(); // Refuse before registration/browser launch; never replace earlier evidence.
  if (['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'PLAYWRIGHT_TRACE_DIR', 'PLAYWRIGHT_BROWSERS_PATH'].some(key => process.env[key])) throw new Fault('UNSAFE_DEBUG_ENVIRONMENT');
  process.env.TSX_DISABLE_CACHE = '1'; // Transpile in memory, not into a new disk cache.
  const book = new ResultBook();
  book.record('llm_generation', 'BLOCKED', 'GENERATION_NOT_AUTHORIZED');
  const contexts = [], scans = new Map();
  const stats = { scanLaunches: 0, accountsCreated: 0, pageErrors: 0, blockedRequests: 0, ignoredEligibility: 0 };
  const owner = { email: `public-product-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const foreign = { email: `public-product-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  let browser, stopped = false, browserClosed = false, activeLaunch = null, pendingCreation = Promise.resolve();
  let currentCase = 'tooling', fatalCode = null, interrupt;
  const interrupted = new Promise((_, reject) => { interrupt = code => { fatalCode = code; reject(new Fault(code)); }; });
  const globalTimer = setTimeout(() => interrupt('GLOBAL_DEADLINE'), GLOBAL_MS);
  const signal = () => interrupt('INTERRUPTED');
  process.once('SIGINT', signal); process.once('SIGTERM', signal); process.once('SIGHUP', signal);
  const ensureLive = () => { if (stopped || fatalCode) throw new Fault(fatalCode ?? 'INTERRUPTED'); };
  const step = async (id, operation) => {
    ensureLive(); currentCase = id;
    try {
      const result = await operation();
      assert.ok(result && typeof result === 'object');
      book.record(id, result?.status ?? 'PASS', result?.code ?? 'VERIFIED', result?.meta ?? {});
      return result?.value;
    } catch (e) {
      book.record(id, 'BLOCKED', e instanceof Fault ? e.message : 'ASSERTION_FAILED', {}, e instanceof Fault ? e.failure : true);
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
    const state = { context, permit: null, generationPosts: 0, fence: new EligibilityFence(), eligibilityPending: Promise.resolve(), target: null };
    await context.route('**/*', async route => {
      try {
        const request = route.request(), u = new URL(request.url()), method = request.method();
        const deny = async () => { stats.blockedRequests++; await route.abort(); };
        if (stopped || !fixedUrl(request.url())) return deny();
        if (['GET', 'HEAD'].includes(method)) {
          if (u.pathname.startsWith(`${SCANS}/`) && activeLaunch && !scans.has(u.pathname.split('/')[5])) await bounded(pendingCreation, 45_000).catch(() => {});
          if (!u.pathname.startsWith('/api/') || allowedGet(u.pathname, scans.keys())) return route.continue();
          return deny();
        }
        if (method !== 'POST') return deny();
        const headers = await request.allHeaders();
        if (stopped || fatalCode || !safeMutationRequest(request.url(), headers)) return deny();
        let body; try { body = request.postDataJSON(); } catch { return deny(); }
        if (method === 'POST' && u.pathname === `${SCANS}/images/eligibility`) {
          const target = state.target;
          if (!target || body?.imageReference !== target.reference) { stats.ignoredEligibility++; return route.abort(); }
          if (!exact(body, ['checks', 'imageReference']) || !Array.isArray(body.checks) || !body.checks.length || !body.checks.every((x, i) => CHECKS.includes(x) && (i === 0 || CHECKS.indexOf(body.checks[i - 1]) < CHECKS.indexOf(x)))) return deny();
          const sequence = state.fence.start();
          state.eligibilityPending = (async () => {
            await route.continue();
            const response = await request.response();
            if (response?.status() === 200) state.fence.accept(sequence, body, await response.json(), target);
          })();
          await state.eligibilityPending;
          return;
        }
        if (method === 'POST' && u.pathname === SCANS && activeLaunch?.state === state && activeLaunch.armed && validIntent(body, activeLaunch.target) && stats.scanLaunches < 3) {
          const launch = activeLaunch;
          // The UI can receive an eligibility response before our response.json()
          // finishes. Await that genuine check, then recheck cancellation/authority.
          const ready = await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending,
            () => !stopped && !fatalCode && activeLaunch === launch && launch.armed && stats.scanLaunches < 3);
          if (!ready) return deny();
          launch.armed = false; stats.scanLaunches++;
          pendingCreation = (async () => {
            await route.continue(); const response = await request.response();
            if (response?.status() === 202) {
              const value = await response.json();
              if (UUID.test(value?.scanId)) scans.set(value.scanId, { target: state.target, launchAt: Date.now(), terminal: false });
            }
          })();
          await pendingCreation; return;
        }
        if (consumePermit(state.permit, method, u.pathname, body)) {
          if (u.pathname.endsWith('/llm/chat') || u.pathname.endsWith('/llm/summary')) state.generationPosts++;
          await route.continue(); return;
        }
        return deny();
      } catch { stats.blockedRequests++; await route.abort().catch(() => {}); }
    });
    context.on('request', request => { if (!fixedUrl(request.url())) { stats.blockedRequests++; interrupt('REQUEST_GUARD'); } });
    context.on('response', response => { if (response.status() >= 300 && response.status() < 400) { stats.blockedRequests++; interrupt('REQUEST_GUARD'); } });
    await context.routeWebSocket('**/*', socket => { stats.blockedRequests++; socket.close(); });
    const page = await context.newPage(); page.setDefaultTimeout(15_000); page.setDefaultNavigationTimeout(20_000);
    page.on('pageerror', () => { stats.pageErrors++; });
    return { ...state, page, state };
  };
  let decoder, reportViewSearch, validateCveMetadata, cveMetadataIdentity, chat;
  const auth = async (handle, account, action) => {
    const { page, state } = handle;
    await page.goto(`${ORIGIN}/${action}`);
    await page.getByLabel('Email', { exact: true }).fill(account.email);
    await page.getByLabel('Пароль', { exact: true }).fill(account.password);
    permit(state, `/api/v1/auth/${action}`, body => exact(body, ['email', 'password']) && body.email === account.email && body.password === account.password);
    const pending = waitResponse(page, `/api/v1/auth/${action}`, 'POST');
    await page.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти', exact: true }).click();
    assert.equal((await pending)?.status(), action === 'register' ? 201 : 200);
    if (action === 'register') stats.accountsCreated++;
    const me = await http(page, '/api/v1/auth/me'); assert.equal(me.status, 200); assert.equal(me.value.email, account.email);
    assert.ok(UUID.test(me.value.id));
    if (account.subject) assert.equal(me.value.id, account.subject); else account.subject = me.value.id;
    const session = (await handle.context.cookies(ORIGIN)).find(item => item.name === 'demo_session');
    assert.ok(session?.httpOnly && session.sameSite === 'Lax');
  };
  const launch = async (handle, target) => {
    handle.state.target = target;
    await handle.page.goto(`${ORIGIN}/scans/new`);
    await handle.page.getByRole('textbox', { name: 'Canonical reference Docker Hub' }).fill(target.reference);
    for (const check of CHECKS) await handle.page.locator(`input[name="checks"][value="${check}"]`).check();
    assert.ok(sameChecks(await handle.page.locator('input[name="checks"]:checked').evaluateAll(inputs => inputs.map(input => input.value))));
    const eligible = await http(handle.page, `${SCANS}/images/eligibility`, { imageReference: target.reference, checks: CHECKS });
    if (eligible.status !== 200 || !eligibilityReady(eligible.value, target)) throw new Fault('ELIGIBILITY_NOT_READY');
    const consent = handle.page.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
    const submit = handle.page.getByRole('button', { name: 'Запустить скан', exact: true });
    await expect(consent).not.toBeChecked(); await expect(submit).toBeDisabled();
    await consent.check(); await expect(submit).toBeEnabled();
    activeLaunch = { state: handle.state, target, sequence: handle.state.fence.sequence, armed: true };
    const pending = waitResponse(handle.page, SCANS, 'POST'); await submit.click(); const response = await pending;
    await pendingCreation.catch(() => {});
    if (!response || response.status() !== 202) throw new Fault('LAUNCH_UNCONFIRMED_NO_RETRY');
    const body = await response.json(); assert.ok(UUID.test(body.scanId) && scans.has(body.scanId));
    activeLaunch = null;
    await expect(handle.page).toHaveURL(`${ORIGIN}/scans/${body.scanId}`);
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
  const statusMeta = snapshot => ({ scanId: snapshot.scanId, state: snapshot.state,
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
      for (const target of TARGETS) {
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
          await step(`${target.name}.pagination`, () => pagination(own.page, snapshot, reports));
          await step(`${target.name}.filters`, () => filters(own.page, snapshot, reports));
          await step(`${target.name}.reload`, async () => {
            await own.page.reload(); assert.deepEqual(await status(own.page, snapshot.scanId), snapshot);
            assert.deepEqual(await verifyReport(own.page, snapshot), reports); return ok();
          });
        }
        await step(`${target.name}.events`, async () => {
          const response = await http(own.page, `${SCANS}/${snapshot.scanId}/events`, undefined, true); assert.equal(response.status, 200);
          return { status: response.hint ? 'PASS' : 'INCONCLUSIVE', code: response.hint ? 'VERIFIED' : 'SSE_NOT_OBSERVED', meta: { observedEvents: response.hint ? 1 : 0 } };
        });
      }
      if (!completed.length) return;
      await step('scan_history', () => history(own.page, completed));
      const other = await newPage();
      const foreignRegistered = await step('foreign_registration', async () => { await auth(other, foreign, 'register'); return ok(true); });
      if (foreignRegistered) await step('ownership', () => deny(other, completed[0].scanId, 404));
      const anonymous = await newPage(); await anonymous.page.goto(`${ORIGIN}/login`);
      await step('anonymous', () => deny(anonymous, completed[0].scanId, 401));
      const report = completed.find(s => CHECKS.some(key => key !== 'sbom' && s.perCheck?.[key]?.outcome === 'checked' && s.perCheck[key].findingCount > 0)) ?? completed[0];
      const llmPath = `${SCANS}/${report.scanId}/llm`;
      const openChat = async page => {
        const panel = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
        await panel.getByRole('button', { name: 'Открыть чат и прочитать условия', exact: true }).click();
        await expect(panel.getByRole('region', { name: 'Готовность генерации', exact: true })).toContainText('generationVerified: false');
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
          await expect(panel.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ })).not.toBeChecked();
          await expect(panel.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ })).toBeDisabled();
          await expect(panel.getByRole('button', { name: 'Отправить вопрос', exact: true })).toBeDisabled();
        }
        await expect(own.page.getByRole('heading', { name: 'Image config · только метаданные образа', exact: true })).toBeVisible();
        return ok(undefined, { credential: ready.credential, blockers: ready.blockers, noGenerationPosts: true });
      });
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
      // Close the original context: no cookie injection or inherited storage in the next login.
      await own.context.close(); own = await newPage(); await own.page.goto(`${ORIGIN}/login`);
      const loggedIn = await step('fresh_login', async () => {
        assert.equal((await http(own.page, `${SCANS}/${completed[0].scanId}`)).status, 401);
        await auth(own, owner, 'login'); await history(own.page, completed);
        for (const snapshot of completed) { await own.page.goto(`${ORIGIN}/scans/${snapshot.scanId}`); assert.deepEqual(await status(own.page, snapshot.scanId), snapshot); await verifyReport(own.page, snapshot); }
        return ok(true, { checkedSets: completed.length });
      });
      if (!loggedIn) return;
      await step('llm_fresh_login', async () => {
        if (!savedHistory) throw new Fault('PREREQUISITE_UNAVAILABLE');
        await own.page.goto(`${ORIGIN}/scans/${report.scanId}`); panel = await openChat(own.page);
        assert.deepEqual((await readChat(own.page)).saved, savedHistory); await expect(panel.getByText(DECISION, { exact: true })).toBeVisible();
        await expect(panel.getByRole('checkbox', { name: /Разрешаю один запрос чата:/ })).not.toBeChecked();
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
      const cancelled = await step('cancel', async () => {
        if (stats.scanLaunches !== scans.size || [...scans.values()].some(record => !record.terminal)) throw new Fault('PREREQUISITE_UNAVAILABLE');
        const id = await launch(own, TARGETS[0]); let before = await status(own.page, id);
        // Observe real subset publication if it happens; never add artificial worker barriers.
        const observationDeadline = Date.now() + 20_000;
        while (!TERMINAL.has(before.state) && !CHECKS.some(key => before.perCheck?.[key] != null) && Date.now() < observationDeadline) { await wait(500); before = await status(own.page, id); }
        const observed = CHECKS.filter(key => before.perCheck?.[key] != null);
        const subsets = {}; let subsetChanged = false;
        if (!TERMINAL.has(before.state)) for (const kind of observed.filter(key => key !== 'config' && before.perCheck[key].outcome === 'checked')) {
          try { subsets[kind] = await collect(own.page, before, kind); }
          catch (error) {
            const current = await status(own.page, id);
            if (isDeepStrictEqual(current, before)) throw error;
            subsetChanged = true; // A real advancing cursor/snapshot, not preserved-row proof.
          }
        }
        let httpStatus = null;
        if (!TERMINAL.has(before.state)) {
          const button = own.page.getByRole('button', { name: 'Отменить скан', exact: true });
          if (await button.isVisible()) {
            const path = `${SCANS}/${id}/cancel`; permit(own.state, path, body => exact(body, []));
            const pending = waitResponse(own.page, path, 'POST');
            own.page.once('dialog', dialog => dialog.type() === 'confirm' && dialog.message() === 'Отменить скан? Сохранённые результаты завершённых проверок останутся доступны. Остальные проверки не будут завершены.' ? dialog.accept() : dialog.dismiss());
            try { await button.click({ timeout: 2000 }); }
            catch (error) { if (!TERMINAL.has((await status(own.page, id)).state)) throw error; }
            const response = await pending; httpStatus = response?.status() ?? null;
            if (httpStatus === 200) assert.deepEqual(await response.json(), { scanId: id, state: 'cancelled' });
          }
        }
        const after = await terminalStatus(own.page, id), verdict = cancelVerdict(after.state, httpStatus);
        return { ...verdict, value: { before, after, observed, subsets, subsetChanged }, meta: { ...statusMeta(after), ...(httpStatus ? { httpStatus } : {}), observedCompletedChecks: observed } };
      });
      if (cancelled) {
        await step('cancel_preservation', async () => {
          const { before, after, observed, subsets, subsetChanged } = cancelled;
          if (after.state !== 'cancelled') return { status: 'INCONCLUSIVE', code: 'CANCEL_RACE' };
          for (const key of observed) assert.deepEqual(after.perCheck[key], before.perCheck[key]);
          if (observed.includes('config')) assert.deepEqual(after.config, before.config);
          const persisted = await verifyReport(own.page, after);
          for (const [kind, original] of Object.entries(subsets)) {
            assert.deepEqual(persisted[kind].rows, original.rows); assert.deepEqual(persisted[kind].baseline, original.baseline);
          }
          await own.page.reload(); assert.deepEqual(await status(own.page, after.scanId), after); assert.deepEqual(await verifyReport(own.page, after), persisted);
          await wait(2000); // Bounded late-publication observation, not a guarantee about all future writes.
          const final = await status(own.page, after.scanId);
          for (const key of CHECKS.filter(key => !observed.includes(key))) assert.deepEqual(final.perCheck[key], after.perCheck[key]);
          return { ...preservationVerdict(before, observed, subsets, subsetChanged), meta: { observedCompletedChecks: observed } };
        });
        await step('cancel_history', () => history(own.page, [...completed, cancelled.after]));
        await step('cancel_fresh_login', async () => {
          await own.context.close(); own = await newPage(); await own.page.goto(`${ORIGIN}/login`);
          assert.equal((await http(own.page, `${SCANS}/${cancelled.after.scanId}`)).status, 401);
          await auth(own, owner, 'login'); await history(own.page, [...completed, cancelled.after]);
          await own.page.goto(`${ORIGIN}/scans/${cancelled.after.scanId}`);
          assert.deepEqual(await status(own.page, cancelled.after.scanId), cancelled.after); await verifyReport(own.page, cancelled.after);
          return ok(undefined, { state: cancelled.after.state, historyUnchanged: true });
        });
      }
    })()]);
  } catch (e) {
    const code = fatalCode ?? (e instanceof Fault ? e.message : 'ASSERTION_FAILED');
    book.record(currentCase, 'BLOCKED', code, {}, !(e instanceof Fault) || e.failure);
  } finally {
    stopped = true; clearTimeout(globalTimer); process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); process.removeListener('SIGHUP', signal);
    try { await bounded(Promise.allSettled(contexts.map(context => context.close())), 10_000); if (browser) await bounded(browser.close(), 10_000); browserClosed = !browser || !browser.isConnected(); }
    catch { browserClosed = false; }
    const failure = !browserClosed || stats.blockedRequests > 0 || stats.pageErrors > 0;
    book.record('safety', failure ? 'BLOCKED' : 'PASS', !browserClosed ? 'CLEANUP_FAILED' : stats.blockedRequests ? 'REQUEST_GUARD' : stats.pageErrors ? 'PAGE_ERRORS' : 'VERIFIED', { ...stats, browserClosed, nativeScanMayRemainActive: stats.scanLaunches !== scans.size || [...scans.values()].some(record => !record.terminal) }, failure);
    book.finishedAt = new Date().toISOString();
    const evidence = book.evidence();
    // Only our projected cases go to stdout/disk, never caught exceptions or Playwright diagnostics.
    try { await writeEvidence(evidence); } catch { book.record('safety', 'BLOCKED', 'EVIDENCE_WRITE_FAILED', {}, true); }
    console.log(JSON.stringify(book.evidence(), null, 2));
  }
  const results = Object.entries(book.cases);
  if (results.some(([, item]) => item.failure)) return 1;
  return results.some(([id, item]) => item.status === 'BLOCKED' && id !== 'llm_generation') ? 2 : 0;
}

export function offlineSelfTest() {
  assert.equal(parseMode([]), 'not-run'); assert.equal(parseMode(['--self-test']), 'offline');
  assert.throws(() => parseMode(['--run']));
  assert.equal(parseMode(['--run', '--ack-coordinator-go', '--ack-no-key-activation']), 'native');
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
  try { return await runNative(); }
  catch (e) { console.log(JSON.stringify({ status: 'BLOCKED', code: e instanceof Fault ? e.message : 'ASSERTION_FAILED', rawDiagnosticsSuppressed: true })); return 1; }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main();
