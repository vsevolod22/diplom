// Inert by default. Separate GET-only verification and exact native-owner metadata
// reconciliation. NEVER sends a provider POST, resets a marker, or repairs old wire evidence.
import * as fs from 'node:fs';
import { request as nodeHttpRequest } from 'node:http';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import { captureNativeDeploymentRecords, captureNativeRuntimeSource, createNativeRuntimeAuthority, createNativeRuntimeObserver, NATIVE_ORIGIN, NATIVE_PROJECT } from './native-runtime-authority.mjs';
import { archiveDirectory, archiveFile } from './public-llm-deployment-catalog.mjs';
import { validateReferenceCustody, custodyCompletionReferences, completionReferences } from './deploy-reference-custody.mjs';
import { assertReconciliationHistory } from './public-image-stand.mjs';
import { inspectDeploySupervisor } from './deploy-supervisor.mjs';
import { REVIEW_SOURCE, reviewFingerprint as originalFingerprint, browserIo, validateSummary, routePlan, SESSION_FILE, bounded } from '../tests-e2e/batch27-final-native.mjs';
import { contracts, fingerprint, policyMatches, readinessMatches, SCAN, BASE, QUESTION } from '../tests-e2e/native-h7v3-paid-sol.mjs';
import { privateSnapshot, validateStorage, extraContracts, replyProof, assertNoCaptureEnvironment } from '../tests-e2e/batch26-native-chat.mjs';
import { diagnosticContracts } from '../tests-e2e/native-h7v3-finite-diagnostics.mjs';
import { BROWSER_ARGS, assertAuthUser } from '../tests-e2e/public-product-live.mjs';

const ROOT = resolve(fileURLToPath(new URL('../', import.meta.url)));
export const READONLY_SLOT = 'test-results/batch32-native-readonly-20261104';
export const ABANDONED_SLOT = 'test-results/batch33-native-abandoned-fence-20261104';
export const ABANDONED_CONTINUATION_SLOT = 'test-results/batch34-native-abandoned-fence-20261104';
export const ABANDONED_DIRECT_SLOT = 'test-results/batch35-native-abandoned-fence-20261104';
export const ABANDONED_PARALLEL_SLOT = 'test-results/batch36-native-abandoned-fence-20261104';
const OLD_SLOT = 'test-results/batch31-final-native-20261104';
const SHA = /^[a-f0-9]{64}$/, NONCE = /^[a-f0-9]{32}$/, UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const need = (v, code = 'RECONCILE_REFUSED') => { if (!v) throw Error(code); };
const keys = (v, names) => v && Object.getPrototypeOf(v) === Object.prototype && equal(Object.keys(v).sort(), [...names].sort());
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const stamp = s => [s.dev, s.ino, s.uid, s.mode];
export const READONLY_FAILURE_PHASES = Object.freeze(['admission', 'failed-stage', 'session', 'contracts', 'browser-launch', 'browser-context', 'routes', 'browser-io', 'preflight', 'history-get', 'usage-get', 'current-get', 'quiescence', 'browser-work', 'cleanup', 'session-postcheck', 'runtime-before', 'runtime-after', 'final-fence', 'freshness', 'metadata', 'archive', 'direct-http', 'owner-get', 'context-get', 'prepare', 'commit-admission', 'unclassified']);
export const READONLY_FAILURE_CODES = Object.freeze(['ABANDON_REQUALIFICATION_UNQUALIFIED', 'ABANDON_ATTEMPT_BLOCKED', 'ABANDON_PREPARED_EXPIRED', 'ABANDON_PIN_CHANGED', 'ABANDON_PIN_BOUND', 'ABANDON_ARCHIVE_UNCERTAIN', 'UNCLASSIFIED_FAILURE', 'CAPTURE_DEBUG_ENABLED', 'DIRECT_SESSION_UNSAFE', 'DIRECT_TRANSPORT_FAILED', 'DIRECT_HTTP_REFUSED', 'DIRECT_BODY_BOUND', 'DIRECT_JSON_INVALID', 'DIRECT_DEADLINE', 'DIRECT_OWNER_CHANGED', 'DIRECT_CONTEXT_INVALID', 'DIRECT_SCHEMA_INVALID', 'DIRECT_REQUEST_BOUND', 'ABANDON_FAILED_FRESHNESS_UNQUALIFIED', 'ABANDON_FAILED_ARCHIVE_UNQUALIFIED', 'READONLY_ROUTE_REFUSED', 'READONLY_TRANSPORT_FAILED', 'READONLY_REQUEST_BOUND', 'READONLY_PAGE_ERROR', 'READONLY_GUARD_REFUSED', 'READONLY_CLEANUP_FAILED', 'READONLY_DEADLINE', 'PRIVATE_SESSION_CHANGED', 'GET_FAILED', 'GET_BOUND', 'CURRENT_POLICY', 'AUTOMATION_NOT_OFF', 'ABANDON_CURRENT_OBSERVATION_CHANGED', 'ABANDON_CURRENT_QUIESCENCE_UNPROVEN', 'ABANDON_CURRENT_HELD_NOT_ZERO', 'ABANDON_RUNTIME_PROOF_EXPIRED', 'ABANDON_RUNTIME_CHANGED', 'RECONCILE_SOURCE_CHANGED', 'RECONCILE_METADATA_CHANGED', 'ABANDONMENT_SLOT_NOT_FRESH', 'ABANDON_FAILED_STAGE_UNQUALIFIED', 'ABANDON_SUPERVISOR_UNQUALIFIED', 'ABANDON_SUPERVISOR_CHANGED', 'ABANDON_OTHER_HOLD', 'ABANDON_RUNTIME_NAMESPACE_CHANGED', 'ABANDON_RUNTIME_REFERENCE_CHANGED', 'ABANDON_RUNTIME_EPOCH_CHANGED', 'ABANDON_DEPLOYED_SHIPPED_MAP_UNAVAILABLE', 'ABANDON_DEPLOYED_SHIPPED_MAP_INVALID', 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID', 'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNAVAILABLE', 'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNQUALIFIED']);
const readonlyFailures = new WeakMap();
export function readonlyFailure(error) {
  return readonlyFailures.get(error) ?? { phase: 'unclassified', code: READONLY_FAILURE_CODES.includes(error?.message) ? error.message : 'UNCLASSIFIED_FAILURE' };
}
function phaseError(error, phase) {
  if (!(error instanceof Error)) error = Error('UNCLASSIFIED_FAILURE');
  if (!readonlyFailures.has(error)) readonlyFailures.set(error, { phase: READONLY_FAILURE_PHASES.includes(phase) ? phase : 'unclassified', code: readonlyFailure(error).code });
  return error;
}
async function inPhase(phase, fn) { try { return await fn(); } catch (error) { throw phaseError(error, phase); } }
const vectorKeys = ['input', 'output', 'costMicros'];
export const EXPECTED_USED = Object.freeze({ input: 30085, output: 1118, costMicros: 27596 });
export const EXPECTED_SUMMARY_DELTA = Object.freeze({ input: 13189, output: 769, costMicros: 13353 });
export const HISTORICAL_WIRE = Object.freeze({ summaryHttp: 200, chatHttp: 502, chatFiniteHeaders: 'absent', chatBody: 'unavailable', originalWireResult: 'FAILED_NOT_REPAIRED' });
export const RECONCILE_REVIEW_FILES = Object.freeze([...new Set([...REVIEW_SOURCE, 'scripts/native-runtime-reconcile.mjs', 'scripts/native-runtime-reconcile.test.mjs', 'server/api/src/auth/auth.controller.ts', 'src/shared/api/auth/demoAuth.ts'])].sort());
export async function reconcileFingerprint() {
  const rows = [];
  for (const name of RECONCILE_REVIEW_FILES) {
    const path = join(ROOT, name), s = fs.lstatSync(path);
    need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && !(s.mode & 0o022) && s.size <= 1024 ** 2);
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { const bytes = fs.readFileSync(fd); need(equal([s.ino, s.size, s.mtimeMs, s.ctimeMs], [fs.fstatSync(fd).ino, fs.fstatSync(fd).size, fs.fstatSync(fd).mtimeMs, fs.fstatSync(fd).ctimeMs])); rows.push([name, sha(bytes)]); }
    finally { fs.closeSync(fd); }
  }
  return fingerprint(rows);
}
function selectionValid(s) {
  need(keys(s, ['deployment', 'attempt', 'originalReview']) && NONCE.test(s.deployment) && UUID.test(s.attempt) && SHA.test(s.originalReview), 'EXACT_NATIVE_SELECTION_REQUIRED');
}
function anchorsValid(a) {
  need(keys(a, ['evidence', 'summary', 'history', 'priorHistory', 'mutation']) && ['evidence', 'summary', 'history', 'priorHistory'].every(k => SHA.test(a[k])) && UUID.test(a.mutation), 'COORDINATOR_HASH_ANCHORS_REQUIRED');
}
function directoryFence(path, privateMode = true) {
  const s = fs.lstatSync(path);
  need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && (privateMode ? (s.mode & 0o7777) === 0o700 : !(s.mode & 0o022)), 'RECONCILE_DIRECTORY_UNSAFE');
  return { path, identity: stamp(s), verify() { const next = fs.lstatSync(path); need(next.isDirectory() && !next.isSymbolicLink() && equal(stamp(next), stamp(s)), 'RECONCILE_DIRECTORY_CHANGED'); } };
}
function processAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { need(e.code === 'ESRCH', 'ORIGINAL_PROCESS_UNPROVEN'); return false; }
}
// Only fixed public audit/finite metadata. No private snapshots, DB, env or keys.
// The returned seal is a recomputed constraint for the coordinator, NOT a success flag.
export function captureNativeReconcileEvidence(root, selection, alive = processAlive) {
  selectionValid(selection); need(resolve(root) === root && fs.realpathSync(root) === root);
  const parents = [directoryFence(root, false), directoryFence(join(root, '.local-public-images')),
    directoryFence(join(root, '.local-public-images/native-runtime-v1')), directoryFence(join(root, 'test-results'), false)];
  const lockPath = join(root, '.local-public-images/.operation.lock'), lock = archiveDirectory(lockPath);
  need(equal(lock.names, ['native-runtime-owner.json']), 'EXACT_NATIVE_OWNER_REQUIRED');
  const files = [], read = (path, label, json = true) => {
    const proof = archiveFile(path, 262144); files.push({ proof, label }); return json ? JSON.parse(proof.bytes) : proof.bytes;
  };
  const owner = read(join(lockPath, 'native-runtime-owner.json'), 'owner');
  need(keys(owner, ['version', 'kind', 'project', 'attempt', 'deployment', 'review', 'audit', 'lockIdentity']) && owner.version === 1 && owner.kind === 'native-runtime-authority' &&
    owner.project === NATIVE_PROJECT && owner.attempt === selection.attempt && owner.deployment === selection.deployment && owner.review === selection.originalReview &&
    owner.audit === 'native-runtime-v1/' + selection.attempt && equal(owner.lockIdentity, stamp(fs.lstatSync(lockPath))), 'EXACT_NATIVE_OWNER_REQUIRED');
  const audit = archiveDirectory(join(root, '.local-public-images', owner.audit));
  const intent = read(join(audit.path, 'intent.json'), 'native/intent.json');
  need(keys(intent, ['version', 'kind', 'project', 'attempt', 'deployment', 'review', 'origin', 'pid', 'uid', 'createdAt', 'lock']) && intent.version === 1 &&
    intent.kind === owner.kind && intent.project === owner.project && intent.attempt === owner.attempt && intent.deployment === owner.deployment && intent.review === owner.review &&
    intent.origin === NATIVE_ORIGIN && intent.lock === '.operation.lock' && intent.uid === process.getuid() && Number.isSafeInteger(intent.pid) && intent.pid > 0 &&
    Number.isFinite(Date.parse(intent.createdAt)), 'NATIVE_INTENT_MISMATCH');
  need(!alive(intent.pid), 'ORIGINAL_PROCESS_STILL_ALIVE');
  const events = audit.names.filter(n => n !== 'intent.json');
  const expected = [['acquired', null], ['admitted', null], ['dispatch-submitted', 'summary'], ['dispatch-observed', 'summary'],
    ['dispatch-submitted', 'chat'], ['dispatch-observed', 'chat'], ['retained-unknown', null]];
  need(events.length === expected.length && audit.names.length === expected.length + 1, 'UNKNOWN_NATIVE_OPERATIONS');
  expected.forEach(([phase, operation], index) => {
    const name = `${String(index + 1).padStart(4, '0')}-${phase}.json`;
    need(events[index] === name, 'UNKNOWN_NATIVE_OPERATIONS');
    const row = read(join(audit.path, name), 'native/' + name);
    need(equal(row, { version: 1, attempt: owner.attempt, phase, operation, lockIdentity: owner.lockIdentity }), 'NATIVE_AUDIT_MISMATCH');
  });
  const old = archiveDirectory(join(root, OLD_SLOT));
  const oldNames = ['aggregate.json', 'attempt.spent.json', 'chat.spent.json', 'diagnostics.ndjson', 'journey-aggregate.json', 'summary.spent.json'];
  need(equal(old.names, oldNames), 'ORIGINAL_BATCH_FILES_UNQUALIFIED');
  const data = Object.fromEntries(oldNames.map(name => [name, read(join(old.path, name), 'batch31/' + name, name !== 'diagnostics.ndjson')]));
  need(equal(data['attempt.spent.json'], { spent: true, deployment: selection.deployment, review: selection.originalReview, path: 'fresh-summary' }) &&
    equal(data['summary.spent.json'], { spent: true, operation: 'summary' }) && equal(data['chat.spent.json'], { spent: true, operation: 'chat' }), 'ORIGINAL_SPENT_BINDING');
  const aggregate = data['aggregate.json'], journey = data['journey-aggregate.json'];
  for (const a of [aggregate, journey]) need(a.status === 'BLOCKED_OR_PARTIAL' && a.deployment === selection.deployment && a.review === selection.originalReview &&
    a.path === 'fresh-summary' && a.summaryPosts === 1 && a.chatPosts === 1 && a.dispatched === 2 && a.postAttempts === 2 && a.browserClosed === true && a.retainedSessionUnchanged === true,
  'ORIGINAL_BATCH_NOT_QUALIFIED');
  need(aggregate.runtimeFenceReleased === false && equal(aggregate.usageBefore, journey.usageBefore) && equal(aggregate.summaryAccounting, journey.summaryAccounting), 'ORIGINAL_BATCH_NOT_QUALIFIED');
  const text = data['diagnostics.ndjson']; need(text.endsWith('\n'), 'ORIGINAL_DIAGNOSTICS_INCOMPLETE');
  const diagnostics = text.slice(0, -1).split('\n').map(line => JSON.parse(line));
  need(diagnostics.length === 6 && equal(diagnostics[0], { event: 'durable-dispatch-intent', operation: 'summary' }) &&
    equal(diagnostics[3], { event: 'durable-dispatch-intent', operation: 'chat' }), 'ORIGINAL_DIAGNOSTICS_INCOMPLETE');
  need(diagnostics[1].httpStatus === 200 && diagnostics[1].bodyInspection === 'not-read' && diagnostics[2].httpStatus === 200 && diagnostics[2].bodyInspection === 'json' &&
    diagnostics[2].terminalFailureCaptured === false && diagnostics[2].usageReceiptCaptured === false &&
    diagnostics[4].httpStatus === 502 && diagnostics[4].bodyInspection === 'not-read' && diagnostics[5].httpStatus === 502 && diagnostics[5].bodyInspection === 'unavailable' &&
    equal(diagnostics[4].headers, {}) && equal(diagnostics[5].headers, {}) && diagnostics[4].headerReadFailed === false && diagnostics[5].headerReadFailed === false && !diagnostics[5].applicationFailure, 'ORIGINAL_WIRE_BRANCH_UNSUPPORTED');
  const seal = fingerprint(files.map(({ proof, label }) => ({ path: label, sha256: proof.digest, bytes: Buffer.byteLength(proof.bytes) })).sort((a, b) => a.path.localeCompare(b.path)));
  const verify = () => { parents.forEach(p => p.verify()); lock.verify(); audit.verify(); old.verify(); files.forEach(f => f.proof.verify()); need(!alive(intent.pid), 'ORIGINAL_PROCESS_STILL_ALIVE'); };
  verify(); return { seal, owner, ownerDigest: files[0].proof.digest, intent, aggregate, lockPath, lockIdentity: owner.lockIdentity, verify };
}
const vector = v => keys(v, vectorKeys) && vectorKeys.every(k => Number.isSafeInteger(v[k]) && v[k] >= 0);
const zero = v => vector(v) && vectorKeys.every(k => v[k] === 0);
const sameBinding = (a, b) => ['scanId', 'digest', 'platform', 'reportVersion'].every(k => a?.[k] === b?.[k]);
// No invoice or original wire receipt is inferred from a successful durable GET.
export function qualifyDurableCommit({ first, second, original, anchors, corpus, tools, c }) {
  anchorsValid(anchors); need(original.seal === anchors.evidence, 'ORIGINAL_EVIDENCE_PIN_CHANGED');
  const summary = tools.summary.summaryReplySchema.parse(first.summary), history = c.chat.chatHistorySchema.parse(first.history), usage = c.usage.parse(first.usage);
  need(fingerprint(first) === fingerprint(second), 'CURRENT_GET_PROOF_CHANGED');
  need(fingerprint(summary) === anchors.summary && fingerprint(history) === anchors.history, 'CURRENT_RESULT_ANCHOR_MISMATCH');
  need(first.context.s.scanId === SCAN && policyMatches(first.context.s) && policyMatches(first.context.h) && sameBinding(first.context.s, first.context.h) &&
    readinessMatches(first.context.r, first.context.h) && !first.context.h.pending && first.context.h.revision === 6 && sameBinding(summary, first.context.h) &&
    sameBinding(history, first.context.h) && sameBinding(usage, first.context.h), 'CURRENT_BINDING_UNQUALIFIED');
  need(summary.hypotheses.length === 4 && history.revision === 6 && !history.pending && history.epoch === first.context.h.epoch && history.turns.length === 3 && history.decisions.length === 0 &&
    history.turns.slice(0, 2).every(t => t.state === 'failed' && sameBinding(t.report, history)), 'CURRENT_HISTORY_UNQUALIFIED');
  const last = history.turns[2], prior = { ...history, revision: 4, turns: history.turns.slice(0, 2), pending: null };
  need(fingerprint(prior) === anchors.priorHistory && last.state === 'completed' && last.mutationId === anchors.mutation && last.question === QUESTION &&
    sameBinding(last.report, history) && last.reply.sources.length === 3 && last.createdAt >= Date.parse(original.intent.createdAt), 'ORIGINAL_REQUEST_CORRELATION_UNPROVEN');
  validateSummary(summary, first.context.s, corpus, tools);
  replyProof({ reply: last.reply }, corpus, c, tools);
  const before = original.aggregate.usageBefore, accounting = original.aggregate.summaryAccounting;
  need(usage.available && usage.integrationEnabled && usage.quotaEnabled && usage.monetaryLimit === 'uncapped' && before?.available && before.windowStart === usage.window.start &&
    accounting?.valid === true && accounting.receipt === 'NOT_EXPOSED_BY_SUMMARY_DTO' && accounting.receiptMatched === false, 'CURRENT_ACCOUNTING_UNQUALIFIED');
  const delta = {};
  for (const scope of ['user', 'scan']) {
    need(vector(before[scope]?.used) && zero(before[scope]?.held) && zero(usage[scope].held) && vector(before[scope]?.carried) &&
      equal(before[scope].carried, usage[scope].carried) && equal(usage[scope].used, EXPECTED_USED) &&
      equal(accounting.delta?.[scope]?.used, EXPECTED_SUMMARY_DELTA) && zero(accounting.delta[scope].held) && zero(accounting.delta[scope].carried), 'HISTORICAL_LIABILITY_OR_ESTIMATE_CHANGED');
    delta[scope] = Object.fromEntries(vectorKeys.map(k => [k, usage[scope].used[k] - before[scope].used[k] - EXPECTED_SUMMARY_DELTA[k]]));
    need(vector(delta[scope]) && delta[scope].input > 0 && delta[scope].output > 0 && delta[scope].costMicros > 0, 'CURRENT_ACCOUNTING_UNQUALIFIED');
  }
  need(equal(delta.user, delta.scan), 'CURRENT_ACCOUNTING_UNQUALIFIED');
  return { kind: 'durable-product-commit-not-original-wire-success', summaryHash: anchors.summary, historyHash: anchors.history, priorHistoryHash: anchors.priorHistory,
    originalMutationHash: fingerprint(anchors.mutation), citations: 3, paragraphs: 4, historyRevision: 6, estimates: { used: EXPECTED_USED, summaryDelta: EXPECTED_SUMMARY_DELTA,
      chatAggregateDelta: delta.scan, basis: 'server-estimated-configured-rates-not-invoice', originalChatReceipt: 'UNAVAILABLE_NOT_RECONSTRUCTED' },
    historicalLiabilities: 'PRESERVED_NOT_RECONCILED_OR_REFUNDED', historicalWire: HISTORICAL_WIRE,
    semanticAccuracy: 'NOT_ESTABLISHED_BY_READONLY_VERIFIER',
    attribution: 'COORDINATOR_PINNED_ORIGINAL_MUTATION_AND_BASELINE_PLUS_SEALED_AUDIT_AND_CURRENT_GET' };
}
export function readonlyPlan(url, method, redirected = false) { return method === 'GET' && routePlan(url, 'GET', redirected) === 'read' ? 'read' : 'deny'; }
function stopReadonly(guard, code) {
  guard.firstFailure ??= phaseError(Error(code), 'routes'); guard.stopped = true;
}
export async function installReadonlyRoutes(context, guard) {
  await context.route('**/*', async route => {
    const request = route.request(); let response;
    const deny = async code => { guard.denied++; stopReadonly(guard, code); await route.abort().catch(() => {}); };
    if (request.method() !== 'GET') guard.nonGet++;
    if (readonlyPlan(request.url(), request.method(), !!request.redirectedFrom()) !== 'read') return deny('READONLY_ROUTE_REFUSED');
    if (guard.closing) return route.abort().catch(() => {});
    if (++guard.requests > 240) return deny('READONLY_REQUEST_BOUND');
    if (guard.stopped) return deny('READONLY_ROUTE_REFUSED');
    try {
      response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15000 });
      const status = response.status();
      need(Number.isInteger(status) && status >= 200 && status <= 599 && !(status >= 300 && status < 400) && response.url() === request.url(), 'READONLY_ROUTE_REFUSED');
      if (guard.closing) return await route.abort().catch(() => {});
      need(!guard.stopped, 'READONLY_ROUTE_REFUSED');
      await route.fulfill({ response });
    } catch (error) {
      // Only expected transport cancellation after deliberate quiescence is not
      // a new denial. Policy/response failures and all earlier failures survive.
      if (guard.closing && error?.message !== 'READONLY_ROUTE_REFUSED') await route.abort().catch(() => {});
      else await deny(error?.message === 'READONLY_ROUTE_REFUSED' ? 'READONLY_ROUTE_REFUSED' : 'READONLY_TRANSPORT_FAILED');
    } finally { await response?.dispose().catch(() => {}); }
  });
  await context.routeWebSocket('**/*', socket => { guard.denied++; stopReadonly(guard, 'READONLY_ROUTE_REFUSED'); socket.close(); });
}
export async function closeReadonlyBrowser(context, browser, guard) {
  if (guard.stopped || guard.denied || guard.nonGet || guard.pageErrors) guard.firstFailure ??= phaseError(Error('READONLY_GUARD_REFUSED'), 'browser-work');
  guard.closing = true; guard.stopped = true;
  let error = guard.firstFailure;
  for (const handle of [context, browser]) if (handle) {
    try { await bounded(() => handle.close(), 15000, () => {}); }
    catch { error ??= guard.firstFailure ?? phaseError(Error('READONLY_CLEANUP_FAILED'), 'cleanup'); }
  }
  error ??= guard.firstFailure;
  if (guard.denied || guard.nonGet || guard.pageErrors) error ??= phaseError(Error('READONLY_GUARD_REFUSED'), 'cleanup');
  if (error) throw error;
}
function syncDirectory(path) { const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function writeRecord(directory, name, value) {
  const bytes = Buffer.from(JSON.stringify(value)); need(bytes.length <= 262144, 'RECONCILE_RECORD_BOUND');
  const fd = fs.openSync(join(directory, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  syncDirectory(directory); return sha(bytes);
}
// This validates through existing authority code with a NON-OWNING, read-only fence.
// No event is appended, no original authority handle is resumed, dispatch is never exposed.
async function currentRuntime(root, selection, original, review, getReview) {
  need(await originalFingerprint() === selection.originalReview && await getReview() === review, 'RECONCILE_SOURCE_CHANGED');
  const records = captureNativeDeploymentRecords(root, selection.deployment), source = captureNativeRuntimeSource(root, records);
  const [{ createDeployAdapter }, { runIsolatedDocker }, { homedir }] = await Promise.all([import('./deploy-adapter.mjs'), import('./public-image-stand.mjs'), import('node:os')]);
  const observe = createNativeRuntimeObserver(() => createDeployAdapter({ root }).status(), runIsolatedDocker, root, homedir());
  let observed;
  const handle = await createNativeRuntimeAuthority({ records: () => records, captureSource: () => source, readReview: originalFingerprint,
    acquire: () => ({ verify: original.verify, record(phase) { need(['admitted', 'release'].includes(phase)); }, release() {} }),
    observe: async receipt => { observed = await observe(receipt); return observed; } })({ deployment: selection.deployment, review: selection.originalReview, origin: NATIVE_ORIGIN });
  await handle.close(false); original.verify(); records.verify(); source.verify();
  return { digest: fingerprint({ daemon: observed.status.daemon, epochs: observed.epochs, references: observed.referenceImages }),
    verify() { original.verify(); records.verify(); source.verify(); } };
}
export async function verifyReadonlyDurableIo(io, original, anchors, tools, c) {
  const preflight = await io.preflight(), corpus = await io.corpus();
  const sample = async contextProof => {
    const summary = await io.summaryRead(); need(summary.status === 200, 'READONLY_SUMMARY_HTTP_UNQUALIFIED');
    return { context: contextProof, summary: summary.value, history: await io.history(), usage: await io.usage() };
  };
  const first = await sample({ s: preflight.s, h: preflight.h, r: preflight.r });
  // Two explicit GET samples, never reload/autorefresh/generate/save/retry.
  const second = await sample(await io.current());
  const proof = qualifyDurableCommit({ first, second, original, anchors, corpus, tools, c });
  await io.summaryVisible(first.summary); await io.chatVisible({ reply: first.history.turns[2].reply });
  return proof;
}
async function browserGetProof(verify) {
  const session = await inPhase('session', async () => { assertNoCaptureEnvironment(process.env); const value = await privateSnapshot(SESSION_FILE); validateStorage(value.value); return value; });
  const storage = validateStorage(session.value);
  const [tools, c, { chromium }] = await inPhase('contracts', async () => [await contracts(), { ...await diagnosticContracts(), ...await extraContracts() }, await import('@playwright/test')]);
  const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
  let browser, context;
  const guard = { requests: 0, denied: 0, nonGet: 0, stopped: false, pageErrors: 0 };
  let result;
  try {
    browser = await inPhase('browser-launch', () => chromium.launch({ headless: true, timeout: 20000, env, args: [...BROWSER_ARGS] }));
    context = await inPhase('browser-context', () => browser.newContext({ storageState: storage, serviceWorkers: 'block', acceptDownloads: false, viewport: { width: 1280, height: 960 }, reducedMotion: 'reduce' }));
    await inPhase('routes', () => installReadonlyRoutes(context, guard));
    const page = await inPhase('browser-context', () => context.newPage()); page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(15000);
    page.on('pageerror', () => { guard.pageErrors++; stopReadonly(guard, 'READONLY_PAGE_ERROR'); });
    const io = await inPhase('browser-io', () => browserIo(page, tools, c, {}, async () => {}));
    result = await inPhase('browser-work', () => bounded(() => verify(io, tools, c), 120000, () => { stopReadonly(guard, 'READONLY_DEADLINE'); }));
  } catch (error) {
    guard.firstFailure ??= phaseError(error, 'browser-work');
  } finally {
    await closeReadonlyBrowser(context, browser, guard);
  }
  await inPhase('session-postcheck', async () => need((await privateSnapshot(SESSION_FILE)).byteHash === session.byteHash, 'PRIVATE_SESSION_CHANGED'));
  return { ...result, readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } };
}
function browserDurableProof(original, anchors) {
  return browserGetProof((io, tools, c) => verifyReadonlyDurableIo(io, original, anchors, tools, c));
}
// Code-injected dependencies are for offline tests; production CLI never accepts
// alternate readers, success JSON, transport factories, proof objects or paths.
export function createNativeReconciler({ root, capture = captureNativeReconcileEvidence, getReview = reconcileFingerprint, runtime = currentRuntime,
  durable = browserDurableProof, now = () => Date.now(), clock = () => performance.now(), io = fs }) {
  return async options => {
    need(keys(options, ['mode', 'selection', 'anchors', 'review', 'verification']) && ['verify', 'reconcile'].includes(options.mode) && SHA.test(options.review), 'EXACT_RECONCILE_GO_REQUIRED');
    selectionValid(options.selection); anchorsValid(options.anchors);
    need(options.mode === 'verify' ? options.verification === null : SHA.test(options.verification), 'EXACT_RECONCILE_GO_REQUIRED');
    options = structuredClone(options);
    need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
    const original = capture(root, options.selection); need(original.seal === options.anchors.evidence, 'ORIGINAL_EVIDENCE_PIN_CHANGED');
    const resultParent = directoryFence(join(root, 'test-results'), false), slot = join(root, READONLY_SLOT);
    const binding = { selection: options.selection, anchors: options.anchors, review: options.review };
    let prior, priorFile;
    const staged = [];
    const write = (name, value) => {
      const digest = writeRecord(slot, name, value), proof = archiveFile(join(slot, name), 262144);
      need(proof.digest === digest, 'RECONCILE_METADATA_CHANGED'); staged.push(proof); return digest;
    };
    const verifyStaged = () => {
      need(equal(io.readdirSync(slot).sort(), staged.map(f => f.path.slice(slot.length + 1)).sort()), 'RECONCILE_METADATA_CHANGED');
      staged.forEach(f => f.verify());
    };
    if (options.mode === 'verify') {
      io.mkdirSync(slot, { mode: 0o700 }); syncDirectory(resultParent.path);
      write('verification-intent.json', { version: 1, kind: 'native-readonly-verification', ...binding });
    } else {
      directoryFence(slot);
      need(equal(io.readdirSync(slot).sort(), ['verification-intent.json', 'verification.json']), 'READONLY_SLOT_NOT_FRESH');
      priorFile = archiveFile(join(slot, 'verification.json'), 262144); prior = JSON.parse(priorFile.bytes);
      const intent = archiveFile(join(slot, 'verification-intent.json'), 262144); staged.push(intent, priorFile);
      need(priorFile.digest === options.verification && prior.version === 1 && prior.kind === 'native-durable-product-verification' && equal(prior.binding, binding) &&
        equal(JSON.parse(intent.bytes), { version: 1, kind: 'native-readonly-verification', ...binding }) &&
        Number.isSafeInteger(prior.observedAt) && now() >= prior.observedAt && now() - prior.observedAt <= 300000, 'READONLY_PROOF_STALE_OR_REPLACED');
      write('reconciliation-intent.json', { version: 1, kind: 'exact-native-owner-reconciliation', ...binding, verification: options.verification });
    }
    const slotFence = directoryFence(slot), start = clock();
    original.verify(); const before = await runtime(root, options.selection, original, options.review, getReview);
    const product = structuredClone(await durable(original, options.anchors));
    need(product?.kind === 'durable-product-commit-not-original-wire-success' && equal(product.historicalWire, HISTORICAL_WIRE) &&
      equal(product.readonly, { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true }), 'READONLY_PRODUCT_PROOF_REQUIRED');
    const after = await runtime(root, options.selection, original, options.review, getReview), checkedAt = clock();
    need(after.digest === before.digest && clock() >= start && clock() - start < 180000, 'RECONCILE_RUNTIME_CHANGED');
    need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
    original.verify(); before.verify(); after.verify(); slotFence.verify(); resultParent.verify(); verifyStaged();
    const result = { version: 1, kind: 'native-durable-product-verification', binding, observedAt: now(), evidence: original.seal, runtime: after.digest, product };
    if (options.mode === 'verify') {
      const digest = write('verification.json', result); verifyStaged();
      return { status: 'DURABLE_PRODUCT_VERIFIED_ORIGINAL_WIRE_FAILED_LOCK_RETAINED', verificationSha256: digest, historicalWire: HISTORICAL_WIRE };
    }
    need(prior.runtime === result.runtime && equal(prior.product, result.product) && prior.evidence === result.evidence, 'DURABLE_PROOF_CHANGED');
    priorFile.verify();
    const disposition = { version: 1, kind: 'exact-native-known-commit-disposition', ...binding, originalEvidence: original.seal, verification: options.verification,
      runtime: result.runtime, product, action: 'archive-exact-native-operation-lock', destination: READONLY_SLOT + '/reconciled-operation.lock',
      oldAggregate: 'IMMUTABLE_FAILED', originalWire: 'FAILED_NOT_REPAIRED', paidRetryAuthorized: false, historicalLiabilities: 'UNCHANGED' };
    write('disposition.json', disposition); // fsync BEFORE touching the exact original lock.
    need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
    original.verify(); before.verify(); after.verify(); slotFence.verify(); resultParent.verify(); priorFile.verify(); verifyStaged();
    need(clock() >= checkedAt && clock() - checkedAt < 15000, 'RECONCILE_PROOF_EXPIRED');
    const target = join(slot, 'reconciled-operation.lock'); need(!io.existsSync(target), 'RECONCILE_TARGET_EXISTS');
    io.renameSync(original.lockPath, target); // Whole fence/owner retained, NEVER unlink/adopt a foreign or empty lock.
    syncDirectory(slot); syncDirectory(join(root, '.local-public-images'));
    need(equal(stamp(io.lstatSync(target)), original.lockIdentity) && equal(io.readdirSync(target), ['native-runtime-owner.json']) &&
      archiveFile(join(target, 'native-runtime-owner.json'), 4096).digest === original.ownerDigest, 'RECONCILE_ARCHIVE_UNCERTAIN');
    writeRecord(slot, 'released.json', { version: 1, action: disposition.action, disposition: sha(Buffer.from(JSON.stringify(disposition))), originalEvidence: original.seal,
      originalWire: 'FAILED_NOT_REPAIRED', paidRetryAuthorized: false });
    return { status: 'EXACT_NATIVE_LOCK_ARCHIVED_DURABLE_PRODUCT_VERIFIED_WIRE_STILL_FAILED', paidRetryAuthorized: false, historicalWire: HISTORICAL_WIRE };
  };
}
const ABANDON_ROLES = ['api', 'auth-volume-init', 'egress', 'llm-egress', 'openai-egress', 'scan-volume-init', 'web', 'worker'];
const SHIPPED_PATH = /^(src\/|public\/|server\/api\/|server\/runtime\/|server\/deploy\/)|^(package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|index\.html|admin\.html|vite\.config\.ts|tsconfig\.json)$/;
export const ABANDONED_TRUTH = Object.freeze({ kind: 'abandoned-native-diagnostic-fence', requestReconciliation: 'NOT_PERFORMED',
  originalCorrelation: 'UNKNOWN_UNRECOVERABLE', originalReceipt: 'UNKNOWN', originalWire: 'FAILED_HTTP502_BODY_UNAVAILABLE',
  historicalLiabilities: 'UNKNOWN_PRESERVED', accountingMutation: 'NONE', providerRetryAuthorized: false, maintenanceAuthorization: 'SEPARATE_NORMAL_GATES_REQUIRED' });
function otherHoldsAbsent(root, expectedSupervisor) {
  const names = fs.readdirSync(join(root, '.local-public-images')), sentinel = '.deploy-supervisor-v1.lock';
  let supervisor = null;
  // This exact producer file persists while idle. Only the existing identity +
  // FREE OS-lease probe qualifies it; this is not ownership or apply authority.
  if (names.includes(sentinel)) {
    try { supervisor = inspectDeploySupervisor(root); } catch { throw Error('ABANDON_SUPERVISOR_UNQUALIFIED'); }
  }
  need(expectedSupervisor === undefined || equal(supervisor, expectedSupervisor), 'ABANDON_SUPERVISOR_CHANGED');
  need(!names.some(n => n !== '.operation.lock' && n !== sentinel && (n.endsWith('.lock') || n.endsWith('.pending'))), 'ABANDON_OTHER_HOLD');
  assertReconciliationHistory(root); return supervisor;
}
export function captureAbandonedEvidence(root, selection, alive = processAlive) {
  const original = captureNativeReconcileEvidence(root, selection, alive), supervisor = otherHoldsAbsent(root);
  const verify = () => { original.verify(); otherHoldsAbsent(root, supervisor); };
  // Bind presence/identity across the separate verify and archive invocations,
  // not just within one capture. The known-commit evidence contract is unchanged.
  const seal = fingerprint({ nativeEvidence: original.seal, supervisor });
  verify(); return { ...original, seal, verify };
}
// Consume ACTUAL sealed deployment data, not a caller source object or today's
// working tree. The shipped map is a partial COPY-input commitment; its parent
// full-source digest is recorded, NOT recomputed or invented from that subset.
export function qualifyAbandonedDeployment(r, selection) {
  selectionValid(selection); r.verify();
  const { complete: c, intent: i, built: b, recovery: q, published: p, authority: a, migrationIntent: m, migrationComplete: d, custody, reuse } = r;
  need(c?.version === 4 && c.project === NATIVE_PROJECT && c.nonce === selection.deployment && c.outcome === 'published' &&
    equal(r.owner, { version: 2, nonce: c.nonce, kind: 'preserving-deployment' }) && i?.version === 2 && i.project === c.project && i.nonce === c.nonce &&
    i.kind === 'preserving-deployment' && i.mode === 'app' && i.lifecycle === false && equal(i.services, ['api', 'web']) &&
    b?.version === 1 && b.nonce === c.nonce && b.lifecycle === false && b.outcome === 'candidate-built-old-site-unchanged' && keys(b.candidates, i.services) &&
    q?.version === 2 && q.project === c.project && q.nonce === c.nonce && q.daemon === i.daemon && equal(q.services, i.services) &&
    p?.version === 2 && p.project === c.project && p.nonce === c.nonce && p.mode === 'app' && equal(p.services, i.services) && p.healthy === true &&
    typeof p.verified === 'boolean' && Number.isFinite(Date.parse(p.completedAt)), 'ABANDON_DEPLOYMENT_BRANCH_UNQUALIFIED');
  const source = reuse?.source;
  need(Array.isArray(source?.shippedFiles) && SHA.test(source?.shippedSource), 'ABANDON_DEPLOYED_SHIPPED_MAP_UNAVAILABLE');
  need(keys(source, ['version', 'basis', 'originalSource', 'currentSource', 'originalAdapter', 'originalEntrySources', 'currentAdapter', 'currentEntrySources', 'shippedFiles', 'shippedSource']) &&
    source.version === 1 && source.basis === 'exact-sealed-ordered-source-path-digests' && [source.originalSource, source.currentSource, source.originalAdapter, source.currentAdapter].every(v => SHA.test(v)) &&
    [source.originalEntrySources, source.currentEntrySources].every(v => Array.isArray(v) && v.length === 7 && v.every(h => SHA.test(h))) &&
    source.originalSource === source.currentSource && source.currentSource === i.source && source.currentAdapter === i.adapter && equal(source.currentEntrySources, i.entrySources), 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID');
  const files = source.shippedFiles;
  need(files.length > 0 && files.length <= 4096 && files.every(f => keys(f, ['path', 'digest']) && typeof f.path === 'string' && f.path.length <= 512 && SHIPPED_PATH.test(f.path) &&
    !f.path.split('/').some(part => !part || part === '.' || part === '..') && !f.path.includes('\\') && SHA.test(f.digest)) &&
    new Set(files.map(f => f.path)).size === files.length && sha(JSON.stringify(files)) === source.shippedSource &&
    ['src/', 'server/api/src/', 'server/runtime/src/'].every(prefix => files.some(f => f.path.startsWith(prefix))) &&
    ['package.json', 'server/api/package.json', 'server/deploy/openai-api.Dockerfile'].every(path => files.some(f => f.path === path)), 'ABANDON_DEPLOYED_SHIPPED_MAP_INVALID');
  need(keys(reuse, ['version', 'origin', 'source', 'qualification', 'referenceCustody']) && reuse.version === 1 && equal(reuse.qualification, { typescript: true, bundle: true, openai: true }) &&
    equal(reuse.referenceCustody, custody) && equal(r.origins, c.borrowedReferences) && custody?.version === 2, 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID');
  validateReferenceCustody(custody, c.nonce, r.origins); completionReferences(c, c.nonce);
  const refs = custodyCompletionReferences(custody, c.nonce, b.candidates);
  need(equal(refs.references, c.references) && equal(refs.borrowedReferences, c.borrowedReferences) && equal(custody.old.map(v => v.name), i.services), 'ABANDON_DEPLOYED_IMAGE_CHAIN_INVALID');
  for (const record of [c, i, b, q, p]) need(equal(record.candidateReuse, source) && equal(record.reuseOrigin, reuse.origin) && equal(record.referenceCustody, custody), 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID');
  need(r.candidateOrigins?.length === 1, 'ABANDON_DEPLOYED_ORIGIN_UNAVAILABLE');
  const old = r.candidateOrigins[0];
  need(equal(old.origin, reuse.origin) && old.complete?.version === 3 && old.complete.nonce === old.origin.nonce && old.complete.project === c.project &&
    old.complete.outcome === 'pre-mutation-aborted' && old.intent?.version === 2 && old.intent.kind === 'preserving-deployment' && old.intent.project === c.project && old.intent.nonce === old.origin.nonce &&
        old.intent.source === source.originalSource && old.intent.adapter === source.originalAdapter &&
    equal(old.intent.entrySources, source.originalEntrySources) && equal(old.intent.services, i.services) && old.intent.mode === 'app' && old.intent.lifecycle === false &&
    old.intent.daemon === i.daemon && old.intent.backendSource === i.backendSource && equal(old.intent.old, i.old) && equal(old.recovery?.old, q.old) &&
    old.recovery.version === 2 && old.recovery.project === c.project && old.recovery.nonce === old.origin.nonce && old.recovery.daemon === i.daemon && equal(old.recovery.services, i.services) &&
    old.recovery.historyVersion === 4 && old.recovery.migration === false && old.recovery.historyMigration === q.historyMigration &&
    old.built?.version === 1 && old.built.nonce === old.origin.nonce && old.built.lifecycle === false && old.built.outcome === 'candidate-built-old-site-unchanged' &&
    [old.complete, old.intent, old.built, old.recovery].every(v => equal(v.referenceCustody, old.custody)), 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID');
  const originalRefs = custodyCompletionReferences(old.custody, old.origin.nonce, old.built.candidates);
  need(equal(originalRefs.references, old.complete.references) && equal(originalRefs.borrowedReferences, old.complete.borrowedReferences) && originalRefs.references.length === 2 &&
    i.services.every(name => equal(old.built.candidates[name], b.candidates[name]) && custody.candidates.some(v => v.name === name && v.image === b.candidates[name].image &&
      v.tag === `dip-deploy-${name}:candidate-${old.origin.nonce}` && equal(v.origin, old.origin))), 'ABANDON_DEPLOYED_IMAGE_CHAIN_INVALID');
  const migration = 'history-reservations-v4-to-v5', proof = d?.proof;
  need(q.migration === false && q.historyVersion === 4 && q.historyMigration === migration && p.migration === false && p.historyMigration === migration &&
    equal(q.interruptedServices, ['api', 'web', 'worker']) && equal(p.interruptedServices, q.interruptedServices) &&
    m?.version === 1 && m.migration === migration && m.from === 4 && m.to === 5 && m.source === i.source && m.candidateImage === b.candidates.api.image &&
    d?.version === 1 && d.candidateImage === m.candidateImage && equal(proof, m.expected) && equal(proof, p.historyProof) && equal(d.before, m.baseline) &&
    d.before?.historyVersion === 4 && d.after?.historyVersion === 5 && p.stores?.historyVersion === 5 &&
    keys(proof, ['version', 'migration', 'from', 'to', 'before', 'after', 'allRowsPreserved']) && proof.version === 1 && proof.migration === migration && proof.from === 4 && proof.to === 5 &&
    proof.allRowsPreserved === true && SHA.test(proof.before) && SHA.test(proof.after) && d.before.llm?.history === proof.before && d.after.llm?.history === proof.after,
  'ABANDON_DEPLOYED_MIGRATION_UNQUALIFIED');
  need(a?.version === 3 && a.project === c.project && a.nonce === c.nonce && Array.isArray(a.authority?.containers) &&
    equal(a.authority.containers.map(v => v.role).sort(), ABANDON_ROLES) && Array.isArray(q.old) && equal(q.old.map(v => v.role).sort(), ABANDON_ROLES) && new Set(q.old.map(v => v.id)).size === 8 &&
    equal(i.old, i.services.map(role => { const v = q.old.find(v => v.role === role); return { role, id: v.id, image: v.image }; })) &&
    keys(p.pins, ['services']) && keys(p.pins.services, ABANDON_ROLES), 'ABANDON_DEPLOYED_IDENTITY_INVALID');
  const expected = Object.fromEntries(ABANDON_ROLES.map(name => {
    const prior = q.old.find(v => v.role === name), pre = a.authority.containers.find(v => v.role === name), start = r.starts[name], running = !name.endsWith('volume-init');
    need(SHA.test(prior.id) && /^sha256:[a-f0-9]{64}$/.test(prior.image) && Number.isFinite(Date.parse(prior.startedAt)) && pre.Id === prior.id && pre.Image === prior.image &&
      Number.isFinite(Date.parse(pre.Created)) && Date.parse(pre.Created) <= Date.parse(prior.startedAt) && pre.process?.length === 7 && pre.process[0] === prior.startedAt &&
      pre.process[2] === running && pre.process[3] === (running ? 'running' : 'exited') && Number.isSafeInteger(pre.process[4]) && (running ? pre.process[4] > 0 : pre.process[4] === 0) &&
      pre.process[5] === 0 && pre.process[6] === 0, 'ABANDON_DEPLOYED_IDENTITY_INVALID');
    const target = i.services.includes(name);
    if (target || name === 'worker') need(keys(start, ['role', 'id', 'image', 'startedAt']) && start.role === name && SHA.test(start.id) && Number.isFinite(Date.parse(start.startedAt)) &&
      Date.parse(start.startedAt) <= Date.parse(p.completedAt) && (target ? start.id !== prior.id && start.image === b.candidates[name].image : start.id === prior.id && start.image === prior.image && Date.parse(start.startedAt) > Date.parse(prior.startedAt)), 'ABANDON_DEPLOYED_IDENTITY_INVALID');
    else need(start === undefined, 'ABANDON_DEPLOYED_IDENTITY_INVALID');
    const row = start ?? prior;
    need(keys(p.pins.services[name], ['image']) && p.pins.services[name].image === row.image, 'ABANDON_DEPLOYED_IDENTITY_INVALID');
    return [name, { id: row.id, image: row.image, startedAt: row.startedAt, ...(!target ? { created: pre.Created, ...(name !== 'worker' ? { pid: pre.process[4] } : {}) } : {}) }];
  }));
  need(new Set(Object.values(expected).map(v => v.id)).size === 8, 'ABANDON_DEPLOYED_IDENTITY_INVALID');
  return { expected, daemon: i.daemon, references: [...refs.references, ...refs.borrowedReferences], provenance: {
    basis: 'sealed-shipped-map-and-direct-owned-image-chain', fullSourceCommitment: i.source, fullSourceDigestRecomputed: false, shippedMapSha256: source.shippedSource,
    originalBuildNonce: old.origin.nonce, originalBuildCompletionSha256: old.origin.sha256, currentWorkingTreeEqualsDeployed: 'NOT_CLAIMED', retainedRolesCurrentSourceClaim: false } };
}
export function qualifyAbandonedRuntime(observed, receipt) {
  const { status, epochs, referenceImages } = observed;
  need(status?.version === 1 && status.project === NATIVE_PROJECT && status.origin === NATIVE_ORIGIN && status.hold === true && status.reason === 'SHARED_OPERATION_HOLD' && status.daemon === receipt.daemon &&
    Array.isArray(status.services) && equal(status.services.map(v => v.name).sort(), ABANDON_ROLES) && Array.isArray(epochs) && equal(epochs.map(v => v.name).sort(), ABANDON_ROLES), 'ABANDON_RUNTIME_NAMESPACE_CHANGED');
  need(Array.isArray(referenceImages) && referenceImages.length === receipt.references.length && referenceImages.every((v, i) => keys(v, ['image', 'tags']) && v.image === receipt.references[i].image &&
    Array.isArray(v.tags) && v.tags.length <= 256 && v.tags.every(t => typeof t === 'string' && t.length <= 384) && v.tags.includes(receipt.references[i].tag)), 'ABANDON_RUNTIME_REFERENCE_CHANGED');
  for (const name of ABANDON_ROLES) {
    const expected = receipt.expected[name], service = status.services.find(v => v.name === name), epoch = epochs.find(v => v.name === name), running = !name.endsWith('volume-init');
    need(service.id === expected.id && service.image === expected.image && service.running === running && service.restartCount === 0 && (!running || service.healthy === true) &&
      keys(epoch, ['name', 'id', 'image', 'created', 'startedAt', 'pid', 'restartCount']) && epoch.id === expected.id && epoch.image === expected.image && epoch.startedAt === expected.startedAt &&
      Number.isFinite(Date.parse(epoch.created)) && Date.parse(epoch.created) <= Date.parse(epoch.startedAt) && (!expected.created || epoch.created === expected.created) &&
      (expected.pid === undefined || epoch.pid === expected.pid) && Number.isSafeInteger(epoch.pid) && (running ? epoch.pid > 0 : epoch.pid === 0) && epoch.restartCount === 0, 'ABANDON_RUNTIME_EPOCH_CHANGED');
  }
  return fingerprint({ epochs, references: referenceImages, daemon: status.daemon, provenance: receipt.provenance });
}
// Retirement ONLY after the operator explicitly started Docker. Container IDs
// bind Docker's immutable Created field; where the old receipt records Created
// it must also match literally. Never fabricate missing historical target PIDs.
export function qualifyOwnerDockerRestart(observed, receipt) {
  need(Array.isArray(observed?.epochs) && equal(observed.epochs.map(e => e.name).sort(), ABANDON_ROLES), 'ABANDON_RUNTIME_EPOCH_CHANGED');
  const expected = structuredClone(receipt.expected), starts = [];
  for (const epoch of observed.epochs) {
    const old = receipt.expected[epoch.name], start = Date.parse(epoch.startedAt), created = Date.parse(epoch.created), prior = Date.parse(old.startedAt);
    need(epoch.id === old.id && epoch.image === old.image && Number.isFinite(created) && created <= prior &&
      (!old.created || epoch.created === old.created), 'ABANDON_RUNTIME_EPOCH_CHANGED');
    if (epoch.name.endsWith('volume-init')) need(epoch.startedAt === old.startedAt && epoch.pid === 0, 'ABANDON_RUNTIME_EPOCH_CHANGED');
    else {
      need(Number.isFinite(start) && start > prior && Number.isSafeInteger(epoch.pid) && epoch.pid > 0, 'ABANDON_RUNTIME_EPOCH_CHANGED');
      starts.push(start); expected[epoch.name] = { ...old, created: epoch.created, startedAt: epoch.startedAt, pid: epoch.pid };
    }
  }
  const first = Math.min(...starts), last = Math.max(...starts);
  need(starts.length === 6 && first > Math.max(...Object.values(receipt.expected).map(e => Date.parse(e.startedAt))) && last - first <= 60000, 'ABANDON_RUNTIME_EPOCH_CHANGED');
  const digest = qualifyAbandonedRuntime(observed, { ...receipt, expected });
  return { digest, restart: { kind: 'OWNER_STARTED_DOCKER_ABANDONED_LEASE_ONLY', epochs: structuredClone(observed.epochs),
    window: { first, last, spreadMs: last - first, maximumSpreadMs: 60000 }, createdBasis: 'SAME_IMMUTABLE_CONTAINER_IDS_CREATED_BEFORE_OLD_START_RECORDED_CREATED_MATCHES',
    nativeAuthorityAdopted: false } };
}
export function captureAbandonedDeployment(root, selection) {
  try { const records = captureNativeDeploymentRecords(root, selection.deployment); return { records, receipt: qualifyAbandonedDeployment(records, selection) }; }
  catch (error) {
    if (error.message?.startsWith('ABANDON_DEPLOYED_')) throw error;
    throw Error(error.code === 'ENOENT' ? 'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNAVAILABLE' : 'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNQUALIFIED');
  }
}
async function abandonedRuntime(root, selection, original, review, getReview) {
  need(await getReview() === review, 'RECONCILE_SOURCE_CHANGED'); original.verify();
  const { records, receipt } = captureAbandonedDeployment(root, selection);
  const [{ createDeployAdapter }, { runIsolatedDocker }, { homedir }] = await Promise.all([import('./deploy-adapter.mjs'), import('./public-image-stand.mjs'), import('node:os')]);
  const observer = createNativeRuntimeObserver(() => createDeployAdapter({ root }).status(), runIsolatedDocker, root, homedir()), start = performance.now();
  const digest = qualifyAbandonedRuntime(await observer(receipt), receipt);
  need(performance.now() - start < 15000, 'ABANDON_RUNTIME_PROOF_EXPIRED');
  const verify = () => { original.verify(); records.verify(); };
  verify(); return { digest, provenance: receipt.provenance, observedAt: start, verify };
}
export function qualifyAbandonedQuiescence(first, second, c) {
  need(fingerprint(first) === fingerprint(second), 'ABANDON_CURRENT_OBSERVATION_CHANGED');
  const h = c.chat.chatContextSchema.parse(first.context.h), history = c.chat.chatHistorySchema.parse(first.history), usage = c.usage.parse(first.usage);
  need(h.scanId === SCAN && !h.pending && !history.pending && history.epoch === h.epoch && history.revision === h.revision && sameBinding(history, h) &&
    usage.available && sameBinding(usage, h), 'ABANDON_CURRENT_QUIESCENCE_UNPROVEN');
  for (const scope of ['user', 'scan']) need(zero(usage[scope].held) && vector(usage[scope].used) && vector(usage[scope].carried), 'ABANDON_CURRENT_HELD_NOT_ZERO');
  return { ...ABANDONED_TRUTH, currentObservation: { basis: 'FRESH_CONCURRENCY_PIN_NOT_HISTORICAL_CORRELATION', historySha256: fingerprint(history),
    contextSha256: fingerprint(first.context), window: usage.window, user: { used: usage.user.used, held: usage.user.held, carried: usage.user.carried },
    scan: { used: usage.scan.used, held: usage.scan.held, carried: usage.scan.carried }, estimates: 'SERVER_ESTIMATED_NOT_INVOICE', globalServiceIdleness: 'NOT_CLAIMED' } };
}
export async function verifyReadonlyQuiescentIo(io, c) {
  const preflight = await inPhase('preflight', () => io.preflight());
  const sample = async context => ({ context, history: await inPhase('history-get', () => io.history()), usage: await inPhase('usage-get', () => io.usage()) });
  const first = await sample({ s: preflight.s, h: preflight.h, r: preflight.r });
  await inPhase('quiescence', () => need(fingerprint(preflight.history) === fingerprint(first.history), 'ABANDON_CURRENT_OBSERVATION_CHANGED'));
  const second = await sample(await inPhase('current-get', () => io.current()));
  return inPhase('quiescence', () => qualifyAbandonedQuiescence(first, second, c));
}
export const DIRECT_GET_PATHS = Object.freeze(['/api/v1/auth/me', BASE + '/llm/chat/context', BASE + '/llm/history', BASE + '/llm/usage']);
export const DIRECT_READONLY = Object.freeze({ transport: 'fixed-same-origin-node-get', requests: 8, maxConcurrency: 4, nonGet: 0, redirects: 0, retries: 0, sessionUnchanged: true, browser: 'NOT_STARTED' });
export function directGetAllowed(url, method) { return method === 'GET' && DIRECT_GET_PATHS.some(path => url === NATIVE_ORIGIN + path); }
function directEnvironment(environment) {
  assertNoCaptureEnvironment(environment);
  need(!environment.NODE_OPTIONS && !process.execArgv.some(v => /^--inspect(?:-brk|-port)?(?:=|$)/.test(v)), 'CAPTURE_DEBUG_ENABLED');
}
function directCookie(value) {
  let cookie;
  try { cookie = validateStorage(value).cookies[0]; } catch { throw Error('DIRECT_SESSION_UNSAFE'); }
  // Exact backend tokenFrom/setCookie grammar, not a generic cookie jar. Never
  // forward localStorage, arbitrary headers, extra cookies or cookie attributes.
  need(/^[A-Za-z0-9_-]{43}$/.test(cookie.value) && cookie.secure === false && cookie.sameSite === 'Lax', 'DIRECT_SESSION_UNSAFE');
  return 'demo_session=' + cookie.value;
}
function directJson(path, cookie, signal, request) {
  need(directGetAllowed(NATIVE_ORIGIN + path, 'GET') && !signal.aborted, 'DIRECT_HTTP_REFUSED');
  const max = path === DIRECT_GET_PATHS[0] ? 16384 : path === DIRECT_GET_PATHS[2] ? 1048576 : 65536;
  return new Promise((resolveValue, reject) => {
    let req, response, settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer); signal.removeEventListener('abort', abort);
      response?.destroy(); req?.destroy(); error ? reject(Error(error)) : resolveValue(value);
    };
    const abort = () => finish('DIRECT_DEADLINE');
    const timer = setTimeout(abort, 15000);
    signal.addEventListener('abort', abort, { once: true });
    try {
      // node:http neither follows redirects nor retries. agent:false prevents a
      // retained authenticated socket; the target is literal loopback, no DNS.
      req = request(new URL(NATIVE_ORIGIN + path), { method: 'GET', agent: false, signal, maxHeaderSize: 16384,
        headers: { Cookie: cookie, Accept: 'application/json', Origin: NATIVE_ORIGIN, 'Cache-Control': 'no-store' } }, res => {
        response = res;
        const length = res.headers['content-length'];
        if (signal.aborted || res.statusCode !== 200 || res.headers.location !== undefined || res.headers['set-cookie'] !== undefined ||
          !/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] ?? '') || res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') return finish('DIRECT_HTTP_REFUSED');
        if (length !== undefined && (typeof length !== 'string' || !/^\d+$/.test(length) || Number(length) > max)) return finish('DIRECT_BODY_BOUND');
        const chunks = []; let size = 0;
        res.on('data', chunk => {
          if (settled) return;
          size += chunk.length; if (size > max || signal.aborted) return finish(signal.aborted ? 'DIRECT_DEADLINE' : 'DIRECT_BODY_BOUND');
          chunks.push(chunk);
        });
        res.on('error', () => finish('DIRECT_TRANSPORT_FAILED')); res.on('aborted', () => finish('DIRECT_TRANSPORT_FAILED'));
        res.on('end', () => {
          if (settled) return;
          if (signal.aborted || res.complete !== true) return finish(signal.aborted ? 'DIRECT_DEADLINE' : 'DIRECT_TRANSPORT_FAILED');
          try { const bytes = Buffer.concat(chunks), text = bytes.toString('utf8'); need(Buffer.from(text).equals(bytes)); finish(null, JSON.parse(text)); }
          catch { finish('DIRECT_JSON_INVALID'); }
        });
        res.on('close', () => { if (!settled) finish('DIRECT_TRANSPORT_FAILED'); });
      });
      req.on('error', () => finish(signal.aborted ? 'DIRECT_DEADLINE' : 'DIRECT_TRANSPORT_FAILED'));
      req.end(); // No body, POST interface, retries, redirects or follow-up URL.
    } catch { finish('DIRECT_TRANSPORT_FAILED'); }
  });
}
function directSchema(schema, value) { try { return schema.parse(value); } catch { throw Error('DIRECT_SCHEMA_INVALID'); } }
export function createAbandonedDirectQuiescence({ snapshot = privateSnapshot, request = nodeHttpRequest, load = async () => ({ ...await diagnosticContracts(), ...await extraContracts() }), environment = () => process.env, clock = () => performance.now() } = {}) {
  return async () => {
    await inPhase('session', () => directEnvironment(environment())); // BEFORE private read or Node HTTP.
    const session = await inPhase('session', () => { directEnvironment(environment()); return snapshot(SESSION_FILE); });
    let cookie = await inPhase('session', () => directCookie(session.value));
    const c = await inPhase('contracts', load), controller = new AbortController(); let requests = 0, active = 0, peak = 0;
    try {
      const proof = await inPhase('direct-http', () => bounded(async () => {
        const read = async (index, phase) => inPhase(phase, async () => {
          need(!controller.signal.aborted, 'DIRECT_DEADLINE');
          need(requests < 8 && active < 4, 'DIRECT_REQUEST_BOUND'); directEnvironment(environment());
          requests++; active++; peak = Math.max(peak, active);
          try { return await directJson(DIRECT_GET_PATHS[index], cookie, controller.signal, request); }
          finally { active--; }
        });
        const sample = async () => {
          need(active === 0, 'DIRECT_REQUEST_BOUND');
          // Independent passive GETs share one bounded observation window. The
          // next sample cannot start until all four reads and schemas complete.
          let values;
          try { values = await Promise.all(['owner-get', 'context-get', 'history-get', 'usage-get'].map((phase, i) => read(i, phase))); }
          catch (error) { controller.abort(); throw error; }
          const [owner, contextValue, historyValue, usageValue] = values;
          await inPhase('owner-get', () => {
            need(typeof owner?.email === 'string' && Buffer.byteLength(owner.email) <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(owner.email), 'DIRECT_OWNER_CHANGED');
            try { assertAuthUser(owner, owner.email); } catch { throw Error('DIRECT_OWNER_CHANGED'); }
          });
          const h = await inPhase('context-get', () => directSchema(c.chat.chatContextSchema, contextValue));
          need(h.scanId === SCAN && h.digest === 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55' && h.platform === 'linux/amd64' && policyMatches(h), 'DIRECT_CONTEXT_INVALID');
          const value = { owner, context: { h }, history: await inPhase('history-get', () => directSchema(c.chat.chatHistorySchema, historyValue)),
            usage: await inPhase('usage-get', () => directSchema(c.usage, usageValue)) };
          await inPhase('quiescence', () => qualifyAbandonedQuiescence(value, value, c)); return value;
        };
        const observedAt = clock(), first = await sample(), second = await sample();
        need(equal(first.owner, second.owner), 'DIRECT_OWNER_CHANGED');
        const result = await inPhase('quiescence', () => qualifyAbandonedQuiescence(first, second, c));
        return { ...result, observedAt, readonly: { ...DIRECT_READONLY } };
      }, 60000, () => controller.abort()));
      await inPhase('session-postcheck', async () => { directEnvironment(environment()); need((await snapshot(SESSION_FILE)).byteHash === session.byteHash, 'PRIVATE_SESSION_CHANGED'); });
      need(!controller.signal.aborted && requests === 8, 'DIRECT_DEADLINE'); need(active === 0 && peak === 4, 'DIRECT_REQUEST_BOUND'); return proof;
    } finally { cookie = undefined; controller.abort(); }
  };
}
const abandonedQuiescence = createAbandonedDirectQuiescence();
function quietEnvelope(quiet, directOnly = false) {
  return Object.entries(ABANDONED_TRUTH).every(([k, v]) => equal(quiet?.[k], v)) && quiet.currentObservation?.basis === 'FRESH_CONCURRENCY_PIN_NOT_HISTORICAL_CORRELATION' &&
    (equal(quiet.readonly, DIRECT_READONLY) || !directOnly && equal(quiet.readonly, { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true }));
}
function prepareObservationAllowed(quiet, historical) {
  if (!quietEnvelope(quiet, true)) return false;
  const prior = historical.currentObservation, fresh = quiet.currentObservation;
  return equal(quiet, { ...historical, currentObservation: { ...prior, window: fresh.window,
    user: { ...prior.user, used: fresh.user.used }, scan: { ...prior.scan, used: fresh.scan.used } } }) && fresh.window.start >= prior.window.start;
}
export function captureFailedReadonlyStage(root, selection, failedReview, original) {
  selectionValid(selection); need(SHA.test(failedReview), 'ABANDON_FAILED_STAGE_UNQUALIFIED');
  const directory = archiveDirectory(join(root, ABANDONED_SLOT));
  need(equal(directory.names, ['verification-intent.json']), 'ABANDON_FAILED_STAGE_UNQUALIFIED');
  const intent = archiveFile(join(directory.path, 'verification-intent.json'), 262144);
  need(intent.bytes === JSON.stringify({ version: 1, kind: 'abandoned-fence-readonly-intent', binding: { selection, review: failedReview }, originalEvidence: original.seal }), 'ABANDON_FAILED_STAGE_UNQUALIFIED');
  const verify = () => { directory.verify(); intent.verify(); original.verify(); };
  verify(); return { predecessor: { slot: ABANDONED_SLOT, review: failedReview, intentSha256: intent.digest, outcome: 'INCOMPLETE_READONLY_NO_ELIGIBILITY', firstFailure: 'UNRECORDED_UNKNOWN' }, verify };
}
export function captureFailedArchiveStage(root, selection, failedReview, failedArchiveReview, original, evidencePin) {
  need(SHA.test(failedArchiveReview) && (evidencePin === undefined || SHA.test(evidencePin)), 'ABANDON_FAILED_ARCHIVE_UNQUALIFIED');
  const failed = captureFailedReadonlyStage(root, selection, failedReview, original), directory = archiveDirectory(join(root, ABANDONED_CONTINUATION_SLOT));
  const names = ['archive-intent.json', 'eligibility.json', 'failure.json', 'verification-intent.json'];
  need(equal(directory.names, names), 'ABANDON_FAILED_ARCHIVE_UNQUALIFIED');
  const files = names.map(name => ({ name, file: archiveFile(join(directory.path, name), 262144) }));
  const read = name => JSON.parse(files.find(v => v.name === name).file.bytes);
  const binding = { selection, review: failedArchiveReview, predecessor: failed.predecessor };
  const eligibilityFile = files.find(v => v.name === 'eligibility.json').file, eligible = read('eligibility.json');
  need(equal(read('verification-intent.json'), { version: 1, kind: 'abandoned-fence-readonly-intent', binding, originalEvidence: original.seal }) &&
    eligible.version === 1 && eligible.kind === 'abandoned-native-fence-eligibility' && equal(eligible.binding, binding) && eligible.originalEvidence === original.seal &&
    SHA.test(eligible.runtime) && Number.isSafeInteger(eligible.observedAt) && quietEnvelope(eligible.quiescence) &&
    equal(read('archive-intent.json'), { version: 1, kind: 'exact-abandoned-native-fence-archive-intent', binding, eligibility: eligibilityFile.digest, ...ABANDONED_TRUTH }) &&
    equal(read('failure.json'), { version: 1, firstFailure: { phase: 'routes', code: 'READONLY_TRANSPORT_FAILED' }, ...ABANDONED_TRUTH }), 'ABANDON_FAILED_ARCHIVE_UNQUALIFIED');
  const evidence = files.map(({ name, file }) => ({ path: name, sha256: file.digest, bytes: Buffer.byteLength(file.bytes) })), evidenceSha256 = fingerprint(evidence);
  need(evidencePin === undefined || evidenceSha256 === evidencePin, 'ABANDON_FAILED_ARCHIVE_UNQUALIFIED');
  const verify = () => { failed.verify(); directory.verify(); files.forEach(v => v.file.verify()); original.verify(); };
  verify(); return { evidenceSha256, predecessor: { ...failed.predecessor, failedArchive: { slot: ABANDONED_CONTINUATION_SLOT, review: failedArchiveReview,
    evidenceSha256, evidence, outcome: 'PRE_RENAME_ARCHIVE_REFUSAL', firstFailure: { phase: 'routes', code: 'READONLY_TRANSPORT_FAILED' }, cause: 'UNKNOWN_NOT_ATTRIBUTED' } }, verify };
}
export function captureFailedFreshnessStage(root, options, original) {
  const { selection, failedReview, failedArchiveReview, failedArchiveEvidence, failedDirectReview, failedDirectEvidence } = options;
  need(SHA.test(failedDirectReview) && (failedDirectEvidence === undefined || SHA.test(failedDirectEvidence)), 'ABANDON_FAILED_FRESHNESS_UNQUALIFIED');
  const prior = captureFailedArchiveStage(root, selection, failedReview, failedArchiveReview, original, failedArchiveEvidence);
  const directory = archiveDirectory(join(root, ABANDONED_DIRECT_SLOT)), names = ['failure.json', 'verification-intent.json'];
  need(equal(directory.names, names), 'ABANDON_FAILED_FRESHNESS_UNQUALIFIED');
  const files = names.map(name => ({ name, file: archiveFile(join(directory.path, name), 262144) })), read = name => JSON.parse(files.find(v => v.name === name).file.bytes);
  const binding = { selection, review: failedDirectReview, predecessor: prior.predecessor }, firstFailure = { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' };
  need(equal(read('verification-intent.json'), { version: 1, kind: 'abandoned-fence-readonly-intent', binding, originalEvidence: original.seal }) &&
    equal(read('failure.json'), { version: 1, firstFailure, ...ABANDONED_TRUTH }), 'ABANDON_FAILED_FRESHNESS_UNQUALIFIED');
  const evidence = files.map(({ name, file }) => ({ path: name, sha256: file.digest, bytes: Buffer.byteLength(file.bytes) })), evidenceSha256 = fingerprint(evidence);
  need(failedDirectEvidence === undefined || failedDirectEvidence === evidenceSha256, 'ABANDON_FAILED_FRESHNESS_UNQUALIFIED');
  const verify = () => { prior.verify(); directory.verify(); files.forEach(v => v.file.verify()); original.verify(); };
  verify(); return { evidenceSha256, predecessor: { ...prior.predecessor, failedFreshness: { slot: ABANDONED_DIRECT_SLOT, review: failedDirectReview,
    evidenceSha256, evidence, outcome: 'READONLY_FRESHNESS_REFUSAL_NO_ELIGIBILITY', firstFailure } }, verify };
}
export function createAbandonedReadonlyDiagnostic({ root, capture = captureAbandonedEvidence, getReview = reconcileFingerprint, runtime = abandonedRuntime, quiescence = abandonedQuiescence, clock = () => performance.now() }) {
  return async options => {
    try {
      await inPhase('admission', async () => {
        const direct = options?.mode === 'abandon-diagnose-direct';
        need(keys(options, ['mode', 'selection', 'review', 'failedReview', ...(direct ? ['failedArchiveReview', 'failedArchiveEvidence'] : [])]) && ['abandon-diagnose', 'abandon-diagnose-direct'].includes(options.mode) && SHA.test(options.review) && SHA.test(options.failedReview) &&
          (!direct || SHA.test(options.failedArchiveReview) && SHA.test(options.failedArchiveEvidence)), 'EXACT_ABANDONMENT_GO_REQUIRED');
        selectionValid(options.selection); options = structuredClone(options); directEnvironment(process.env); need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
      });
      const original = await inPhase('admission', () => capture(root, options.selection));
      const direct = options.mode === 'abandon-diagnose-direct';
      const failed = await inPhase('failed-stage', () => direct ? captureFailedArchiveStage(root, options.selection, options.failedReview, options.failedArchiveReview, original, options.failedArchiveEvidence) : captureFailedReadonlyStage(root, options.selection, options.failedReview, original));
      const before = await inPhase('runtime-before', () => runtime(root, options.selection, original, options.review, getReview));
      const quiet = await inPhase('browser-work', () => quiescence(original));
      const after = await inPhase('runtime-after', () => runtime(root, options.selection, original, options.review, getReview));
      await inPhase('final-fence', async () => {
        need(after.digest === before.digest && equal(after.provenance, before.provenance), 'ABANDON_RUNTIME_CHANGED');
        need(quietEnvelope(quiet, direct), 'ABANDON_CURRENT_QUIESCENCE_UNPROVEN');
        need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED'); failed.verify(); before.verify(); after.verify();
      });
      await inPhase('freshness', () => need([quiet.observedAt, after.observedAt].every(at => Number.isFinite(at) && clock() >= at && clock() - at < 15000), 'ABANDON_RUNTIME_PROOF_EXPIRED'));
      return { status: 'READONLY_DIAGNOSTIC_PASS_NO_ELIGIBILITY_NO_DISPOSITION', firstFailure: null, slotWrites: 0, ...ABANDONED_TRUTH };
    } catch (error) {
      return { status: 'READONLY_DIAGNOSTIC_REFUSED', firstFailure: readonlyFailure(error), slotWrites: 0, ...ABANDONED_TRUTH };
    }
  };
}
// Explicit opt-in exported coordinator seam. Import/default CLI remains inert;
// production supplies no alternate reader, proof, slot, browser or transport.
export function diagnoseAbandonedQuiescence(options) { return createAbandonedReadonlyDiagnostic({ root: ROOT })(options); }
// Deliberately separate from known-commit reconciliation. No historical request
// anchors, originalFingerprint, current-tree source capture, refund or retry path.
export function createAbandonedFenceDisposer({ root, capture = captureAbandonedEvidence, getReview = reconcileFingerprint, runtime = abandonedRuntime,
  quiescence = abandonedQuiescence, now = () => Date.now(), clock = () => performance.now(), io = fs }) {
  return async options => {
    let failureSlot, failureFence, phase = 'admission';
    try {
    const parallel = ['abandon-verify-parallel', 'abandon-archive-parallel'].includes(options?.mode),
      direct = parallel || ['abandon-verify-direct', 'abandon-archive-direct'].includes(options?.mode), continuation = direct || ['abandon-verify-continuation', 'abandon-archive-continuation'].includes(options?.mode),
      verifying = ['abandon-verify', 'abandon-verify-continuation', 'abandon-verify-direct', 'abandon-verify-parallel'].includes(options?.mode);
    need(keys(options, ['mode', 'selection', 'review', 'verification', ...(continuation ? ['failedReview'] : []), ...(direct ? ['failedArchiveReview', 'failedArchiveEvidence'] : []), ...(parallel ? ['failedDirectReview', 'failedDirectEvidence'] : [])]) &&
      ['abandon-verify', 'abandon-archive', 'abandon-verify-continuation', 'abandon-archive-continuation', 'abandon-verify-direct', 'abandon-archive-direct', 'abandon-verify-parallel', 'abandon-archive-parallel'].includes(options.mode) && SHA.test(options.review) &&
      (!continuation || SHA.test(options.failedReview)) && (!direct || SHA.test(options.failedArchiveReview) && SHA.test(options.failedArchiveEvidence)) &&
      (!parallel || SHA.test(options.failedDirectReview) && SHA.test(options.failedDirectEvidence)) && (verifying ? options.verification === null : SHA.test(options.verification)), 'EXACT_ABANDONMENT_GO_REQUIRED');
    selectionValid(options.selection); options = structuredClone(options); directEnvironment(process.env);
    need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
    const original = capture(root, options.selection), slotName = parallel ? ABANDONED_PARALLEL_SLOT : direct ? ABANDONED_DIRECT_SLOT : continuation ? ABANDONED_CONTINUATION_SLOT : ABANDONED_SLOT,
      slot = join(root, slotName), parent = directoryFence(join(root, 'test-results'), false);
    phase = 'failed-stage';
    const failed = parallel ? captureFailedFreshnessStage(root, options, original) : direct ? captureFailedArchiveStage(root, options.selection, options.failedReview, options.failedArchiveReview, original, options.failedArchiveEvidence) : continuation ? captureFailedReadonlyStage(root, options.selection, options.failedReview, original) : null;
    phase = 'metadata';
    const binding = { selection: options.selection, review: options.review, ...(failed ? { predecessor: failed.predecessor } : {}) }, staged = [];
    const write = (name, value) => { const digest = writeRecord(slot, name, value), f = archiveFile(join(slot, name), 262144); need(f.digest === digest, 'RECONCILE_METADATA_CHANGED'); staged.push(f); return digest; };
    const verifyStage = () => { need(equal(io.readdirSync(slot).sort(), staged.map(f => f.path.slice(slot.length + 1)).sort()), 'RECONCILE_METADATA_CHANGED'); staged.forEach(f => f.verify()); };
    let prior;
    if (verifying) {
      io.mkdirSync(slot, { mode: 0o700 }); failureFence = directoryFence(slot); failureSlot = slot; syncDirectory(parent.path);
      write('verification-intent.json', { version: 1, kind: 'abandoned-fence-readonly-intent', binding, originalEvidence: original.seal });
    } else {
      directoryFence(slot); need(equal(io.readdirSync(slot).sort(), ['eligibility.json', 'verification-intent.json']), 'ABANDONMENT_SLOT_NOT_FRESH');
      const proof = archiveFile(join(slot, 'eligibility.json'), 262144), intent = archiveFile(join(slot, 'verification-intent.json'), 262144); staged.push(proof, intent);
      prior = JSON.parse(proof.bytes);
      need(proof.digest === options.verification && prior.version === 1 && prior.kind === 'abandoned-native-fence-eligibility' && equal(prior.binding, binding) &&
        prior.originalEvidence === original.seal && equal(JSON.parse(intent.bytes), { version: 1, kind: 'abandoned-fence-readonly-intent', binding, originalEvidence: original.seal }) &&
        Number.isSafeInteger(prior.observedAt) && now() >= prior.observedAt && now() - prior.observedAt <= 300000, 'ABANDONMENT_PROOF_STALE_OR_CHANGED');
      write('archive-intent.json', { version: 1, kind: 'exact-abandoned-native-fence-archive-intent', binding, eligibility: options.verification, ...ABANDONED_TRUTH });
      failureFence = directoryFence(slot); failureSlot = slot;
    }
    const slotFence = directoryFence(slot), start = clock();
    phase = 'runtime-before'; original.verify(); const before = await inPhase('runtime-before', () => runtime(root, options.selection, original, options.review, getReview));
    phase = direct ? 'direct-http' : 'browser-work'; const quiet = structuredClone(await inPhase(phase, () => quiescence(original))), quiescenceAt = quiet.observedAt; delete quiet.observedAt;
    need(quietEnvelope(quiet, direct), 'ABANDON_CURRENT_QUIESCENCE_UNPROVEN');
    phase = 'runtime-after'; const after = await inPhase('runtime-after', () => runtime(root, options.selection, original, options.review, getReview));
    const fresh = () => { phase = 'freshness'; need([quiescenceAt, after.observedAt].every(at => Number.isFinite(at) && clock() >= at && clock() - at < 15000), 'ABANDON_RUNTIME_PROOF_EXPIRED'); };
    phase = 'final-fence'; need(after.digest === before.digest && equal(after.provenance, before.provenance) && clock() >= start && clock() - start < 180000, 'ABANDON_RUNTIME_CHANGED');
    need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
    const fence = () => { phase = 'final-fence'; original.verify(); failed?.verify(); before.verify(); after.verify(); slotFence.verify(); parent.verify(); verifyStage(); };
    fence(); fresh();
    const result = { version: 1, kind: 'abandoned-native-fence-eligibility', binding, originalEvidence: original.seal, observedAt: now(), runtime: after.digest, provenance: after.provenance, quiescence: quiet };
    if (verifying) { phase = 'metadata'; const digest = write('eligibility.json', result); fence(); fresh(); return { status: 'ABANDONMENT_ELIGIBLE_LOCK_RETAINED', eligibilitySha256: digest, ...ABANDONED_TRUTH }; }
    phase = 'final-fence'; need(prior.runtime === result.runtime && equal(prior.provenance, result.provenance) && equal(prior.quiescence, quiet), 'ABANDON_CURRENT_OBSERVATION_CHANGED');
    const disposition = { version: 1, ...ABANDONED_TRUTH, binding, originalEvidence: original.seal, eligibility: options.verification, runtime: after.digest,
      provenance: after.provenance, currentObservation: quiet.currentObservation, action: 'archive-exact-abandoned-native-fence', destination: slotName + '/abandoned-operation.lock' };
    phase = 'metadata'; write('disposition.json', disposition);
    phase = 'final-fence'; need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED'); fence();
    fresh();
    phase = 'archive'; const destination = join(slot, 'abandoned-operation.lock'); need(!io.existsSync(destination), 'RECONCILE_TARGET_EXISTS');
    io.renameSync(original.lockPath, destination); syncDirectory(slot); syncDirectory(join(root, '.local-public-images'));
    need(equal(stamp(io.lstatSync(destination)), original.lockIdentity) && equal(io.readdirSync(destination), ['native-runtime-owner.json']) &&
      archiveFile(join(destination, 'native-runtime-owner.json'), 4096).digest === original.ownerDigest, 'ABANDON_ARCHIVE_UNCERTAIN');
    writeRecord(slot, 'archived.json', { version: 1, dispositionSha256: sha(JSON.stringify(disposition)), ...ABANDONED_TRUTH });
    return { status: 'EXACT_ABANDONED_NATIVE_FENCE_ARCHIVED_UNKNOWN_PRESERVED', ...ABANDONED_TRUTH };
    } catch (error) {
      const failure = phaseError(error, phase);
      // Append only in this invocation's proven own stage directory. An old
      // failed slot is never amended or reset by diagnosis/continuation.
      if (failureSlot) try { failureFence.verify(); writeRecord(failureSlot, 'failure.json', { version: 1, firstFailure: readonlyFailure(failure), ...ABANDONED_TRUTH }); } catch { /* Preserve the original failure even if diagnostic persistence fails. */ }
      throw failure;
    }
  };
}
// Batch36 remains immutable at its root. Requalification adds at most three
// explicit attempts; a prepared/pending/uncertain attempt is NOT a retry ticket.
const REQUALIFICATION_FILES = ['archive-intent.json', 'eligibility.json', 'failure.json', 'verification-intent.json'];
export function captureFailedParallelStage(root, options, original) {
  const prior = captureFailedFreshnessStage(root, options, original), path = join(root, ABANDONED_PARALLEL_SLOT), dir = directoryFence(path);
  need(SHA.test(options.failedParallelReview) && (options.failedParallelEvidence === undefined || SHA.test(options.failedParallelEvidence)), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const names = fs.readdirSync(path).sort();
  need(equal(names, REQUALIFICATION_FILES) || equal(names, [...REQUALIFICATION_FILES, 'requalification'].sort()), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const files = REQUALIFICATION_FILES.map(name => ({ name, file: archiveFile(join(path, name), 262144) }));
  const read = name => JSON.parse(files.find(v => v.name === name).file.bytes), eligible = read('eligibility.json');
  const binding = { selection: options.selection, review: options.failedParallelReview, predecessor: prior.predecessor };
  need(equal(read('verification-intent.json'), { version: 1, kind: 'abandoned-fence-readonly-intent', binding, originalEvidence: original.seal }) &&
    eligible.version === 1 && eligible.kind === 'abandoned-native-fence-eligibility' && equal(eligible.binding, binding) && eligible.originalEvidence === original.seal &&
    SHA.test(eligible.runtime) && Number.isSafeInteger(eligible.observedAt) && quietEnvelope(eligible.quiescence, true) &&
    equal(read('archive-intent.json'), { version: 1, kind: 'exact-abandoned-native-fence-archive-intent', binding, eligibility: files.find(v => v.name === 'eligibility.json').file.digest, ...ABANDONED_TRUTH }) &&
    equal(read('failure.json'), { version: 1, firstFailure: { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' }, ...ABANDONED_TRUTH }), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const evidence = files.map(({ name, file }) => ({ path: name, sha256: file.digest, bytes: Buffer.byteLength(file.bytes) })), evidenceSha256 = fingerprint(evidence);
  need(options.failedParallelEvidence === undefined || options.failedParallelEvidence === evidenceSha256, 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const verify = () => { prior.verify(); dir.verify(); files.forEach(v => v.file.verify());
    need(equal(fs.readdirSync(path).filter(n => n !== 'requalification').sort(), REQUALIFICATION_FILES), 'ABANDON_REQUALIFICATION_UNQUALIFIED'); };
  verify(); return { evidenceSha256, eligible, verify };
}
const highStamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs];
// A hash is checked while these descriptors are pinned, BEFORE fresh reads. The
// final gate binds those exact bytes via ctimeNs as well as the CURRENT pathname.
export function pinAbandonedPaths(root, paths, io = fs) {
  const rows = new Map(); let closed = false;
  const check = row => {
    const fdStat = io.fstatSync(row.fd, { bigint: true }), pathStat = io.lstatSync(row.path, { bigint: true });
    need(equal(highStamp(fdStat), row.stat) && equal(highStamp(pathStat), row.stat), 'ABANDON_PIN_CHANGED');
    if (row.names) { const names = io.readdirSync(row.path); need(names.length <= 4096 && equal(names.sort(), row.names), 'ABANDON_PIN_CHANGED'); }
  };
  const close = () => { if (!closed) { closed = true; for (const row of rows.values()) io.closeSync(row.fd); } };
  try {
    for (const path of paths) {
      need(path === root || path.startsWith(root + '/'), 'ABANDON_PIN_CHANGED');
      let current = path;
      while (!rows.has(current)) {
        need(rows.size < 8192, 'ABANDON_PIN_BOUND');
        const s = io.lstatSync(current, { bigint: true }), dir = s.isDirectory();
        need((dir || s.isFile() && s.nlink === 1n) && !s.isSymbolicLink() && s.uid === BigInt(process.getuid()) && !(s.mode & 0o022n), 'ABANDON_PIN_CHANGED');
        const fd = io.openSync(current, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK | (dir ? fs.constants.O_DIRECTORY : 0));
        const row = { path: current, fd, stat: highStamp(s), names: null }; rows.set(current, row);
        if (dir) { row.names = io.readdirSync(current); need(row.names.length <= 4096, 'ABANDON_PIN_BOUND'); row.names.sort(); }
        check(row); if (current === root) break; current = dirname(current);
      }
    }
    return { verify() { need(!closed, 'ABANDON_PIN_CHANGED'); for (const row of rows.values()) check(row); }, close };
  } catch (error) { close(); throw error; }
}
// Existing boundary authenticates the exact persistent sentinel. Inheriting the
// SAME open-file description retains flock after the probe child exits. This is
// exclusion ONLY: no supervisor env/session/deploy authority is created.
export function acquireAbandonedSupervisor(root) {
  let fd;
  try {
    const identity = inspectDeploySupervisor(root), path = join(root, '.local-public-images/.deploy-supervisor-v1.lock');
    fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const s = fs.fstatSync(fd, { bigint: true }), stat = highStamp(s);
    need(s.dev === BigInt(identity.dev) && s.ino === BigInt(identity.ino), 'ABANDON_SUPERVISOR_CHANGED');
    const result = spawnSync('/usr/bin/python3', ['-I', '-c', 'import fcntl; fcntl.flock(3, fcntl.LOCK_EX | fcntl.LOCK_NB)'],
      { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'ignore', 'ignore', fd], timeout: 5000 });
    need(!result.error && !result.signal && result.status === 0, 'ABANDON_SUPERVISOR_UNQUALIFIED');
    let closed = false;
    const lease = { verify() { need(!closed && equal(highStamp(fs.fstatSync(fd, { bigint: true })), stat) && equal(highStamp(fs.lstatSync(path, { bigint: true })), stat), 'ABANDON_SUPERVISOR_CHANGED'); },
      close() { if (!closed) { closed = true; fs.closeSync(fd); } } };
    lease.verify(); return lease;
  } catch (error) { if (fd !== undefined) fs.closeSync(fd); throw phaseError(Error(READONLY_FAILURE_CODES.includes(error?.message) ? error.message : 'ABANDON_SUPERVISOR_UNQUALIFIED'), 'admission'); }
}
// Closed metadata locations only. Never recursively enter store snapshots,
// fenced/before-api/after-api, environment, JWT, settings, or private payloads.
function abandonedPinPaths(root, selection, sourcePaths) {
  const paths = new Set(sourcePaths.map(p => join(root, p))), state = join(root, '.local-public-images');
  const tree = (path, depth, descend) => {
    if (!fs.existsSync(path)) return;
    need(paths.size < 8192 && depth <= 6, 'ABANDON_PIN_BOUND'); paths.add(path);
    const names = fs.readdirSync(path); need(names.length <= 4096, 'ABANDON_PIN_BOUND');
    for (const name of names) {
      const child = join(path, name);
      if (/\.(json|jsonl|ndjson)$/.test(name)) { need(paths.size < 8192, 'ABANDON_PIN_BOUND'); paths.add(child); }
      else if (descend(name, depth)) tree(child, depth + 1, descend);
    }
  };
  paths.add(state); paths.add(join(state, '.deploy-supervisor-v1.lock')); paths.add(join(state, '.operation.lock/native-runtime-owner.json'));
  for (const name of ['profile.json', 'llm-profile.json', 'compose.images.json', 'compose.llm-env.json', 'compose.cve.json']) if (fs.existsSync(join(state, name))) paths.add(join(state, name));
  tree(join(state, 'native-runtime-v1', selection.attempt), 0, () => false);
  for (const slot of [OLD_SLOT, ABANDONED_SLOT, ABANDONED_CONTINUATION_SLOT, ABANDONED_DIRECT_SLOT, ABANDONED_PARALLEL_SLOT])
    tree(join(root, slot), 0, (n, d) => d === 0 && n === 'requalification' || d === 1 && /^(01|02|03)$/.test(n));
  // Pin all adapter receipt directories, but no snapshot/helper/store subtrees.
  tree(join(state, 'deploy-adapter-v1'), 0, (n, d) => d === 0 && NONCE.test(n) || d === 1 && n === 'operation.lock');
  for (const catalog of ['llm-deployments', 'llm-deployments-archive', 'llm-deployment-archive-operations'])
    tree(join(state, catalog), 0, (n, d) => d === 0 && (/^deploy-[a-f0-9]{32}$/.test(n) || SHA.test(n)) || d === 1 && n === 'stop-diagnostics' || d === 2 && ['web', 'api', 'worker', 'egress', 'llm-egress'].includes(n));
  tree(join(state, 'reconciliations'), 0, (n, d) => d === 0 && /^(build-only|network-only|running-build-only)-[a-f0-9]{32}$/.test(n) || d === 1 && ['original-operation.lock', 'reconciliation-operation.lock'].includes(n));
  tree(join(state, 'redeployments'), 0, (n, d) => d === 0 && /^redeploy-[a-f0-9]{32}$/.test(n) || d === 1 && ['original-operation.lock', 'recovery-operation.lock'].includes(n) || d === 2 && /^(resume|continue-drain|started-drain|backup-transfer)\.lock$/.test(n));
  // The existing history validator hashes these backups. Pin only their fixed
  // filesystem identities here; do not read or serialize their payloads.
  const redeploys = join(state, 'redeployments');
  if (fs.existsSync(redeploys)) for (const name of fs.readdirSync(redeploys)) for (const role of ['auth', 'ledger']) paths.add(join(redeploys, name, 'backups', role + '.sqlite'));
  return [...paths];
}
async function prepareAbandonedRuntime(root, selection, original, review, getReview, clock, ownerDocker = false) {
  need(await getReview() === review, 'RECONCILE_SOURCE_CHANGED'); original.verify();
  const { records, receipt } = captureAbandonedDeployment(root, selection);
  const [{ createDeployAdapter }, { runIsolatedDocker }, { homedir }] = await Promise.all([import('./deploy-adapter.mjs'), import('./public-image-stand.mjs'), import('node:os')]);
  const observer = createNativeRuntimeObserver(() => createDeployAdapter({ root }).status(), runIsolatedDocker, root, homedir());
  return { verify: records.verify, async observe() {
    const observedAt = clock(), observed = await observer(receipt);
    const proof = ownerDocker ? qualifyOwnerDockerRestart(observed, receipt) : { digest: qualifyAbandonedRuntime(observed, receipt) };
    need(clock() >= observedAt && clock() - observedAt < 15000, 'ABANDON_RUNTIME_PROOF_EXPIRED');
    return { observedAt, ...proof, provenance: receipt.provenance };
  } };
}
const ATTEMPT_NAMES = ['intent.json', 'prepared.json', 'commit-intent.json', 'disposition.json', 'failure.json'];
function requalificationHistory(path, ordinal, original, options, committing) {
  const names = fs.readdirSync(path).sort(), end = committing ? ordinal : ordinal - 1;
  need(equal(names, Array.from({ length: end }, (_, i) => String(i + 1).padStart(2, '0'))), 'ABANDON_ATTEMPT_BLOCKED');
  const history = [];
  for (let i = 1; i < ordinal; i++) {
    const dir = archiveDirectory(join(path, String(i).padStart(2, '0')));
    need(dir.names.includes('intent.json') && dir.names.includes('failure.json') && dir.names.every(n => ATTEMPT_NAMES.includes(n)), 'ABANDON_ATTEMPT_BLOCKED');
    const files = dir.names.map(name => ({ name, file: archiveFile(join(dir.path, name), 262144) }));
    const intent = JSON.parse(files.find(v => v.name === 'intent.json').file.bytes), failure = JSON.parse(files.find(v => v.name === 'failure.json').file.bytes);
    need(intent.version === 1 && intent.kind === 'abandoned-fence-requalification-intent' && intent.ordinal === i && intent.originalEvidence === original.seal &&
      equal(intent.selection, options.selection) && intent.failedParallelEvidence === options.failedParallelEvidence && SHA.test(intent.review) &&
      equal(failure, { version: 1, ordinal: i, review: intent.review, renameAttempted: false, originalEvidence: original.seal,
        firstFailure: failure.firstFailure, ...ABANDONED_TRUTH }) && READONLY_FAILURE_PHASES.includes(failure.firstFailure?.phase) &&
      READONLY_FAILURE_CODES.includes(failure.firstFailure?.code), 'ABANDON_ATTEMPT_BLOCKED');
    history.push({ ordinal: i, evidence: files.map(({ name, file }) => ({ path: name, sha256: file.digest })) });
  }
  return history;
}
// Production exposes no alternate paths, proof factories, clocks or transports.
// Test seams remain here so the fast commit boundary is executable offline.
export function createAbandonedRequalification({ root, capture = captureAbandonedEvidence, getReview = reconcileFingerprint,
  prepareRuntime = prepareAbandonedRuntime, quiescence = abandonedQuiescence, acquireSupervisor = acquireAbandonedSupervisor,
  sourcePaths = RECONCILE_REVIEW_FILES, now = () => Date.now(), clock = () => performance.now(), alive = processAlive, io = fs }) {
  return async options => {
    let own, ownFence, pins, lease, renameAttempted = false, phase = 'admission', original;
    try {
      const ownerDocker = ['abandon-requalify-docker-prepare', 'abandon-requalify-docker-commit'].includes(options?.mode);
      const committing = ['abandon-requalify-commit', 'abandon-requalify-docker-commit'].includes(options?.mode);
      need(keys(options, ['mode', 'selection', 'review', 'failedReview', 'failedArchiveReview', 'failedArchiveEvidence', 'failedDirectReview', 'failedDirectEvidence',
        'failedParallelReview', 'failedParallelEvidence', 'ordinal', 'prepared']) && ['abandon-requalify-prepare', 'abandon-requalify-commit', 'abandon-requalify-docker-prepare', 'abandon-requalify-docker-commit'].includes(options.mode) &&
        ['review', 'failedReview', 'failedArchiveReview', 'failedArchiveEvidence', 'failedDirectReview', 'failedDirectEvidence', 'failedParallelReview', 'failedParallelEvidence'].every(k => SHA.test(options[k])) &&
        Number.isInteger(options.ordinal) && options.ordinal >= 1 && options.ordinal <= 3 && (committing ? SHA.test(options.prepared) : options.prepared === null), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
      selectionValid(options.selection); options = structuredClone(options); directEnvironment(process.env);
      need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED');
      original = capture(root, options.selection);
      phase = 'failed-stage'; const failed = captureFailedParallelStage(root, options, original);
      const stage = join(root, ABANDONED_PARALLEL_SLOT), attempts = join(stage, 'requalification');
      if (!fs.existsSync(attempts)) { need(!committing && options.ordinal === 1, 'ABANDON_ATTEMPT_BLOCKED'); io.mkdirSync(attempts, { mode: 0o700 }); syncDirectory(stage); }
      directoryFence(attempts);
      const history = requalificationHistory(attempts, options.ordinal, original, options, committing), path = join(attempts, String(options.ordinal).padStart(2, '0'));
      const intent = { version: 1, kind: 'abandoned-fence-requalification-intent', selection: options.selection, review: options.review, ordinal: options.ordinal,
        originalEvidence: original.seal, failedParallelEvidence: failed.evidenceSha256, previousAttempts: history,
                ...(ownerDocker ? { retirementOnly: 'EXPLICIT_OWNER_STARTED_DOCKER_SAME_CONTAINERS_NO_NATIVE_ADOPTION' } : {}) };
      const destination = join(path, 'abandoned-operation.lock'), target = ABANDONED_PARALLEL_SLOT + '/requalification/' + String(options.ordinal).padStart(2, '0') + '/abandoned-operation.lock';
      if (!committing) {
        phase = 'prepare'; io.mkdirSync(path, { mode: 0o700 }); own = path; ownFence = directoryFence(path); syncDirectory(attempts);
        writeRecord(path, 'intent.json', intent);
        // Old eligibility is ONLY an immutable comparison constraint. No timestamp
        // here represents a new GET/runtime observation or fresh authority.
        const candidate = { runtime: failed.eligible.runtime, provenance: failed.eligible.provenance, quiescence: failed.eligible.quiescence };
        if (ownerDocker) {
          const runtime = await prepareRuntime(root, options.selection, original, options.review, getReview, clock, true); runtime.verify();
          lease = acquireSupervisor(root); lease.verify();
          const current = await runtime.observe();
          need(SHA.test(current.digest) && current.restart?.kind === 'OWNER_STARTED_DOCKER_ABANDONED_LEASE_ONLY' && equal(current.provenance, candidate.provenance), 'ABANDON_RUNTIME_CHANGED');
          candidate.runtime = current.digest; candidate.restart = current.restart;
          const quiet = structuredClone(await inPhase('direct-http', () => quiescence(original))), observedAt = quiet.observedAt; delete quiet.observedAt;
          // Current window/used are observations, not historical forgiveness.
          need(prepareObservationAllowed(quiet, failed.eligible.quiescence), 'ABANDON_CURRENT_OBSERVATION_CHANGED');
          need(Number.isFinite(observedAt) && clock() >= observedAt && clock() - observedAt < 15000, 'ABANDON_RUNTIME_PROOF_EXPIRED');
          candidate.quiescence = quiet;
          candidate.observationBasis = 'FRESH_PREPARE_TWO_DIRECT_GET_SAMPLES_NOT_HISTORICAL_USAGE';
          lease.verify(); lease.close(); lease = undefined;
        }
        need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED'); failed.verify();
        const prepared = { version: 1, kind: 'abandoned-fence-prepared-constraint', intent, preparedAt: now(), candidate, destination: target, ...ABANDONED_TRUTH };
        const digest = writeRecord(path, 'prepared.json', prepared);
        return { status: 'ABANDONED_REQUALIFICATION_PREPARED_LOCK_RETAINED_SEPARATE_COMMIT_GO_REQUIRED', ordinal: options.ordinal, preparedSha256: digest, ...ABANDONED_TRUTH };
      }
      phase = 'commit-admission'; ownFence = directoryFence(path);
      need(equal(io.readdirSync(path).sort(), ['intent.json', 'prepared.json']), 'ABANDON_ATTEMPT_BLOCKED');
      const intentFile = archiveFile(join(path, 'intent.json'), 262144), preparedFile = archiveFile(join(path, 'prepared.json'), 262144), prepared = JSON.parse(preparedFile.bytes);
      need(equal(JSON.parse(intentFile.bytes), intent) && preparedFile.digest === options.prepared &&
        equal(prepared, { version: 1, kind: 'abandoned-fence-prepared-constraint', intent, preparedAt: prepared.preparedAt,
          candidate: { runtime: ownerDocker ? prepared.candidate?.runtime : failed.eligible.runtime, provenance: failed.eligible.provenance, quiescence: ownerDocker ? prepared.candidate?.quiescence : failed.eligible.quiescence,
                      ...(ownerDocker ? { restart: prepared.candidate?.restart, observationBasis: 'FRESH_PREPARE_TWO_DIRECT_GET_SAMPLES_NOT_HISTORICAL_USAGE' } : {}) }, destination: target, ...ABANDONED_TRUTH }) &&
                  (!ownerDocker || SHA.test(prepared.candidate.runtime) && prepareObservationAllowed(prepared.candidate.quiescence, failed.eligible.quiescence) && prepared.candidate.restart?.kind === 'OWNER_STARTED_DOCKER_ABANDONED_LEASE_ONLY'), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
      const preparedFresh = () => need(Number.isSafeInteger(prepared.preparedAt) && now() >= prepared.preparedAt && now() - prepared.preparedAt <= 300000, 'ABANDON_PREPARED_EXPIRED');
      // Exclusive commit intent also serializes duplicate commits of this ordinal.
      writeRecord(path, 'commit-intent.json', { version: 1, ordinal: options.ordinal, preparedSha256: options.prepared, review: options.review, ...ABANDONED_TRUTH }); own = path;
      preparedFresh();
      const disposition = { version: 1, action: 'archive-exact-abandoned-native-fence', preparedSha256: options.prepared, intent,
        candidate: prepared.candidate, destination: target, freshCommitRule: 'ACTUAL_TWO_GET_SAMPLES_AND_RUNTIME_MATCH_UNDER_BARE_SUPERVISOR_15S', ...ABANDONED_TRUTH };
      const dispositionSha256 = writeRecord(path, 'disposition.json', disposition);
      // Pin BEFORE all last slow byte/hash/schema checks, after own journal writes.
      pins = pinAbandonedPaths(root, abandonedPinPaths(root, options.selection, sourcePaths), io);
      phase = 'final-fence'; need(await getReview() === options.review, 'RECONCILE_SOURCE_CHANGED'); failed.verify(); intentFile.verify(); preparedFile.verify();
      const runtime = await prepareRuntime(root, options.selection, original, options.review, getReview, clock, ownerDocker); runtime.verify();
      pins.verify(); preparedFresh();
      lease = acquireSupervisor(root); // BEFORE any fresh runtime/GET, held until commit/uncertainty is durably recorded.
      lease.verify(); pins.verify();
      phase = 'runtime-before'; const before = await inPhase(phase, () => runtime.observe());
      phase = 'direct-http'; const quiet = structuredClone(await inPhase(phase, () => quiescence(original))), quiescenceAt = quiet.observedAt; delete quiet.observedAt;
      phase = 'runtime-after'; const after = await inPhase(phase, () => runtime.observe());
      // FAST COMMIT BOUNDARY: no await, byte reads/hash/fsync or subprocess from
      // here through rename. A stale fd alone never authenticates a current path.
      phase = 'final-fence';
      need(quietEnvelope(quiet, true) && equal(quiet, prepared.candidate.quiescence), 'ABANDON_CURRENT_OBSERVATION_CHANGED');
      need(before.digest === prepared.candidate.runtime && after.digest === before.digest && equal(before.provenance, prepared.candidate.provenance) && equal(after.provenance, before.provenance), 'ABANDON_RUNTIME_CHANGED');
      if (ownerDocker) need(equal(before.restart, prepared.candidate.restart) && equal(after.restart, before.restart), 'ABANDON_RUNTIME_CHANGED');
      directEnvironment(process.env); lease.verify(); pins.verify();
      need(!alive(original.intent.pid), 'ABANDON_ATTEMPT_BLOCKED'); preparedFresh();
      need(!io.existsSync(destination) && equal(stamp(io.lstatSync(original.lockPath)), original.lockIdentity) && equal(io.readdirSync(original.lockPath), ['native-runtime-owner.json']), 'ABANDON_PIN_CHANGED');
      phase = 'freshness'; const at = clock();
      need([quiescenceAt, after.observedAt].every(t => Number.isFinite(t) && at >= t && at - t < 15000), 'ABANDON_RUNTIME_PROOF_EXPIRED');
      phase = 'archive'; renameAttempted = true; io.renameSync(original.lockPath, destination);
      syncDirectory(path); syncDirectory(join(root, '.local-public-images'));
      need(equal(stamp(io.lstatSync(destination)), original.lockIdentity) && equal(io.readdirSync(destination), ['native-runtime-owner.json']) &&
        archiveFile(join(destination, 'native-runtime-owner.json'), 4096).digest === original.ownerDigest, 'ABANDON_ARCHIVE_UNCERTAIN');
      writeRecord(path, 'archived.json', { version: 1, ordinal: options.ordinal, preparedSha256: options.prepared, dispositionSha256,
        freshObservationsMatched: true, ...ABANDONED_TRUTH });
      return { status: 'EXACT_ABANDONED_NATIVE_FENCE_ARCHIVED_UNKNOWN_PRESERVED', ordinal: options.ordinal, dispositionSha256, ...ABANDONED_TRUTH };
    } catch (error) {
      const failure = phaseError(renameAttempted ? Error('ABANDON_ARCHIVE_UNCERTAIN') : error, phase);
      if (own) try { ownFence.verify(); writeRecord(own, 'failure.json', { version: 1, ordinal: options.ordinal, review: options.review, renameAttempted,
        originalEvidence: original.seal, firstFailure: readonlyFailure(failure), ...ABANDONED_TRUTH }); } catch { /* Incomplete/pending journal blocks ALL further attempts. */ }
      throw failure;
    } finally { try { pins?.close(); } finally { lease?.close(); } }
  };
}
function requalificationMode(args) {
  const ownerDocker = ['--prepare-abandoned-owner-docker-requalification', '--commit-abandoned-owner-docker-requalification'].includes(args[0]);
  if (ownerDocker) {
    need(args[4] === '--ack-owner-started-docker-same-containers-no-native-adoption', 'ABANDON_REQUALIFICATION_UNQUALIFIED');
    const commit = args[0] === '--commit-abandoned-owner-docker-requalification';
    const result = requalificationMode([commit ? '--commit-abandoned-requalification' : '--prepare-abandoned-requalification', ...args.slice(1, 4), ...args.slice(5)]);
    return { ...result, mode: commit ? 'abandon-requalify-docker-commit' : 'abandon-requalify-docker-prepare' };
  }
  const commit = args[0] === '--commit-abandoned-requalification';
  need(args[1] === (commit ? '--ack-new-coordinator-requalification-commit-go' : '--ack-new-coordinator-requalification-prepare-go') &&
    args[2] === '--ack-unknown-liabilities-no-provider-retry' && args[3] === '--ack-batch36-append-only-max-three', 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const names = ['--deployment', '--native-attempt', '--original-review', '--review', '--failed-review', '--failed-archive-review', '--failed-archive-evidence-sha256',
    '--failed-direct-review', '--failed-direct-evidence-sha256', '--failed-parallel-review', '--failed-parallel-evidence-sha256', '--attempt', ...(commit ? ['--prepared-sha256'] : [])];
  need(args.length === 4 + names.length * 2 && names.every((n, i) => args[4 + i * 2] === n), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const v = names.map((_, i) => args[5 + i * 2]);
  need(/^(01|02|03)$/.test(v[11]) && v.slice(3, 11).every(h => SHA.test(h)) && (!commit || SHA.test(v[12])), 'ABANDON_REQUALIFICATION_UNQUALIFIED');
  const result = { mode: commit ? 'abandon-requalify-commit' : 'abandon-requalify-prepare', selection: { deployment: v[0], attempt: v[1], originalReview: v[2] },
    review: v[3], failedReview: v[4], failedArchiveReview: v[5], failedArchiveEvidence: v[6], failedDirectReview: v[7], failedDirectEvidence: v[8],
    failedParallelReview: v[9], failedParallelEvidence: v[10], ordinal: Number(v[11]), prepared: commit ? v[12] : null };
  selectionValid(result.selection); return result;
}
function abandonedMode(args) {
  const archive = args[0] === '--archive-abandoned-native-fence', offset = archive ? 4 : 3;
  need(args[1] === (archive ? '--ack-new-coordinator-abandon-archive-go' : '--ack-new-coordinator-readonly-go') && args[2] === '--ack-unknown-liabilities-no-provider-retry' &&
    (!archive || args[3] === '--ack-exact-owned-native-fence-only'), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const names = ['--deployment', '--native-attempt', '--original-review', '--review', ...(archive ? ['--eligibility-sha256'] : [])];
  need(args.length === offset + names.length * 2 && names.every((n, i) => args[offset + i * 2] === n), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const values = names.map((_, i) => args[offset + 1 + i * 2]);
  const result = { mode: archive ? 'abandon-archive' : 'abandon-verify', selection: { deployment: values[0], attempt: values[1], originalReview: values[2] }, review: values[3], verification: archive ? values[4] : null };
  selectionValid(result.selection); need(SHA.test(result.review) && (!archive || SHA.test(result.verification)), 'EXACT_ABANDONMENT_GO_REQUIRED'); return result;
}
function failedReadonlyMode(args) {
  const diagnose = args[0] === '--diagnose-abandoned-readonly', archive = args[0] === '--archive-continued-abandoned-native-fence';
  const offset = diagnose ? 3 : 4;
  need(args[1] === (diagnose ? '--ack-new-coordinator-readonly-diagnostic-go' : archive ? '--ack-new-coordinator-abandon-archive-go' : '--ack-new-coordinator-readonly-continuation-go') &&
    args[2] === (diagnose ? '--ack-no-slot-writes-no-provider-posts' : '--ack-unknown-liabilities-no-provider-retry') &&
    (diagnose || args[3] === (archive ? '--ack-exact-owned-native-fence-only' : '--ack-preserved-incomplete-readonly-stage')), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const names = ['--deployment', '--native-attempt', '--original-review', '--review', '--failed-review', ...(archive ? ['--eligibility-sha256'] : [])];
  need(args.length === offset + names.length * 2 && names.every((name, i) => args[offset + i * 2] === name), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const values = names.map((_, i) => args[offset + 1 + i * 2]);
  const options = { mode: diagnose ? 'abandon-diagnose' : archive ? 'abandon-archive-continuation' : 'abandon-verify-continuation',
    selection: { deployment: values[0], attempt: values[1], originalReview: values[2] }, review: values[3], failedReview: values[4], ...(!diagnose ? { verification: archive ? values[5] : null } : {}) };
  selectionValid(options.selection); need(SHA.test(options.review) && SHA.test(options.failedReview) && (!archive || SHA.test(options.verification)), 'EXACT_ABANDONMENT_GO_REQUIRED'); return options;
}
function directReadonlyMode(args) {
  const parallel = ['--verify-abandoned-parallel', '--archive-abandoned-parallel'].includes(args[0]), diagnose = args[0] === '--diagnose-abandoned-direct',
    archive = ['--archive-abandoned-direct', '--archive-abandoned-parallel'].includes(args[0]), offset = diagnose ? 3 : 4;
  need(args[1] === (diagnose ? '--ack-new-coordinator-readonly-diagnostic-go' : archive ? '--ack-new-coordinator-abandon-archive-go' : parallel ? '--ack-new-coordinator-parallel-readonly-go' : '--ack-new-coordinator-direct-readonly-go') &&
    args[2] === (diagnose ? '--ack-no-slot-writes-no-provider-posts' : '--ack-unknown-liabilities-no-provider-retry') &&
    (diagnose || args[3] === (archive ? '--ack-exact-owned-native-fence-only' : parallel ? '--ack-preserved-freshness-refusal' : '--ack-preserved-failed-archive-stage')), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const names = ['--deployment', '--native-attempt', '--original-review', '--review', '--failed-review', '--failed-archive-review', '--failed-archive-evidence-sha256',
    ...(parallel ? ['--failed-direct-review', '--failed-direct-evidence-sha256'] : []), ...(archive ? ['--eligibility-sha256'] : [])];
  need(args.length === offset + names.length * 2 && names.every((name, i) => args[offset + i * 2] === name), 'EXACT_ABANDONMENT_GO_REQUIRED');
  const v = names.map((_, i) => args[offset + 1 + i * 2]), options = { mode: diagnose ? 'abandon-diagnose-direct' : parallel ? archive ? 'abandon-archive-parallel' : 'abandon-verify-parallel' : archive ? 'abandon-archive-direct' : 'abandon-verify-direct',
    selection: { deployment: v[0], attempt: v[1], originalReview: v[2] }, review: v[3], failedReview: v[4], failedArchiveReview: v[5], failedArchiveEvidence: v[6],
    ...(parallel ? { failedDirectReview: v[7], failedDirectEvidence: v[8] } : {}), ...(!diagnose ? { verification: archive ? v[parallel ? 9 : 7] : null } : {}) };
  selectionValid(options.selection); need([options.review, options.failedReview, options.failedArchiveReview, options.failedArchiveEvidence, ...(parallel ? [options.failedDirectReview, options.failedDirectEvidence] : [])].every(s => SHA.test(s)) && (!archive || SHA.test(options.verification)), 'EXACT_ABANDONMENT_GO_REQUIRED'); return options;
}
export function reconcileMode(args) {
  if (!args.length) return { mode: 'inert' };
  if (equal(args, ['--fingerprint'])) return { mode: 'fingerprint' };
  if (['--prepare-abandoned-requalification', '--commit-abandoned-requalification', '--prepare-abandoned-owner-docker-requalification', '--commit-abandoned-owner-docker-requalification'].includes(args[0])) return requalificationMode(args);
  if (['--verify-abandoned-native-fence', '--archive-abandoned-native-fence'].includes(args[0])) return abandonedMode(args);
  if (['--diagnose-abandoned-readonly', '--continue-abandoned-readonly', '--archive-continued-abandoned-native-fence'].includes(args[0])) return failedReadonlyMode(args);
  if (['--diagnose-abandoned-direct', '--verify-abandoned-direct', '--archive-abandoned-direct', '--verify-abandoned-parallel', '--archive-abandoned-parallel'].includes(args[0])) return directReadonlyMode(args);
  need(['--verify-readonly', '--reconcile-known-commits'].includes(args[0]) && args[1] === '--ack-new-coordinator-readonly-go' && args[2] === '--ack-original-wire-failed-no-provider-posts', 'EXACT_RECONCILE_GO_REQUIRED');
  const names = ['--deployment', '--native-attempt', '--original-review', '--review', '--original-evidence', '--summary-sha256', '--history-sha256', '--prior-history-sha256', '--original-mutation-id'];
  const reconcile = args[0] === '--reconcile-known-commits', offset = reconcile ? 4 : 3;
  if (reconcile) { need(args[3] === '--ack-archive-exact-native-operation-lock', 'EXACT_RECONCILE_GO_REQUIRED'); names.push('--verification-sha256'); }
  need(args.length === offset + names.length * 2 && names.every((name, i) => args[offset + i * 2] === name), 'EXACT_RECONCILE_GO_REQUIRED');
  const values = names.map((_, i) => args[offset + 1 + i * 2]);
  const options = { mode: reconcile ? 'reconcile' : 'verify', selection: { deployment: values[0], attempt: values[1], originalReview: values[2] }, review: values[3],
    anchors: { evidence: values[4], summary: values[5], history: values[6], priorHistory: values[7], mutation: values[8] }, verification: reconcile ? values[9] : null };
  selectionValid(options.selection); anchorsValid(options.anchors); need(SHA.test(options.review) && (!reconcile || SHA.test(options.verification)), 'EXACT_RECONCILE_GO_REQUIRED');
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = reconcileMode(process.argv.slice(2));
    if (options.mode === 'inert') console.log('INERT_READONLY_RECONCILIATION_NO_PRIVATE_READS_NO_NETWORK');
    else if (options.mode === 'fingerprint') console.log(await reconcileFingerprint());
    else if (['abandon-diagnose', 'abandon-diagnose-direct'].includes(options.mode)) {
      const result = await diagnoseAbandonedQuiescence(options); console.log(JSON.stringify(result)); if (result.firstFailure) process.exitCode = 1;
    }
    else if (options.mode.startsWith('abandon-requalify-')) console.log(JSON.stringify(await createAbandonedRequalification({ root: ROOT })(options)));
    else if (options.mode.startsWith('abandon-')) console.log(JSON.stringify(await createAbandonedFenceDisposer({ root: ROOT })(options)));
    else console.log(JSON.stringify(await createNativeReconciler({ root: ROOT })(options)));
  } catch (error) {
    const gaps = ['ABANDON_DEPLOYED_SHIPPED_MAP_UNAVAILABLE', 'ABANDON_DEPLOYED_SHIPPED_MAP_INVALID', 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID',
      'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNAVAILABLE', 'ABANDON_DEPLOYED_RECEIPT_CHAIN_UNQUALIFIED'];
    console.log(JSON.stringify({ status: 'REFUSED_RECONCILIATION_NO_RETRY_NO_PROVIDER_POSTS', firstFailure: readonlyFailure(error), ...(gaps.includes(error?.message) ? { provenanceGap: error.message } : {}) })); process.exitCode = 1;
  }
}
