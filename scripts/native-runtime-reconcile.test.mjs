// OFFLINE synthetic filesystem, DTOs and injected command boundaries only.
// Never call the production native/Docker/browser/private-session entry points.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { candidateSourceEquivalence, custodyCompletionReferences } from './deploy-reference-custody.mjs';
import { createNativeRuntimeObserver, NATIVE_EPOCH_FORMAT, NATIVE_REFERENCE_FORMAT } from './native-runtime-authority.mjs';
import { DEPLOY_SUPERVISOR_PROGRAM, inspectDeploySupervisor } from './deploy-supervisor.mjs';
import { captureNativeReconcileEvidence, qualifyDurableCommit, createNativeReconciler, installReadonlyRoutes, readonlyPlan, reconcileMode,
  READONLY_SLOT, EXPECTED_USED, EXPECTED_SUMMARY_DELTA, HISTORICAL_WIRE, reconcileFingerprint, RECONCILE_REVIEW_FILES, verifyReadonlyDurableIo,
  ABANDONED_SLOT, ABANDONED_TRUTH, captureAbandonedEvidence, captureAbandonedDeployment, qualifyAbandonedRuntime, qualifyAbandonedQuiescence,
  verifyReadonlyQuiescentIo, createAbandonedFenceDisposer, closeReadonlyBrowser, readonlyFailure, READONLY_FAILURE_PHASES, READONLY_FAILURE_CODES,
  ABANDONED_CONTINUATION_SLOT, createAbandonedReadonlyDiagnostic, captureFailedReadonlyStage, ABANDONED_DIRECT_SLOT,
    DIRECT_GET_PATHS, DIRECT_READONLY, directGetAllowed, createAbandonedDirectQuiescence, captureFailedArchiveStage,
      ABANDONED_PARALLEL_SLOT, captureFailedFreshnessStage, captureFailedParallelStage, createAbandonedRequalification, acquireAbandonedSupervisor, pinAbandonedPaths, qualifyOwnerDockerRestart } from './native-runtime-reconcile.mjs';
import { contracts, fingerprint, SCAN, BASE, QUESTION } from '../tests-e2e/native-h7v3-paid-sol.mjs';
import { extraContracts } from '../tests-e2e/batch26-native-chat.mjs';
import { diagnosticContracts } from '../tests-e2e/native-h7v3-finite-diagnostics.mjs';
const c = { ...await diagnosticContracts(), ...await extraContracts() }, tools = await contracts();
const id = n => n.toString(16).padStart(64, '0'), uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const selection = { deployment: 'c63d2e0ce8ecdce681de307fc6e25d6f', attempt: uuid(50), originalReview: id(1) }, review = id(2);
const binding = { scanId: SCAN, digest: 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55', platform: 'linux/amd64', reportVersion: id(3) };
const createdAt = '2026-11-04T18:00:00.000Z';
const text = 'Сканер сообщил о находках; требуется проверка.';
function context() {
  return c.chat.chatContextSchema.parse({ ...binding, epoch: uuid(1), revision: 6, enabled: true, policyVersion: id(4),
    disclosure: { provider: 'OpenAI', model: 'gpt-5.4-mini-2026-03-17', monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
      retention: 'no-training', operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false,
      costBasis: c.public.OPENAI_COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1000000, output: 2000000 },
      data: c.public.REMEDIATION_SCANNER_DISCLOSURE, sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
      localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.' },
    limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response', pending: false });
}
function fixture(t) {
  const zero = { input: 0, output: 0, costMicros: 0 }, carried = { input: 7, output: 8, costMicros: 9 };
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'native-reconcile-synthetic-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const state = join(root, '.local-public-images'), audit = join(state, 'native-runtime-v1', selection.attempt), lock = join(state, '.operation.lock'), old = join(root, 'test-results/batch31-final-native-20261104');
  for (const path of [audit, lock, old]) fs.mkdirSync(path, { recursive: true, mode: 0o700 });
  const s = fs.lstatSync(lock), lockIdentity = [s.dev, s.ino, s.uid, s.mode];
  const write = (path, value) => fs.writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  const owner = { version: 1, kind: 'native-runtime-authority', project: 'dip-public-images', attempt: selection.attempt, deployment: selection.deployment,
    review: selection.originalReview, audit: 'native-runtime-v1/' + selection.attempt, lockIdentity };
  write(join(lock, 'native-runtime-owner.json'), owner);
  write(join(audit, 'intent.json'), { version: 1, kind: owner.kind, project: owner.project, attempt: owner.attempt, deployment: owner.deployment,
    review: owner.review, origin: 'http://127.0.0.1:8081', pid: 2147483647, uid: process.getuid(), createdAt, lock: '.operation.lock' });
  const phases = [['acquired', null], ['admitted', null], ['dispatch-submitted', 'summary'], ['dispatch-observed', 'summary'], ['dispatch-submitted', 'chat'], ['dispatch-observed', 'chat'], ['retained-unknown', null]];
  phases.forEach(([phase, operation], i) => write(join(audit, `${String(i + 1).padStart(4, '0')}-${phase}.json`), { version: 1, attempt: selection.attempt, phase, operation, lockIdentity }));
  write(join(old, 'attempt.spent.json'), { spent: true, deployment: selection.deployment, review: selection.originalReview, path: 'fresh-summary' });
  for (const operation of ['summary', 'chat']) write(join(old, operation + '.spent.json'), { spent: true, operation });
  const accounting = { valid: true, receiptMatched: false, receipt: 'NOT_EXPOSED_BY_SUMMARY_DTO', delta: Object.fromEntries(['user', 'scan'].map(k => [k, { used: EXPECTED_SUMMARY_DELTA, held: zero, carried: zero }])) };
  const aggregate = { status: 'BLOCKED_OR_PARTIAL', deployment: selection.deployment, review: selection.originalReview, path: 'fresh-summary',
    summaryPosts: 1, chatPosts: 1, dispatched: 2, postAttempts: 2, browserClosed: true, retainedSessionUnchanged: true, firstFailure: { phase: 'chat-capture', code: 'UNCLASSIFIED_FAILURE' },
    usageBefore: { available: true, windowStart: Date.parse('2026-11-04T00:00:00.000Z'), user: { used: zero, held: zero, carried }, scan: { used: zero, held: zero, carried } }, summaryAccounting: accounting };
  write(join(old, 'journey-aggregate.json'), aggregate); write(join(old, 'aggregate.json'), { ...aggregate, runtimeFenceReleased: false });
  const diagnostics = [{ event: 'durable-dispatch-intent', operation: 'summary' },
    { httpStatus: 200, headers: {}, headerReadFailed: false, bodyInspection: 'not-read', terminalFailureCaptured: false, usageReceiptCaptured: false },
    { httpStatus: 200, headers: {}, headerReadFailed: false, bodyInspection: 'json', terminalFailureCaptured: false, usageReceiptCaptured: false },
    { event: 'durable-dispatch-intent', operation: 'chat' },
    { httpStatus: 502, headers: {}, headerReadFailed: false, bodyInspection: 'not-read' }, { httpStatus: 502, headers: {}, headerReadFailed: false, bodyInspection: 'unavailable' }];
  write(join(old, 'diagnostics.ndjson'), diagnostics.map(v => JSON.stringify(v)).join('\n') + '\n');
  const capture = () => captureNativeReconcileEvidence(root, selection, () => false), original = capture();
  const facts = [1, 2, 3].map(n => ({ check: 'vuln', findingId: 'vuln-' + id(n), severity: 'HIGH', cveId: `CVE-2026-${1000 + n}`, identifierKind: 'cve',
    ecosystem: 'deb', severitySources: ['debian'], provenanceRef: 'target-' + id(n + 10), fixedVersionReported: false, packageName: 'libc6', installedVersion: '1.0', fixedVersion: null, advisoryState: 'unknown' }));
  const summary = { ...binding, hypotheses: [1, 2, 3, 4].map(() => ({ kind: 'hypothesis', text, citations: facts.map(v => v.findingId) })), scannerFacts: facts };
  const prior = { ...binding, epoch: uuid(1), revision: 4, pending: null, decisions: [], turns: [2, 3].map(n => ({ id: uuid(n), mutationId: uuid(n + 10), question: 'Сохранённый вопрос.', report: binding, createdAt: 1, state: 'failed' })),
    retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' };
  const history = { ...prior, revision: 6, turns: [...prior.turns, { id: uuid(4), mutationId: uuid(20), question: QUESTION, report: binding, createdAt: Date.parse(createdAt) + 1, state: 'completed',
    reply: { ...binding, kind: 'hypothesis', text, sources: facts.map(finding => ({ ...binding, finding })) } }] };
  const scope = { limits: { input: 1000000, output: 1000000, costMicros: null }, used: { ...EXPECTED_USED }, held: zero, carried,
    remaining: { input: 1000000 - EXPECTED_USED.input - carried.input, output: 1000000 - EXPECTED_USED.output - carried.output, costMicros: null }, warning: false, exhausted: false };
  const usage = { ...binding, integrationEnabled: true, quotaEnabled: true, available: true, monetaryLimit: 'uncapped', reason: 'ready',
    admission: { status: 'unavailable' }, window: { start: aggregate.usageBefore.windowStart, end: aggregate.usageBefore.windowStart + 86400000 }, signals: [], user: scope, scan: scope };
  const h = context(), first = { context: { s: h, h, r: { ...binding, localReady: true, status: 'locally-configured', blockers: [], provider: { name: 'OpenAI', model: h.disclosure.model, status: 'configured-unprobed', liveVerified: false },
    credential: 'environment-valid', accounting: 'configured', history: 'available', quota: 'available', requiresConsent: true, acceptsCredentials: false, generationVerified: false } }, summary, history, usage };
  const anchors = { evidence: original.seal, summary: fingerprint(summary), history: fingerprint(history), priorHistory: fingerprint(prior), mutation: uuid(20) };
  const corpus = new Map(facts.map(f => [f.findingId, structuredClone(f)]));
  const qualify = () => qualifyDurableCommit({ first, second: structuredClone(first), original, anchors, corpus, tools, c });
  const snapshots = [audit, old].flatMap(path => fs.readdirSync(path).map(name => ({ path: join(path, name), bytes: fs.readFileSync(join(path, name)) })));
  return { root, state, audit, lock, old, owner, capture, original, write, first, anchors, corpus, qualify, snapshots };
}
test('sealed native kind audit + current schemas verify durable product commit WITHOUT repairing HTTP502 or invoice/receipt', t => {
  const f = fixture(t), result = f.qualify();
  assert.equal(result.kind, 'durable-product-commit-not-original-wire-success'); assert.deepEqual(result.historicalWire, HISTORICAL_WIRE);
  assert.equal(result.estimates.originalChatReceipt, 'UNAVAILABLE_NOT_RECONSTRUCTED'); assert.equal(result.estimates.basis, 'server-estimated-configured-rates-not-invoice');
  assert.deepEqual(result.estimates.chatAggregateDelta, { input: 16896, output: 349, costMicros: 14243 });
  assert.equal(result.historicalLiabilities, 'PRESERVED_NOT_RECONCILED_OR_REFUNDED');
  assert.equal(JSON.stringify(result).includes(QUESTION), false); assert.equal(JSON.stringify(result).includes(text), false);
  assert.ok(fs.existsSync(f.lock)); f.original.verify();
});
for (const [name, change] of [
  ['wrong summary anchor', f => { f.anchors.summary = id(999); }], ['wrong history anchor', f => { f.anchors.history = id(999); }],
  ['missing prior anchor', f => { delete f.anchors.priorHistory; }], ['invented historical baseline', f => { f.anchors.priorHistory = id(999); }],
  ['wrong original mutation', f => { f.anchors.mutation = uuid(999); }], ['wrong evidence anchor', f => { f.anchors.evidence = id(999); }],
  ['not completed', f => { f.first.history.turns[2].state = 'failed'; }], ['pending', f => { f.first.history.pending = { turnId: uuid(4), state: 'pending' }; }],
  ['revision changed', f => { f.first.history.revision = 8; }], ['prior turn changed', f => { f.first.history.turns[0].question = 'Изменено.'; }],
  ['unknown extra completed turn', f => { f.first.history.turns.push({ ...f.first.history.turns[2], id: uuid(40), mutationId: uuid(41) }); }],
  ['missing citation', f => { f.first.history.turns[2].reply.sources.pop(); }], ['source mismatch', f => { f.first.history.turns[2].reply.sources[0].finding.provenanceRef = 'target-' + id(999); }],
  ['no four-paragraph summary', f => { f.first.summary.hypotheses.pop(); }], ['summary fact mismatch', f => { f.first.summary.scannerFacts[0].installedVersion = '2.0'; }],
  ['held liability', f => { f.first.usage.user.held.input = 1; }], ['carried liability erased', f => { f.first.usage.scan.carried.costMicros = 0; }],
  ['usage total mismatch', f => { f.first.usage.user.used.costMicros++; }], ['summary delta changed', f => { f.original.aggregate.summaryAccounting.delta.scan.used = { input: 1, output: 1, costMicros: 1 }; }],
  ['different report', f => { f.first.history.reportVersion = id(999); }], ['before native attempt', f => { f.first.history.turns[2].createdAt = 1; }],
]) test(`current durable proof refuses ${name}; original lock/failed evidence untouched`, t => {
  const f = fixture(t); change(f); assert.throws(f.qualify); assert.ok(fs.existsSync(f.lock));
  for (const s of f.snapshots) assert.deepEqual(fs.readFileSync(s.path), s.bytes);
});
for (const [name, change] of [
  ['completed request must really match original mutation', f => { f.anchors.mutation = uuid(999); }],
  ['retained historical rows must match pinned baseline', f => { f.anchors.priorHistory = id(999); }],
  ['three actual citations required', f => { f.first.history.turns[2].reply.sources.pop(); }],
  ['native source projection must match', f => { f.corpus.get(f.first.summary.scannerFacts[0].findingId).installedVersion = '2.0'; }],
  ['not before original dispatch audit', f => { f.first.history.turns[2].createdAt = 1; }],
  ['accounting must preserve old carried liabilities', f => { f.first.usage.user.carried.costMicros = 0; }],
]) test(`even current hash pins cannot waive mandatory proof: ${name}`, t => {
  const f = fixture(t); change(f);
  f.anchors.summary = fingerprint(f.first.summary); f.anchors.history = fingerprint(f.first.history);
  assert.throws(f.qualify); assert.ok(fs.existsSync(f.lock));
});
function readonlyIo(f, calls, summaryStatus = 200) {
  const copy = value => structuredClone(value);
  return { preflight: async () => { calls.push('preflight'); return { ...copy(f.first.context), history: copy(f.first.history) }; },
    corpus: async () => { calls.push('corpus'); return f.corpus; }, current: async () => { calls.push('current'); return copy(f.first.context); },
    summaryRead: async () => { calls.push('summary-get'); return { status: summaryStatus, value: copy(f.first.summary) }; },
    history: async () => { calls.push('history-get'); return copy(f.first.history); }, usage: async () => { calls.push('usage-get'); return copy(f.first.usage); },
    summaryVisible: async () => { calls.push('summary-visible'); }, chatVisible: async () => { calls.push('chat-visible'); },
    generate: async () => assert.fail('no generation'), paidSummary: async () => assert.fail('no paid summary'), paidChat: async () => assert.fail('no paid chat'),
    reload: async () => assert.fail('no autorefresh'), disableAutomation: async () => assert.fail('no preference mutation') };
}
test('actual verifier IO flow takes two GET-only samples and UI reads; no generation, reload or preference writes', async t => {
  const f = fixture(t), calls = [];
  const proof = await verifyReadonlyDurableIo(readonlyIo(f, calls), f.original, f.anchors, tools, c);
  assert.equal(proof.historyHash, f.anchors.history);
  assert.deepEqual(calls, ['preflight', 'corpus', 'summary-get', 'history-get', 'usage-get', 'current', 'summary-get', 'history-get', 'usage-get', 'summary-visible', 'chat-visible']);
});
for (const status of [404, 502]) test(`GET summary HTTP${status} cannot be reclassified successful even with a valid-looking DTO`, async t => {
  const f = fixture(t), calls = [];
  await assert.rejects(verifyReadonlyDurableIo(readonlyIo(f, calls, status), f.original, f.anchors, tools, c), /READONLY_SUMMARY_HTTP_UNQUALIFIED/);
  assert.deepEqual(calls, ['preflight', 'corpus', 'summary-get']); assert.ok(fs.existsSync(f.lock));
});
test('second authenticated GET must match the entire first current proof', t => {
  const f = fixture(t), second = structuredClone(f.first); second.history.revision = 8;
  assert.throws(() => qualifyDurableCommit({ first: f.first, second, original: f.original, anchors: f.anchors, corpus: f.corpus, tools, c }), /CURRENT_GET_PROOF_CHANGED/);
});
for (const attack of ['owner-nonce', 'owner-review', 'owner-origin', 'foreign-file', 'duplicate-operation', 'missing-observed', 'old-aggregate-pass', 'wrong-spent', 'wire-was-not502', 'unavailable-header-read', 'audit-byte-drift', 'audit-replaced', 'owner-symlink']) test(`exact original audit refuses ${attack}`, t => {
  const f = fixture(t), ownerFile = join(f.lock, 'native-runtime-owner.json');
  if (attack.startsWith('owner-') && attack !== 'owner-symlink') { const owner = { ...f.owner }; owner[attack === 'owner-nonce' ? 'attempt' : attack === 'owner-review' ? 'review' : 'kind'] = 'foreign'; f.write(ownerFile, owner); }
  if (attack === 'foreign-file') f.write(join(f.lock, 'deploy-adapter-owner.json'), {});
  if (attack === 'duplicate-operation') f.write(join(f.audit, '0008-dispatch-submitted.json'), { operation: 'chat' });
  if (attack === 'missing-observed') fs.unlinkSync(join(f.audit, '0006-dispatch-observed.json'));
  if (attack === 'old-aggregate-pass') { const p = join(f.old, 'aggregate.json'), value = JSON.parse(fs.readFileSync(p)); value.status = 'PASS'; f.write(p, value); }
  if (attack === 'wrong-spent') f.write(join(f.old, 'chat.spent.json'), { spent: false, operation: 'chat' });
  if (attack === 'wire-was-not502' || attack === 'unavailable-header-read') {
    const p = join(f.old, 'diagnostics.ndjson'), rows = fs.readFileSync(p, 'utf8').trim().split('\n').map(JSON.parse);
    if (attack === 'wire-was-not502') rows[5].httpStatus = 200; else rows[5].headerReadFailed = true;
    f.write(p, rows.map(v => JSON.stringify(v)).join('\n') + '\n');
  }
  if (attack === 'audit-byte-drift' || attack === 'audit-replaced') {
    const p = join(f.audit, '0003-dispatch-submitted.json');
    if (attack === 'audit-byte-drift') fs.appendFileSync(p, ' '); else { fs.renameSync(p, p + '.old'); fs.copyFileSync(p + '.old', p); }
    assert.throws(f.original.verify); return;
  }
  if (attack === 'owner-symlink') { fs.renameSync(ownerFile, ownerFile + '.old'); fs.symlinkSync(ownerFile + '.old', ownerFile); }
  assert.throws(f.capture);
});
test('live original process can never be reconciled or adopted', t => {
  const f = fixture(t); assert.throws(() => captureNativeReconcileEvidence(f.root, selection, () => true), /ORIGINAL_PROCESS_STILL_ALIVE/);
});
function workflow(f, overrides = {}) {
  const state = { reads: 0, runtime: 0, reviews: 0, clock: 0 };
  const run = createNativeReconciler({ root: f.root, capture: () => f.capture(), getReview: async () => { state.reviews++; return review; },
    runtime: async () => { state.runtime++; return { digest: id(500), verify: f.original.verify }; },
    durable: async () => { state.reads++; return { ...f.qualify(), readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } }; },
    now: () => Date.parse('2026-11-04T18:01:00.000Z'), clock: () => state.clock, ...overrides });
  const options = { mode: 'verify', selection, anchors: f.anchors, review, verification: null };
  return { run, state, options, slot: join(f.root, READONLY_SLOT) };
}
test('two explicit stages: readonly verification retains hold; fresh exact reconciliation archives ONLY its whole lock and never modifies old evidence', async t => {
  const f = fixture(t), w = workflow(f), ownerBytes = fs.readFileSync(join(f.lock, 'native-runtime-owner.json'));
  const verified = await w.run(w.options); assert.ok(fs.existsSync(f.lock)); assert.equal(w.state.reads, 1); assert.equal(w.state.runtime, 2);
  assert.match(verified.status, /LOCK_RETAINED/); f.original.verify();
  const done = await w.run({ ...w.options, mode: 'reconcile', verification: verified.verificationSha256 });
  assert.equal(done.paidRetryAuthorized, false); assert.equal(fs.existsSync(f.lock), false);
  const archived = join(w.slot, 'reconciled-operation.lock'); assert.deepEqual(fs.readFileSync(join(archived, 'native-runtime-owner.json')), ownerBytes);
  assert.deepEqual(fs.readdirSync(archived), ['native-runtime-owner.json']);
  for (const s of f.snapshots) assert.deepEqual(fs.readFileSync(s.path), s.bytes);
  const disposition = JSON.parse(fs.readFileSync(join(w.slot, 'disposition.json')));
  assert.equal(disposition.originalWire, 'FAILED_NOT_REPAIRED'); assert.equal(disposition.oldAggregate, 'IMMUTABLE_FAILED');
  assert.equal(JSON.stringify(disposition).includes(QUESTION), false); assert.equal(JSON.stringify(disposition).includes(text), false);
  await assert.rejects(w.run({ ...w.options, mode: 'reconcile', verification: verified.verificationSha256 }));
});
for (const attack of ['wrong-proof-hash', 'stale-proof', 'new-history', 'new-runtime', 'source-changed', 'staged-tamper', 'expired-runtime', 'proof-replaced']) test(`reconciliation refuses ${attack} and retains exact original hold`, async t => {
  const f = fixture(t), first = workflow(f), verified = await first.run(first.options);
  let reads = 0, runtimes = 0, reviews = 0, clock = 0;
  const overrides = { getReview: async () => {
    reviews++;
    if (attack === 'staged-tamper' && reviews === 3) fs.appendFileSync(join(first.slot, 'disposition.json'), ' ');
    if (attack === 'expired-runtime' && reviews === 3) clock = 15000;
    return attack === 'source-changed' && reviews > 1 ? id(999) : review;
  }, runtime: async () => { runtimes++; return { digest: attack === 'new-runtime' && runtimes === 2 ? id(999) : id(500), verify: f.original.verify }; },
  durable: async () => { reads++; const product = { ...f.qualify(), readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } }; if (attack === 'new-history') product.historyHash = id(999); return product; },
  now: () => Date.parse(attack === 'stale-proof' ? '2026-11-04T18:06:00.001Z' : '2026-11-04T18:02:00.000Z'), clock: () => clock };
  if (attack === 'proof-replaced') { const p = join(first.slot, 'verification.json'); fs.appendFileSync(p, ' '); }
  const w = workflow(f, overrides);
  await assert.rejects(w.run({ ...w.options, mode: 'reconcile', verification: attack === 'wrong-proof-hash' ? id(999) : verified.verificationSha256 }));
  assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(w.slot, 'released.json')), false);
  assert.ok(reads <= 1); f.original.verify();
});
test('serialized success, factory, path or alternate authority cannot bypass fixed production inputs', async t => {
  const f = fixture(t), w = workflow(f);
  for (const extra of [{ passed: true }, { durable: () => ({ passed: true }) }, { path: '/other' }, { authority: { validated: true } }])
    await assert.rejects(w.run({ ...w.options, ...extra }), /EXACT_RECONCILE_GO_REQUIRED/);
  assert.equal(fs.existsSync(w.slot), false); assert.ok(fs.existsSync(f.lock));
});
test('a success boolean without fresh typed durable GET qualification never reconciles', async t => {
  const f = fixture(t), w = workflow(f, { durable: async () => ({ passed: true }) });
  await assert.rejects(w.run(w.options), /READONLY_PRODUCT_PROOF_REQUIRED/);
  assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(w.slot, 'verification.json')), false);
});
test('post-rename I/O failure preserves archived owner and durable disposition, never rolls back/retries or changes old records', async t => {
  const f = fixture(t), first = workflow(f), verified = await first.run(first.options); let renames = 0;
  const io = { ...fs, renameSync(from, to) { renames++; fs.renameSync(from, to); throw Error('SYNTHETIC_IO_UNCERTAIN'); } };
  const w = workflow(f, { io }); await assert.rejects(w.run({ ...w.options, mode: 'reconcile', verification: verified.verificationSha256 }));
  assert.equal(renames, 1); assert.ok(fs.existsSync(join(w.slot, 'reconciled-operation.lock/native-runtime-owner.json')));
  assert.ok(fs.existsSync(join(w.slot, 'disposition.json'))); assert.equal(fs.existsSync(join(w.slot, 'released.json')), false);
  for (const s of f.snapshots) assert.deepEqual(fs.readFileSync(s.path), s.bytes);
});
test('readonly route refuses all POST/translation/scan creation/events/foreign/redirect shapes', () => {
  const origin = 'http://127.0.0.1:8081';
  for (const method of ['POST', 'PATCH', 'DELETE', 'PUT', 'HEAD']) assert.equal(readonlyPlan(origin + BASE + '/llm/chat', method), 'deny');
  for (const url of [origin + BASE + '/llm/translation', origin + BASE + '/events', 'http://127.0.0.1:8080' + BASE, 'https://foreign.invalid/', origin + '/api/v1/auth/login']) assert.equal(readonlyPlan(url, 'GET'), 'deny');
  assert.equal(readonlyPlan(origin + BASE + '/llm/history', 'GET'), 'read'); assert.equal(readonlyPlan(origin + BASE + '/llm/history', 'GET', true), 'deny');
});
test('installed READONLY route forwards only original GET with no follow/retry and never calls any POST transport', async () => {
  let handler; const guard = { requests: 0, denied: 0, nonGet: 0, stopped: false };
  await installReadonlyRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, guard);
  let sends = 0, aborts = 0, fulfills = 0;
  const url = 'http://127.0.0.1:8081' + BASE + '/llm/history';
  const route = method => ({ request: () => ({ method: () => method, url: () => url, redirectedFrom: () => null }),
    fetch: async options => { sends++; assert.deepEqual(options, { maxRedirects: 0, maxRetries: 0, timeout: 15000 }); return { status: () => 200, url: () => url, dispose: async () => {} }; },
    fulfill: async () => { fulfills++; }, abort: async () => { aborts++; } });
  await handler(route('GET')); await handler(route('POST')); await handler(route('POST'));
  assert.equal(sends, 1); assert.equal(fulfills, 1); assert.equal(aborts, 2); assert.equal(guard.nonGet, 2); assert.equal(guard.stopped, true);
});
// Preserved pre-fix installed handler: context shutdown rejected its in-flight
// GET and catch counted a transport denial. This is an offline counterexample,
// not attribution of the coordinator's still-undiagnosed actual refusal.
async function oldReadonlyRoutes(context, guard) {
  await context.route('**/*', async route => {
    const request = route.request(); let response;
    const deny = async () => { guard.denied++; guard.stopped = true; await route.abort().catch(() => {}); };
    if (request.method() !== 'GET') guard.nonGet++;
    if (guard.stopped || ++guard.requests > 240 || readonlyPlan(request.url(), request.method(), !!request.redirectedFrom()) !== 'read') return deny();
    try {
      response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15000 });
      const status = response.status();
      assert.ok(!guard.stopped && Number.isInteger(status) && status >= 200 && status <= 599 && !(status >= 300 && status < 400) && response.url() === request.url());
      await route.fulfill({ response });
    } catch { await deny(); } finally { await response?.dispose().catch(() => {}); }
  });
}
async function closingGet(install) {
  let handler, reject, pending, browserClosed = false;
  const guard = { requests: 0, denied: 0, nonGet: 0, pageErrors: 0, stopped: false };
  const context = { route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {}, close: async () => { reject(Error('PRIVATE_TRANSPORT_TEXT')); await pending; } };
  await install(context, guard);
  pending = handler({ request: () => ({ method: () => 'GET', url: () => 'http://127.0.0.1:8081' + BASE + '/llm/history', redirectedFrom: () => null }),
    fetch: () => new Promise((_, r) => { reject = r; }), fulfill: async () => assert.fail('cancelled GET is not success'), abort: async () => {} });
  let failure;
  try { await closeReadonlyBrowser(context, { close: async () => { browserClosed = true; } }, guard); } catch (error) { failure = readonlyFailure(error); }
  return { guard, failure, browserClosed };
}
test('actual installed GET route close cancellation reproduces old false denial and quiesced cleanup fixes only that cancellation', async () => {
  const old = await closingGet(oldReadonlyRoutes); assert.equal(old.guard.denied, 1); assert.ok(old.failure);
  const fixed = await closingGet(installReadonlyRoutes); assert.equal(fixed.guard.denied, 0); assert.equal(fixed.failure, undefined); assert.equal(fixed.browserClosed, true);
});
test('quiescence never hides forbidden requests, redirects, preexisting route failures or cleanup failure', async () => {
  for (const kind of ['POST', 'foreign', 'redirect']) {
    let handler; const guard = { requests: 0, denied: 0, nonGet: 0, pageErrors: 0, closing: true, stopped: true };
    await installReadonlyRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, guard);
    await handler({ request: () => ({ method: () => kind === 'POST' ? 'POST' : 'GET', url: () => kind === 'foreign' ? 'https://foreign.invalid/' : 'http://127.0.0.1:8081' + BASE + '/llm/history', redirectedFrom: () => kind === 'redirect' ? {} : null }),
      fetch: async () => assert.fail('no shutdown transport'), fulfill: async () => assert.fail(), abort: async () => {} });

    assert.equal(guard.denied, 1); await assert.rejects(closeReadonlyBrowser(null, null, guard));
  }
  let handler, resolve; const guard = { requests: 0, denied: 0, nonGet: 0, pageErrors: 0, stopped: false }, url = 'http://127.0.0.1:8081' + BASE + '/llm/history';
  const context = { route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {}, close: async () => { resolve({ status: () => 302, url: () => url, dispose: async () => {} }); await pending; } };
  await installReadonlyRoutes(context, guard);
  const pending = handler({ request: () => ({ method: () => 'GET', url: () => url, redirectedFrom: () => null }), fetch: () => new Promise(r => { resolve = r; }), fulfill: async () => assert.fail(), abort: async () => {} });
  await assert.rejects(closeReadonlyBrowser(context, { close: async () => { throw Error('PRIVATE_CLOSE_TEXT'); } }, guard));
  assert.equal(guard.denied, 1); assert.deepEqual(readonlyFailure(guard.firstFailure), { phase: 'routes', code: 'READONLY_ROUTE_REFUSED' });
  const preexisting = guard.firstFailure;
  await assert.rejects(closeReadonlyBrowser(null, { close: async () => { throw Error('PRIVATE_CLOSE_TEXT'); } }, guard), error => error === preexisting);
  await assert.rejects(closeReadonlyBrowser({ close: async () => { throw Error('PRIVATE_CLOSE_TEXT'); } }, null,
    { stopped: false, denied: 0, nonGet: 0, pageErrors: 0 }), error => {
    assert.deepEqual(readonlyFailure(error), { phase: 'cleanup', code: 'READONLY_CLEANUP_FAILED' }); return true;
  });
});
test('strict CLI needs distinct readonly/reconciliation GO, exact owner and hash anchors; no arbitrary path/factory/success assertion', () => {
  assert.equal(reconcileMode([]).mode, 'inert'); assert.equal(reconcileMode(['--fingerprint']).mode, 'fingerprint');
  const args = ['--verify-readonly', '--ack-new-coordinator-readonly-go', '--ack-original-wire-failed-no-provider-posts', '--deployment', selection.deployment,
    '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review, '--original-evidence', id(5), '--summary-sha256', id(6),
    '--history-sha256', id(7), '--prior-history-sha256', id(8), '--original-mutation-id', uuid(20)];
  assert.equal(reconcileMode(args).mode, 'verify');
  assert.equal(reconcileMode(['--reconcile-known-commits', ...args.slice(1, 3), '--ack-archive-exact-native-operation-lock', ...args.slice(3), '--verification-sha256', id(9)]).mode, 'reconcile');
  assert.throws(() => reconcileMode(['--reconcile-known-commits', ...args.slice(1), '--verification-sha256', id(9)]));
  for (let i = 0; i < args.length; i++) { const changed = [...args]; changed[i] = 'wrong'; assert.throws(() => reconcileMode(changed)); }
  for (const extra of ['--retry-paid', '--unlock', '--path', '--passed', '--authority']) assert.throws(() => reconcileMode([...args, extra]));
});
// Real fixed reader/seals + actual producer's candidateSourceEquivalence shape.
// The historical full map exists only in this fixture producer; the reader gets
// precisely the sealed shipped subset/commitment that production retains.
function deploymentFixture(f, changeSource = () => {}) {
  const digest = v => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v)).digest('hex');
  const roles = ['api', 'auth-volume-init', 'egress', 'llm-egress', 'openai-egress', 'scan-volume-init', 'web', 'worker'];
  const parent = join(f.state, 'deploy-adapter-v1'), originNonce = 'e'.repeat(32), retainedNonce = 'c'.repeat(32), targets = ['api', 'web'];
  const created = '2026-11-04T00:59:00.000Z', started = '2026-11-04T01:00:00.000Z', migration = 'history-reservations-v4-to-v5';
  const old = roles.map((role, n) => ({ role, id: id(n + 1), image: 'sha256:' + id(n + 1), startedAt: started }));
  const retained = { version: 2, project: 'dip-public-images', nonce: retainedNonce, outcome: 'published', references: targets.map(name => ({ name,
    tag: `dip-deploy-${name}:candidate-${retainedNonce}`, image: old.find(v => v.role === name).image })) };
  const retainedOrigin = { kind: 'adapter-completion', nonce: retainedNonce, sha256: digest(retained) };
  const oldCustody = { version: 1, old: retained.references.map(row => ({ ...row, ownership: 'borrowed', origin: retainedOrigin })),
    candidates: targets.map(name => ({ name, tag: `dip-deploy-${name}:candidate-${originNonce}` })) };
  const candidates = Object.fromEntries(targets.map((name, n) => [name, { image: 'sha256:' + id(n + 21), tag: oldCustody.candidates[n].tag,
    oldImage: oldCustody.old[n].image, oldTag: oldCustody.old[n].tag }]));
  const sourceFiles = ['package.json', 'server/api/package.json', 'server/deploy/openai-api.Dockerfile', 'server/api/src/main.ts', 'src/app.tsx', 'server/runtime/src/contract.ts', '.dockerignore', 'scripts/public-llm-stand.mjs']
    .map((path, n) => ({ path, digest: id(n + 600) }));
  const fullSource = digest(sourceFiles), currentEntries = [921, 922, 923, 924, 925, 926, 927].map(id), originalEntries = [911, 912, 913, 914, 915, 916, 917].map(id);
  const originalIntent = { version: 2, kind: 'preserving-deployment', project: 'dip-public-images', nonce: originNonce, mode: 'app', services: targets,
    lifecycle: false, source: fullSource, adapter: id(901), entrySources: originalEntries, backendSource: id(820), daemon: 'daemon:synthetic',
    old: targets.map(role => { const row = old.find(v => v.role === role); return { role, id: row.id, image: row.image }; }), referenceCustody: oldCustody };
  const originalBuilt = { version: 1, nonce: originNonce, outcome: 'candidate-built-old-site-unchanged', candidates, lifecycle: false, referenceCustody: oldCustody };
  const originalRecovery = { version: 2, nonce: originNonce, project: originalIntent.project, daemon: originalIntent.daemon, services: targets, old,
    migration: false, historyVersion: 4, historyMigration: migration, referenceCustody: oldCustody };
  const oldFiles = { 'intent.json': originalIntent, 'built.json': originalBuilt, 'recovery.json': originalRecovery, 'reference-custody.json': oldCustody,
    'failure-preparerecovery.json': { code: 'JOURNAL_SIZE' }, 'engine.jsonl': JSON.stringify({ seq: 1, state: 'submitted', code: 'CANDIDATE_IMAGE_INSPECT_FAILED' }) + '\n' + JSON.stringify({ seq: 1, state: 'settled', exit: 0 }) + '\n' };
  const evidence = files => Object.entries(files).map(([path, v]) => ({ path, bytes: Buffer.byteLength(typeof v === 'string' ? v : JSON.stringify(v)), sha256: digest(v) }));
  const originalComplete = { version: 3, project: originalIntent.project, nonce: originNonce, outcome: 'pre-mutation-aborted', referenceCustody: oldCustody,
    ...custodyCompletionReferences(oldCustody, originNonce, candidates), evidence: evidence(oldFiles) };
  const origin = { kind: 'adapter-completion', nonce: originNonce, sha256: digest(originalComplete) };
  const custody = { version: 2, old: oldCustody.old, candidates: targets.map(name => ({ name, tag: candidates[name].tag, image: candidates[name].image, ownership: 'borrowed', origin })) };
  const source = candidateSourceEquivalence({ originalSource: fullSource, files: sourceFiles, originalAdapter: originalIntent.adapter, originalEntrySources: originalEntries,
    currentAdapter: id(902), currentEntrySources: currentEntries }); changeSource(source);
  const reuseFields = { referenceCustody: custody, candidateReuse: source, reuseOrigin: origin };
  const intent = { ...originalIntent, nonce: selection.deployment, adapter: id(902), entrySources: currentEntries, ...reuseFields };
  const built = { ...originalBuilt, nonce: selection.deployment, ...reuseFields };
  const recovery = { ...originalRecovery, nonce: selection.deployment, interruptedServices: ['api', 'web', 'worker'], ...reuseFields };
  const starts = Object.fromEntries(targets.map((role, n) => [role, { role, id: id(n + 21), image: candidates[role].image, startedAt: started }]));
  starts.worker = { ...old.find(v => v.role === 'worker'), startedAt: '2026-11-04T01:00:30.000Z' };
  const proof = { version: 1, migration, from: 4, to: 5, before: id(201), after: id(202), allRowsPreserved: true };
  const before = { historyVersion: 4, llm: { history: proof.before } }, after = { historyVersion: 5, llm: { history: proof.after } };
  const published = { version: 2, project: intent.project, nonce: intent.nonce, mode: 'app', services: targets, healthy: true, verified: false,
    completedAt: '2026-11-04T01:01:00.000Z', migration: false, historyMigration: migration, historyProof: proof, stores: after,
    interruptedServices: ['api', 'web', 'worker'], pins: { services: Object.fromEntries(roles.map(name => [name, { image: (starts[name] ?? old.find(v => v.role === name)).image }])) }, ...reuseFields };
  const files = { 'intent.json': intent, 'built.json': built, 'recovery.json': recovery, 'published.json': published, 'reference-custody.json': custody,
    'candidate-reuse.json': { version: 1, origin, source, qualification: { typescript: true, bundle: true, openai: true }, referenceCustody: custody },
    'authority-v3.json': { version: 3, project: intent.project, nonce: intent.nonce, authority: { containers: old.map(v => ({ role: v.role, Id: v.id, Image: v.image,
      Created: created, process: [started, '', !v.role.endsWith('volume-init'), v.role.endsWith('volume-init') ? 'exited' : 'running', v.role.endsWith('volume-init') ? 0 : 100, 0, 0] })) } },
    'history-migration-intent.json': { version: 1, migration, from: 4, to: 5, source: fullSource, candidateImage: candidates.api.image, expected: proof, baseline: before },
    'history-migration-complete.json': { version: 1, candidateImage: candidates.api.image, proof, before, after },
    ...Object.fromEntries(Object.entries(starts).map(([name, row]) => [`start-${name}-complete.json`, row])) };
  const complete = { version: 4, project: intent.project, nonce: intent.nonce, outcome: 'published', ...reuseFields,
    ...custodyCompletionReferences(custody, intent.nonce, candidates), evidence: evidence(files) };
  function save(nonce, values) {
    const path = join(parent, nonce); fs.mkdirSync(join(path, 'operation.lock'), { recursive: true, mode: 0o700 });
    for (const [name, value] of Object.entries(values)) f.write(join(path, name), value);
    f.write(join(path, 'operation.lock/deploy-adapter-owner.json'), { version: 2, nonce, kind: 'preserving-deployment' });
  }
  save(retainedNonce, { 'complete.json': retained }); save(originNonce, { ...oldFiles, 'complete.json': originalComplete }); save(selection.deployment, { ...files, 'complete.json': complete });
  const captured = () => captureAbandonedDeployment(f.root, selection), result = captured;
  const peers = Object.fromEntries(roles.map(name => [name, starts[name] ?? old.find(v => v.role === name)]));
  const refs = [...complete.references, ...complete.borrowedReferences];
  const observed = { status: { version: 1, project: intent.project, origin: 'http://127.0.0.1:8081', hold: true, reason: 'SHARED_OPERATION_HOLD', daemon: intent.daemon,
    services: roles.map(name => ({ name, id: peers[name].id, image: peers[name].image, running: !name.endsWith('volume-init'), healthy: !name.endsWith('volume-init'), restartCount: 0 })) },
  epochs: roles.map(name => ({ name, id: peers[name].id, image: peers[name].image, created, startedAt: peers[name].startedAt, pid: name.endsWith('volume-init') ? 0 : 100, restartCount: 0 })),
  referenceImages: refs.map(row => ({ image: row.image, tags: [row.tag] })) };
  return { capture: result, observed, directory: join(parent, selection.deployment), originalDirectory: join(parent, originNonce), source, files, complete };
}
function abandonWorkflow(f, deployment, overrides = {}) {
  const state = { runtime: 0, reads: 0, reviews: 0, clock: 0 };
  const run = createAbandonedFenceDisposer({ root: f.root, capture: () => captureAbandonedEvidence(f.root, selection, () => false),
    getReview: async () => { state.reviews++; return review; },
    runtime: async () => { state.runtime++; const { records, receipt } = deployment.capture();
      return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: state.clock, verify: () => { records.verify(); f.original.verify(); } }; },
    quiescence: async () => { state.reads++; return { ...qualifyAbandonedQuiescence(f.first, structuredClone(f.first), c), observedAt: state.clock, readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } }; },
    clock: () => state.clock, now: () => Date.parse('2026-11-04T18:02:00.000Z'), ...overrides });
  return { run, state, slot: join(f.root, ABANDONED_SLOT), options: { mode: 'abandon-verify', selection, review, verification: null } };
}
test('abandonment independently reads sealed source-map/image chain despite intentionally different working tree and original tool review', t => {
  const f = fixture(t), deployment = deploymentFixture(f);
  fs.mkdirSync(join(f.root, 'src')); f.write(join(f.root, 'src/app.tsx'), 'INTENTIONALLY_CHANGED_DELIVERY');
  const { records, receipt } = deployment.capture();
  assert.equal(receipt.provenance.currentWorkingTreeEqualsDeployed, 'NOT_CLAIMED'); assert.equal(receipt.provenance.fullSourceDigestRecomputed, false);
  assert.equal(receipt.provenance.shippedMapSha256, deployment.source.shippedSource);
  assert.match(qualifyAbandonedRuntime(deployment.observed, receipt), /^[a-f0-9]{64}$/); records.verify();
  assert.notEqual(selection.originalReview, review); assert.ok(fs.existsSync(f.lock));
});
for (const [name, mutate, code] of [
  ['missing map', s => { delete s.shippedFiles; }, 'ABANDON_DEPLOYED_SHIPPED_MAP_UNAVAILABLE'],
  ['missing map commitment', s => { delete s.shippedSource; }, 'ABANDON_DEPLOYED_SHIPPED_MAP_UNAVAILABLE'],
  ['wrong map hash', s => { s.shippedSource = id(999); }, 'ABANDON_DEPLOYED_SHIPPED_MAP_INVALID'],
  ['unknown map path', s => { s.shippedFiles[0].path = '.local-public-images/private'; }, 'ABANDON_DEPLOYED_SHIPPED_MAP_INVALID'],
  ['original source mismatch', s => { s.originalSource = id(999); }, 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID'],
  ['orchestration mismatch', s => { s.currentEntrySources = [id(999)]; }, 'ABANDON_DEPLOYED_SOURCE_CHAIN_INVALID'],
]) test(`abandonment provenance reports precise gap/invalidity: ${name}`, t => {
  const f = fixture(t), deployment = deploymentFixture(f, mutate);
  assert.throws(deployment.capture, { message: code }); assert.ok(fs.existsSync(f.lock));
});
test('unsealed or missing source-chain file is refused, never replaced by caller/current-tree hashes', t => {
  const f = fixture(t), deployment = deploymentFixture(f), path = join(deployment.directory, 'candidate-reuse.json');
  fs.appendFileSync(path, ' '); assert.throws(deployment.capture, /ABANDON_DEPLOYED_RECEIPT_CHAIN_UNQUALIFIED/);
  fs.unlinkSync(path); assert.throws(deployment.capture, /ABANDON_DEPLOYED_RECEIPT_CHAIN_UNAVAILABLE/);
});
for (const [name, file, change] of [
  ['publication commitment differs', 'published.json', value => { value.candidateReuse.currentSource = id(999); }],
  ['publication image differs', 'published.json', value => { value.pins.services.api.image = 'sha256:' + id(999); }],
  ['migration rows not preserved', 'history-migration-complete.json', value => { value.proof.allRowsPreserved = false; }],
  ['recorded preflight image differs', 'authority-v3.json', value => { value.authority.containers[2].Image = 'sha256:' + id(999); }],
]) test(`a recomputed file seal cannot waive semantic deployed provenance: ${name}`, t => {
  const f = fixture(t), deployment = deploymentFixture(f), value = structuredClone(deployment.files[file]); change(value);
  f.write(join(deployment.directory, file), value);
  const bytes = fs.readFileSync(join(deployment.directory, file)), complete = structuredClone(deployment.complete);
  complete.evidence = complete.evidence.map(row => row.path === file ? { path: file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') } : row);
  f.write(join(deployment.directory, 'complete.json'), complete);
  assert.throws(deployment.capture, /ABANDON_DEPLOYED_/); assert.ok(fs.existsSync(f.lock));
});
for (const attack of ['image', 'tag', 'epoch', 'retained-created', 'daemon']) test(`abandonment runtime refuses ${attack} drift`, t => {
  const f = fixture(t), deployment = deploymentFixture(f), { receipt } = deployment.capture();
  if (attack === 'image') deployment.observed.epochs[0].image = 'sha256:' + id(999);
  if (attack === 'tag') deployment.observed.referenceImages[0].tags = [];
  if (attack === 'epoch') deployment.observed.epochs[0].startedAt = '2026-11-04T02:00:00.000Z';
  if (attack === 'retained-created') deployment.observed.epochs[2].created = '2026-11-04T00:58:00.000Z';
  if (attack === 'daemon') deployment.observed.status.daemon = 'other';
  assert.throws(() => qualifyAbandonedRuntime(deployment.observed, receipt)); assert.ok(fs.existsSync(f.lock));
});
test('sealed completion4 provenance composes with existing production observer commands, never a caller runtime-success assertion', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), { records, receipt } = deployment.capture(), calls = [];
  const observe = createNativeRuntimeObserver(async () => deployment.observed.status, async (args, options) => {
    calls.push(args); assert.equal(options.timeout, 10000); assert.equal(options.root, f.root);
    if (args[0] === 'context') return JSON.stringify('unix:///synthetic-readonly/docker.sock');
    assert.equal(options.env.DOCKER_HOST, 'unix:///synthetic-readonly/docker.sock');
    if (args[0] === 'info') return JSON.stringify(receipt.daemon);
    if (args[0] === 'container') {
      assert.deepEqual(args, ['container', 'inspect', ...Object.keys(receipt.expected).map(name => `dip-public-images-${name}-1`), '--format', NATIVE_EPOCH_FORMAT]);
      return deployment.observed.epochs.map(v => JSON.stringify(v)).join('\n');
    }
    assert.deepEqual(args, ['image', 'inspect', ...receipt.references.map(v => v.tag), '--format', NATIVE_REFERENCE_FORMAT]);
    return deployment.observed.referenceImages.map(v => JSON.stringify(v)).join('\n');
  }, f.root, '/synthetic-readonly');
  const actual = await observe(receipt);
  assert.equal(qualifyAbandonedRuntime(actual, receipt), qualifyAbandonedRuntime(deployment.observed, receipt)); records.verify();
  assert.deepEqual(calls.map(v => v[0]), ['context', 'info', 'container', 'image', 'info']);
  assert.ok(fs.existsSync(f.lock));
});
test('abandonment quiescence needs no historical anchors, permits unchanged nonzero carried liabilities and never calls product/generation/reload flows', async t => {
  const f = fixture(t), calls = [], io = readonlyIo(f, calls);
  io.corpus = io.summaryRead = io.summaryVisible = io.chatVisible = async () => assert.fail('not request/product reconciliation');
  const result = await verifyReadonlyQuiescentIo(io, c);
  for (const [k, value] of Object.entries(ABANDONED_TRUTH)) assert.deepEqual(result[k], value);
  assert.equal(result.currentObservation.user.carried.costMicros, 9);
  assert.equal(result.currentObservation.basis, 'FRESH_CONCURRENCY_PIN_NOT_HISTORICAL_CORRELATION');
  assert.deepEqual(calls, ['preflight', 'history-get', 'usage-get', 'current', 'history-get', 'usage-get']);
  assert.equal(JSON.stringify(result).includes(QUESTION), false);
});
for (const name of ['pending', 'held', 'used-drift', 'carried-drift']) test(`abandonment quiescence refuses ${name}`, t => {
  const f = fixture(t), second = structuredClone(f.first);
  if (name === 'pending') second.context.h.pending = true;
  if (name === 'held') second.usage.user.held.costMicros = 1;
  if (name === 'used-drift') second.usage.user.used.costMicros++;
  if (name === 'carried-drift') second.usage.user.carried.costMicros++;
  assert.throws(() => qualifyAbandonedQuiescence(f.first, second, c));
});
function idleSupervisor(f) {
  // Actual producer creates/fsyncs its sentinel, runs ONLY an inert child, and
  // intentionally leaves the idle file behind. No deploy CLI or engine is run.
  const result = spawnSync('/usr/bin/python3', ['-I', '-c', DEPLOY_SUPERVISOR_PROGRAM, f.root, f.state,
    process.execPath, '-e', 'new', 'void 0'], { cwd: f.root, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr);
  const path = join(f.state, '.deploy-supervisor-v1.lock'), identity = inspectDeploySupervisor(f.root);
  return { path, identity };
}
function busySupervisor(t, f, path) {
  const fd = fs.openSync(path, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW); t.after(() => fs.closeSync(fd));
  const result = spawnSync('/usr/bin/python3', ['-I', '-c', 'import fcntl; fcntl.flock(3, fcntl.LOCK_EX | fcntl.LOCK_NB)'],
    { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe', fd], timeout: 5000 });
  assert.equal(result.error, undefined); assert.equal(result.status, 0);
  // The inherited open-file description remains leased by this fixture's fd.
  assert.throws(() => inspectDeploySupervisor(f.root), /DEPLOY_SUPERVISOR_REQUIRED/);
}
test('actual producer idle supervisor sentinel is qualified FREE and preserved through both abandonment stages', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), supervisor = idleSupervisor(f), w = abandonWorkflow(f, deployment);
  const before = fs.lstatSync(supervisor.path), eligibility = await w.run(w.options);
  assert.ok(fs.existsSync(f.lock)); assert.deepEqual(inspectDeploySupervisor(f.root), supervisor.identity);
  const result = await w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 });
  assert.equal(result.status, 'EXACT_ABANDONED_NATIVE_FENCE_ARCHIVED_UNKNOWN_PRESERVED');
  assert.deepEqual(inspectDeploySupervisor(f.root), supervisor.identity);
  const after = fs.lstatSync(supervisor.path);
  assert.deepEqual([after.dev, after.ino, after.uid, after.mode, after.size, after.mtimeMs, after.ctimeMs],
    [before.dev, before.ino, before.uid, before.mode, before.size, before.mtimeMs, before.ctimeMs]);
  assert.equal(fs.readFileSync(supervisor.path).length, 0);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('actual busy OS supervisor lease refuses before GET/staging and never removes either fence', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), supervisor = idleSupervisor(f); busySupervisor(t, f, supervisor.path);
  const w = abandonWorkflow(f, deployment);
  await assert.rejects(w.run(w.options), /ABANDON_SUPERVISOR_UNQUALIFIED/); assert.equal(w.state.reads, 0); assert.equal(w.state.runtime, 0);
  assert.equal(fs.existsSync(w.slot), false); assert.ok(fs.existsSync(f.lock)); assert.ok(fs.existsSync(supervisor.path));
});
for (const kind of ['nonempty', 'wrong-mode', 'symlink', 'hardlink', 'directory']) test(`supervisor sentinel ${kind} is not an exempt lock`, t => {
  const f = fixture(t), supervisor = idleSupervisor(f);
  if (kind === 'nonempty') fs.appendFileSync(supervisor.path, 'unknown');
  if (kind === 'wrong-mode') fs.chmodSync(supervisor.path, 0o644);
  if (['symlink', 'hardlink', 'directory'].includes(kind)) {
    const retained = join(f.root, 'retained-supervisor'); fs.renameSync(supervisor.path, retained);
    if (kind === 'symlink') fs.symlinkSync(retained, supervisor.path);
    if (kind === 'hardlink') fs.linkSync(retained, supervisor.path);
    if (kind === 'directory') fs.mkdirSync(supervisor.path, { mode: 0o700 });
  }
  assert.throws(() => captureAbandonedEvidence(f.root, selection, () => false), /ABANDON_SUPERVISOR_UNQUALIFIED/);
  assert.ok(fs.existsSync(supervisor.path)); assert.ok(fs.existsSync(f.lock));
});
test('supervisor identity is pinned within a capture and across readonly/archive stages, not requalified after replacement', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), supervisor = idleSupervisor(f);
  const original = captureAbandonedEvidence(f.root, selection, () => false), first = abandonWorkflow(f, deployment), eligibility = await first.run(first.options);
  fs.renameSync(supervisor.path, join(f.root, 'retained-supervisor'));
  fs.writeFileSync(supervisor.path, '', { mode: 0o600 });
  assert.notDeepEqual(inspectDeploySupervisor(f.root), supervisor.identity, 'replacement is itself safe/free, but not the pinned inode');
  assert.throws(original.verify, /ABANDON_SUPERVISOR_CHANGED/);
  const next = abandonWorkflow(f, deployment);
  await assert.rejects(next.run({ ...next.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 }), /ABANDONMENT_PROOF_STALE_OR_CHANGED/);
  assert.equal(next.state.reads, 0); assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(first.slot, 'archive-intent.json')), false);
});
test('a supervisor lease becoming busy after readonly eligibility still prevents archive without changing evidence', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), supervisor = idleSupervisor(f), w = abandonWorkflow(f, deployment);
  const original = captureAbandonedEvidence(f.root, selection, () => false), eligibility = await w.run(w.options);
  busySupervisor(t, f, supervisor.path);
  assert.throws(original.verify, /ABANDON_SUPERVISOR_UNQUALIFIED/);
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 }), /ABANDON_SUPERVISOR_UNQUALIFIED/);
  assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(w.slot, 'archive-intent.json')), false);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('qualifying the exact idle supervisor does not exempt any other lock or pending marker', t => {
  const f = fixture(t), supervisor = idleSupervisor(f);
  for (const name of ['.some-other.lock', '.deploy-supervisor-v2.lock', '.compose.images.pending']) {
    const path = join(f.state, name); f.write(path, '');
    assert.throws(() => captureAbandonedEvidence(f.root, selection, () => false), /ABANDON_OTHER_HOLD/);
    fs.renameSync(path, join(f.root, name));
  }
  assert.deepEqual(inspectDeploySupervisor(f.root), supervisor.identity); assert.ok(fs.existsSync(f.lock));
});
test('explicit abandonment stages preserve UNKNOWN/old FAIL/spent evidence and archive only exact whole dead native fence into separate fixed slot', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), w = abandonWorkflow(f, deployment), owner = fs.readFileSync(join(f.lock, 'native-runtime-owner.json'));
  const eligibility = await w.run(w.options); assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(f.root, READONLY_SLOT)), false);
  const result = await w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 });
  assert.equal(result.status, 'EXACT_ABANDONED_NATIVE_FENCE_ARCHIVED_UNKNOWN_PRESERVED');
  for (const [k, value] of Object.entries(ABANDONED_TRUTH)) assert.deepEqual(result[k], value);
  assert.equal(fs.existsSync(f.lock), false); assert.deepEqual(fs.readFileSync(join(w.slot, 'abandoned-operation.lock/native-runtime-owner.json')), owner);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
  const disposition = JSON.parse(fs.readFileSync(join(w.slot, 'disposition.json')));
  assert.equal(disposition.originalCorrelation, 'UNKNOWN_UNRECOVERABLE'); assert.equal(disposition.provenance.currentWorkingTreeEqualsDeployed, 'NOT_CLAIMED');
  assert.equal(disposition.currentObservation.scan.carried.costMicros, 9); assert.equal(disposition.providerRetryAuthorized, false);
  assert.equal(JSON.stringify(disposition).includes(QUESTION), false);
});
for (const name of ['other-hold', 'pending-publication', 'current-drift', 'source-review', 'expired-proof', 'staged-tamper']) test(`abandonment refuses ${name} without removing its fence`, async t => {
  const f = fixture(t), deployment = deploymentFixture(f), first = abandonWorkflow(f, deployment), eligibility = await first.run(first.options); let reviews = 0;
  if (name === 'other-hold') fs.mkdirSync(join(f.state, '.reconcile-build-only.lock'), { mode: 0o700 });
  if (name === 'pending-publication') f.write(join(f.state, '.compose.images.pending'), {});
  if (name === 'current-drift') f.first.usage.user.carried.costMicros++;
  const w = abandonWorkflow(f, deployment, { getReview: async () => { reviews++;
    if (name === 'staged-tamper' && reviews === 3) fs.appendFileSync(join(first.slot, 'disposition.json'), ' ');
    return name === 'source-review' && reviews > 1 ? id(999) : review;
  }, now: () => Date.parse(name === 'expired-proof' ? '2026-11-04T18:07:00.001Z' : '2026-11-04T18:03:00.000Z') });
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 }));
  assert.ok(fs.existsSync(f.lock)); assert.equal(fs.existsSync(join(w.slot, 'archived.json')), false);
});
test('abandonment post-rename uncertainty preserves archived owner/disposition and never rolls back or retries', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), first = abandonWorkflow(f, deployment), eligibility = await first.run(first.options); let renames = 0;
  const w = abandonWorkflow(f, deployment, { io: { ...fs, renameSync(from, to) { renames++; fs.renameSync(from, to); throw Error('SYNTHETIC_POST_RENAME'); } } });
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 }));
  assert.equal(renames, 1); assert.ok(fs.existsSync(join(w.slot, 'abandoned-operation.lock/native-runtime-owner.json')));
  assert.ok(fs.existsSync(join(w.slot, 'disposition.json'))); assert.equal(fs.existsSync(join(w.slot, 'archived.json')), false);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('fresh runtime cannot hide stale current GET quiescence after cleanup/fsync; lock stays held', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), w = abandonWorkflow(f, deployment, { clock: () => 15000,
    quiescence: async () => ({ ...qualifyAbandonedQuiescence(f.first, structuredClone(f.first), c), observedAt: 0,
      readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } }),
    runtime: async () => { const { records, receipt } = deployment.capture(); return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: 15000, verify: records.verify }; } });
  await assert.rejects(w.run(w.options), /ABANDON_RUNTIME_PROOF_EXPIRED/); assert.ok(fs.existsSync(f.lock));
  assert.equal(fs.existsSync(join(w.slot, 'eligibility.json')), false);
});
test('archive final metadata/review delay cannot turn expired GET/runtime proof into a rename', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), first = abandonWorkflow(f, deployment), eligibility = await first.run(first.options);
  let clock = 0;
  const w = abandonWorkflow(f, deployment, { clock: () => clock, getReview: async () => {
    if (fs.existsSync(join(first.slot, 'disposition.json'))) clock = 15000;
    return review;
  } });
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 }), /ABANDON_RUNTIME_PROOF_EXPIRED/);
  assert.ok(fs.existsSync(f.lock)); assert.ok(fs.existsSync(join(w.slot, 'disposition.json')));
  assert.equal(fs.existsSync(join(w.slot, 'abandoned-operation.lock')), false);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('identically pending or held current samples remain ineligible; no historical anchor requirement can waive them', t => {
  for (const kind of ['pending', 'held']) {
    const f = fixture(t);
    if (kind === 'pending') f.first.context.h.pending = true;
    else f.first.usage.user.held.costMicros = 1;
    assert.throws(() => qualifyAbandonedQuiescence(f.first, structuredClone(f.first), c)); assert.ok(fs.existsSync(f.lock));
  }
});
test('abandonment never adopts a live, replaced, or audit-extended original controller fence', async t => {
  const f = fixture(t), deployment = deploymentFixture(f);
  assert.throws(() => captureAbandonedEvidence(f.root, selection, () => true), /ORIGINAL_PROCESS_STILL_ALIVE/);
  const w = abandonWorkflow(f, deployment), eligibility = await w.run(w.options);
  f.write(join(f.audit, '0008-dispatch-submitted.json'), { operation: 'chat' });
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-archive', verification: eligibility.eligibilitySha256 })); assert.ok(fs.existsSync(f.lock));
});
test('abandonment CLI is separate, no fabricated anchors/factories/known-commit waiver, and both stages require exact new GO', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), w = abandonWorkflow(f, deployment);
  const args = ['--verify-abandoned-native-fence', '--ack-new-coordinator-readonly-go', '--ack-unknown-liabilities-no-provider-retry',
    '--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review];
  assert.deepEqual(reconcileMode(args), w.options);
  assert.equal(reconcileMode(['--archive-abandoned-native-fence', '--ack-new-coordinator-abandon-archive-go', args[2], '--ack-exact-owned-native-fence-only', ...args.slice(3), '--eligibility-sha256', id(900)]).mode, 'abandon-archive');
  for (let i = 0; i < args.length; i++) { const a = [...args]; a[i] = 'wrong'; assert.throws(() => reconcileMode(a)); }
  for (const extra of [{ anchors: f.anchors }, { passed: true }, { source: { build: id(9) } }, { provenance: true }, { root: '/other' }]) await assert.rejects(w.run({ ...w.options, ...extra }));
  assert.equal(fs.existsSync(w.slot), false);
});
const failedReview = id(801);
function incompleteReadonlyStage(f) {
  const slot = join(f.root, ABANDONED_SLOT); fs.mkdirSync(slot, { mode: 0o700 });
  const intent = { version: 1, kind: 'abandoned-fence-readonly-intent', binding: { selection, review: failedReview }, originalEvidence: captureAbandonedEvidence(f.root, selection, () => false).seal };
  f.write(join(slot, 'verification-intent.json'), intent);
  return { slot, intent, bytes: fs.readFileSync(join(slot, 'verification-intent.json')) };
}
function diagnosticWorkflow(f, deployment, overrides = {}) {
  return createAbandonedReadonlyDiagnostic({ root: f.root, capture: () => captureAbandonedEvidence(f.root, selection, () => false), getReview: async () => review,
    runtime: async () => { const { records, receipt } = deployment.capture(); return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: 0, verify: records.verify }; },
    quiescence: async () => ({ ...await verifyReadonlyQuiescentIo(readonlyIo(f, []), c), observedAt: 0, readonly: { nonGet: 0, denied: 0, pageErrors: 0, browserClosed: true, sessionUnchanged: true } }),
    clock: () => 0, ...overrides });
}
const diagnosticOptions = { mode: 'abandon-diagnose', selection, review, failedReview };
test('explicit failed-stage diagnostic is GET-only, emits no eligibility and writes no slot or native/paid evidence', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), old = incompleteReadonlyStage(f), run = diagnosticWorkflow(f, deployment);
  const before = fs.readdirSync(join(f.root, 'test-results'));
  const result = await run(diagnosticOptions);
  assert.equal(result.status, 'READONLY_DIAGNOSTIC_PASS_NO_ELIGIBILITY_NO_DISPOSITION'); assert.equal(result.firstFailure, null); assert.equal(result.slotWrites, 0);
  assert.deepEqual(fs.readdirSync(join(f.root, 'test-results')), before); assert.deepEqual(fs.readdirSync(old.slot), ['verification-intent.json']);
  assert.deepEqual(fs.readFileSync(join(old.slot, 'verification-intent.json')), old.bytes); assert.ok(fs.existsSync(f.lock));
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
for (const phase of ['preflight', 'history-get', 'usage-get', 'current-get']) test(`diagnostic first failure identifies ${phase} without arbitrary errors/payload`, async t => {
  const f = fixture(t), deployment = deploymentFixture(f); incompleteReadonlyStage(f);
  const run = diagnosticWorkflow(f, deployment, { quiescence: () => {
    const io = readonlyIo(f, []), key = { preflight: 'preflight', 'history-get': 'history', 'usage-get': 'usage', 'current-get': 'current' }[phase];
    io[key] = async () => { throw Error('PRIVATE_UPPERCASE_SECRET_BODY'); }; return verifyReadonlyQuiescentIo(io, c);
  } });
  const result = await run(diagnosticOptions);
  assert.deepEqual(result.firstFailure, { phase, code: 'UNCLASSIFIED_FAILURE' }); assert.equal(JSON.stringify(result).includes('PRIVATE'), false); assert.equal(result.slotWrites, 0);
});
test('diagnostic reports exact finite freshness/final-fence failures, not inferred browser root cause', async t => {
  const f = fixture(t), deployment = deploymentFixture(f); incompleteReadonlyStage(f);
  const expired = await diagnosticWorkflow(f, deployment, { clock: () => 15000 })(diagnosticOptions);
  assert.deepEqual(expired.firstFailure, { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' });
  assert.deepEqual(readonlyFailure(Error('ARBITRARY_UPPERCASE_TEXT')), { phase: 'unclassified', code: 'UNCLASSIFIED_FAILURE' });
  assert.ok(READONLY_FAILURE_PHASES.includes(expired.firstFailure.phase)); assert.ok(READONLY_FAILURE_CODES.includes(expired.firstFailure.code));
});
test('fresh explicitly authorized readonly continuation binds preserved incomplete intent and archives only through its separately gated new slot', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), old = incompleteReadonlyStage(f), w = abandonWorkflow(f, deployment);
  const options = { ...w.options, mode: 'abandon-verify-continuation', failedReview }, eligibility = await w.run(options), slot = join(f.root, ABANDONED_CONTINUATION_SLOT);
  assert.ok(fs.existsSync(f.lock)); assert.deepEqual(fs.readdirSync(old.slot), ['verification-intent.json']);
  const intent = JSON.parse(fs.readFileSync(join(slot, 'verification-intent.json')));
  assert.equal(intent.binding.predecessor.firstFailure, 'UNRECORDED_UNKNOWN'); assert.equal(intent.binding.predecessor.review, failedReview);
  const result = await w.run({ ...options, mode: 'abandon-archive-continuation', verification: eligibility.eligibilitySha256 });
  assert.equal(result.requestReconciliation, 'NOT_PERFORMED'); assert.equal(result.providerRetryAuthorized, false);
  assert.ok(fs.existsSync(join(slot, 'abandoned-operation.lock/native-runtime-owner.json')));
  assert.deepEqual(fs.readFileSync(join(old.slot, 'verification-intent.json')), old.bytes);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
for (const attack of ['missing', 'eligibility', 'wrong-review', 'wrong-evidence', 'tampered-after-capture']) test(`failed readonly stage refuses ${attack}; no blind repeat or new-slot fallback`, async t => {
  const f = fixture(t), deployment = deploymentFixture(f), old = incompleteReadonlyStage(f), original = captureAbandonedEvidence(f.root, selection, () => false);
  if (attack === 'missing') fs.renameSync(join(old.slot, 'verification-intent.json'), join(f.root, 'retained-intent'));
  if (attack === 'eligibility') f.write(join(old.slot, 'eligibility.json'), {});
  if (attack === 'wrong-review') { old.intent.binding.review = id(999); f.write(join(old.slot, 'verification-intent.json'), old.intent); }
  if (attack === 'wrong-evidence') { old.intent.originalEvidence = id(999); f.write(join(old.slot, 'verification-intent.json'), old.intent); }
  if (attack === 'tampered-after-capture') {
    const failed = captureFailedReadonlyStage(f.root, selection, failedReview, original); fs.appendFileSync(join(old.slot, 'verification-intent.json'), ' '); assert.throws(failed.verify);
  }
  const run = diagnosticWorkflow(f, deployment), result = await run(diagnosticOptions);
  assert.equal(result.status, 'READONLY_DIAGNOSTIC_REFUSED'); assert.equal(result.firstFailure.phase, 'failed-stage');
  const w = abandonWorkflow(f, deployment);
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-verify-continuation', failedReview }));
  assert.equal(fs.existsSync(join(f.root, ABANDONED_CONTINUATION_SLOT)), false); assert.ok(fs.existsSync(f.lock));
});
test('new first-stage failure persists only finite first failure in its own new stage, not paid/audit/old stage', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), old = incompleteReadonlyStage(f), w = abandonWorkflow(f, deployment, { quiescence: async () => { throw Error('PRIVATE_RAW_ERROR'); } });
  await assert.rejects(w.run({ ...w.options, mode: 'abandon-verify-continuation', failedReview }));
  const failure = fs.readFileSync(join(f.root, ABANDONED_CONTINUATION_SLOT, 'failure.json'), 'utf8');
  assert.equal(failure.includes('PRIVATE_RAW_ERROR'), false); assert.deepEqual(JSON.parse(failure).firstFailure, { phase: 'browser-work', code: 'UNCLASSIFIED_FAILURE' });
  assert.deepEqual(fs.readFileSync(join(old.slot, 'verification-intent.json')), old.bytes);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('diagnostic and continuation CLI require separate exact GO, old review plus current review; reject paths/factories/paid retry', () => {
  const pairs = ['--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review, '--failed-review', failedReview];
  const diagnose = ['--diagnose-abandoned-readonly', '--ack-new-coordinator-readonly-diagnostic-go', '--ack-no-slot-writes-no-provider-posts', ...pairs];
  assert.deepEqual(reconcileMode(diagnose), diagnosticOptions);
  const continuation = ['--continue-abandoned-readonly', '--ack-new-coordinator-readonly-continuation-go', '--ack-unknown-liabilities-no-provider-retry', '--ack-preserved-incomplete-readonly-stage', ...pairs];
  assert.equal(reconcileMode(continuation).mode, 'abandon-verify-continuation');
  assert.equal(reconcileMode(['--archive-continued-abandoned-native-fence', '--ack-new-coordinator-abandon-archive-go', continuation[2], '--ack-exact-owned-native-fence-only', ...pairs, '--eligibility-sha256', id(900)]).mode, 'abandon-archive-continuation');
  for (const args of [diagnose, continuation]) {
    for (let i = 0; i < args.length; i++) { const changed = [...args]; changed[i] = 'wrong'; assert.throws(() => reconcileMode(changed)); }
    for (const extra of ['--retry-paid', '--path', '--factory', '--passed', '--unlock']) assert.throws(() => reconcileMode([...args, extra]));
  }
});
function directReadFixture(f, attack = () => {}) {
  const cookie = 'S'.repeat(43), owner = { id: 'b'.repeat(32), email: 'synthetic-owner@example.invalid' }, requests = [];
  const storage = { cookies: [{ name: 'demo_session', value: cookie, domain: '127.0.0.1', path: '/', httpOnly: true, secure: false, sameSite: 'Lax', expires: -1 }], origins: [] };
  const state = { snapshots: 0, loads: 0, requests, cookie, owner, storage, postcheckChanged: false, active: 0, peak: 0 };
  const request = (url, options, callback) => {
    const index = requests.length; requests.push({ url: url.href, options, endArgs: null, destroyed: false });
    state.active++; state.peak = Math.max(state.peak, state.active);
    const row = requests[index], req = new EventEmitter(); req.destroy = () => { if (!row.destroyed) { row.destroyed = true; state.active--; clearTimeout(row.timer); } };
    req.end = (...args) => {
      row.endArgs = args;
      queueMicrotask(() => {
        if (row.destroyed) return;
        const values = [owner, f.first.context.h, f.first.history, f.first.usage];
        const response = new EventEmitter(); response.statusCode = 200; response.headers = { 'content-type': 'application/json; charset=utf-8' }; response.complete = true;
        response.destroy = () => { row.responseDestroyed = true; };
        const sample = { index, value: structuredClone(values[index % 4]), response, req, row, noResponse: false, bytes: null, error: false, delayMs: 0 };
        attack(sample);
        const deliver = () => {
          if (row.destroyed) return;
          if (sample.error) { req.emit('error', Error('PRIVATE_HTTP_ERROR_' + cookie)); return; }
          if (sample.noResponse) return;
          callback(response);
          if (row.destroyed) return;
          response.emit('data', sample.bytes ?? Buffer.from(JSON.stringify(sample.value))); response.emit('end');
        };
        if (sample.delayMs) row.timer = setTimeout(deliver, sample.delayMs); else deliver();
      });
    };
    return req;
  };
  const settings = { request, snapshot: async path => {
    assert.match(path, /batch25-browser-final-evidence\/private-storage\.json$/); state.snapshots++;
    return { value: structuredClone(storage), byteHash: state.postcheckChanged && state.snapshots > 1 ? id(888) : id(777) };
  }, load: async () => { state.loads++; return c; }, environment: () => ({}), clock: () => 0 };
  return { state, settings, run: createAbandonedDirectQuiescence(settings) };
}
test('direct abandon quiescence uses exactly eight fixed authenticated GETs, actual schemas and MEMORY-ONLY exact cookie; never pages/assets/POST', async t => {
  const f = fixture(t), d = directReadFixture(f), before = fs.readdirSync(join(f.root, 'test-results'));
  const proof = await d.run();
  assert.deepEqual(proof.readonly, DIRECT_READONLY); assert.equal(proof.currentObservation.user.carried.costMicros, 9);
  assert.equal(d.state.snapshots, 2); assert.equal(d.state.loads, 1); assert.equal(d.state.requests.length, 8); assert.equal(d.state.peak, 4); assert.equal(d.state.active, 0);
  d.state.requests.forEach((row, i) => {
    assert.equal(row.url, 'http://127.0.0.1:8081' + DIRECT_GET_PATHS[i % 4]); assert.ok(directGetAllowed(row.url, 'GET'));
    assert.deepEqual(row.options.headers, { Cookie: 'demo_session=' + d.state.cookie, Accept: 'application/json', Origin: 'http://127.0.0.1:8081', 'Cache-Control': 'no-store' });
    assert.equal(row.options.method, 'GET'); assert.equal(row.options.agent, false); assert.equal(row.options.maxHeaderSize, 16384); assert.deepEqual(row.endArgs, []);
    assert.equal(row.destroyed, true); assert.equal(row.responseDestroyed, true);
  });
  for (const secret of [d.state.cookie, d.state.owner.email, d.state.owner.id, QUESTION]) assert.equal(JSON.stringify(proof).includes(secret), false);
  assert.deepEqual(fs.readdirSync(join(f.root, 'test-results')), before);
  for (const row of f.snapshots) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
  for (const method of ['POST', 'PUT', 'HEAD', 'DELETE']) assert.equal(directGetAllowed(d.state.requests[0].url, method), false);
  for (const url of ['http://127.0.0.1:8080/api/v1/auth/me', 'https://foreign.invalid/api/v1/auth/me', 'http://127.0.0.1:8081/account', 'http://127.0.0.1:8081/assets/app.js', 'http://127.0.0.1:8081/api/v1/auth/me?x=1', 'http://127.0.0.1:8081' + BASE + '/llm/chat', 'http://127.0.0.1:8081/api/v1/auth/login']) assert.equal(directGetAllowed(url, 'GET'), false);
});
for (const [name, change, code] of [
  ['redirect', s => { s.response.statusCode = 302; s.response.headers.location = 'https://foreign.invalid/private'; }, 'DIRECT_HTTP_REFUSED'],
  ['401', s => { s.response.statusCode = 401; }, 'DIRECT_HTTP_REFUSED'],
  ['502', s => { s.response.statusCode = 502; }, 'DIRECT_HTTP_REFUSED'],
  ['set-cookie', s => { s.response.headers['set-cookie'] = ['demo_session=PRIVATE']; }, 'DIRECT_HTTP_REFUSED'],
  ['html', s => { s.response.headers['content-type'] = 'text/html'; }, 'DIRECT_HTTP_REFUSED'],
  ['encoded', s => { s.response.headers['content-encoding'] = 'gzip'; }, 'DIRECT_HTTP_REFUSED'],
  ['oversized-header', s => { s.response.headers['content-length'] = '16385'; }, 'DIRECT_BODY_BOUND'],
  ['oversized-body', s => { s.bytes = Buffer.alloc(16385, 32); }, 'DIRECT_BODY_BOUND'],
  ['invalid-json', s => { s.bytes = Buffer.from('PRIVATE_INVALID_JSON'); }, 'DIRECT_JSON_INVALID'],
  ['invalid-utf8', s => { s.bytes = Buffer.from([0xff]); }, 'DIRECT_JSON_INVALID'],
  ['truncated', s => { s.response.complete = false; }, 'DIRECT_TRANSPORT_FAILED'],
  ['socket-error', s => { s.error = true; }, 'DIRECT_TRANSPORT_FAILED'],
]) test(`direct GET ${name} fails finite, does not follow/retry or disclose cookie/body`, async t => {
  const f = fixture(t), d = directReadFixture(f, change);
  await assert.rejects(d.run(), error => { const diagnostic = readonlyFailure(error); assert.equal(diagnostic.code, code); assert.equal(JSON.stringify(diagnostic).includes('PRIVATE'), false); assert.equal(JSON.stringify(diagnostic).includes(d.state.cookie), false); return true; });
  assert.equal(d.state.requests.length, 4); assert.equal(d.state.active, 0); assert.ok(d.state.requests.every(row => row.destroyed)); assert.ok(fs.existsSync(f.lock));
});
for (const attack of ['owner', 'context', 'history', 'usage', 'pending', 'held', 'used', 'carried']) test(`direct two-sample quiescence rejects ${attack} mismatch`, async t => {
  const f = fixture(t), d = directReadFixture(f, s => {
    if (attack === 'owner' && s.index === 4) s.value.id = 'c'.repeat(32);
    if (attack === 'context' && s.index === 1) s.value.digest = 'sha256:' + id(999);
    if (attack === 'history' && s.index === 2) s.value.unexpected = 'PRIVATE';
    if (attack === 'usage' && s.index === 3) s.value.unexpected = 'PRIVATE';
    if (attack === 'pending' && s.index % 4 === 1) s.value.pending = true;
    if (attack === 'held' && s.index % 4 === 3) s.value.user.held.input = 1;
    if (attack === 'used' && s.index === 7) s.value.user.used.input++;
    if (attack === 'carried' && s.index === 7) s.value.scan.carried.costMicros++;
  });
  await assert.rejects(d.run()); assert.equal(d.state.requests.length, ['owner', 'used', 'carried'].includes(attack) ? 8 : 4); assert.equal(d.state.peak, 4); assert.equal(d.state.active, 0); assert.ok(fs.existsSync(f.lock));
});
test('direct debug environment refuses BEFORE private snapshot/contracts/Node HTTP; invalid cookie never reaches transport', async t => {
  const f = fixture(t);
  for (const environment of [{ NODE_DEBUG: 'http' }, { DEBUG: 'PRIVATE' }, { NODE_OPTIONS: '--inspect' }]) {
    const d = directReadFixture(f), run = createAbandonedDirectQuiescence({ ...d.settings, environment: () => environment });
    await assert.rejects(run(), error => readonlyFailure(error).code === 'CAPTURE_DEBUG_ENABLED');
    assert.equal(d.state.snapshots, 0); assert.equal(d.state.loads, 0); assert.equal(d.state.requests.length, 0);
  }
  for (const value of ['PRIVATE; another=cookie', 'x\r\nPRIVATE', 'x'.repeat(42), 'x'.repeat(44)]) {
    const d = directReadFixture(f); d.state.storage.cookies[0].value = value;
    await assert.rejects(d.run(), error => readonlyFailure(error).code === 'DIRECT_SESSION_UNSAFE'); assert.equal(d.state.requests.length, 0);
  }
  for (const change of [cookie => { cookie.domain = 'foreign.invalid'; }, cookie => { cookie.path = '/other'; }, cookie => { cookie.httpOnly = false; }, cookie => { cookie.secure = true; }, cookie => { cookie.sameSite = 'None'; }, cookie => { cookie.expires = 1; }]) {
    const d = directReadFixture(f); change(d.state.storage.cookies[0]);
    await assert.rejects(d.run(), error => readonlyFailure(error).code === 'DIRECT_SESSION_UNSAFE'); assert.equal(d.state.requests.length, 0);
  }
  const extra = directReadFixture(f); extra.state.storage.cookies.push({ ...extra.state.storage.cookies[0], name: 'other' });
  await assert.rejects(extra.run(), error => readonlyFailure(error).code === 'DIRECT_SESSION_UNSAFE'); assert.equal(extra.state.requests.length, 0);
  const d = directReadFixture(f); d.state.postcheckChanged = true;
  await assert.rejects(d.run(), error => readonlyFailure(error).code === 'PRIVATE_SESSION_CHANGED'); assert.equal(d.state.requests.length, 8);
});
test('direct GET absolute deadline aborts its bounded four-request sample, no retry or remaining sample', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), d = directReadFixture(f, s => { s.noResponse = true; }), result = d.run();
  for (let i = 0; i < 40; i++) await Promise.resolve();
  assert.equal(d.state.requests.length, 4); assert.equal(d.state.peak, 4); t.mock.timers.tick(15000);
  await assert.rejects(result, error => readonlyFailure(error).code === 'DIRECT_DEADLINE');
  assert.equal(d.state.requests.length, 4); assert.equal(d.state.active, 0); assert.ok(d.state.requests.every(row => row.destroyed));
});
async function flushReads() { for (let i = 0; i < 128; i++) await Promise.resolve(); }
test('parallel four-GET samples keep earliest observation fresh without overlapping samples, retimestamping or raising the15s bound', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), d = directReadFixture(f, s => { s.delayMs = 2640; }); let clock = 0;
  const result = createAbandonedDirectQuiescence({ ...d.settings, clock: () => clock })();
  await flushReads(); assert.equal(d.state.requests.length, 4); assert.equal(d.state.active, 4);
  clock = 2639; t.mock.timers.tick(2639); await flushReads(); assert.equal(d.state.requests.length, 4, 'second sample waits for complete first sample');
  clock = 2640; t.mock.timers.tick(1); await flushReads(); assert.equal(d.state.requests.length, 8); assert.equal(d.state.active, 4);
  assert.ok(d.state.requests.slice(0, 4).every(row => row.destroyed));
  clock = 5280; t.mock.timers.tick(2640); const proof = await result;
  assert.equal(proof.observedAt, 0, 'timestamp remains before the FIRST GET, not sample2 or completion');
  assert.equal(d.state.peak, 4); assert.equal(d.state.active, 0); assert.equal(proof.readonly.requests, 8); assert.equal(proof.readonly.maxConcurrency, 4);
  assert.ok(8 * 2640 > 15000, 'same fixture latency is too old when serialized');
  assert.ok(clock + 1914 + 18 + 147 - proof.observedAt < 15000, 'two batches plus profiled post-observation overhead fit unchanged freshness');
});
test('one slower independent GET holds the sample barrier; no overlapping sample or replacement requests', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), d = directReadFixture(f, s => { s.delayMs = s.index % 4 === 2 ? 3000 : 1000; });
  const result = d.run(); await flushReads(); assert.equal(d.state.requests.length, 4);
  t.mock.timers.tick(1000); await flushReads(); assert.equal(d.state.active, 1); assert.equal(d.state.requests.length, 4);
  t.mock.timers.tick(2000); await flushReads(); assert.equal(d.state.requests.length, 8); assert.equal(d.state.active, 4);
  t.mock.timers.tick(1000); await flushReads(); assert.equal(d.state.active, 1); assert.equal(d.state.requests.length, 8);
  t.mock.timers.tick(2000); const proof = await result;
  assert.equal(proof.readonly.requests, 8); assert.equal(d.state.peak, 4); assert.equal(d.state.active, 0);
});
test('parallel reads still refuse genuinely old successful observations instead of moving timestamp to sample2/completion', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), deployment = deploymentFixture(f); incompleteReadonlyStage(f);
  const d = directReadFixture(f, s => { s.delayMs = 8000; }); let clock = 0;
  const run = diagnosticWorkflow(f, deployment, { quiescence: createAbandonedDirectQuiescence({ ...d.settings, clock: () => clock }), clock: () => clock,
    runtime: async () => { const { records, receipt } = deployment.capture(); return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: clock, verify: records.verify }; } });
  const result = run(diagnosticOptions); await flushReads(); assert.equal(d.state.requests.length, 4);
  clock = 8000; t.mock.timers.tick(8000); await flushReads(); assert.equal(d.state.requests.length, 8);
  clock = 16000; t.mock.timers.tick(8000); const refused = await result;
  assert.equal(d.state.requests.length, 8); assert.equal(d.state.peak, 4); assert.equal(d.state.active, 0);
  assert.deepEqual(refused.firstFailure, { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' }); assert.ok(fs.existsSync(f.lock));
});
const failedArchiveReview = review;
async function failedArchiveFixture(f, deployment) {
  const old = incompleteReadonlyStage(f), first = abandonWorkflow(f, deployment), options = { ...first.options, mode: 'abandon-verify-continuation', failedReview };
  const eligible = await first.run(options);
  const refused = abandonWorkflow(f, deployment, { quiescence: async () => {
    let handler; const guard = { requests: 0, denied: 0, nonGet: 0, pageErrors: 0, stopped: false };
    await installReadonlyRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, guard);
    await handler({ request: () => ({ method: () => 'GET', url: () => 'http://127.0.0.1:8081' + DIRECT_GET_PATHS[2], redirectedFrom: () => null }),
      fetch: async () => { throw Error('UNKNOWN_TRANSPORT_CAUSE'); }, abort: async () => {} });
    throw guard.firstFailure;
  } });
  await assert.rejects(refused.run({ ...options, mode: 'abandon-archive-continuation', verification: eligible.eligibilitySha256 }));
  const original = captureAbandonedEvidence(f.root, selection, () => false), proof = captureFailedArchiveStage(f.root, selection, failedReview, failedArchiveReview, original);
  const files = [old.slot, join(f.root, ABANDONED_CONTINUATION_SLOT)].flatMap(path => fs.readdirSync(path).map(name => ({ path: join(path, name), bytes: fs.readFileSync(join(path, name)) })));
  return { proof, files, options: { mode: 'abandon-verify-direct', selection, review, failedReview, failedArchiveReview, failedArchiveEvidence: proof.evidenceSha256, verification: null } };
}
test('Batch35 direct-only verification/archive binds both prior failed stages and exact before-rename evidence SHA without resetting anything', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), prior = await failedArchiveFixture(f, deployment);
  let direct = directReadFixture(f), w = abandonWorkflow(f, deployment, { quiescence: () => direct.run() });
  const eligibility = await w.run(prior.options), slot = join(f.root, ABANDONED_DIRECT_SLOT);
  assert.ok(fs.existsSync(f.lock)); assert.equal(direct.state.requests.length, 8);
  const intent = JSON.parse(fs.readFileSync(join(slot, 'verification-intent.json')));
  assert.equal(intent.binding.predecessor.failedArchive.evidenceSha256, prior.proof.evidenceSha256);
  assert.equal(intent.binding.predecessor.failedArchive.cause, 'UNKNOWN_NOT_ATTRIBUTED');
  direct = directReadFixture(f); w = abandonWorkflow(f, deployment, { quiescence: () => direct.run() });
  const result = await w.run({ ...prior.options, mode: 'abandon-archive-direct', verification: eligibility.eligibilitySha256 });
  assert.equal(result.providerRetryAuthorized, false); assert.ok(fs.existsSync(join(slot, 'abandoned-operation.lock/native-runtime-owner.json')));
  for (const row of [...prior.files, ...f.snapshots]) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
for (const attack of ['wrong-sha', 'changed-intent', 'changed-failure', 'postrename', 'browser-proof']) test(`Batch35 refuses ${attack} without native unlock or old-stage rewrite`, async t => {
  const f = fixture(t), deployment = deploymentFixture(f), prior = await failedArchiveFixture(f, deployment), slot = join(f.root, ABANDONED_CONTINUATION_SLOT);
  if (attack === 'wrong-sha') prior.options.failedArchiveEvidence = id(999);
  if (attack === 'changed-intent') fs.appendFileSync(join(slot, 'archive-intent.json'), ' ');
  if (attack === 'changed-failure') f.write(join(slot, 'failure.json'), { version: 1, firstFailure: { phase: 'archive', code: 'UNCLASSIFIED_FAILURE' }, ...ABANDONED_TRUTH });
  if (attack === 'postrename') f.write(join(slot, 'disposition.json'), {});
  const w = abandonWorkflow(f, deployment);
  await assert.rejects(w.run(prior.options)); assert.ok(fs.existsSync(f.lock));
  if (attack !== 'browser-proof') assert.equal(fs.existsSync(join(f.root, ABANDONED_DIRECT_SLOT)), false);
});
test('Batch35 direct diagnostic has no slotwrites and never pretends original routes failure is causally fixed', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), prior = await failedArchiveFixture(f, deployment), d = directReadFixture(f);
  const run = diagnosticWorkflow(f, deployment, { quiescence: d.run });
  const { verification: _verification, ...options } = { ...prior.options, mode: 'abandon-diagnose-direct' }; void _verification;
  const result = await run(options); assert.equal(result.status, 'READONLY_DIAGNOSTIC_PASS_NO_ELIGIBILITY_NO_DISPOSITION'); assert.equal(result.slotWrites, 0);
  assert.equal(fs.existsSync(join(f.root, ABANDONED_DIRECT_SLOT)), false); assert.ok(fs.existsSync(f.lock));
  for (const row of [...prior.files, ...f.snapshots]) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('Batch35 direct CLI is explicit and fixed, exact failed-archive evidence pin and separate archive GO required', () => {
  const pairs = ['--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review,
    '--failed-review', failedReview, '--failed-archive-review', failedArchiveReview, '--failed-archive-evidence-sha256', id(900)];
  const args = ['--verify-abandoned-direct', '--ack-new-coordinator-direct-readonly-go', '--ack-unknown-liabilities-no-provider-retry', '--ack-preserved-failed-archive-stage', ...pairs];
  assert.equal(reconcileMode(args).mode, 'abandon-verify-direct');
  assert.equal(reconcileMode(['--archive-abandoned-direct', '--ack-new-coordinator-abandon-archive-go', args[2], '--ack-exact-owned-native-fence-only', ...pairs, '--eligibility-sha256', id(901)]).mode, 'abandon-archive-direct');
  assert.equal(reconcileMode(['--diagnose-abandoned-direct', '--ack-new-coordinator-readonly-diagnostic-go', '--ack-no-slot-writes-no-provider-posts', ...pairs]).mode, 'abandon-diagnose-direct');
  for (let i = 0; i < args.length; i++) { const changed = [...args]; changed[i] = 'wrong'; assert.throws(() => reconcileMode(changed)); }
  for (const extra of ['--POST', '--cookie', '--url', '--path', '--retry-paid', '--passed', '--factory']) assert.throws(() => reconcileMode([...args, extra]));
});
async function failedFreshnessFixture(f, deployment) {
  const prior = await failedArchiveFixture(f, deployment), d = directReadFixture(f); let clock = 0;
  const w = abandonWorkflow(f, deployment, { clock: () => clock, quiescence: async () => { const proof = await d.run(); clock = 15000; return proof; },
    runtime: async () => { const { records, receipt } = deployment.capture(); return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: clock, verify: records.verify }; } });
  await assert.rejects(w.run(prior.options), error => {
    assert.deepEqual(readonlyFailure(error), { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' }); return true;
  });
  assert.equal(d.state.requests.length, 8, 'failure is NOT a fabricated zero-GET attempt');
  const options = { ...prior.options, mode: 'abandon-verify-parallel', failedDirectReview: review };
  const original = captureAbandonedEvidence(f.root, selection, () => false), proof = captureFailedFreshnessStage(f.root, options, original);
  options.failedDirectEvidence = proof.evidenceSha256;
  const slot = join(f.root, ABANDONED_DIRECT_SLOT), files = [...prior.files, ...fs.readdirSync(slot).map(name => ({ path: join(slot, name), bytes: fs.readFileSync(join(slot, name)) }))];
  return { options, files, proof };
}
test('Batch36 one explicit continuation pins immutable Batch35 freshness failure SHA and repeats exact proof before separate archive', async t => {
  const f = fixture(t), deployment = deploymentFixture(f), prior = await failedFreshnessFixture(f, deployment);
  let direct = directReadFixture(f), w = abandonWorkflow(f, deployment, { quiescence: () => direct.run() });
  const eligible = await w.run(prior.options), slot = join(f.root, ABANDONED_PARALLEL_SLOT);
  assert.equal(direct.state.requests.length, 8); assert.equal(direct.state.peak, 4); assert.ok(fs.existsSync(f.lock));
  const intent = JSON.parse(fs.readFileSync(join(slot, 'verification-intent.json')));
  assert.equal(intent.binding.predecessor.failedFreshness.evidenceSha256, prior.proof.evidenceSha256);
  assert.deepEqual(intent.binding.predecessor.failedFreshness.firstFailure, { phase: 'freshness', code: 'ABANDON_RUNTIME_PROOF_EXPIRED' });
  assert.equal(Object.hasOwn(intent.binding.predecessor.failedFreshness, 'requests'), false, 'do not invent old request counts');
  direct = directReadFixture(f); w = abandonWorkflow(f, deployment, { quiescence: () => direct.run() });
  const done = await w.run({ ...prior.options, mode: 'abandon-archive-parallel', verification: eligible.eligibilitySha256 });
  assert.equal(done.providerRetryAuthorized, false); assert.equal(done.historicalLiabilities, 'UNKNOWN_PRESERVED');
  assert.ok(fs.existsSync(join(slot, 'abandoned-operation.lock/native-runtime-owner.json')));
  for (const row of [...prior.files, ...f.snapshots]) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
for (const attack of ['wrong-sha', 'wrong-review', 'wrong-failure', 'changed-intent', 'eligibility-exists', 'slot-collision', 'zero-get-proof']) test(`Batch36 ${attack} refuses without clearing earlier readonly failures or native fence`, async t => {
  const f = fixture(t), deployment = deploymentFixture(f), prior = await failedFreshnessFixture(f, deployment), old = join(f.root, ABANDONED_DIRECT_SLOT);
  if (attack === 'wrong-sha') prior.options.failedDirectEvidence = id(999);
  if (attack === 'wrong-review') prior.options.failedDirectReview = id(999);
  if (attack === 'wrong-failure') f.write(join(old, 'failure.json'), { version: 1, firstFailure: { phase: 'direct-http', code: 'DIRECT_TRANSPORT_FAILED' }, ...ABANDONED_TRUTH });
  if (attack === 'changed-intent') fs.appendFileSync(join(old, 'verification-intent.json'), ' ');
  if (attack === 'eligibility-exists') f.write(join(old, 'eligibility.json'), {});
  const slot = join(f.root, ABANDONED_PARALLEL_SLOT);
  if (attack === 'slot-collision') fs.mkdirSync(slot, { mode: 0o700 });
  const w = abandonWorkflow(f, deployment, attack === 'zero-get-proof' ? { quiescence: async () => ({ ...qualifyAbandonedQuiescence(f.first, f.first, c), observedAt: 0, readonly: { ...DIRECT_READONLY, requests: 0 } }) } : {});
  await assert.rejects(w.run(prior.options)); assert.ok(fs.existsSync(f.lock));
  if (attack === 'slot-collision') assert.deepEqual(fs.readdirSync(slot), []);
  else if (attack !== 'zero-get-proof') assert.equal(fs.existsSync(slot), false);
});
test('Batch36 reuses direct CLI contract plus exact failed-Batch35 pins; no slot/path/time/concurrency override', () => {
  const pairs = ['--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review,
    '--failed-review', failedReview, '--failed-archive-review', failedArchiveReview, '--failed-archive-evidence-sha256', id(900), '--failed-direct-review', review, '--failed-direct-evidence-sha256', id(901)];
  const args = ['--verify-abandoned-parallel', '--ack-new-coordinator-parallel-readonly-go', '--ack-unknown-liabilities-no-provider-retry', '--ack-preserved-freshness-refusal', ...pairs];
  assert.equal(reconcileMode(args).mode, 'abandon-verify-parallel');
  assert.equal(reconcileMode(['--archive-abandoned-parallel', '--ack-new-coordinator-abandon-archive-go', args[2], '--ack-exact-owned-native-fence-only', ...pairs, '--eligibility-sha256', id(902)]).mode, 'abandon-archive-parallel');
  for (let i = 0; i < args.length; i++) { const changed = [...args]; changed[i] = 'wrong'; assert.throws(() => reconcileMode(changed)); }
  for (const extra of ['--slot', '--path', '--max-concurrency', '--freshness-ms', '--retry-paid', '--passed']) assert.throws(() => reconcileMode([...args, extra]));
});
async function requalificationFixture(t) {
  const f = fixture(t), deployment = deploymentFixture(f); idleSupervisor(f);
  const prior = await failedFreshnessFixture(f, deployment), d = directReadFixture(f);
  const eligibility = await abandonWorkflow(f, deployment, { quiescence: d.run }).run(prior.options);
  let clock = 0;
  await assert.rejects(abandonWorkflow(f, deployment, { clock: () => clock, quiescence: async () => { const proof = await directReadFixture(f).run(); clock = 15000; return proof; },
    runtime: async () => { const { receipt } = deployment.capture(); return { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: clock, verify() {} }; }
  }).run({ ...prior.options, mode: 'abandon-archive-parallel', verification: eligibility.eligibilitySha256 }));
  const { verification: _verification, ...old } = prior.options; void _verification;
  const options = { ...old, mode: 'abandon-requalify-prepare', failedParallelReview: review, ordinal: 1, prepared: null };
  options.failedParallelEvidence = captureFailedParallelStage(f.root, options, captureAbandonedEvidence(f.root, selection, () => false)).evidenceSha256;
  const stage = join(f.root, ABANDONED_PARALLEL_SLOT), source = join(f.root, 'review-source.mjs'); f.write(source, 'export const reviewed = true;');
  const files = [...prior.files, ...f.snapshots, ...fs.readdirSync(stage).map(name => ({ path: join(stage, name), bytes: fs.readFileSync(join(stage, name)) }))];
  const state = { clock: 0, wall: Date.parse(createdAt), reads: 0, observations: 0, held: false, final: false, renamed: false };
  const settings = { root: f.root, sourcePaths: ['review-source.mjs'], capture: () => captureAbandonedEvidence(f.root, selection, () => false), alive: () => false,
    now: () => state.wall, clock: () => state.clock, getReview: async () => { assert.equal(state.final, false, 'no source hashing after final observation'); return review; },
    prepareRuntime: async () => { const { records, receipt } = deployment.capture(); let samples = 0; return { verify: records.verify, observe: async () => {
      assert.equal(state.held, true); assert.throws(() => inspectDeploySupervisor(f.root));
      state.observations++; const proof = { digest: qualifyAbandonedRuntime(deployment.observed, receipt), provenance: receipt.provenance, observedAt: state.clock };
      if (++samples === 2) state.final = true; return proof;
    } }; },
    quiescence: async () => { assert.equal(state.held, true); const d = directReadFixture(f); const proof = await createAbandonedDirectQuiescence({ ...d.settings, clock: () => state.clock })(); state.reads += d.state.requests.length; return proof; },
    acquireSupervisor: root => { const lease = acquireAbandonedSupervisor(root); state.held = true; return { verify: lease.verify, close() { state.held = false; lease.close(); } }; },
    io: { ...fs, renameSync(from, to) { assert.equal(state.final, true); assert.equal(state.held, true); fs.renameSync(from, to); state.renamed = true; } } };
  const run = overrides => async options => { state.final = false; return createAbandonedRequalification({ ...settings, ...overrides })(options); };
  return { f, deployment, options, files, stage, source, state, settings, run,
    commit: (prepared, ordinal = 1) => ({ ...options, mode: 'abandon-requalify-commit', ordinal, prepared: prepared.preparedSha256 }) };
}
test('requalification prepare→fresh→commit: slow preparation cannot age later real8GET; exact bare lease held through rename, old bytes preserved', async t => {
  const w = await requalificationFixture(t), prepared = await w.run()(w.options);
  assert.equal(w.state.reads, 0); assert.equal(w.state.observations, 0); assert.ok(fs.existsSync(w.f.lock));
  const run = w.run({ prepareRuntime: async (...args) => { w.state.clock += 60000; return w.settings.prepareRuntime(...args); } });
  const result = await run(w.commit(prepared));
  assert.equal(w.state.reads, 8); assert.equal(w.state.renamed, true); assert.equal(w.state.held, false); inspectDeploySupervisor(w.f.root);
  assert.equal(result.originalCorrelation, 'UNKNOWN_UNRECOVERABLE'); assert.equal(result.originalWire, 'FAILED_HTTP502_BODY_UNAVAILABLE');
  assert.equal(result.providerRetryAuthorized, false); assert.ok(fs.existsSync(join(w.stage, 'requalification/01/abandoned-operation.lock/native-runtime-owner.json')));
  for (const row of w.files) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
  const src = fs.readFileSync(new URL('./native-runtime-reconcile.mjs', import.meta.url), 'utf8');
  const fast = src.slice(src.indexOf('// FAST COMMIT BOUNDARY'), src.indexOf('syncDirectory(path); syncDirectory(join(root'));
  assert.doesNotMatch(fast.replace(/\/\/[^\n]*/g, ''), /\bawait\b|readFile|fsync|spawn|fingerprint\(|sha\(/);
});
for (const attack of ['expired-get', 'changed-current', 'changed-runtime', 'owner-replaced', 'source-replaced', 'source-inplace-restored-mtime', 'directory-member', 'supervisor-replaced', 'dead-process-revived'])
  test(`requalification refuses ${attack} after fresh reads, no rename/old evidence rewrite`, async t => {
    const w = await requalificationFixture(t), prepared = await w.run()(w.options);
    const run = w.run({ alive: () => attack === 'dead-process-revived', prepareRuntime: async (...args) => {
      const runtime = await w.settings.prepareRuntime(...args); return { ...runtime, observe: async () => {
        const result = await runtime.observe(); if (!w.state.final) return result;
        if (attack === 'expired-get') w.state.clock += 15000;
        if (attack === 'changed-runtime') result.digest = id(999);
        const target = attack === 'owner-replaced' ? join(w.f.lock, 'native-runtime-owner.json') : attack === 'supervisor-replaced' ? join(w.f.state, '.deploy-supervisor-v1.lock') : w.source;
        if (['owner-replaced', 'source-replaced', 'supervisor-replaced'].includes(attack)) { const bytes = fs.readFileSync(target); fs.renameSync(target, target + '.old'); w.f.write(target, bytes); }
        if (attack === 'source-inplace-restored-mtime') { const s = fs.statSync(target); fs.appendFileSync(target, ' '); fs.utimesSync(target, s.atime, s.mtime); }
        if (attack === 'directory-member') w.f.write(join(w.f.state, '.unknown.pending'), {});
        return result;
      } };
    }, ...(attack === 'changed-current' ? { quiescence: async () => { const result = await w.settings.quiescence(); result.currentObservation.user.used.input++; return result; } } : {}) });
    await assert.rejects(run(w.commit(prepared))); assert.equal(w.state.renamed, false); assert.equal(w.state.held, false); assert.ok(fs.existsSync(w.f.lock));
    const failure = JSON.parse(fs.readFileSync(join(w.stage, 'requalification/01/failure.json'))); assert.equal(failure.renameAttempted, false);
    for (const row of w.files) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
  });
test('requalification busy supervisor refuses before fresh reads and safely terminalizes own attempt', async t => {
  const w = await requalificationFixture(t), prepared = await w.run()(w.options);
  // Capture was already FREE; simulate another operator winning the race at the exact acquire boundary.
  const run = w.run({ acquireSupervisor(root) { busySupervisor(t, w.f, join(w.f.state, '.deploy-supervisor-v1.lock')); return acquireAbandonedSupervisor(root); } });
  await assert.rejects(run(w.commit(prepared))); assert.equal(w.state.reads, 0); assert.equal(w.state.observations, 0); assert.ok(fs.existsSync(w.f.lock));
});
test('requalification max3 explicit contiguous attempts; prepared/pending blocks next; only terminal pre-rename failure admits next GO', async t => {
  const w = await requalificationFixture(t);
  for (let ordinal = 1; ordinal <= 3; ordinal++) {
    const prepared = await w.run()({ ...w.options, ordinal });
    await assert.rejects(w.run()({ ...w.options, ordinal: ordinal + 1 }));
    const run = w.run({ quiescence: async () => { throw Error('PRIVATE_RAW_COOKIE_MUST_NOT_ESCAPE'); } });
    await assert.rejects(run(w.commit(prepared, ordinal)));
    const failure = fs.readFileSync(join(w.stage, 'requalification', String(ordinal).padStart(2, '0'), 'failure.json'), 'utf8');
    assert.equal(failure.includes('PRIVATE_RAW_COOKIE'), false); assert.equal(JSON.parse(failure).renameAttempted, false);
    await assert.rejects(w.run()(w.commit(prepared, ordinal)), /ABANDON_ATTEMPT_BLOCKED/);
  }
  await assert.rejects(w.run()({ ...w.options, ordinal: 4 }));
  assert.deepEqual(fs.readdirSync(join(w.stage, 'requalification')), ['01', '02', '03']); assert.ok(fs.existsSync(w.f.lock));
});
test('requalification post-rename uncertainty is retained and blocks every later attempt; never rollback', async t => {
  const w = await requalificationFixture(t), prepared = await w.run()(w.options);
  await assert.rejects(w.run({ io: { ...w.settings.io, renameSync(from, to) { w.settings.io.renameSync(from, to); throw Error('UNCONFIRMED'); } } })(w.commit(prepared)), /ABANDON_ARCHIVE_UNCERTAIN/);
  const path = join(w.stage, 'requalification/01'), failure = JSON.parse(fs.readFileSync(join(path, 'failure.json')));
  assert.equal(failure.renameAttempted, true); assert.ok(fs.existsSync(join(path, 'abandoned-operation.lock/native-runtime-owner.json')));
  await assert.rejects(w.run()({ ...w.options, ordinal: 2 })); assert.equal(w.state.held, false);
});
test('requalification prepared SHA/review/5minute lifetime cannot be waived; old stage pin tamper refused', async t => {
  for (const attack of ['sha', 'review', 'age', 'stage']) {
    const w = await requalificationFixture(t), prepared = await w.run()(w.options), options = w.commit(prepared);
    if (attack === 'sha') options.prepared = id(999);
    if (attack === 'review') options.review = id(999);
    if (attack === 'age') w.state.wall += 300001;
    if (attack === 'stage') fs.appendFileSync(join(w.stage, 'failure.json'), ' ');
    await assert.rejects(w.run()(options)); assert.equal(w.state.reads, 0); assert.ok(fs.existsSync(w.f.lock));
  }
});
test('pinned path membership rejects replacement with SAME bytes, and all fds close', t => {
  const f = fixture(t), path = join(f.root, 'source.mjs'); f.write(path, 'const a=1;');
  const pins = pinAbandonedPaths(f.root, [path]); fs.renameSync(path, path + '.old'); f.write(path, 'const a=1;');
  assert.throws(pins.verify, /ABANDON_PIN_CHANGED/); pins.close(); assert.throws(pins.verify, /ABANDON_PIN_CHANGED/);
});
test('requalification CLI exact prepare/commit GO, fixedBatch36, ordinal01..03, prepared SHA; no transport/time overrides', () => {
  const pairs = ['--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review,
    '--failed-review', failedReview, '--failed-archive-review', review, '--failed-archive-evidence-sha256', id(901), '--failed-direct-review', review,
    '--failed-direct-evidence-sha256', id(902), '--failed-parallel-review', review, '--failed-parallel-evidence-sha256', id(903), '--attempt', '01'];
  const args = ['--prepare-abandoned-requalification', '--ack-new-coordinator-requalification-prepare-go', '--ack-unknown-liabilities-no-provider-retry', '--ack-batch36-append-only-max-three', ...pairs];
  assert.equal(reconcileMode(args).mode, 'abandon-requalify-prepare'); assert.equal(reconcileMode(args).prepared, null);
  const commit = ['--commit-abandoned-requalification', '--ack-new-coordinator-requalification-commit-go', ...args.slice(2), '--prepared-sha256', id(904)];
  assert.equal(reconcileMode(commit).mode, 'abandon-requalify-commit');
  for (let i = 0; i < args.length; i++) { const next = [...args]; next[i] = 'wrong'; assert.throws(() => reconcileMode(next)); }
  for (const extra of ['--slot', '--cookie', '--freshness-ms', '--retry-paid']) assert.throws(() => reconcileMode([...args, extra]));
});
function ownerDockerRestart(deployment) {
  const observed = structuredClone(deployment.observed); let index = 0;
  for (const epoch of observed.epochs) if (!epoch.name.endsWith('volume-init')) {
    epoch.startedAt = new Date(Date.parse('2026-11-05T09:00:00.000Z') + index++ * 1000).toISOString(); epoch.pid += 1000;
  }
  return observed;
}
test('owner Docker restart qualifies all6 newer coherent starts with same8 immutable IDs/images/Created, init unchanged; original exact epoch branch still refuses', t => {
  const f = fixture(t), deployment = deploymentFixture(f), { receipt } = deployment.capture(), prior = structuredClone(receipt), observed = ownerDockerRestart(deployment);
  const result = qualifyOwnerDockerRestart(observed, receipt);
  assert.equal(result.restart.window.spreadMs, 5000); assert.equal(result.restart.epochs.length, 8);
  assert.equal(result.restart.nativeAuthorityAdopted, false); assert.deepEqual(receipt, prior);
  assert.throws(() => qualifyAbandonedRuntime(observed, receipt), /ABANDON_RUNTIME_EPOCH_CHANGED/);
});
for (const attack of ['replacement', 'retarget', 'created', 'partial-restart', 'init-restarted', 'noncoherent', 'restart-count', 'daemon', 'unhealthy'])
  test(`owner Docker restart refuses ${attack} without any epoch waiver`, t => {
    const f = fixture(t), deployment = deploymentFixture(f), { receipt } = deployment.capture(), observed = ownerDockerRestart(deployment);
    const gateway = observed.epochs.find(e => e.name === 'egress'), service = observed.status.services.find(e => e.name === 'egress');
    if (attack === 'replacement') { gateway.id = id(999); service.id = gateway.id; }
    if (attack === 'retarget') { gateway.image = 'sha256:' + id(999); service.image = gateway.image; }
    if (attack === 'created') gateway.created = '2026-11-04T00:00:00.000Z';
    if (attack === 'partial-restart') gateway.startedAt = receipt.expected.egress.startedAt;
    if (attack === 'init-restarted') observed.epochs.find(e => e.name === 'auth-volume-init').startedAt = gateway.startedAt;
    if (attack === 'noncoherent') gateway.startedAt = '2026-11-05T09:02:00.000Z';
    if (attack === 'restart-count') { gateway.restartCount = 1; service.restartCount = 1; }
    if (attack === 'daemon') observed.status.daemon = 'different-daemon';
    if (attack === 'unhealthy') service.healthy = false;
    assert.throws(() => qualifyOwnerDockerRestart(observed, receipt));
  });
for (const drift of [false, true, 'window-rollover', 'window-drift']) test(`owner Docker restart prepared protocol ${drift === true ? 'rejects CURRENT epoch drift' : drift || 'pins independent CURRENT epochs and commits only matching repeated reads'}`, async t => {
  const w = await requalificationFixture(t), observed = ownerDockerRestart(w.deployment), options = { ...w.options, mode: 'abandon-requalify-docker-prepare' };
  const run = w.run({ prepareRuntime: async (...args) => {
    assert.equal(args[6], true); const { records, receipt } = w.deployment.capture(); let samples = 0;
    return { verify: records.verify, observe: async () => {
      assert.equal(w.state.held, true); assert.throws(() => inspectDeploySupervisor(w.f.root));
      const proof = qualifyOwnerDockerRestart(observed, receipt); w.state.observations++;
      if (++samples === 2) w.state.final = true;
      return { ...proof, observedAt: w.state.clock, provenance: receipt.provenance };
    } };
  } });
  let ordinal = 1;
  if (typeof drift === 'string') {
    const first = await run(options), firstPath = join(w.stage, 'requalification/01/prepared.json'), firstBytes = fs.readFileSync(firstPath);
    w.f.first.usage.window.start += 86400000; w.f.first.usage.window.end += 86400000;
    for (const scope of ['user', 'scan']) {
      const usage = w.f.first.usage[scope]; usage.used = { input: 123, output: 45, costMicros: 67 };
      usage.remaining.input = usage.limits.input - usage.used.input - usage.carried.input;
      usage.remaining.output = usage.limits.output - usage.used.output - usage.carried.output;
    }
    await assert.rejects(run({ ...w.commit(first), mode: 'abandon-requalify-docker-commit' }), /ABANDON_CURRENT_OBSERVATION_CHANGED/);
    assert.equal(JSON.parse(fs.readFileSync(join(w.stage, 'requalification/01/failure.json'))).renameAttempted, false);
    assert.deepEqual(fs.readFileSync(firstPath), firstBytes); ordinal = 2;
  }
  const prepared = await run({ ...options, ordinal }), path = join(w.stage, 'requalification', String(ordinal).padStart(2, '0'), 'prepared.json'), constraint = JSON.parse(fs.readFileSync(path));
  assert.deepEqual(constraint.candidate.restart.epochs, observed.epochs); assert.ok(fs.existsSync(w.f.lock));
  assert.equal(constraint.candidate.observationBasis, 'FRESH_PREPARE_TWO_DIRECT_GET_SAMPLES_NOT_HISTORICAL_USAGE');
  assert.equal(constraint.candidate.quiescence.currentObservation.window.start, w.f.first.usage.window.start);
  assert.deepEqual(constraint.candidate.quiescence.currentObservation.user.used, w.f.first.usage.user.used);
  if (drift === true) observed.epochs.find(e => e.name === 'api').pid++;
  if (drift === 'window-drift') { w.f.first.usage.window.start += 86400000; w.f.first.usage.window.end += 86400000; }
  const commit = { ...w.commit(prepared, ordinal), mode: 'abandon-requalify-docker-commit' };
  if (drift === true || drift === 'window-drift') { await assert.rejects(run(commit), drift === true ? /ABANDON_RUNTIME_CHANGED/ : /ABANDON_CURRENT_OBSERVATION_CHANGED/); assert.ok(fs.existsSync(w.f.lock)); }
  else { const result = await run(commit); assert.equal(result.providerRetryAuthorized, false); assert.equal(result.accountingMutation, 'NONE'); assert.equal(w.state.reads, ordinal === 1 ? 16 : 32); assert.equal(w.state.renamed, true); }
  assert.equal(w.state.held, false); for (const row of w.files) assert.deepEqual(fs.readFileSync(row.path), row.bytes);
});
test('owner Docker restart CLI requires distinct mode AND exact owner-started acknowledgement, never a caller epoch JSON grant', () => {
  const pairs = ['--deployment', selection.deployment, '--native-attempt', selection.attempt, '--original-review', selection.originalReview, '--review', review,
    '--failed-review', failedReview, '--failed-archive-review', review, '--failed-archive-evidence-sha256', id(901), '--failed-direct-review', review,
    '--failed-direct-evidence-sha256', id(902), '--failed-parallel-review', review, '--failed-parallel-evidence-sha256', id(903), '--attempt', '01'];
  const args = ['--prepare-abandoned-owner-docker-requalification', '--ack-new-coordinator-requalification-prepare-go', '--ack-unknown-liabilities-no-provider-retry',
    '--ack-batch36-append-only-max-three', '--ack-owner-started-docker-same-containers-no-native-adoption', ...pairs];
  assert.equal(reconcileMode(args).mode, 'abandon-requalify-docker-prepare');
  const commit = ['--commit-abandoned-owner-docker-requalification', '--ack-new-coordinator-requalification-commit-go', ...args.slice(2), '--prepared-sha256', id(904)];
  assert.equal(reconcileMode(commit).mode, 'abandon-requalify-docker-commit');
  assert.throws(() => reconcileMode(args.filter((_, i) => i !== 4)));
  for (const extra of ['--epochs', '--window-ms', '--adopt-native', '--retry-paid']) assert.throws(() => reconcileMode([...args, extra]));
});
test('inert executable and fingerprint touch source only; separate reconciler files are reviewed without rewriting original review list', async () => {
  const file = new URL('./native-runtime-reconcile.mjs', import.meta.url).pathname;
  const result = spawnSync(process.execPath, [file], { timeout: 10000, encoding: 'utf8' });
  assert.equal(result.status, 0); assert.match(result.stdout, /INERT.*NO_PRIVATE_READS_NO_NETWORK/);
  assert.ok(RECONCILE_REVIEW_FILES.includes('scripts/native-runtime-reconcile.test.mjs'));
  assert.match(await reconcileFingerprint(), /^[a-f0-9]{64}$/);
});
