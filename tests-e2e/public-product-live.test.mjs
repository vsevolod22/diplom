// Offline pure guards only: no browser/server/scanner, credentials, key files or native state.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import test from 'node:test';
import { ORIGIN, SCANS, CHECKS, TARGETS, parseMode, fixedUrl, allowedGet, validIntent, eligibilityReady,
  EligibilityFence, awaitEligibility, awaitStableUiEligibility, uiLaunchReady, PhaseEvidence, progressExpectation, progressSampleMatches, consumePermit, partition, cancelVerdict, preservationVerdict, keyBoundaryAllowed, checkPage, readAllPages, loadContracts, safeMeta, ResultBook, GLOBAL_MS, WORKER_MS,
    BROWSER_ARGS, BROWSER_READ_STAGES, BROWSER_READ_CAUSES, BrowserReadError, browserReadFailureMeta, classifyBrowserReadFailure, trackBrowserReadPage, readBrowserJson, settleReportNavigation, settleAuthNavigation, safeMutationRequest, allowedApiGet, safeReadRequest, runtimeProbeRead, assertRuntimeOffReply, assertDeniedReply, assertChatUsage, renderedRowParts, paginationVerdict, evidenceDocuments, writeEvidence,
    SMOKE_MS, CANCEL_MS, nativePlan, scanLaunchAllowed, smokeMutationAllowed, cancelMutationAllowed, completedChecks, durableProgress, checkpointChecks, cancelObservation, assertCancelOutcomePreservation, resultExitCode, assertAuthUser, failureMeta } from './public-product-live.mjs';

const id = '12345678-1234-4234-8234-123456789abc';
const ready = target => ({ imageReference: target.reference, eligible: true, reason: 'READY', eligibility: 'public-hub-profile', allowedCheckSets: [[...CHECKS]] });
const intent = target => ({ imageReference: target.reference, scope: 'image', checks: [...CHECKS], idempotencyKey: 'offline-idempotency' });

test('default is not-run; full explicit GO/no-key-activation acknowledgements required', () => {
  assert.equal(parseMode([]), 'not-run');
  assert.equal(parseMode(['--self-test']), 'offline');
  assert.equal(parseMode(['--run', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', id]), 'native');
  for (const args of [['--run'], ['--run', '--ack-coordinator-go'], ['--native-child'], ['--run-native'], ['--url', ORIGIN], ['--self-test', '--run'], ['--run', '--ack-coordinator-go', '--ack-no-key-activation', '--target=other']]) assert.throws(() => parseMode(args));
});

test('auth user identity is the backend 32-hex ID, not a scan UUID, and remains bound across login', () => {
  const subject = '0123456789abcdef0123456789abcdef', email = 'offline@example.invalid';
  assert.equal(assertAuthUser({ id: subject, email }, email), subject);
  assert.equal(assertAuthUser({ id: subject, email }, email, subject), subject);
  for (const user of [null, { id, email }, { id: subject.toUpperCase(), email }, { id: subject.slice(1), email }, { id: subject, email: 'other@example.invalid' }, { id: subject, email, token: 'synthetic' }]) assert.throws(() => assertAuthUser(user, email));
  assert.throws(() => assertAuthUser({ id: subject, email }, email, 'f'.repeat(32)));
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  assert.ok(source.includes('account.subject = assertAuthUser(me.value, account.email, account.subject)'));
  assert.equal(source.includes('UUID.test(me.value.id)'), false);
});

test('one-scan smoke requires the exact run flag and both GO/no-key acknowledgements', () => {
  assert.equal(parseMode(['--run', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', id]), 'smoke');
  for (const args of [
    ['--smoke-only'], ['--run', '--smoke-only'], ['--run', '--smoke-only', '--ack-coordinator-go'],
    ['--run', '--smoke-only', '--ack-no-key-activation'],
    ['--run', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation', '--target=debian'],
    ['--self-test', '--smoke-only'], ['--run', '--smoke-only', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation'],
  ]) assert.throws(() => parseMode(args));
});

test('smoke shares the fixed Node target/four checks but has a hard one-launch, 15-minute budget', () => {
  const plan = nativePlan('smoke');
  assert.deepEqual(plan.targets, [TARGETS[0]]); assert.equal(plan.maxScans, 1);
  assert.equal(plan.globalMs, SMOKE_MS); assert.equal(SMOKE_MS, 15 * 60000); assert.ok(SMOKE_MS > WORKER_MS);
  assert.ok(Object.isFrozen(plan) && Object.isFrozen(plan.targets) && Object.isFrozen(plan.cases));
  assert.ok(scanLaunchAllowed(plan, TARGETS[0], 0));
  for (const [target, launches] of [[TARGETS[0], 1], [TARGETS[0], -1], [TARGETS[0], NaN], [TARGETS[1], 0], [{ ...TARGETS[0] }, 0]]) assert.equal(scanLaunchAllowed(plan, target, launches), false);
  assert.ok(validIntent(intent(plan.targets[0]), plan.targets[0]));
  const full = nativePlan(); assert.deepEqual(full.targets, TARGETS); assert.equal(full.maxScans, 3); assert.equal(full.globalMs, GLOBAL_MS);
  assert.ok(scanLaunchAllowed(full, TARGETS[1], 2)); assert.equal(scanLaunchAllowed(full, TARGETS[0], 3), false);
  assert.throws(() => nativePlan('other'));
});

test('smoke mutation gate forbids every LLM POST, cancel, foreign routes and query overrides even with a permit', () => {
  for (const path of ['/api/v1/auth/register', '/api/v1/auth/login', SCANS, `${SCANS}/images/eligibility`]) assert.ok(smokeMutationAllowed(path));
  for (const path of [`${SCANS}/${id}/llm/chat`, `${SCANS}/${id}/llm/summary`, `${SCANS}/${id}/llm/history/decision`, `${SCANS}/${id}/cancel`, `${SCANS}?extra=1`, '/api/v1/admin', '/api/v1/auth/logout']) assert.equal(smokeMutationAllowed(path), false);
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const gate = source.indexOf('plan.smokeOnly && !smokeMutationAllowed(u.pathname)');
  assert.ok(gate > 0 && gate < source.indexOf('if (consumePermit(state.permit'));
  assert.equal(source.includes('stats.scanLaunches < 3'), false);
});

test('smoke evidence has only selected assertions, no provider qualification and distinct exclusive launch paths', async () => {
  const book = new ResultBook('smoke'), evidence = book.evidence(), full = nativePlan();
  assert.equal(evidence.scope, 'native-public8081-one-scan-smoke');
  assert.equal(evidence.generationPolicy, 'readiness-only-no-llm-posts');
  assert.equal(evidence.providerGenerationQualified, false); assert.equal(evidence.providerDispatchIndependentlyObserved, false);
  for (const required of ['node.scan', 'node.report', 'node.filters', 'node.reload', 'scan_history', 'llm_readiness', 'llm_reload', 'fresh_login', 'llm_fresh_login', 'safety']) assert.ok(required in evidence.cases);
  for (const excluded of ['debian.scan', 'node.pagination', 'node.events', 'foreign_registration', 'cancel', 'llm_no_consent', 'llm_missing_key', 'llm_manual_history']) {
    assert.equal(excluded in evidence.cases, false); assert.throws(() => book.record(excluded, 'PASS', 'VERIFIED'));
  }
  const paths = [];
  await writeEvidence(evidence, async (path, mode, permissions) => {
    paths.push(path); assert.equal(mode, 'wx'); assert.equal(permissions, 0o600);
    return { writeFile: async () => {}, sync: async () => {}, close: async () => {} };
  });
  assert.deepEqual(paths.map(path => path.split('/').at(-1)), ['public8081launch-20261022.attempt2.json', 'public8081launch-20261022.attempt2.md']);
  assert.ok(paths.every(path => !full.evidencePaths.includes(path)));
  assert.equal(evidence.evidenceRoot, 'docs/public8081launch-20261022.attempt2');
  assert.ok(paths.every(path => !path.endsWith('/public8081launch-20261022.json') && !path.endsWith('/public8081launch-20261022.md')));
  const [json, md] = evidenceDocuments(evidence);
  assert.equal(JSON.parse(json).mode, 'smoke'); assert.ok(md.includes('no LLM POST'));
});

test('cancel-only accepts only its exact acknowledged CLI with a fresh UUID; mixed modes and overrides refuse', () => {
  const flags = ['--run', '--cancel-only', '--ack-coordinator-go', '--ack-no-key-activation'];
  assert.equal(parseMode([...flags, '--attempt-id', id]), 'cancel');
  for (const args of [flags, ['--cancel-only'], ['--run', '--cancel-only'],
    ['--run', '--cancel-only', '--ack-coordinator-go', '--attempt-id', id],
    ['--run', '--cancel-only', '--ack-no-key-activation', '--attempt-id', id],
    ['--run', '--cancel-only', '--ack-coordinator-readygo', '--ack-no-key-activation', '--attempt-id', id],
    [...flags, '--attempt-id', '../attempt2'], [...flags, '--attempt-id', id, '--target=other'],
    ['--run', '--smoke-only', ...flags.slice(1), '--attempt-id', id],
    [...flags, '--cancel-only', '--attempt-id', id],
  ]) assert.throws(() => parseMode(args));
});

test('cancel-only plan has one fixed four-check Node launch and only cancellation durability cases', () => {
  const plan = nativePlan('cancel', id);
  assert.equal(plan.cancelOnly, true); assert.equal(plan.smokeOnly, false);
  assert.deepEqual(plan.targets, [TARGETS[0]]); assert.equal(plan.maxScans, 1);
  assert.equal(plan.globalMs, CANCEL_MS); assert.equal(CANCEL_MS, 15 * 60000); assert.ok(CANCEL_MS > WORKER_MS);
  assert.ok(scanLaunchAllowed(plan, TARGETS[0], 0));
  for (const [target, launches] of [[TARGETS[0], 1], [TARGETS[0], 2], [TARGETS[1], 0], [{ ...TARGETS[0] }, 0]]) assert.equal(scanLaunchAllowed(plan, target, launches), false);
  assert.ok(validIntent(intent(plan.targets[0]), plan.targets[0]));
  assert.deepEqual(plan.cases, ['tooling', 'registration', 'cancel', 'cancel_progress', 'cancel_report', 'cancel_preservation', 'cancel_reload', 'cancel_history', 'cancel_fresh_login', 'safety']);
  assert.ok(Object.isFrozen(plan) && Object.isFrozen(plan.targets) && Object.isFrozen(plan.cases));
  assert.throws(() => nativePlan('cancel')); assert.throws(() => nativePlan('cancel', 'attempt3'));
  const book = new ResultBook('cancel', id);
  for (const name of ['node.scan', 'debian.scan', 'llm_readiness', 'llm_missing_key', 'llm_no_consent', 'llm_manual_history', 'llm_generation', 'ownership_mutations']) assert.throws(() => book.record(name, 'PASS', 'VERIFIED'));
});

test('cancel-only hard gate rejects ALL LLM POST paths even with permits and only permits known-scan cancellation', () => {
  for (const path of ['/api/v1/auth/register', '/api/v1/auth/login', SCANS, `${SCANS}/images/eligibility`, `${SCANS}/${id}/cancel`]) assert.equal(cancelMutationAllowed(path, [id]), true);
  for (const suffix of ['chat', 'summary', 'translation', 'history/decision', 'history', 'chat/context', 'readiness', 'unknown']) assert.equal(cancelMutationAllowed(`${SCANS}/${id}/llm/${suffix}`, [id]), false);
  for (const path of [`${SCANS}/${id}/cancel?x=1`, `${SCANS}/${id}/cancel/extra`, `${SCANS}/${id}/cancel/`, `${SCANS}?x=1`, '/api/v1/auth/logout', '/api/v1/admin', '/api/v1/browser/runtime/consents']) assert.equal(cancelMutationAllowed(path, [id]), false);
  assert.equal(cancelMutationAllowed(`${SCANS}/${id}/cancel`, []), false);
  assert.equal(cancelMutationAllowed(`${SCANS}/private/cancel`, ['private']), false);
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const gate = source.indexOf('!cancelMutationAllowed(u.pathname, scans.keys())');
  assert.ok(gate > 0 && gate < source.indexOf('if (consumePermit(state.permit'));
  assert.ok(source.includes("u.pathname.endsWith('/cancel') && stats.cancelPosts >= 1"));
  assert.ok(source.includes("u.pathname === '/api/v1/auth/register' && stats.accountsCreated >= 1"));
});

const progressOf = (outcomes = {}) => {
  const values = { ...Object.fromEntries(CHECKS.map(check => [check, null])), ...outcomes };
  return { basis: 'durable-outcomes-v1', requestedChecks: [...CHECKS], outcomes: values,
    resolvedChecks: Object.values(values).filter(value => value !== null).length,
    checkedChecks: Object.values(values).filter(value => value === 'checked').length };
};
test('cancel waits for checked durable progress, never private running perCheck; terminal wins the race', () => {
  assert.deepEqual(completedChecks({ perCheck: { secret: { outcome: 'checked' }, sbom: { outcome: 'failed' }, config: { outcome: 'checked' } } }), ['secret', 'config']);
  for (const perCheck of [undefined, {}, { secret: null }, { secret: { outcome: 'checked', findingCount: 0 } }]) assert.equal(cancelObservation({ state: 'running', perCheck }), 'waiting');
  for (const outcomes of [{}, { secret: 'failed' }, { sbom: 'unsupported', config: 'skipped' }]) assert.equal(cancelObservation({ state: 'running', progress: progressOf(outcomes) }), 'waiting');
  for (const check of CHECKS) {
    const snapshot = { state: 'running', perCheck: Object.fromEntries(CHECKS.map(key => [key, null])), progress: progressOf({ [check]: 'checked' }) };
    assert.equal(cancelObservation(snapshot), 'ready'); assert.deepEqual(checkpointChecks(snapshot), [check]);
  }
  for (const state of ['completed', 'partial', 'failed', 'cancelled']) assert.equal(cancelObservation({ state, progress: progressOf({ secret: 'checked' }) }), 'terminal');
});

test('cancel-only cannot pass missing, blocked or inconclusive criteria, including terminal races', () => {
  const book = new ResultBook('cancel', id); assert.equal(resultExitCode(book), 2);
  for (const name of book.plan.cases) book.record(name, 'PASS', 'VERIFIED');
  assert.equal(resultExitCode(book), 0);
  for (const name of book.plan.cases) {
    book.record(name, 'INCONCLUSIVE', 'CANCEL_RACE'); assert.equal(resultExitCode(book), 2);
    book.record(name, 'PASS', 'VERIFIED');
    book.record(name, 'BLOCKED', 'PREREQUISITE_UNAVAILABLE'); assert.equal(resultExitCode(book), 2);
    book.record(name, 'PASS', 'VERIFIED');
  }
  book.record('cancel', 'INCONCLUSIVE', 'NO_COMPLETED_SUBSET_OBSERVED'); assert.equal(resultExitCode(book), 2);
  book.record('cancel', 'BLOCKED', 'ASSERTION_FAILED'); assert.equal(resultExitCode(book), 1);
  book.record('cancel', 'PASS', 'VERIFIED'); assert.equal(resultExitCode(book), 1);
});

test('cancel-only evidence is exclusive new cancel UUID paths, no key-absent condition or historical overwrite', async () => {
  const book = new ResultBook('cancel', id), evidence = book.evidence(), opened = [];
  assert.equal(evidence.scope, 'native-public8081-one-scan-cancel');
  assert.equal(evidence.generationPolicy, 'all-llm-posts-denied'); assert.equal(evidence.providerGenerationQualified, false);
  await writeEvidence(evidence, async (path, mode, permissions) => {
    opened.push(path); assert.equal(mode, 'wx'); assert.equal(permissions, 0o600);
    return { writeFile: async () => {}, sync: async () => {}, close: async () => {} };
  });
  assert.deepEqual(opened.map(path => path.split('/').at(-1)), [`public-final-${id}-cancel.json`, `public-final-${id}-cancel.md`]);
  assert.ok(opened.every(path => !nativePlan().evidencePaths.includes(path) && !nativePlan('smoke').evidencePaths.includes(path)));
  const [json, md] = evidenceDocuments(evidence);
  assert.equal(JSON.parse(json).mode, 'cancel');
  assert.ok(md.includes('key presence is irrelevant')); assert.ok(md.includes('All LLM POSTs are denied'));
});

test('cancel-only source branches before all full/LLM flows and reuses real UI eligibility, confirm, durable reads and fresh login', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const branch = source.indexOf('if (plan.cancelOnly) {\n        await runCancellation();\n        return;\n      }');
  assert.ok(branch > 0 && branch < source.indexOf('for (const target of plan.targets)'));
  assert.ok(branch < source.indexOf("await step('llm_readiness'"));
  const cancellation = source.slice(source.indexOf('async function runCancellation()'), source.indexOf('    })()]);', source.indexOf('async function runCancellation()')));
  for (const forbidden of ['keyBoundaryAllowed(', 'readChat(', 'openChat(', 'llmPath', 'DECISION', 'QUESTION']) assert.equal(cancellation.includes(forbidden), false);
  for (const required of ['await launch(own, TARGETS[0])', 'plan.cancelOnly ? WORKER_MS : 20_000', "cancelObservation(before) === 'waiting'", 'checkpointChecks(before)', "dialog.type() === 'confirm'", "dialog.message() === 'Отменить скан?", "await step('cancel_report'", "await step('cancel_reload'", "await step('cancel_history'", "await step('cancel_fresh_login'", "await auth(own, owner, 'login')", 'assert.equal((await own.context.cookies()).length, 0)', 'assert.deepEqual(final, after)', 'if (plan.cancelOnly && focusedReports) assert.deepEqual(reports, focusedReports)']) assert.ok(cancellation.includes(required), required);
  assert.equal((cancellation.match(/await launch\(/g) ?? []).length, 1);
  assert.ok(source.includes('if (!plan.cancelOnly) book.record(\'llm_generation\''));
  assert.ok(source.includes('plan.smokeOnly || plan.cancelOnly'));
});

test('failure diagnostics project only runner line numbers, never raw stack/credentials/payload', () => {
  const error = new Error('SYNTHETIC_PRIVATE_MARKER');
  error.stack = 'SYNTHETIC_PRIVATE_MARKER\n    at auth (file:///synthetic/tests-e2e/public-product-live.mjs:431:12)';
  assert.deepEqual(failureMeta(error), { runnerLine: 431 });
  assert.equal(JSON.stringify(failureMeta(error)).includes('SYNTHETIC_PRIVATE_MARKER'), false);
  assert.deepEqual(failureMeta({ stack: 'other-module.mjs:5:10' }), {});
  assert.deepEqual(failureMeta({ stack: 'public-product-live.mjs:9999999:1' }), {});
  assert.deepEqual(failureMeta(null), {});
  assert.deepEqual(safeMeta({ digest: 'sha256:' + 'a'.repeat(64), platform: 'linux/amd64' }), { digest: 'sha256:' + 'a'.repeat(64), platform: 'linux/amd64' });
  assert.deepEqual(safeMeta({ digest: 'SYNTHETIC_PRIVATE_MARKER', platform: 'other' }), {});
});

test('smoke cannot exit successfully with missing, blocked or inconclusive selected assertions', () => {
  const book = new ResultBook('smoke'); assert.equal(resultExitCode(book), 2);
  book.record('llm_generation', 'BLOCKED', 'GENERATION_NOT_AUTHORIZED');
  for (const name of book.plan.cases.filter(name => name !== 'llm_generation')) book.record(name, 'PASS', 'VERIFIED');
  assert.equal(resultExitCode(book), 0);
  book.record('llm_readiness', 'BLOCKED', 'KEY_NOT_ABSENT_NO_POST'); assert.equal(resultExitCode(book), 2);
  book.record('llm_readiness', 'PASS', 'VERIFIED');
  book.record('node.report', 'INCONCLUSIVE', 'PREREQUISITE_UNAVAILABLE'); assert.equal(resultExitCode(book), 2);
  book.record('node.report', 'BLOCKED', 'ASSERTION_FAILED'); assert.equal(resultExitCode(book), 1);
  book.record('node.report', 'PASS', 'VERIFIED'); assert.equal(resultExitCode(book), 1);
});

test('exact public origin: no old port, localhost, credentials, fragments, redirect destinations', () => {
  assert.ok(fixedUrl(`${ORIGIN}/scans`));
  assert.ok(fixedUrl(`${ORIGIN}${SCANS}?limit=100`));
  for (const value of ['http://127.0.0.1:8080/scans', 'http://localhost:8081/scans', 'https://127.0.0.1:8081/scans', 'http://[::1]:8081/scans', 'http://127.0.0.1:8081@outside.invalid/scans', `${ORIGIN}/scans#other`, 'http://user:synthetic@127.0.0.1:8081/scans', `${ORIGIN}.outside.invalid/scans`]) assert.equal(fixedUrl(value), false);
});

test('GET allowlist contains actual report/LLM routes and known scan IDs only', () => {
  for (const suffix of ['', '/events', '/results', '/sbom', '/vuln', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage']) assert.ok(allowedGet(`${SCANS}/${id}${suffix}`, [id]));
  assert.ok(allowedGet('/api/v1/auth/me', [])); assert.ok(allowedGet(SCANS, []));
  for (const path of [`${SCANS}/${id}/llm/chat`, `${SCANS}/${id}/cancel`, `${SCANS}/${id}/runtime`, `${SCANS}/images`, '/api/v1/admin', `${SCANS}/${id}/llm/history/decision`]) assert.equal(allowedGet(path, [id]), false);
  assert.equal(allowedGet(`${SCANS}/${id}`, []), false);
});

test('two fixed image targets; exact image-only canonical four-check intent', () => {
  assert.equal(TARGETS.length, 2);
  for (const target of TARGETS) {
    assert.ok(validIntent(intent(target), target));
    for (const mutation of [{ scope: 'host' }, { platform: 'linux/arm64' }, { checks: ['secret'] }, { checks: [...CHECKS].reverse() }, { imageReference: 'registry-1.docker.io/library/node:latest' }, { idempotencyKey: '' }, { key: 'synthetic' }]) assert.equal(validIntent({ ...intent(target), ...mutation }, target), false);
  }
  assert.equal(validIntent(intent(TARGETS[0]), TARGETS[1]), false);
});

test('fresh real full-check eligibility grant is sequence/target/time fenced', () => {
  const fence = new EligibilityFence(), target = TARGETS[0];
  const body = { imageReference: target.reference, checks: [...CHECKS] };
  const old = fence.start(), current = fence.start();
  fence.accept(old, body, ready(target), target, 1000); assert.equal(fence.fresh(0, 1001), false);
  fence.accept(current, body, ready(target), target, 1000);
  assert.ok(fence.fresh(current - 1, 1001)); assert.equal(fence.fresh(current, 1001), false);
  assert.equal(fence.fresh(0, 999), false); assert.equal(fence.fresh(0, 31001), false);
  fence.start(); assert.equal(fence.fresh(0, 1001), false);
  for (const mutation of [{ eligible: false }, { reason: 'DB_UNAVAILABLE' }, { allowedCheckSets: [['secret']] }, { imageReference: TARGETS[1].reference }]) assert.equal(eligibilityReady({ ...ready(target), ...mutation }, target), false);
  const seq = fence.start(); fence.accept(seq, { ...body, checks: ['secret'] }, ready(target), target, 1000); assert.equal(fence.fresh(0, 1001), false);
});

test('create guard waits for genuine eligibility inspection, not browser response delivery order', async () => {
  const fence = new EligibilityFence(), target = TARGETS[0];
  const sequence = fence.start();
  let finish, settled = false;
  const pending = new Promise(resolve => { finish = () => {
    fence.accept(sequence, { imageReference: target.reference, checks: CHECKS }, ready(target), target);
    resolve();
  }; });
  assert.equal(fence.fresh(sequence - 1), false);
  const allowed = awaitEligibility(fence, sequence - 1, pending, () => true).then(value => { settled = true; return value; });
  await Promise.resolve(); assert.equal(settled, false);
  finish(); assert.equal(await allowed, true);
});

test('eligibility wait rechecks abort/authority and bounds missing or rejected responses', async () => {
  const fence = new EligibilityFence(), target = TARGETS[0], sequence = fence.start();
  fence.accept(sequence, { imageReference: target.reference, checks: CHECKS }, ready(target), target);
  assert.equal(await awaitEligibility(fence, sequence - 1, Promise.resolve(), () => false), false);
  fence.start();
  assert.equal(await awaitEligibility(fence, sequence - 1, Promise.resolve(), () => true), false);
  await assert.rejects(awaitEligibility(fence, 0, new Promise(() => {}), () => true, 1));
  await assert.rejects(awaitEligibility(fence, 0, Promise.reject(new Error('synthetic response failure')), () => true));
});

// Controlled scheduling proof only; this does not diagnose historical f086.
async function withEligibilityClient(operation) {
  process.env.TSX_DISABLE_CACHE = '1';
  const require = createRequire(new URL('../server/api/package.json', import.meta.url));
  const manifest = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
  const { EligibilityClient } = await tsImport(new URL('../src/shared/api/scans/eligibilityClient.ts', import.meta.url).pathname, { parentURL: import.meta.url, tsconfig: false });
  const previousFetch = globalThis.fetch, previousWindow = globalThis.window;
  const reads = [], clients = [];
  globalThis.window = { setTimeout, clearTimeout };
  globalThis.fetch = (path, init) => new Promise((resolve, reject) => {
    assert.equal(path, `${SCANS}/images/eligibility`); assert.equal(init.method, 'POST');
    const read = { body: JSON.parse(init.body), signal: init.signal, finish: (value, status = 200) => resolve(new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } })) };
    reads.push(read);
    init.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  });
  const client = (current = () => true, onWait = () => {}) => {
    const value = new EligibilityClient(current, onWait); clients.push(value); return value;
  };
  try { await operation({ client, reads }); }
  finally { for (const value of clients) value.retire(); globalThis.fetch = previousFetch; if (previousWindow === undefined) delete globalThis.window; else globalThis.window = previousWindow; }
}

test('controlled real EligibilityClient: external READY does not settle pending UI or commit its readiness', async () => {
  await withEligibilityClient(async ({ client, reads }) => {
    const coordinator = client(), fence = new EligibilityFence(), target = TARGETS[0];
    let uiReady = false;
    const ui = coordinator.request(target.reference, CHECKS).then(value => { uiReady = eligibilityReady(value, target); });
    const externalSequence = fence.start();
    fence.accept(externalSequence, { imageReference: target.reference, checks: CHECKS }, ready(target), target);
    assert.equal(fence.fresh(0), true); assert.equal(uiReady, false); assert.equal(reads.length, 1);
    reads[0].finish(ready(target)); await ui; assert.equal(uiReady, true);
  });
});

test('controlled real EligibilityClient: dedupes hints, serializes fresh submit, discards obsolete consumer', async () => {
  await withEligibilityClient(async ({ client, reads }) => {
    const coordinator = client(), target = TARGETS[0]; let current = true;
    const hint = coordinator.request(target.reference, ['secret']);
    const shared = coordinator.request(target.reference, ['secret']);
    const obsolete = coordinator.request(target.reference, ['sbom'], false, () => current).catch(error => error);
    const fresh = coordinator.request(target.reference, CHECKS, true);
    current = false; assert.equal(reads.length, 1);
    reads[0].finish(ready(target)); await hint; await shared;
    assert.equal((await obsolete).name, 'AbortError'); assert.equal(reads.length, 2);
    assert.deepEqual(reads[1].body.checks, CHECKS);
    reads[1].finish(ready(target)); await fresh;
    assert.equal(reads.length, 2);
  });
});

test('controlled real EligibilityClient: session change and retire cannot authorize a queued submit', async () => {
  await withEligibilityClient(async ({ client, reads }) => {
    let current = true; const coordinator = client(() => current);
    const hint = coordinator.request(TARGETS[0].reference, CHECKS).catch(error => error);
    const fresh = coordinator.request(TARGETS[0].reference, CHECKS, true).catch(error => error);
    current = false; reads[0].finish(ready(TARGETS[0]));
    assert.ok(await hint instanceof Error); assert.ok(await fresh instanceof Error); assert.equal(reads.length, 1);
    const other = client();
    const pending = other.request(TARGETS[0].reference, CHECKS).catch(error => error);
    other.retire(); assert.equal((await pending).name, 'AbortError'); assert.equal(reads.length, 2);
  });
});

const uiReady = (confirmed = false) => ({ formPresent: true, referenceMatches: true, inputEnabled: true, inputValid: true,
  checksMatch: true, checksEnabled: true, consentEnabled: true, consentChecked: confirmed, submitEnabled: confirmed,
  uiEligibilityReady: true, hasAlert: false, waitActive: false });
function stableFixture() {
  let time = 1000;
  const fence = new EligibilityFence(), state = { fence, eligibilityPending: Promise.resolve() };
  const grant = (target = TARGETS[0], checks = CHECKS) => {
    const sequence = fence.start(); fence.accept(sequence, { imageReference: target.reference, checks }, ready(target), TARGETS[0], time); return sequence;
  };
  return { state, grant, options: { timeoutMs: 10, now: () => time, pause: async () => { time++; } } };
}

test('stable UI gate ignores old resolved pending promise, waits for actual full-check grant AND rendered readiness', async () => {
  const { state, grant, options } = stableFixture(); let samples = 0;
  const value = await awaitStableUiEligibility(state, 0, async () => {
    samples++;
    if (samples === 2) grant(); // Current debounce dispatch after initial resolved promise.
    return samples < 4 ? { ...uiReady(), uiEligibilityReady: false } : uiReady();
  }, () => true, () => {}, options);
  assert.equal(samples, 5); assert.equal(value.sequence, state.fence.sequence);

});

test('stable UI gate cannot accept changed target/checks, stale grant or API READY before DOM commit', async () => {
  for (const setup of [
    fixture => fixture.grant(TARGETS[1]), fixture => fixture.grant(TARGETS[0], ['secret']),
    fixture => { fixture.grant(); fixture.state.fence.grant.at = -31000; },
  ]) {
    const fixture = stableFixture(); setup(fixture);

    await assert.rejects(awaitStableUiEligibility(fixture.state, 0, async () => uiReady(), () => true, () => {}, fixture.options));
  }
  for (const key of Object.keys(uiReady())) {
    const { state, grant, options } = stableFixture(); grant();
    const changed = { ...uiReady(), [key]: !uiReady()[key] };
    assert.equal(uiLaunchReady(changed), false, key);
    await assert.rejects(awaitStableUiEligibility(state, 0, async () => changed, () => true, () => {}, options), { message: 'ELIGIBILITY_NOT_READY' });
  }
});

test('stable UI gate requires two current observations and rechecks authority AFTER async DOM sampling', async () => {
  const { state, grant, options } = stableFixture(); grant(); let samples = 0;
  await awaitStableUiEligibility(state, 0, async () => { if (++samples === 2) grant(); return uiReady(); }, () => true, () => {}, options);
  assert.equal(samples, 4); // Sequence changed during sample2, so samples3+4 must agree.
  let active = true;
  await assert.rejects(awaitStableUiEligibility(state, 0, async () => { active = false; return uiReady(); }, () => active, () => {}, options), { message: 'ELIGIBILITY_NOT_READY' });
  assert.equal(uiLaunchReady(uiReady(true), true), true);
  assert.equal(uiLaunchReady(uiReady(true)), false); assert.equal(uiLaunchReady(uiReady(), true), false);
});

test('stable UI gate stops on classified refusal, rejected reads and missing response; never retries or arms', async () => {
  for (const httpStatus of [400, 401, 403, 429, 503]) {
    const { state, options } = stableFixture(); const sequence = state.fence.start();
    state.eligibilityResult = { sequence, refused: true, httpStatus };
    let reads = 0;
    await assert.rejects(awaitStableUiEligibility(state, 0, async () => { reads++; return uiReady(); }, () => true, () => {}, options), { message: 'ELIGIBILITY_NOT_READY' });
    assert.equal(reads, 1);
  }
  const { state, options } = stableFixture();
  await assert.rejects(awaitStableUiEligibility(state, 0, async () => { throw new Error('synthetic read rejection'); }, () => true, () => {}, options));
  await assert.rejects(awaitStableUiEligibility(state, 0, () => new Promise(() => {}), () => true, () => {}, { timeoutMs: 1 }));
});

test('operation evidence separates consent/check/submit failures and projects only finite phases, booleans and elapsed time', () => {
  let now = 100; const phase = new PhaseEvidence(() => now);
  for (const name of ['ui-eligibility', 'consent-fresh', 'consent-check', 'submit-enabled', 'launch-click', 'launch-receipt', 'subset-observation', 'cancel-click', 'cancel-receipt', 'cancel-terminal', 'cancel-fresh-login']) {
    phase.enter(name); phase.observe({ ...uiReady(), password: 'PRIVATE_MARKER', message: 'PRIVATE_MARKER', phase: 'PRIVATE_MARKER' }); now += 3;
    const result = phase.meta(); assert.equal(result.phase, name); assert.equal(result.phaseElapsedMs, 3);
    assert.equal(JSON.stringify(result).includes('PRIVATE_MARKER'), false);
    const book = new ResultBook('cancel', id); book.record('cancel', 'BLOCKED', 'ASSERTION_FAILED', result);
    assert.equal(book.evidence().cases.cancel.phase, name);
  }
  assert.throws(() => phase.enter('PRIVATE_MARKER'));
  assert.deepEqual(safeMeta({ phase: 'PRIVATE_MARKER', phaseElapsedMs: -1, consentChecked: 'PRIVATE_MARKER', httpStatus: 0 }), {});
  phase.enter('launch-receipt'); phase.observe({ httpStatus: 202 });
  phase.enter('cancel-receipt'); assert.equal('httpStatus' in phase.meta(), false);
  phase.reset(); assert.deepEqual(phase.meta(), {});
});

test('native launch uses only real UI eligibility, no external probe/force/retry, and retains post-arm fence', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const launch = source.slice(source.indexOf('  const launch = async'), source.indexOf('  const status = async'));
  assert.equal(launch.includes('await http('), false);
  assert.ok(launch.includes('await awaitStableUiEligibility('));
  assert.ok(launch.indexOf('await awaitStableUiEligibility(') < launch.indexOf('await consent.check()'));
  assert.ok(launch.indexOf('uiLaunchReady(confirmed, true)') < launch.indexOf('activeLaunch ='));
  assert.equal((launch.match(/await submit.click\(/g) ?? []).length, 1);
  for (const forbidden of ['force:', 'setChecked', 'waitForTimeout', 'Проверить допуск снова', 'dispatchEvent', 'http(']) assert.equal(launch.includes(forbidden), false);
  assert.ok(source.includes('await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending,'));
  assert.ok(source.includes('sequence: state.fence.sequence, armed: true'));
});

test('durable progress evidence is exact finite metadata; bad basis/counts/outcomes/private fields refuse', () => {
  const valid = progressOf({ secret: 'checked', sbom: 'failed' });
  assert.deepEqual(durableProgress(valid), valid); assert.notEqual(durableProgress(valid).outcomes, valid.outcomes);
  for (const mutation of [{ basis: 'PRIVATE' }, { requestedChecks: ['secret'] }, { checkedChecks: 0 }, { resolvedChecks: 4 },
    { checkedChecks: '1' }, { resolvedChecks: NaN }, { outcomes: { ...valid.outcomes, secret: 'PRIVATE' } },
    { outcomes: { ...valid.outcomes, extra: 'checked' } }, { outcomes: [] }, { message: 'PRIVATE' }, { payload: {} }]) {
    assert.throws(() => durableProgress({ ...valid, ...mutation }));
    assert.deepEqual(safeMeta({ preCancelProgress: { ...valid, ...mutation } }), {});
  }
  assert.deepEqual(safeMeta({ preCancelProgress: valid, preCancelByteComparison: false, preCancelFindingsRead: false,
    preservationBasis: 'post-cancel-published-baseline-v1', postCancelBaselineVerified: true, privateRows: ['PRIVATE'] }),
  { preCancelProgress: valid, preservationBasis: 'post-cancel-published-baseline-v1', preCancelFindingsRead: false, preCancelByteComparison: false, postCancelBaselineVerified: true });
});

test('cancel preservation compares public outcome metadata, never claims pre-cancel row/byte equality', () => {
  const before = { state: 'running', progress: progressOf({ secret: 'checked', sbom: 'failed' }), perCheck: Object.fromEntries(CHECKS.map(check => [check, null])) };
  const after = { state: 'cancelled', progress: progressOf({ secret: 'checked', sbom: 'failed', config: 'unsupported' }),
    perCheck: { secret: { outcome: 'checked', findingCount: 0 }, sbom: { outcome: 'failed' }, config: { outcome: 'unsupported' }, vuln: null } };
  assertCancelOutcomePreservation(before, after); // Additional completed outcome may precede cancellation's commit.
  for (const mutation of [{ state: 'completed' }, { progress: progressOf({ secret: 'failed', sbom: 'failed' }) },
    { perCheck: { ...after.perCheck, secret: { outcome: 'unsupported' } } }]) assert.throws(() => assertCancelOutcomePreservation(before, { ...after, ...mutation }));
  assert.throws(() => assertCancelOutcomePreservation({ ...before, progress: progressOf({ sbom: 'failed' }) }, after));
  assert.throws(() => assertCancelOutcomePreservation({ ...before, perCheck: { secret: { outcome: 'checked', findingCount: 0 } } }, after));
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('async function runCancellation()'), source.indexOf('    })()]);', source.indexOf('async function runCancellation()')));
  const preCancel = flow.slice(0, flow.indexOf("phase.enter('cancel-terminal')"));
  for (const forbidden of ['await collect(', 'verifyReport(', '.rows', 'before.config, after.config']) assert.equal(preCancel.includes(forbidden), false);
  assert.ok(flow.includes('assertCancelOutcomePreservation(before, after)'));
  assert.ok(flow.includes('assert.deepEqual(await verifyReport(own.page, after), persisted)'));
  assert.ok(flow.includes('assert.deepEqual(await verifyReport(own.page, final), focusedReports)'));
  assert.ok(flow.includes('preCancelByteComparison: false'));
});

test('actual frontend progress decoder accepts durable running metadata with unpublished results and rejects private/mismatched snapshots', async () => {
  const { decoder } = await loadContracts();
  const wire = { scanId: id, state: 'running', checks: CHECKS, result: null,
    perCheck: Object.fromEntries(CHECKS.map(check => [check, null])), progress: progressOf({ secret: 'checked', sbom: 'failed' }) };
  const parsed = decoder.parseCurrentStatus(wire);
  assert.equal(parsed.percent, null); assert.deepEqual(parsed.progress, wire.progress);
  assert.equal(cancelObservation(parsed), 'ready'); assert.ok(Object.values(parsed.perCheck).every(value => value === null));
  for (const mutation of [{ progress: { ...wire.progress, checkedChecks: 0 } }, { state: 'queued' },
    { progress: { ...wire.progress, findingCount: 0 } }, { progress: { ...wire.progress, requestedChecks: ['secret'] } },
    { perCheck: { ...wire.perCheck, secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0 } } }]) assert.throws(() => decoder.parseCurrentStatus({ ...wire, ...mutation }));
});

test('stable UI gate ignores obsolete refusal when the sequence changes during DOM sampling', async () => {
  const { state, grant, options } = stableFixture(); const sequence = state.fence.start();
  state.eligibilityResult = { sequence, refused: true, httpStatus: 429 };
  let samples = 0;
  await awaitStableUiEligibility(state, 0, async () => { if (++samples === 1) grant(); return uiReady(); }, () => true, () => {}, options);
  assert.equal(samples, 3);
});

test('progress derives check totals from authoritative snapshots, not elapsed time or successful-only counts', () => {
  const snapshot = { checks: CHECKS, state: 'running', percent: null, progress: progressOf({ secret: 'checked', sbom: 'failed' }),
    perCheck: Object.fromEntries(CHECKS.map(check => [check, null])) };
  assert.deepEqual(progressExpectation(snapshot), { active: true, hasCheckSnapshot: true, total: 4, resolved: 2, checked: 1, remaining: 2, percent: null });
  assert.equal(progressExpectation({ ...snapshot, state: 'cancelled', percent: 100 }).percent, null);
  assert.equal(progressExpectation({ ...snapshot, progress: undefined, perCheck: undefined }).hasCheckSnapshot, false);
  for (const percent of [undefined, null, NaN, Infinity, -1, 101, '50']) assert.equal(progressExpectation({ ...snapshot, percent }).percent, null);
  assert.equal(progressExpectation({ ...snapshot, percent: 25 }).percent, 25);
  // Reconnect/no terminal receipt never manufactures 100% or an ETA.
  assert.equal(progressExpectation({ ...snapshot, perCheck: Object.fromEntries(CHECKS.map(check => [check, { check, outcome: 'checked' }])) }).percent, null);
  assert.throws(() => progressExpectation({ ...snapshot, checks: ['secret'] }));
});

test('progress acceptance requires all actual DOM facts; unknown or partial samples never qualify', () => {
  const sample = { stateMatches: true, barMatches: true, countsMatch: true, remainingMatch: true, percentMatches: true, timeHonest: true };
  assert.ok(progressSampleMatches(sample));
  for (const key of Object.keys(sample)) for (const value of [false, undefined, 'true', null]) assert.equal(progressSampleMatches({ ...sample, [key]: value }), false);
  const book = new ResultBook('cancel', id);
  for (const name of book.plan.cases) book.record(name, 'PASS', 'VERIFIED');
  book.record('cancel_progress', 'INCONCLUSIVE', 'PROGRESS_NOT_OBSERVED'); assert.equal(resultExitCode(book), 2);
  book.record('cancel_progress', 'BLOCKED', 'ASSERTION_FAILED'); assert.equal(resultExitCode(book), 1);
  book.record('cancel_progress', 'PASS', 'VERIFIED'); assert.equal(resultExitCode(book), 1);
  assert.deepEqual(safeMeta({ progressObserved: true, progressIndeterminate: true, progressActive: true, percent: 'PRIVATE_MARKER', eta: 'PRIVATE_MARKER' }), { progressObserved: true, progressIndeterminate: true, progressActive: true });
});

test('product chat opening matches final readonly UI copy while readiness metadata remains independently strict', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const ui = readFileSync(new URL('../src/features/scans/ScanChatPanel.tsx', import.meta.url), 'utf8');
  const openChat = source.slice(source.indexOf('      const openChat = async'), source.indexOf('      const readChat = async'));
  assert.ok(ui.includes("'Открыть чат'")); assert.ok(ui.includes('Генерация не проверена.'));
  assert.ok(openChat.includes("name: 'Открыть чат', exact: true"));
  assert.ok(openChat.includes("toContainText('Генерация не проверена.')"));
  assert.equal(openChat.includes("toContainText('generationVerified: false')"), false);
  for (const forbidden of ['permit(', 'http(', 'checkbox', 'consent.check', 'force:']) assert.equal(openChat.includes(forbidden), false);
  assert.ok(source.includes('assert.equal(ready.generationVerified, false)'));
  assert.ok(source.includes('assert.equal(ready.requiresConsent, true)'));
  assert.ok(source.includes('assert.equal(own.state.generationPosts, before)'));
  assert.ok(ui.includes('Нажимая «Отправить вопрос», вы разрешаете один запрос:'));
});

function controlledReadPage() {
  const listeners = new Map(), mainFrame = {}, state = { url: `${ORIGIN}/scans/${id}`, active: true, session: 0, closed: false, reads: 0, waits: 0 };
  const page = {
    on: (name, callback) => { const list = listeners.get(name) ?? []; list.push(callback); listeners.set(name, list); },
    mainFrame: () => mainFrame, url: () => state.url, isClosed: () => state.closed,
    evaluate: async (fn, path) => { state.reads++; return state.evaluate ? state.evaluate(fn, path) : { status: 200, value: { synthetic: true } }; },
    waitForURL: async (url, options) => { state.waits++; assert.equal(options.timeout, 20000); if (state.navigation) await state.navigation; state.url = url; page.emit('framenavigated', mainFrame); },
    getByRole: (role, options) => {
      assert.equal(role, 'group'); assert.deepEqual(options, { name: `Ход сканирования ${id}`, exact: true });
      return { waitFor: async options => { assert.deepEqual(options, { state: 'visible', timeout: 15000 }); if (state.ui) await state.ui; } };
    },
    emit: (name, value) => { for (const callback of listeners.get(name) ?? []) callback(value); },
  };
  trackBrowserReadPage(page, { active: () => state.active, sessionVersion: () => state.session });
  return { page, state, navigate: () => page.emit('request', { isNavigationRequest: () => true, frame: () => mainFrame }) };
}

test('controlled browser read waits for exact report navigation AND native UI before first GET, never resends', async () => {
  const { page, state, navigate } = controlledReadPage(); state.url = `${ORIGIN}/scans/new`;
  let finishNavigation, finishUi;
  state.navigation = new Promise(resolve => { finishNavigation = resolve; });
  state.ui = new Promise(resolve => { finishUi = resolve; });
  navigate();
  const pending = (async () => { await settleReportNavigation(page, id, () => state.active); return readBrowserJson(page, `${SCANS}/${id}`, [id]); })();
  await new Promise(setImmediate); assert.equal(state.reads, 0);
  finishNavigation(); await new Promise(setImmediate); assert.equal(state.reads, 0);
  finishUi(); assert.deepEqual(await pending, { status: 200, value: { synthetic: true } });
  assert.equal(state.reads, 1); assert.equal(state.waits, 1);
});

test('controlled auth navigation settles actual account UI before identity GET, without a retry or reading visible credentials', async () => {
  const f = controlledReadPage(); f.state.url = `${ORIGIN}/register`;
  let release; f.state.navigation = new Promise(resolve => { release = resolve; });
  f.page.getByRole = (role, options) => {
    assert.equal(role, 'heading'); assert.deepEqual(options, { name: 'Вы вошли', exact: true });
    return { waitFor: async options => { assert.deepEqual(options, { state: 'visible', timeout: 15000 }); } };
  };
  const pending = (async () => { await settleAuthNavigation(f.page, () => f.state.active); return readBrowserJson(f.page, '/api/v1/auth/me', []); })();
  await new Promise(setImmediate); assert.equal(f.state.reads, 0);
  release(); await pending; assert.equal(f.state.url, `${ORIGIN}/account`); assert.equal(f.state.reads, 1);
  const ui = readFileSync(new URL('../src/pages/auth/DemoAuthPage.tsx', import.meta.url), 'utf8');
  assert.ok(ui.includes("navigate('/account')")); assert.ok(ui.includes('<h2>Вы вошли</h2>'));
  const product = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const ai = readFileSync(new URL('./public-ai-translation-live.mjs', import.meta.url), 'utf8');
  assert.ok(product.includes('await settleAuthNavigation(page,')); assert.ok(ai.includes('await settleAuthNavigation(handle.page,'));
});

test('controlled browser read refuses pending navigation, foreign origin, unauthorized path and changed authority without a GET', async () => {
  for (const [change, cause, path] of [
    [f => f.navigate(), 'navigation'], [f => { f.state.url = 'http://127.0.0.1:8080/scans'; }, 'origin-mismatch'],
    [f => { f.state.active = false; }, 'authority-changed'], [f => { f.state.closed = true; }, 'page-closed'],
    [() => {}, 'request-not-approved', `${SCANS}/${id}/cancel`],
  ]) {
    const f = controlledReadPage(); change(f);
    await assert.rejects(readBrowserJson(f.page, path ?? `${SCANS}/${id}`, [id]), error => error instanceof BrowserReadError && error.meta.readCause === cause);
    assert.equal(f.state.reads, 0);
  }
  const f = controlledReadPage(); let finish;
  f.state.navigation = new Promise(resolve => { finish = resolve; });
  const pending = settleReportNavigation(f.page, id, () => true);
  f.state.session++; finish();
  await assert.rejects(pending, error => error.meta.readStage === 'report-navigation' && error.meta.readCause === 'authority-changed');
  assert.equal(f.state.reads, 0);
});

test('controlled browser read classifies context destruction/nav/session changes once without leaking raw errors or retrying', async () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  for (const [error, cause] of [
    [new Error('Execution context was destroyed, most likely because of a navigation. ' + marker), 'execution-context-destroyed'],
    [new Error('Frame was detached ' + marker), 'navigation'], [new DOMException(marker, 'AbortError'), 'caller-abort'],
    [new DOMException(marker, 'TimeoutError'), 'timeout'], [new TypeError('Failed to fetch ' + marker), 'network'], [new Error(marker), 'unknown'],
  ]) {
    assert.equal(classifyBrowserReadFailure(error), cause);
    const f = controlledReadPage(); f.state.evaluate = async () => { throw error; };
    await assert.rejects(readBrowserJson(f.page, `${SCANS}/${id}`, [id]), error => {
      assert.equal(error.meta.readStage, 'evaluate'); assert.equal(error.meta.readCause, cause); assert.equal(error.meta.scanId, id);
      assert.equal(JSON.stringify(error.meta).includes(marker), false); assert.equal('httpStatus' in error.meta, false); return true;
    });
    assert.equal(f.state.reads, 1);
  }
  for (const [change, cause] of [[f => f.navigate(), 'navigation'], [f => { f.state.session++; }, 'authority-changed']]) {
    const f = controlledReadPage(); f.state.evaluate = async () => { change(f); return { status: 200, value: { secret: marker } }; };
    await assert.rejects(readBrowserJson(f.page, `${SCANS}/${id}`, [id]), error => error.meta.readCause === cause);
    assert.equal(f.state.reads, 1);
  }
});

test('controlled browser read captures finite fetch/header/body/decode/json stages with strict size limits', async () => {
  const original = globalThis.fetch, marker = 'SYNTHETIC_PRIVATE_MARKER';
  try {
    for (const [response, stage, cause] of [
      [() => new Response(marker, { status: 502, headers: { 'content-type': 'text/html' } }), 'headers', 'content-type'],
      [() => new Response(null, { headers: { 'content-type': 'application/json' } }), 'body', 'missing-body'],
      [() => new Response(new Uint8Array(4 * 1024 * 1024 + 1), { headers: { 'content-type': 'application/json' } }), 'body', 'body-limit'],
      [() => new Response(new Uint8Array([255]), { headers: { 'content-type': 'application/json' } }), 'decode', 'invalid-utf8'],
      [() => new Response(marker, { headers: { 'content-type': 'application/json' } }), 'json', 'invalid-json'],
      [() => { throw new DOMException(marker, 'TimeoutError'); }, 'fetch', 'timeout'],
      [() => { throw new DOMException(marker, 'AbortError'); }, 'fetch', 'caller-abort'],
      [() => { throw new TypeError('Failed to fetch ' + marker); }, 'fetch', 'network'],
    ]) {
      const f = controlledReadPage(); f.state.evaluate = (fn, path) => fn(path);
      let calls = 0;
      globalThis.fetch = async (path, init) => { calls++; assert.equal(path, `${SCANS}/${id}`); assert.equal(init.method, 'GET'); return response(); };
      await assert.rejects(readBrowserJson(f.page, `${SCANS}/${id}`, [id]), error => {
        assert.equal(error.meta.readStage, stage); assert.equal(error.meta.readCause, cause);
        assert.equal(JSON.stringify(error.meta).includes(marker), false); return true;
      });
      assert.equal(calls, 1); assert.equal(f.state.reads, 1);
    }
  } finally { globalThis.fetch = original; }
});

test('browser read metadata is closed; accepted scan UUID survives a later blocked product status read', () => {
  assert.ok(BROWSER_READ_STAGES.length < 16 && BROWSER_READ_CAUSES.length < 24);
  const meta = { readStage: 'evaluate', readCause: 'execution-context-destroyed', readTarget: 'scan-status', scanId: id };
  assert.deepEqual(browserReadFailureMeta({ ...meta, message: 'PRIVATE', payload: 'PRIVATE' }), meta);
  for (const bad of [{ readStage: 'PRIVATE' }, { readCause: 'PRIVATE' }, { readCause: null }]) assert.deepEqual(browserReadFailureMeta({ ...meta, ...bad }), {});
  const book = new ResultBook('cancel', id);
  book.recordScanReceipt('cancel', 202, { scanId: id, credentials: 'PRIVATE' });
  assert.equal(book.cases.cancel.code, 'NOT_RUN'); assert.equal(book.cases.cancel.status, 'BLOCKED');
  book.record('cancel', 'BLOCKED', 'BROWSER_READ_FAILED', meta, false);
  assert.equal(book.evidence().cases.cancel.scanId, id); assert.equal(book.evidence().cases.cancel.launchHttpStatus, 202);
  assert.equal(book.evidence().cases.cancel.receiptAccepted, true); assert.equal(resultExitCode(book), 2);
  assert.equal(JSON.stringify(book.evidence()).includes('PRIVATE'), false);
});

test('actual progress renderer uses durable running outcomes with unpublished perCheck; percent/ETA remain unknown', () => {
  const require = createRequire(new URL('../server/api/package.json', import.meta.url));
  const ts = require('typescript');
  // Execute the real TSX and label module in memory. Only the stylesheet import
  // is inert in server rendering; no browser, network, app mutation or saved state.
  const compile = (relative, imports = {}) => {
    const text = readFileSync(new URL(relative, import.meta.url), 'utf8');
    const js = ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText;
    const module = { exports: {} };
    new Function('require', 'module', 'exports', js)(name => Object.hasOwn(imports, name) ? imports[name] : require(name), module, module.exports);
    return module.exports;
  };
  const labels = compile('../src/features/scans/scanStateLabels.ts');
  const { ScanProgressPanel } = compile('../src/features/scans/ScanProgressPanel.tsx', { './ScanProgressPanel.css': {}, './scanStateLabels': labels });
  const { createElement } = require('react'); const { renderToStaticMarkup } = require('react-dom/server');
  const scan = { scanId: id, checks: [...CHECKS], state: 'running', percent: null,
    perCheck: Object.fromEntries(CHECKS.map(check => [check, null])), progress: progressOf({ secret: 'checked', sbom: 'failed' }) };
  const html = renderToStaticMarkup(createElement(ScanProgressPanel, { scan }));
  assert.ok(html.includes('Получены итоги: 2 из 4. Успешно выполнено: 1.'), 'ACTIVE_DURABLE_COUNTS_UI_CONTRACT');
  assert.ok(html.includes('Без подтверждённого итога: 2.'), 'ACTIVE_DURABLE_REMAINING_UI_CONTRACT');
  assert.ok(html.includes('Точное оставшееся время неизвестно.'), 'UNKNOWN_ETA_UI_CONTRACT');
  assert.ok(html.includes('<progress') && !/<progress[^>]*\svalue=/.test(html), 'UNKNOWN_PERCENT_UI_CONTRACT');
  const page = readFileSync(new URL('../src/pages/scans/ScanDetailPage.tsx', import.meta.url), 'utf8');
  assert.equal(/connectedStream\s*!==\s*streamKey\s*\?\s*2000/.test(page), false, 'DURABLE_PROGRESS_POLLING_MUST_NOT_DEPEND_ON_SSE');
});

test('progress native plan observes active, cancelled, reload and fresh-login UI without LLM/worker mutations', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  const observe = source.slice(source.indexOf('  const observeProgress ='), source.indexOf('  const statusMeta ='));
  for (const forbidden of ['http(page, SCANS,', 'submit.click', 'cancel', 'llm', 'screenshot', 'storageState']) assert.equal(observe.includes(forbidden), false, forbidden);
  assert.ok(observe.includes('isDeepStrictEqual(before, after)'));
  assert.ok(observe.includes("!progress.hasAttribute('value')"));
  assert.ok(source.includes('await observeProgress(own.page, id, true)'));
  assert.ok(source.includes('await observeProgress(own.page, after.scanId)'));
  assert.ok((source.match(/await observeProgress\(own.page, cancelled.after.scanId\)/g) ?? []).length >= 2);
  const component = readFileSync(new URL('../src/features/scans/ScanProgressPanel.tsx', import.meta.url), 'utf8');
  for (const contract of ['Ход сканирования ${scan.scanId}', 'data-state={scan.state}', 'Процент выполнения неизвестен.', 'Получены итоги:', 'Счётчики проверок не предоставлены сервером.', 'Точное оставшееся время неизвестно.', 'Отсутствующие итоги не считаются успешными проверками.']) assert.ok(component.includes(contract), contract);
});

test('mutation permits are one-shot, exact-path, exact-body and POST-only', () => {
  const value = { question: 'synthetic question', consent: { accepted: false } };
  const permit = { path: `${SCANS}/${id}/llm/chat`, used: false, matches: body => JSON.stringify(body) === JSON.stringify(value) };
  assert.equal(consumePermit(permit, 'GET', permit.path, value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path + '/other', value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path + '?override=true', value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path, { ...value, consent: { accepted: true } }), false);
  assert.equal(permit.used, false);
  assert.equal(consumePermit(permit, 'POST', permit.path, value), true);
  assert.equal(consumePermit(permit, 'POST', permit.path, value), false);
});

test('CVE/TEMP partition is derived from all rows, never hardcoded or conflated', () => {
  const rows = [
    { cveId: 'CVE-2026-1234', ecosystem: 'npm' },
    { cveId: 'CVE-2026-1234', ecosystem: 'deb' },
    { cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'deb' },
  ];
  assert.deepEqual(partition(rows), { cve: 2, debianTemp: 1 }); // Rows, not distinct identifiers.
  assert.deepEqual(partition([]), { cve: 0, debianTemp: 0 });
  for (const row of [{ cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'npm' }, { cveId: 'TEMP-1234567-abcdef', ecosystem: 'deb' }, { cveId: 'GHSA-not-a-cve', ecosystem: 'npm' }, { cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'deb', advisory: { references: ['fabricated'] } }]) assert.throws(() => partition([row]));
});

test('report page counts, offset and row identity must agree across pages', () => {
  const page = (rows, offset, nextCursor = null) => ({ findings: rows.map(findingId => ({ findingId })), nextCursor, page: { totalCount: 3, matchedCount: 3, offset, returnedCount: rows.length } });
  const expected = { whole: 3, matched: 3 }, seen = new Set();
  assert.equal(checkPage('vuln', page(['one', 'two'], 0, 'opaque'), expected, 0, seen).length, 2);
  assert.equal(checkPage('vuln', page(['three'], 2), expected, 2, seen).length, 1);
  assert.throws(() => checkPage('vuln', page(['one'], 2), expected, 2, seen));
  assert.throws(() => checkPage('vuln', page([], 0, 'opaque'), expected, 0, new Set()));
  assert.throws(() => checkPage('vuln', page(['new'], 1), expected, 0, new Set()));
  assert.throws(() => checkPage('vuln', page(['new'], 0), { whole: 4, matched: 3 }, 0, new Set()));
  assert.throws(() => checkPage('vuln', { ...page(['new'], 0), page: { ...page(['new'], 0).page, returnedCount: 2 } }, expected, 0, new Set()));
});

test('whole-page walker requires real EOF, correct total, unique advancing cursors', async () => {
  const page = (offset, ids, nextCursor, total = 3) => ({ findings: ids.map(findingId => ({ findingId })), nextCursor, page: { totalCount: total, matchedCount: total, offset, returnedCount: ids.length } });
  const calls = [];
  const result = await readAllPages('vuln', { whole: 3, matched: 3 }, async cursor => {
    calls.push(cursor); return cursor === undefined ? page(0, ['a', 'b'], 'opaque') : page(2, ['c'], null);
  });
  assert.deepEqual(calls, [undefined, 'opaque']); assert.equal(result.pages, 2); assert.equal(result.rows.length, 3);
  await assert.rejects(readAllPages('vuln', { whole: 3, matched: 3 }, async () => page(0, ['a'], null)));
  await assert.rejects(readAllPages('vuln', { whole: 3, matched: 3 }, async cursor => cursor === undefined ? page(0, ['a'], 'same') : page(1, ['b'], 'same')));
  let index = 0;
  await assert.rejects(readAllPages('vuln', { whole: 201, matched: 201 }, async () => { const offset = index++; return page(offset, [`row-${offset}`], `cursor-${offset}`, 201); }));
  assert.equal(index, 200);
  const empty = await readAllPages('vuln', { whole: 0, matched: 0 }, async () => page(0, [], null, 0));
  assert.equal(empty.rows.length, 0);
});

test('SBOM uniqueness is tuple-based, not only package name', () => {
  const components = [{ ecosystem: 'deb', name: 'same', version: '1' }, { ecosystem: 'npm', name: 'same', version: '1' }];
  const page = { components, nextCursor: null, page: { totalCount: 2, matchedCount: 2, offset: 0, returnedCount: 2 } };
  assert.equal(checkPage('sbom', page, { whole: 2, matched: 2 }, 0, new Set()).length, 2);
  assert.throws(() => checkPage('sbom', { ...page, components: [components[0], components[0]] }, { whole: 2, matched: 2 }, 0, new Set()));
});

test('cancel races are INCONCLUSIVE, not cancel PASS; unexpected replies fail', () => {
  assert.deepEqual(cancelVerdict('cancelled', 200), { status: 'PASS', code: 'VERIFIED' });
  for (const state of ['completed', 'partial', 'failed']) for (const status of [409, null]) assert.equal(cancelVerdict(state, status).status, 'INCONCLUSIVE');
  for (const [state, status] of [['running', 200], ['cancelled', 409], ['completed', 200], ['cancelled', null]]) assert.equal(cancelVerdict(state, status).status, 'BLOCKED');
});

test('consented negative boundary requires fresh missing key, stores and matching report', () => {
  const context = { scanId: id, digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'b'.repeat(64), policyVersion: 'c'.repeat(64), enabled: true, pending: false };
  const readiness = { ...context, credential: 'missing', localReady: false, generationVerified: false, requiresConsent: true, acceptsCredentials: false, blockers: ['public-key-required'], quota: 'available', history: 'available' };
  assert.ok(keyBoundaryAllowed(readiness, context));
  for (const mutation of [{ credential: 'metadata-valid' }, { credential: 'unsafe' }, { localReady: true }, { blockers: [] }, { quota: 'unavailable' }, { history: 'unavailable' }, { reportVersion: 'c'.repeat(64) }, { scanId: 'foreign' }]) assert.equal(keyBoundaryAllowed({ ...readiness, ...mutation }, context), false);
  assert.equal(keyBoundaryAllowed(readiness, { ...context, enabled: false }), false);
  assert.equal(keyBoundaryAllowed(readiness, { ...context, pending: true }), false);
});

test('sanitized metadata is closed and preserves unknown counts rather than zero', () => {
  const projected = safeMeta({ scanId: id, state: 'cancelled', credential: 'missing', blockers: ['public-key-required', 'private-path'], httpStatus: 503,
    counts: { secret: 0, vuln: null, sbom: 17, raw: 100, config: -1 }, checks: { secret: 'checked', vuln: null, sbom: 'not-real', private: 'checked' },
    observedCompletedChecks: ['sbom', 'private'], password: 'SYNTHETIC_PRIVATE_MARKER', token: 'SYNTHETIC_PRIVATE_MARKER', providerPayload: 'SYNTHETIC_PRIVATE_MARKER', error: new Error('SYNTHETIC_PRIVATE_MARKER'), arbitrary: 'SYNTHETIC_PRIVATE_MARKER' });
  assert.equal(JSON.stringify(projected).includes('SYNTHETIC_PRIVATE_MARKER'), false);
  assert.deepEqual(projected.counts, { secret: 0, sbom: 17, vuln: null });
  assert.deepEqual(projected.checks, { secret: 'checked', vuln: null });
  assert.deepEqual(projected.blockers, ['public-key-required']);
  assert.deepEqual(projected.observedCompletedChecks, ['sbom']);
});

test('result book does not accept arbitrary case names/status/error text', () => {
  const book = new ResultBook();
  book.record('llm_generation', 'BLOCKED', 'KEY_ABSENT', { token: 'SYNTHETIC_PRIVATE_MARKER' });
  book.record('cancel', 'INCONCLUSIVE', 'CANCEL_RACE');
  assert.equal(book.evidence().cases.llm_generation.status, 'BLOCKED');
  assert.equal(JSON.stringify(book.evidence()).includes('SYNTHETIC_PRIVATE_MARKER'), false);
  assert.throws(() => book.record('raw-message', 'PASS', 'VERIFIED'));
  assert.throws(() => book.record('cancel', 'PASS', 'raw-message'));
  assert.throws(() => book.record('cancel', 'SUCCESS', 'VERIFIED'));
  book.record('ownership', 'BLOCKED', 'ASSERTION_FAILED');
  book.record('ownership', 'PASS', 'VERIFIED');
  assert.equal(book.evidence().cases.ownership.status, 'BLOCKED');
  assert.equal(book.evidence().cases.ownership.failure, true);
});

test('offline entrypoints do not launch browser, access stand or write evidence', () => {
  const script = fileURLToPath(new URL('./public-product-live.mjs', import.meta.url));
  const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  for (const [args, expected] of [[['--self-test'], 0], [[], 2], [['--run'], 2], [['--smoke-only'], 2], [['--run', '--smoke-only', '--ack-coordinator-go'], 2]]) {
    const result = spawnSync(process.execPath, [script, ...args], { env, timeout: 10000, encoding: 'utf8' });
    assert.equal(result.status, expected); assert.equal(result.stderr, '');
    const value = JSON.parse(result.stdout); assert.equal(value.browserLaunched, false);
    if (args[0] === '--self-test') { assert.equal(value.networkRequests, 0); assert.equal(value.evidenceWritten, false); }
  }
});

test('native single-process TS imports resolve actual decoder and existing chat contracts offline', async () => {
  const { decoder, view, metadata, chat } = await loadContracts();
  for (const name of ['parseCurrentStatus', 'parseCurrentResults', 'parseCurrentSbom', 'parseCurrentVuln', 'parseCurrentList']) assert.equal(typeof decoder[name], 'function');
  assert.equal(typeof metadata.validateCveMetadata, 'function');
  assert.equal(view.reportViewSearch('sbom', { view: 'report-v1', limit: 5, sort: 'name:asc', ecosystem: 'npm' }), 'view=report-v1&limit=5&sort=name%3Aasc&ecosystem=npm');
  for (const name of ['chatReadinessSchema', 'chatContextSchema', 'chatHistorySchema']) assert.equal(typeof chat[name].parse, 'function');
  assert.throws(() => decoder.parseCurrentStatus({ scanId: id, state: 'completed', profile: 'public-hub-amd64-v1' }));
});

test('mutations reject query overrides, injected authorization and non-browser/non-JSON requests', () => {
  const url = `${ORIGIN}${SCANS}`, headers = { origin: ORIGIN, 'content-type': 'application/json' };
  assert.ok(safeMutationRequest(url, headers));
  for (const value of [url + '?model=other', 'http://127.0.0.1:8080/api/v1/browser/scans']) assert.equal(safeMutationRequest(value, headers), false);
  for (const value of [{}, { ...headers, origin: 'http://localhost:8081' }, { ...headers, 'content-type': 'text/plain' }, { ...headers, authorization: 'SYNTHETIC' }, { ...headers, 'Proxy-Authorization': 'SYNTHETIC' }, { ...headers, 'x-api-key': 'SYNTHETIC' }]) assert.equal(safeMutationRequest(url, value), false);
});

test('browser has a deny-by-default proxy fence for redirect hops and other loopback ports', () => {
  assert.ok(BROWSER_ARGS.includes('--proxy-server=http://public-product-denied.invalid:1'));
  assert.ok(BROWSER_ARGS.includes('--proxy-bypass-list=<-loopback>;127.0.0.1:8081'));
  assert.ok(BROWSER_ARGS.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'));
  assert.equal(BROWSER_ARGS.includes('--no-proxy-server'), false);
});

test('denied replies cannot pass with HTML, oversized/null JSON, nested data or extra payloads', () => {
  assert.doesNotThrow(() => assertDeniedReply({ status: 401, value: { errorCode: 'UNAUTHORIZED' } }, 401));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { statusCode: 404, message: 'Not Found', error: 'Not Found' } }, 404));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { errorCode: 'LLM_UNAVAILABLE' } }, 404));
  for (const value of [null, '<html>not found</html>', [], { errorCode: 'LLM_UNAVAILABLE', findings: [] }, { error: { turns: [] } }, { errorCode: 'ARBITRARY_PRIVATE_MESSAGE' }]) assert.throws(() => assertDeniedReply({ status: 404, value }, 404));
  assert.throws(() => assertDeniedReply({ status: 200, value: { errorCode: 'LLM_UNAVAILABLE' } }, 404));
});

test('observed two-field NotFound denial is accepted only for exact 404 without weakening other shapes', () => {
  const value = { statusCode: 404, message: 'Not Found' };
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value }, 404));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { message: 'Not Found', statusCode: 404 } }, 404));
  for (const status of [200, 201, 301, 401, 403, 429, 500, '404']) assert.throws(() => assertDeniedReply({ status, value }, 404));
  for (const expected of [200, 401, 403, 429, 500]) assert.throws(() => assertDeniedReply({ status: expected, value: { statusCode: expected, message: expected === 401 ? 'Unauthorized' : 'Not Found' } }, expected));
  for (const body of [
    { ...value, statusCode: 401 }, { ...value, statusCode: '404' }, { ...value, statusCode: null },
    { ...value, message: 'not found' }, { ...value, message: 'Not Found ' }, { ...value, message: 'PRIVATE' },
    { ...value, message: null }, { ...value, message: ['Not Found'] }, { ...value, message: { text: 'Not Found' } },
    { statusCode: 404 }, { message: 'Not Found' }, { error: 'Not Found' }, { error: 'SCAN_NOT_FOUND' },
    { ...value, findings: [] }, { ...value, turns: [] }, { ...value, data: {} }, { ...value, extra: null },
    { ...value, errorCode: 'SCAN_NOT_FOUND' }, { ...value, error: undefined }, { ...value, error: null },
    { ...value, error: 'SCAN_NOT_FOUND' }, { ...value, error: { message: 'Not Found' } },
    null, [], 'Not Found', '<html>Not Found</html>',
  ]) assert.throws(() => assertDeniedReply({ status: 404, value: body }, 404));
  assert.doesNotThrow(() => assertDeniedReply({ status: 401, value: { statusCode: 401, message: 'Unauthorized', error: 'Unauthorized' } }, 401));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { ...value, error: 'Not Found' } }, 404));
  for (const errorCode of ['SCAN_NOT_FOUND', 'LLM_UNAVAILABLE']) assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { errorCode } }, 404));
});

test('quota unchanged cannot pass by comparing missing vectors or unavailable snapshots', () => {
  const binding = { scanId: id, digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'b'.repeat(64) };
  const vector = n => ({ input: n, output: n, costMicros: 0 });
  const scope = () => ({ limits: vector(100), used: vector(10), held: vector(0), carried: vector(0), remaining: vector(90) });
  const value = { ...binding, available: true, admission: { status: 'unavailable' }, window: { start: 0, end: 86400000 }, user: scope(), scan: scope() };
  assert.doesNotThrow(() => assertChatUsage(value, binding));
  for (const mutation of [{ available: false }, { user: undefined }, { scan: {} }, { window: undefined }, { reportVersion: 'c'.repeat(64) }, { admission: { status: 'fits' } }]) assert.throws(() => assertChatUsage({ ...value, ...mutation }, binding));
  const missing = structuredClone(value); delete missing.user.used; assert.throws(() => assertChatUsage(missing, binding));
  const wrong = structuredClone(value); wrong.scan.remaining.input++; assert.throws(() => assertChatUsage(wrong, binding));
  const invalid = structuredClone(value); invalid.user.held.input = -1; assert.throws(() => assertChatUsage(invalid, binding));
  assert.throws(() => assertChatUsage(null, binding));
});

test('render checks bind every row identity/content, not only the number of rows', () => {
  assert.notDeepEqual(renderedRowParts('sbom', { name: 'one', version: '1', ecosystem: 'npm' }), renderedRowParts('sbom', { name: 'one', version: '2', ecosystem: 'npm' }));
  assert.notDeepEqual(renderedRowParts('secret', { ruleId: 'rule-a', findingId: 'one', line: 1 }), renderedRowParts('secret', { ruleId: 'rule-a', findingId: 'two', line: 1 }));
  const row = { cveId: 'CVE-2026-1234', findingId: 'one', packageName: 'one', installedVersion: '1', severity: 'HIGH' };
  assert.notDeepEqual(renderedRowParts('vuln', row), renderedRowParts('vuln', { ...row, findingId: 'two' }));
});

test('one paginated dataset does not qualify all three; no checked subset is not preservation PASS', () => {
  assert.equal(paginationVerdict(1, 3).status, 'INCONCLUSIVE'); assert.equal(paginationVerdict(3, 3).status, 'PASS');
  const before = { perCheck: { secret: { outcome: 'failed' }, config: { outcome: 'checked' } } };
  assert.equal(preservationVerdict(before, ['secret'], {}, false).status, 'INCONCLUSIVE');
  assert.equal(preservationVerdict(before, ['config'], {}, false).status, 'PASS');
  assert.equal(preservationVerdict(before, ['config'], {}, true).status, 'INCONCLUSIVE');
  assert.equal(preservationVerdict({ perCheck: { secret: { outcome: 'checked' } } }, ['secret'], {}, false).status, 'INCONCLUSIVE');
});

test('evidence files are both acquired first, provisional Markdown precedes final JSON', async () => {
  const book = new ResultBook(), events = []; let index = 0;
  await writeEvidence(book.evidence(), async (_path, mode, permissions) => {
    assert.equal(mode, 'wx'); assert.equal(permissions, 0o600);
    const n = index++; events.push(`open${n}`);
    return { writeFile: async () => { events.push(`write${n}`); }, sync: async () => { events.push(`sync${n}`); }, close: async () => { events.push(`close${n}`); } };
  });
  assert.deepEqual(events.slice(0, 6), ['open0', 'open1', 'write1', 'sync1', 'write0', 'sync0']);
  const [json, md] = evidenceDocuments(book.evidence());
  assert.equal(JSON.parse(json).runId, book.runId); assert.ok(md.includes('Provisional summary only'));
});

test('second evidence-path collision and Markdown failure do not write a passing JSON', async () => {
  let opens = 0, writes = 0, closes = 0;
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => {
    if (opens++) throw new Error('synthetic collision');
    return { writeFile: async () => { writes++; }, sync: async () => {}, close: async () => { closes++; } };
  }));
  assert.equal(writes, 0); assert.equal(closes, 1);
  let index = 0; const events = [];
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => {
    const n = index++;
    return { writeFile: async () => { events.push(n); throw new Error('synthetic write failure'); }, sync: async () => {}, close: async () => {} };
  }));
  assert.deepEqual(events, [1]);
});

test('evidence close failure is not silently accepted as a successful write', async () => {
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => ({
    writeFile: async () => {}, sync: async () => {}, close: async () => { throw new Error('synthetic close failure'); },
  })));
});

test('native mutation guard obtains complete headers, not the security-redacted headers shortcut', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  assert.ok(source.includes('const headers = await request.allHeaders();'));
  assert.equal(source.includes('safeMutationRequest(request.url(), request.headers())'), false);
  assert.ok(source.includes('stopped || fatalCode || !safeMutationRequest(request.url(), headers)'));
});

test('shared GET fence covers current report serializers, exact runtime-off probes and native read headers', async () => {
  const { view } = await loadContracts();
  for (const [kind, suffix, sorts, filters] of [
    ['secret', 'results', ['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc'], [{}, { ruleId: 'Rule-1', linePresence: 'known' }, { linePresence: 'unknown' }]],
    ['sbom', 'sbom', ['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc'], [{}, { ecosystem: 'npm', name: '@scope/package' }]],
    ['vuln', 'vuln', ['severity:asc', 'severity:desc'], [{}, { severity: ['HIGH', 'CRITICAL'] }]],
  ]) for (const limit of [5, 10, 25, 50]) for (const sort of sorts) for (const filter of filters) for (const cursor of [undefined, 'opaque-next']) {
    const query = view.reportViewSearch(kind, { view: 'report-v1', limit, sort, ...filter }, cursor);
    const path = `${SCANS}/${id}/${suffix}?${query}`;
    assert.equal(allowedGet(path, [id]), true, path);
    assert.equal(allowedApiGet(ORIGIN + path, [id]), true);
    for (const extra of ['&limit=25', '&sort=other', '&extra=1']) assert.equal(allowedGet(path + extra, [id]), false);
  }
  for (const suffix of ['capabilities', 'targets', 'captures']) {
    const path = `/api/v1/browser/runtime/${suffix}`, url = ORIGIN + path;
    assert.equal(allowedGet(path, []), true);
    assert.equal(runtimeProbeRead(url), true);
    assert.doesNotThrow(() => assertRuntimeOffReply(url, 'GET', 404));
    for (const status of [200, 202, 401, 403, 500, 503]) assert.throws(() => assertRuntimeOffReply(url, 'GET', status));
    for (const method of ['HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']) assert.equal(allowedGet(path, [], method), false);
    for (const extra of ['?', '?cursor=x', '?limit=100', '/extra']) assert.equal(allowedGet(path + extra, []), false);
  }
  for (const path of [`${SCANS}/${id}/sbom?view=report-v1&limit=25&sort=name:asc&query=x`, `${SCANS}/${id}/vuln?view=report-v1&limit=25&sort=severity:desc&name=x`, '/api/v1/browser/runtime/imports']) assert.equal(allowedGet(path, [id]), false);
  const url = `${ORIGIN}${SCANS}/${id}/events`;
  for (const headers of [{}, { accept: 'text/event-stream', 'last-event-id': '7' }, { cookie: 'ephemeral-browser-cookie', origin: ORIGIN }]) assert.equal(safeReadRequest(url, headers), true);
  for (const headers of [{ Authorization: 'synthetic' }, { 'Proxy-Authorization': 'synthetic' }, { 'X-API-Key': 'synthetic' }, { origin: 'http://127.0.0.1:8080' }]) assert.equal(safeReadRequest(url, headers), false);
});

test('frontend request shapes remain covered without requiring auth headers or weakening mutation origin/JSON checks', () => {
  const readSource = name => readFileSync(new URL(`../src/shared/api/scans/${name}`, import.meta.url), 'utf8');
  const transport = readSource('httpScanTransport.ts');
  assert.match(transport, /BROWSER_SCANS_PATH\}\?limit=100/);
  assert.match(transport, /new EventSource\(path\)/);
  assert.match(transport, /headers: body \? \{ 'Content-Type': 'application\/json'/);
  for (const [name, accept] of [['llmChatClient.ts', 'application/x-ndjson'], ['advisoryTranslationClient.ts', null]]) {
    const code = readSource(name);
    assert.ok(code.includes("method: body ? 'POST' : 'GET'"));
    assert.ok(code.includes("credentials: 'same-origin'"));
    assert.ok(code.includes("redirect: 'error'"));
    assert.ok(code.includes("'Content-Type': 'application/json'"));
    if (accept) assert.ok(code.includes(accept));
  }
  const url = `${ORIGIN}${SCANS}/${id}/llm/chat`;
  assert.equal(safeMutationRequest(url, { origin: ORIGIN, 'content-type': 'application/json', accept: 'application/x-ndjson' }), true);
  const code = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  assert.ok(code.includes('if (fixedUrl(response.url())) book.actual = true'));
  assert.ok(code.includes('if (book.actual) { try { await writeEvidence(evidence)'));
  assert.ok(code.includes('own.state.closing = true; await own.context.close()'));
});

test('new product attempts require UUID destinations and never select historical evidence paths', () => {
  for (const mode of ['native', 'smoke']) {
    const plan = nativePlan(mode, id);
    assert.ok(plan.evidencePaths.every(path => path.includes(`/docs/public-final-${id}-${mode}.`)));
    assert.equal(new ResultBook(mode, id).evidence().attemptId, id);
    assert.throws(() => nativePlan(mode, '../attempt2'));
  }
  for (const args of [
    ['--run', '--ack-coordinator-go', '--ack-no-key-activation'],
    ['--run', '--smoke-only', '--ack-coordinator-go', '--ack-no-key-activation'],
    ['--run', '--ack-coordinator-go', '--ack-no-key-activation', '--attempt-id', '../attempt3'],
  ]) assert.throws(() => parseMode(args));
});

test('runner source has no response mocking, saved browser state, lifecycle or historical holders', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  for (const pattern of [/route\.fulfill\s*\(/, /\.addCookies\s*\(/, /storageState\s*:/, /\.screenshot\s*\(/, /\.tracing\./, /recordHar\s*:/, /recordVideo\s*:/, /\bspawn\s*\(/, /docker (?:run|exec|start|stop|cp|inspect|compose)/, /\.local-auth/, /privateEnv/, /task16-chat-browser/]) assert.equal(pattern.test(source), false);
  assert.ok(GLOBAL_MS > WORKER_MS * 3 && GLOBAL_MS <= 45 * 60000);
});
