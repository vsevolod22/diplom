// Offline guards only. Importing the runner does not launch a browser or contact a stand/provider.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import test from 'node:test';
import {
  ORIGIN, WORKER_MS, GLOBAL_MS, MODEL, ENDPOINT, CASES, EVIDENCE_PATHS, evidencePaths, parseMode,
  projectMeta, llmFailureMeta, assertLlmSuccess, diagnosticFromHeaders, DIAGNOSTIC_PHASES, DIAGNOSTIC_REASONS, ResultBook, Fault, recordFailure, GuardLedger, routeCategory, guardAbortReason, canRunTranslation,
    exitCode, settleAcceptedScan, completeFreshOwnerLogin, evidenceDocuments, writeEvidence, assertFixedPolicy, assertReady,
  qualificationCases, chatBodyMatches, translationBody, canDispatch, allowedApiGet, runtimeProbeRead, assertRuntimeOffReply, eligibleAssessment, assertInitialUsage, renderedReplyMatches, historyMetadata, loadTranslationContracts,
} from './public-ai-translation-live.mjs';

import { BrowserReadError, trackBrowserReadPage, readBrowserJson, settleAuthNavigation, assertAuthUser } from './public-product-live.mjs';

const scanId = '12345678-1234-4234-8234-123456789abc';
const findingId = `vuln-${'a'.repeat(64)}`;
const binding = { scanId, digest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'c'.repeat(64) };
const disclosure = {
  provider: 'OpenRouter', model: MODEL, providers: [ENDPOINT], freeOnly: true, requestBudgetUsd: 0,
  region: 'global', retention: 'no-storage', maxPrice: { prompt: 0, completion: 0, request: 0 },
  operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true,
};
const context = { ...binding, epoch: '12345678-1234-4234-8234-123456789abd', revision: 0, enabled: true,
  policyVersion: 'd'.repeat(64), disclosure, findingId, assessmentIndex: 0, sourceVersion: 'e'.repeat(64), targetLanguage: 'ru' };
const ready = { ...binding, localReady: true, credential: 'metadata-valid', blockers: [], requiresConsent: true,
  acceptsCredentials: false, generationVerified: false, provider: { model: MODEL, endpoint: ENDPOINT, liveVerified: false } };
const question = 'Краткий синтетический вопрос';
const body = () => ({ epoch: context.epoch, revision: context.revision, mutationId: scanId, reportVersion: context.reportVersion,
  question, consent: { accepted: true, policyVersion: context.policyVersion } });
const source = () => readFileSync(new URL('./public-ai-translation-live.mjs', import.meta.url), 'utf8');

test('live requires the exact coordinator READYGO and three-request acknowledgements; default and import are inert', () => {
  assert.equal(parseMode([]), 'not-run'); assert.equal(parseMode(['--self-test']), 'offline');
  assert.equal(parseMode(['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-id', scanId]), 'live-final');
  assert.equal(parseMode(['--run', '--translation-only', '--ack-coordinator-readygo', '--ack-one-translation-request', '--attempt-id', scanId]), 'translation-final');
  for (const args of [
    ['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests'],
    ['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-suffix', 'attempt2'],
    ['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-suffix', 'attempt3'],
    ['--run', '--translation-only', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-id', scanId],
    ['--run', '--ack-coordinator-readygo', '--ack-one-translation-request', '--attempt-id', scanId],
  ]) assert.throws(() => parseMode(args));
  for (const suffix of ['attempt4', '../attempt2', '/tmp/attempt2', '', 'attempt2.json'])
    assert.throws(() => parseMode(['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-suffix', suffix]));
  assert.throws(() => parseMode(['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--attempt-suffix']));
  assert.throws(() => evidencePaths('attempt4'));
  for (const args of [['--run'], ['--run', '--ack-coordinator-readygo'], ['--run', '--ack-three-provider-requests'],
    ['--self-test', '--run'], ['--run', '--ack-coordinator-go', '--ack-three-provider-requests'],
    ['--run', '--ack-coordinator-readygo', '--ack-three-provider-requests', '--target=other']]) assert.throws(() => parseMode(args));
  const paths = [...EVIDENCE_PATHS, ...evidencePaths('attempt2'), ...evidencePaths('attempt3')];
  const prior = paths.map(path => existsSync(path) ? readFileSync(path) : null);
  for (const args of [[], ['--run'], ['--self-test']]) {
    const run = spawnSync(process.execPath, [new URL('./public-ai-translation-live.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(run.status, args.includes('--self-test') ? 0 : 2);
    const result = JSON.parse(run.stdout); assert.equal(result.actuallyRun, false);
    assert.equal(run.stderr, '');
  }
  assert.deepEqual(paths.map(path => existsSync(path) ? readFileSync(path) : null), prior);
});

test('one fixed Node four-check scan, a 660-second worker deadline and a hard 20-minute global budget', () => {
  assert.equal(WORKER_MS, 660000); assert.equal(GLOBAL_MS, 20 * 60000);
  assert.ok(GLOBAL_MS > WORKER_MS + 3 * 30000);
  const code = source();
  assert.ok(code.includes('const target = TARGETS[0]'));
  assert.ok(code.includes('stats.scanLaunches === 0'));
  assert.ok(code.includes('for (const check of CHECKS)'));
  assert.equal(/158/.test(code), false);
  assert.ok(code.includes('partition(rows)'));
});

test('browser GET fence rejects port 8080, credentials, other scans, arbitrary APIs and malformed translation selectors', () => {
  for (const suffix of ['', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage'])
    assert.ok(allowedApiGet(`${ORIGIN}/api/v1/browser/scans/${scanId}${suffix}`, [scanId]));
  assert.ok(allowedApiGet(`${ORIGIN}/api/v1/auth/me`, []));
  const runtimeSource = readFileSync(new URL('../src/shared/api/scans/runtimeTransport.ts', import.meta.url), 'utf8');
  assert.ok(runtimeSource.includes("private readonly prefix = '/api/v1/browser/runtime'"));
  assert.ok(runtimeSource.includes("this.request('/capabilities'"));
  assert.ok(runtimeSource.includes("'/targets'"));
  assert.ok(runtimeSource.includes("`/captures${cursor ? `?cursor=${cursor}` : ''}`"));
  const runtimePanelSource = readFileSync(new URL('../src/features/scans/RuntimeScanPanel.tsx', import.meta.url), 'utf8');
  assert.match(runtimePanelSource, /Promise\.all\(\[\s*transport\.capabilities\(abort\.signal\),\s*transport\.targets\(abort\.signal\),\s*transport\.history\(undefined, abort\.signal\),\s*\]\)/);
  for (const [suffix, category] of [['capabilities', 'runtime-capabilities'], ['targets', 'runtime-targets'], ['captures', 'runtime-captures']]) {
    const url = `${ORIGIN}/api/v1/browser/runtime/${suffix}`;
    assert.equal(allowedApiGet(url, [], 'GET'), true);
    assert.equal(runtimeProbeRead(url, 'GET'), true);
    assert.equal(routeCategory(url), category);
    assert.doesNotThrow(() => assertRuntimeOffReply(url, 'GET', 404));
    for (const status of [200, 201, 401, 403, 503]) assert.throws(() => assertRuntimeOffReply(url, 'GET', status));
    for (const method of ['HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'OTHER']) {
      assert.equal(allowedApiGet(url, [], method), false);
      assert.equal(runtimeProbeRead(url, method), false);
      assert.throws(() => assertRuntimeOffReply(url, method, 404));
    }
    for (const mutation of ['?limit=100', '?cursor=x', '?x=1&x=2', '/', '/extra'])
      assert.equal(allowedApiGet(url + mutation, []), false);
    assert.equal(allowedApiGet(url.replace(':8081', ':8080'), []), false);
    assert.equal(allowedApiGet(url.replace('127.0.0.1', 'localhost'), []), false);
    const state = { aiOwner: true, permit: { context, question, used: false }, chatPosts: 0, translationPosts: 0 };
    assert.equal(canDispatch(state, `/api/v1/browser/runtime/${suffix}`, body()), false);
  }
  for (const suffix of ['captures/' + scanId, 'captures/private', 'imports', 'consents', 'cancel', 'live', 'capabilities-extra', 'targets/private'])
    for (const method of ['GET', 'HEAD', 'POST']) assert.equal(allowedApiGet(`${ORIGIN}/api/v1/browser/runtime/${suffix}`, [], method), false);
  const scanList = `${ORIGIN}/api/v1/browser/scans`;
  for (const query of ['', '?limit=100', '?limit=100&cursor=opaque-next-page', '?cursor=opaque-next-page&limit=100', '?limit=100&cursor=' + 'a'.repeat(512)])
    assert.ok(allowedApiGet(scanList + query, []));
  assert.equal(routeCategory(scanList + '?limit=100'), 'scan-list');
  for (const query of ['?limit=99', '?limit=101', '?limit=0100', '?cursor=opaque', '?limit=100&extra=1',
    '?limit=100&limit=100', '?limit=100&cursor=one&cursor=two', '?limit=100&cursor=',
    '?limit=100&cursor=' + 'a'.repeat(513), '?limit=100&cursor=%0A'])
    assert.equal(allowedApiGet(scanList + query, []), false);
  assert.equal(allowedApiGet(scanList.replace(':8081', ':8080') + '?limit=100', []), false);
  assert.equal(allowedApiGet(`${ORIGIN}/api/v1/auth/me?limit=100`, []), false);
  assert.equal(allowedApiGet(`${ORIGIN}/api/v1/private?limit=100`, []), false);
  const selected = `${ORIGIN}/api/v1/browser/scans/${scanId}/llm/translation/context?findingId=${findingId}&assessmentIndex=0`;
  assert.ok(allowedApiGet(selected, [scanId]));
  assert.ok(allowedApiGet(`${ORIGIN}/api/v1/browser/scans/${scanId}/vuln?view=report-v1&limit=50&sort=severity%3Adesc`, [scanId]));
  for (const url of [selected.replace(':8081', ':8080'), selected.replace('127.0.0.1', 'localhost'), selected + '&extra=1', selected + '&findingId=' + findingId,
    selected.replace('assessmentIndex=0', 'assessmentIndex=16'), selected.replace('assessmentIndex=0', 'assessmentIndex=00'),
    selected.replace(findingId, 'CVE-2026-1234'), `${ORIGIN}/api/v1/admin`, `${ORIGIN}/api/v1/auth/me?extra=1`,
    `${ORIGIN}/api/v1/browser/scans/${scanId}/llm/history/decision`, `${ORIGIN}/api/v1/browser/scans/${scanId}/runtime`,
    `${ORIGIN}/api/v1/browser/scans/${scanId}/vuln?override=1`]) assert.equal(allowedApiGet(url, [scanId]), false);
  assert.equal(allowedApiGet(selected, []), false);
});

test('only the fixed OpenRouter phala free/no-storage/zero-price policy is authorized', () => {
  assertFixedPolicy(context); assertReady(ready, context);
  for (const change of [{ model: 'other/free' }, { providers: ['other'] }, { providers: ['phala', 'fallback'] },
    { freeOnly: false }, { requestBudgetUsd: 0.001 }, { retention: 'no-training' },
    { maxPrice: { prompt: 0, completion: 1, request: 0 } }, { operatorApprovedRouting: false }])
    assert.throws(() => assertFixedPolicy({ ...context, disclosure: { ...disclosure, ...change } }));
  for (const change of [{ credential: 'missing' }, { localReady: false }, { reportVersion: 'f'.repeat(64) },
    { acceptsCredentials: true }, { generationVerified: true }, { blockers: ['public-key-required'] }])
    assert.throws(() => assertReady({ ...ready, ...change }, context));
  const counters = () => ({ limits: { input: 100, output: 100, costMicros: 0 },
    used: { input: 0, output: 0, costMicros: 0 }, held: { input: 0, output: 0, costMicros: 0 },
    carried: { input: 0, output: 0, costMicros: 0 }, remaining: { input: 100, output: 100, costMicros: 0 } });
  const initial = { ...binding, available: true, window: { start: 0, end: 86400000 }, admission: { status: 'unavailable' }, user: counters(), scan: counters() };
  assert.equal(assertInitialUsage(initial, context), initial);
  for (const scope of ['user', 'scan']) for (const vector of ['used', 'held', 'carried']) for (const dimension of ['input', 'output', 'costMicros']) {
    const nonzero = structuredClone(initial);
    nonzero[scope][vector][dimension] = 1;
    nonzero[scope].remaining[dimension] = Math.max(0, nonzero[scope].limits[dimension] - 1);
    assert.throws(() => assertInitialUsage(nonzero, context));
  }
  for (const malformed of [{ ...initial, available: false }, { ...initial, reportVersion: 'f'.repeat(64) },
    { ...initial, user: { ...initial.user, used: { input: 0, output: 0 } } },
    { ...initial, scan: { ...initial.scan, held: { input: 0, output: 0, costMicros: 0, extra: 0 } } }])
    assert.throws(() => assertInitialUsage(malformed, context));
});

test('chat permits require exact CAS/body/question and explicit per-send consent, never arbitrary copied text or credentials', () => {
  assert.ok(chatBodyMatches(body(), context, question));
  for (const change of [{ revision: 2 }, { reportVersion: 'f'.repeat(64) }, { question: 'other' }, { mutationId: 'invalid' },
    { consent: { accepted: false, policyVersion: context.policyVersion } },
    { consent: { accepted: true, policyVersion: 'f'.repeat(64) } }, { targetLanguage: 'ru' }, { apiKey: 'SYNTHETIC_PRIVATE_MARKER' }])
    assert.equal(chatBodyMatches({ ...body(), ...change }, context, question), false);
});

test('LLM permit caps and owner gate prohibit third chat, second translation, foreign generation and reused permits', () => {
  const state = { aiOwner: true, permit: { context, question, used: false }, chatPosts: 0, translationPosts: 0 };
  const chat = `/api/v1/browser/scans/${scanId}/llm/chat`, translation = `/api/v1/browser/scans/${scanId}/llm/translation`;
  assert.ok(canDispatch(state, chat, body())); assert.ok(canDispatch(state, translation, translationBody(context)));
  assert.equal(canDispatch({ ...state, aiOwner: false }, chat, body()), false);
  assert.equal(canDispatch({ ...state, chatPosts: 2 }, chat, body()), false);
  assert.equal(canDispatch({ ...state, translationPosts: 1 }, translation, translationBody(context)), false);
  assert.equal(canDispatch({ ...state, permit: { ...state.permit, used: true } }, chat, body()), false);
  assert.equal(canDispatch({ ...state, permit: null }, chat, body()), false);
  assert.equal(canDispatch({ ...state, permit: {} }, chat, body()), false);
  assert.equal(canDispatch(state, chat + '?override=1', body()), false);
  assert.equal(canDispatch(state, chat.replace('/chat', '/summary'), body()), false);
  assert.equal(canDispatch(state, translation, { ...translationBody(context), targetLanguage: 'en' }), false);
  assert.equal(canDispatch(state, translation, { ...translationBody(context), text: 'payload' }), false);
  const code = source();
  assert.ok(code.includes('consumePermit(state.permit'));
  assert.ok(code.includes('stats.chatPosts >= 2'));
  assert.ok(code.includes('stats.translationPosts >= 1'));
});

test('metadata projection rejects conversations, provider payloads, private diagnostics, credentials and arbitrary strings', () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  const meta = projectMeta({ scanId, findingId, reportVersion: context.reportVersion, cve: 2, debit: marker,
    password: marker, email: marker, token: marker, cookies: marker, text: marker, request: marker, response: marker,
    errorCode: marker, providerMessage: marker, runnerLine: marker, historyFingerprint: marker });
  assert.deepEqual(meta, { scanId, findingId, reportVersion: context.reportVersion, cve: 2 });
  assert.equal(JSON.stringify(meta).includes(marker), false);
  assert.deepEqual(projectMeta({ httpStatus: 503, errorCode: 'LLM_QUOTA_EXCEEDED', costMicros: 0 }),
    { httpStatus: 503, errorCode: 'LLM_QUOTA_EXCEEDED', costMicros: 0 });
  assert.deepEqual(projectMeta({ httpStatus: 502, errorCode: 'LLM_INVALID_RESPONSE', diagnostic: marker }),
    { httpStatus: 502, errorCode: 'LLM_INVALID_RESPONSE' });
  assert.deepEqual(projectMeta({ initialUsageZero: true, used: marker }), { initialUsageZero: true });
  const book = new ResultBook(); book.record('chat_1', 'BLOCKED', 'LLM_HTTP_ERROR', { request: marker, diagnostic: marker });
  const failed = new ResultBook();
  const wireError = new Fault('LLM_HTTP_ERROR', { httpStatus: 200, errorCode: 'LLM_UNAVAILABLE', deliveryKind: 'ndjson-error', diagnostic: marker });
  recordFailure(failed, 'chat_1', wireError);
  recordFailure(failed, 'chat_1', new Error(marker), 'REQUEST_GUARD');
  assert.deepEqual(projectMeta(failed.cases.chat_1), { httpStatus: 200, errorCode: 'LLM_UNAVAILABLE', deliveryKind: 'ndjson-error' });
  assert.equal(failed.cases.chat_1.code, 'LLM_HTTP_ERROR');
  assert.equal(failed.cases.chat_1.status, 'BLOCKED');
  const httpError = new ResultBook();
  recordFailure(httpError, 'translation', new Fault('LLM_HTTP_ERROR', { httpStatus: 502, errorCode: 'LLM_INVALID_RESPONSE', deliveryKind: 'http-error' }));
  recordFailure(httpError, 'translation', new Error(marker));
  assert.equal(httpError.cases.translation.httpStatus, 502);
  assert.equal(httpError.cases.translation.errorCode, 'LLM_INVALID_RESPONSE');
  assert.equal(httpError.cases.translation.deliveryKind, 'http-error');
  const documents = evidenceDocuments(book); assert.ok(documents.every(text => !text.includes(marker)));
  assert.ok(evidenceDocuments(failed).every(text => !text.includes(marker)));
  assert.ok(documents[1].includes('Server egress and billing are NOT independently observed'));
  const history = { turns: [{ state: 'completed', question: marker, reply: { text: marker } }] };
  assert.equal(historyMetadata(history).completedTurns, 1);
  assert.ok(/^[a-f0-9]{64}$/.test(historyMetadata(history).historyFingerprint));
  assert.equal(JSON.stringify(historyMetadata(history)).includes(marker), false);
});

test('finite provider failures survive HTTP/NDJSON faults and repeated evidence projection without raw diagnostics', () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  for (const [status, kind, errorCode] of [
    [429, 'rate_limited', 'LLM_PROVIDER_RATE_LIMITED'], [503, 'rate_limited', 'LLM_PROVIDER_RATE_LIMITED'],
    [401, 'auth_failed', 'LLM_PROVIDER_AUTH_FAILED'], [502, 'unavailable', 'LLM_PROVIDER_UNAVAILABLE'],
  ]) for (const retry of kind === 'rate_limited' ? [undefined, 0, 60, 86400] : [undefined]) {
    const providerFailure = { kind, status, ...(retry === undefined ? {} : { retryAfterSeconds: retry }) };
    for (const deliveryKind of ['http-error', 'ndjson-error']) {
      const httpStatus = deliveryKind === 'ndjson-error' ? 200 : kind === 'auth_failed' ? 503 : status;
      const wire = { errorCode, providerFailure, message: marker, body: marker, payload: { private: marker } };
      const expected = { httpStatus, errorCode, providerFailure, deliveryKind };
      let fault;
      if (deliveryKind === 'http-error') {
        assert.throws(() => assertLlmSuccess({ status: httpStatus, value: wire }), error => {
          fault = error; return error instanceof Fault && error.message === 'LLM_HTTP_ERROR';
        });
      } else fault = new Fault('LLM_HTTP_ERROR', llmFailureMeta(httpStatus, wire, deliveryKind));
      assert.deepEqual(fault.meta, expected);
      assert.deepEqual(projectMeta(projectMeta(fault.meta)), expected);
      assert.notEqual(fault.meta.providerFailure, providerFailure);
      const book = new ResultBook(scanId);
      const name = deliveryKind === 'ndjson-error' ? 'chat_1' : 'translation';
      recordFailure(book, name, fault);
      recordFailure(book, name, new Error(marker));
      assert.equal(book.cases[name].status, 'BLOCKED');
      assert.equal(book.cases[name].code, 'LLM_HTTP_ERROR');
      const { runnerLine, ...persisted } = projectMeta(book.evidence().cases[name]);
            assert.ok(runnerLine === undefined || Number.isSafeInteger(runnerLine) && runnerLine > 0);
            assert.deepEqual(persisted, expected);
      const documents = evidenceDocuments(book);
      assert.deepEqual(JSON.parse(documents[0]).cases[name].providerFailure, providerFailure);
      assert.ok(documents.every(text => !text.includes(marker)));
    }
  }
  assert.equal(assertLlmSuccess({ status: 200, value: null }), null);
    assert.deepEqual(llmFailureMeta(502, null, 'http-error'), { httpStatus: 502, deliveryKind: 'http-error' });
  assert.deepEqual(llmFailureMeta(502, { errorCode: marker, providerFailure: marker }, 'http-error'), { httpStatus: 502, deliveryKind: 'http-error' });
  const code = source();
  assert.ok(code.includes("llmFailureMeta(result.status, result.value, 'http-error', result.providerDiagnostic)"));
  assert.ok(code.includes("llmFailureMeta(200, delivered, 'ndjson-error', diagnosticFromHeaders(response.headers()))"));
});

test('provider metadata rejects unknown kinds, mismatches, unsafe bounds, extra fields and missing hints remain unknown', () => {
  const errorCode = 'LLM_PROVIDER_RATE_LIMITED';
  const valid = { kind: 'rate_limited', status: 429 };
  for (const failure of [null, [], 'private', {}, { ...valid, kind: 'busy' }, { ...valid, status: 401 },
    ...[299, 600, 429.5, '429', NaN, Infinity].map(status => ({ ...valid, status })),
    ...[-1, 86401, 0.5, '60', null, NaN, Infinity].map(retryAfterSeconds => ({ ...valid, retryAfterSeconds })),
    { ...valid, message: 'PRIVATE' }, { ...valid, payload: { private: 'PRIVATE' } },
    { ...valid, kind: 'unavailable', status: 500 }, { ...valid, kind: 'auth_failed', status: 401 },
  ]) assert.equal(projectMeta({ errorCode, providerFailure: failure }).providerFailure, undefined);
  for (const code of ['LLM_UNAVAILABLE', 'LLM_INVALID_RESPONSE', 'LLM_PROVIDER_AUTH_FAILED', 'LLM_PROVIDER_UNAVAILABLE', 'PRIVATE'])
    assert.equal(projectMeta({ errorCode: code, providerFailure: valid }).providerFailure, undefined);
  for (const [code, kind, status] of [['LLM_PROVIDER_AUTH_FAILED', 'auth_failed', 401], ['LLM_PROVIDER_UNAVAILABLE', 'unavailable', 500]])
    assert.equal(projectMeta({ errorCode: code, providerFailure: { kind, status, retryAfterSeconds: 0 } }).providerFailure, undefined);
  const projected = projectMeta({ errorCode, providerFailure: valid });
  assert.deepEqual(projected.providerFailure, valid);
  assert.equal(Object.hasOwn(projected.providerFailure, 'retryAfterSeconds'), false);
  for (let status = 300; status <= 599; status++) {
    const kind = [429, 503].includes(status) ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable';
    const code = kind === 'rate_limited' ? errorCode : kind === 'auth_failed' ? 'LLM_PROVIDER_AUTH_FAILED' : 'LLM_PROVIDER_UNAVAILABLE';
    assert.deepEqual(projectMeta({ errorCode: code, providerFailure: { kind, status } }).providerFailure, { kind, status });
  }
});

test('actual frontend NDJSON parser retains safe provider diagnostics for accepted and unavailable receipts', async () => {
  const { chat } = await loadTranslationContracts();
  for (const [status, kind, errorCode] of [[429, 'rate_limited', 'LLM_PROVIDER_RATE_LIMITED'], [503, 'rate_limited', 'LLM_PROVIDER_RATE_LIMITED'],
    [401, 'auth_failed', 'LLM_PROVIDER_AUTH_FAILED'], [502, 'unavailable', 'LLM_PROVIDER_UNAVAILABLE']]) for (const receipt of ['accepted', 'unavailable']) {
    const providerFailure = { kind, status, ...(kind === 'rate_limited' ? { retryAfterSeconds: 60 } : {}) };
    const frame = { ...binding, v: 1, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
      epoch: context.epoch, revision: context.revision + 2, mutationId: scanId, turnId: scanId };
    const parser = chat.createChatFrameParser(context, scanId);
    if (receipt === 'accepted') parser.accept({ ...frame, type: 'usage', seq: 0,
      usage: { input: 1, output: 1, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' } });
    parser.accept({ ...frame, type: 'error', seq: receipt === 'accepted' ? 1 : 0, receipt, errorCode, providerFailure });
    const delivered = parser.finish();
    const book = new ResultBook(scanId);
    recordFailure(book, 'chat_1', new Fault('LLM_HTTP_ERROR', llmFailureMeta(200, delivered, 'ndjson-error')));
    assert.deepEqual(projectMeta(book.evidence().cases.chat_1), { httpStatus: 200, errorCode, providerFailure, deliveryKind: 'ndjson-error' });
    assert.equal(exitCode(book), 2);
  }
});

test('header diagnostics match the actual backend finite exports, preserve safe pairs, never raw headers or body-forged fields', async () => {
  const { diagnostics } = await loadTranslationContracts();
  assert.deepEqual(DIAGNOSTIC_PHASES, [...diagnostics.FAILURE_PHASES]);
  assert.deepEqual(DIAGNOSTIC_REASONS, [...diagnostics.FAILURE_REASONS]);
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  for (const phase of DIAGNOSTIC_PHASES) for (const reason of DIAGNOSTIC_REASONS) {
    const headers = new Headers({ 'X-LLM-Failure-Phase': phase, 'X-LLM-Failure-Reason': reason, 'x-private': marker });
    const providerDiagnostic = diagnosticFromHeaders(headers);
    assert.deepEqual(providerDiagnostic, { phase, reason });
    const value = { errorCode: 'LLM_INVALID_RESPONSE', providerDiagnostic: { phase: 'tls', reason: 'io_error' }, message: marker };
    for (const deliveryKind of ['http-error', 'ndjson-error']) {
      const meta = llmFailureMeta(deliveryKind === 'http-error' ? 502 : 200, value, deliveryKind, providerDiagnostic);
      assert.deepEqual(meta.providerDiagnostic, { phase, reason });
      const book = new ResultBook(scanId); recordFailure(book, 'chat_1', new Fault('LLM_HTTP_ERROR', meta));
      assert.deepEqual(book.evidence().cases.chat_1.providerDiagnostic, { phase, reason });
      assert.ok(evidenceDocuments(book).every(text => !text.includes(marker)));
    }
    assert.equal(llmFailureMeta(502, value, 'http-error').providerDiagnostic, undefined);
  }
  for (const headers of [{}, { 'x-llm-failure-phase': 'tls' }, { 'x-llm-failure-reason': 'io_error' },
    { 'x-llm-failure-phase': marker, 'x-llm-failure-reason': 'io_error' },
    { 'x-llm-failure-phase': 'tls', 'x-llm-failure-reason': marker },
    { 'x-llm-failure-phase': 'tls,headers', 'x-llm-failure-reason': 'io_error' },
    { 'x-llm-failure-phase': ['tls'], 'x-llm-failure-reason': 'io_error' },
    { 'x-llm-failure-phase': ' tls', 'x-llm-failure-reason': 'io_error' }]) assert.equal(diagnosticFromHeaders(headers), undefined);
  for (const providerDiagnostic of [{ phase: 'tls', reason: 'io_error', message: marker }, { phase: marker, reason: 'io_error' },
    { phase: 'tls', reason: marker }, null, 'PRIVATE', []]) assert.equal(projectMeta({ providerDiagnostic }).providerDiagnostic, undefined);
  const valid = diagnosticFromHeaders({ 'X-LLM-Failure-Phase': 'headers', 'X-LLM-Failure-Reason': 'http_error' });
  assert.deepEqual(valid, { phase: 'headers', reason: 'http_error' });
  assert.throws(() => assertLlmSuccess({ status: 502, value: { errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, providerDiagnostic: valid }),
    error => isSafeDiagnosticFault(error, valid));
});
function isSafeDiagnosticFault(error, expected) {
  assert.ok(error instanceof Fault); assert.deepEqual(error.meta.providerDiagnostic, expected); return true;
}

test('five new finish diagnostic reasons survive only finite response headers, never API body or incomplete pairs', () => {
  for (const reason of ['finish_length', 'finish_content_filter', 'finish_tool_calls', 'finish_error', 'finish_unknown']) {
    const value = { errorCode: 'LLM_UNAVAILABLE', providerDiagnostic: { phase: 'finish', reason }, message: 'PRIVATE' };
    const headers = { 'x-llm-failure-phase': 'finish', 'x-llm-failure-reason': reason };
    const parsed = diagnosticFromHeaders(headers);
    assert.deepEqual(parsed, { phase: 'finish', reason });
    assert.equal(llmFailureMeta(200, value, 'ndjson-error').providerDiagnostic, undefined);
    const book = new ResultBook(scanId);
    recordFailure(book, 'chat_1', new Fault('LLM_HTTP_ERROR', llmFailureMeta(200, value, 'ndjson-error', parsed)));
    assert.deepEqual(book.evidence().cases.chat_1.providerDiagnostic, parsed);
    assert.ok(evidenceDocuments(book).every(text => !text.includes('PRIVATE')));
    assert.equal(diagnosticFromHeaders({ 'x-llm-failure-reason': reason }), undefined);
    assert.equal(diagnosticFromHeaders({ 'x-llm-failure-phase': 'finish' }), undefined);
    assert.equal(diagnosticFromHeaders({ ...headers, 'x-llm-failure-reason': reason + ',PRIVATE' }), undefined);
  }
});

test('legacy manual selectors remain fail-closed on the new preference-authorized UI; chat still has one-click server envelopes', () => {
  const code = source();
  for (const old of ['Открыть чат и прочитать условия', 'Прочитать условия перевода', 'Разрешаю один запрос чата:', 'Разрешаю один запрос перевода:']) assert.equal(code.includes(old), false);
  const chatUi = readFileSync(new URL('../src/features/scans/ScanChatPanel.tsx', import.meta.url), 'utf8');
  const translationUi = readFileSync(new URL('../src/features/scans/AdvisoryTranslationPanel.tsx', import.meta.url), 'utf8');
  assert.equal(chatUi.includes("'Открыть чат'"), false);
  assert.ok(code.includes("name: 'Открыть чат', exact: true")); // Legacy live workflow is not qualification for the new UI.
  for (const text of ['scan-chat-send-help', 'Нажимая «Отправить вопрос», вы разрешаете один запрос:']) {
    assert.ok(chatUi.includes(text)); assert.ok(code.includes(text));
  }
  assert.ok(translationUi.includes("void operate('read', null, true)"));
  assert.ok(translationUi.includes('Сохранённое разрешение аккаунта запускает один перевод при открытии:'));
  assert.equal(translationUi.includes('Нажимая «Перевести на русский», вы разрешаете один запрос:'), false);
  assert.ok(code.includes('Нажимая «Перевести на русский», вы разрешаете один запрос:'));
  const translation = code.slice(code.indexOf("const contextOk = await step('translation_context'"), code.indexOf("await step('translation_toggle'"));
  assert.equal(translation.includes('checkbox'), false); assert.equal(translation.includes('consent.check'), false);
  assert.equal((translation.match(/await submit.click\(/g) ?? []).length, 1);
  assert.equal(translation.includes('Обновить условия перевода'), false); // No extra read-button gesture/autoretry.
  assert.ok(translation.includes('assert.deepEqual(before, translationContext)'));
  assert.ok(translation.includes('assert.equal(stats.translationPosts, 0)'));
  assert.ok(translation.includes('translationBody(before)'));
  assert.ok(code.includes('await awaitStableUiEligibility(own, after, read, authority)'));
  assert.ok(code.includes('await awaitEligibility(state.fence, launch.sequence, state.eligibilityPending'));
});

test('translation panel waits for lazy-mounted region before deployed UI button count and fails closed without retry', async () => {
  const code = source();
  const helper = code.match(/  const translationPanel = (async page => \{[\s\S]*?\n  \});/);
  assert.ok(helper, 'Exercise the actual nested translationPanel helper without running the live workflow');
  assert.ok(code.includes('expect = baseExpect.configure({ timeout: 15_000 })'));
  const deployed = code.slice(code.indexOf("if (!await step('deployed_ui'"), code.indexOf("if (qualification === 'full')", code.indexOf("if (!await step('deployed_ui'")));
  assert.ok(deployed.indexOf('await translationPanel(own.page)') < deployed.indexOf('await button.count()'));
  const selected = { row: { findingId, cveId: 'CVE-2026-1234' }, item: { source: 'NVD' }, index: 0 };
  const calls = []; let present = true, mounted = false, releaseVisibility;
  let visibility = new Promise(resolve => { releaseVisibility = () => { mounted = true; resolve(); }; });
  const button = { count: async () => { calls.push('button-count'); assert.ok(mounted); return 1; } };
  const region = { getByRole: (role, options) => {
    assert.equal(role, 'button'); assert.deepEqual(options, { name: 'Перевести на русский', exact: true });
    return button;
  } };
  const row = {
    count: async () => Number(present),
    locator: selector => { assert.equal(selector, 'details.scan-vuln-row__details > summary'); return { click: async () => { calls.push('summary-click'); } }; },
    getByRole: (role, options) => {
      assert.equal(role, 'region'); assert.deepEqual(options, { name: 'Перевод CVE-2026-1234, источник NVD, оценка 1', exact: true });
      calls.push('region-locator'); return region;
    },
  };
  const page = { locator: selector => {
    assert.equal(selector, 'li.scan-vuln-row');
    return { filter: options => { assert.deepEqual(options, { hasText: `ID находки: ${findingId}` }); return row; } };
  } };
  const expect = actual => { assert.equal(actual, region); return { toBeVisible: () => { calls.push('region-visible'); return visibility; } }; };
  const openPanel = new Function('selected', 'Fault', 'expect', `return (${helper[1]});`)(selected, Fault, expect);
  let returned = false;
  const pending = openPanel(page).then(value => { returned = true; return value; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(returned, false);
  assert.deepEqual(calls, ['summary-click', 'region-locator', 'region-visible']);
  releaseVisibility();
  assert.equal(await pending, region);
  assert.equal(await region.getByRole('button', { name: 'Перевести на русский', exact: true }).count(), 1);
  assert.deepEqual(calls, ['summary-click', 'region-locator', 'region-visible', 'button-count']);

  calls.length = 0; mounted = false;
  const timeout = new Error('synthetic visibility timeout');
  visibility = Promise.resolve().then(() => { throw timeout; });
  await assert.rejects(openPanel(page), error => error === timeout);
  assert.deepEqual(calls, ['summary-click', 'region-locator', 'region-visible']);
  calls.length = 0; present = false;
  await assert.rejects(openPanel(page), error => error instanceof Fault && error.message === 'NO_ELIGIBLE_ASSESSMENT');
  assert.deepEqual(calls, []);
});

test('accepted 202 UUID is retained immediately through later navigation/status failure, never turned into scan PASS', async () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER', book = new ResultBook(scanId);
  for (const [status, value] of [[201, { scanId }], [202, {}], [202, { scanId: marker }]]) assert.throws(() => book.recordScanReceipt(status, value));
  assert.equal(book.scanReceipt, null);
  const page = { waitForURL: async () => { throw new Error('must not navigate without receipt'); } };
  await assert.rejects(settleAcceptedScan(book, page, () => true), error => error instanceof Fault && error.message === 'LAUNCH_UNCONFIRMED_NO_RETRY');
  const accepted = book.recordScanReceipt(202, { scanId, credentials: marker, response: marker });
  assert.equal(accepted, scanId); assert.equal(book.cases.native_scan.status, 'BLOCKED'); assert.equal(book.cases.native_scan.code, 'NOT_RUN');
  assert.deepEqual(book.evidence().scanReceipt, { scanId, launchHttpStatus: 202, receiptAccepted: true });
  for (const stage of ['report-navigation', 'evaluate', 'fetch', 'body']) {
    recordFailure(book, 'native_scan', new BrowserReadError({ readStage: stage, readCause: 'timeout', readTarget: 'scan-status', scanId }));
    const evidence = book.evidence();
    assert.equal(evidence.cases.native_scan.scanId, scanId); assert.equal(evidence.cases.native_scan.receiptAccepted, true);
    assert.equal(evidence.cases.native_scan.launchHttpStatus, 202); assert.equal(evidence.cases.native_scan.code, 'BROWSER_READ_FAILED');
    assert.equal(evidence.cases.native_scan.status, 'BLOCKED'); assert.equal(exitCode(book), 2);
    assert.ok(evidenceDocuments(book).every(value => !value.includes(marker)));
  }
  assert.throws(() => book.recordScanReceipt(202, { scanId: context.epoch }));
});

test('controlled AI navigation barrier gates first GET on actual URL/UI and retains UUID if that single read fails', async () => {
  const book = new ResultBook(scanId), listeners = new Map(), frame = {};
  let url = `${ORIGIN}/scans/new`, reads = 0, releaseNavigation, releaseUi;
  const navigation = new Promise(resolve => { releaseNavigation = resolve; });
  const ui = new Promise(resolve => { releaseUi = resolve; });
  const page = {
    on: (name, callback) => listeners.set(name, callback), mainFrame: () => frame, url: () => url, isClosed: () => false,
    waitForURL: async expected => { await navigation; url = expected; listeners.get('framenavigated')(frame); },
    getByRole: (role, options) => { assert.equal(role, 'group'); assert.deepEqual(options, { name: `Ход сканирования ${scanId}`, exact: true }); return { waitFor: () => ui }; },
    evaluate: async () => { reads++; throw new Error('Execution context was destroyed, most likely because of a navigation. PRIVATE'); },
  };
  trackBrowserReadPage(page, { active: () => true, sessionVersion: () => 1 });
  book.recordScanReceipt(202, { scanId });
  const completed = (async () => {
    await settleAcceptedScan(book, page, () => true);
    return readBrowserJson(page, `/api/v1/browser/scans/${scanId}`, [scanId]);
  })().catch(error => { recordFailure(book, 'native_scan', error); });
  await new Promise(setImmediate); assert.equal(reads, 0);
  releaseNavigation(); await new Promise(setImmediate); assert.equal(reads, 0);
  releaseUi(); await completed; assert.equal(reads, 1);
  assert.equal(book.evidence().cases.native_scan.readCause, 'execution-context-destroyed');
  assert.equal(book.evidence().scanReceipt.scanId, scanId);
  assert.ok(evidenceDocuments(book).every(value => !value.includes('PRIVATE')));
  const code = source();
  const launch = code.slice(code.indexOf("const scanOk = await step('native_scan'"), code.indexOf("if (!scanOk) return"));
  assert.ok(launch.indexOf('await settleAcceptedScan(') >= 0 && launch.indexOf('await settleAcceptedScan(') < launch.indexOf('await readStatus(own.page)'));
  assert.ok(code.includes('scanId = book.recordScanReceipt(response.status(), result.value)'));
  assert.equal(code.includes('scanId = receipt.value?.scanId'), false);
  assert.ok(code.includes('nativeScanMayRemainActive: stats.scanLaunches > 0 && !snapshot'));
});

function freshLoginFixture() {
  const subject = '0123456789abcdef0123456789abcdef', email = 'offline-owner@example.invalid';
  const listeners = new Map(), frame = {}, state = { url: 'about:blank', active: true, cookieCount: 0,
    authenticated: false, hydrated: false, reportVisible: false, authPosts: 0, getPaths: [], navigation: [] };
  let releaseHydration, releaseReport;
  const hydration = new Promise(resolve => { releaseHydration = () => { state.hydrated = true; resolve(); }; });
  const report = new Promise(resolve => { releaseReport = () => { state.reportVisible = true; resolve(); }; });
  const handle = { aiOwner: true, readSession: 0, context: { cookies: async () => Array(state.cookieCount) } };
  const page = {
    on: (name, callback) => listeners.set(name, callback), mainFrame: () => frame, url: () => state.url, isClosed: () => false,
    goto: async url => {
      state.navigation.push(url); listeners.get('request')({ isNavigationRequest: () => true, frame: () => frame });
      state.url = url; listeners.get('framenavigated')(frame);
    },
    waitForURL: async (url, options) => { assert.equal(url, state.url); assert.equal(options.timeout, 20000); },
    getByRole: (role, options) => {
      if (role === 'heading') {
        assert.deepEqual(options, { name: 'Вы вошли', exact: true }); assert.equal(state.authenticated, true);
        return { waitFor: async () => {} };
      }
      assert.equal(role, 'group'); assert.deepEqual(options, { name: `Ход сканирования ${scanId}`, exact: true });
      return { waitFor: () => report };
    },
    evaluate: async (_fn, path) => {
      state.getPaths.push(path);
      assert.equal(state.hydrated, true); assert.equal(state.authenticated, true);
      if (path === '/api/v1/auth/me') return { status: 200, value: { id: subject, email } };
      assert.equal(state.reportVisible, true);
      assert.equal(path, `/api/v1/browser/scans/${scanId}`);
      return { status: 200, value: { scanId, state: 'completed' } };
    },
  };
  handle.page = page;
  trackBrowserReadPage(page, { active: () => state.active, sessionVersion: () => handle.readSession });
  const authenticate = async () => {
    handle.readSession++;
    await page.goto(`${ORIGIN}/login`);
    await hydration; // Controlled initial session/loading/navigation window, not a live auth fixture.
    state.authPosts++; state.authenticated = true;
    await page.goto(`${ORIGIN}/account`); await settleAuthNavigation(page, () => state.active);
    const me = await readBrowserJson(page, '/api/v1/auth/me', []);
    return assertAuthUser(me.value, email, subject);
  };
  const book = new ResultBook(scanId); book.recordScanReceipt(202, { scanId });
  return { book, handle, state, subject, authenticate, releaseHydration, releaseReport };
}

test('fresh owner login omits preauth401 probe during hydration, then verifies identity and exact report UI with no extra POST', async () => {
  const f = freshLoginFixture(); let finished = false;
  const pending = completeFreshOwnerLogin(f.book, f.handle, f.subject, f.authenticate, () => f.state.active).then(result => { finished = true; return result; });
  await new Promise(setImmediate);
  assert.equal(f.state.url, `${ORIGIN}/login`); assert.deepEqual(f.state.getPaths, []); assert.equal(f.state.authPosts, 0);
  f.releaseHydration(); await new Promise(setImmediate);
  assert.deepEqual(f.state.getPaths, ['/api/v1/auth/me']); assert.equal(f.state.authPosts, 1);
  assert.equal(f.state.url, `${ORIGIN}/scans/${scanId}`); assert.equal(finished, false);
  f.releaseReport(); const result = await pending;
  assert.deepEqual(result.meta, { freshContextCookiesEmpty: true, ownerIdentityVerified: true, loginThroughUi: true, reportUiSettled: true, preAuthScanProbe: false });
  assert.equal(f.state.authPosts, 1); assert.deepEqual(f.state.getPaths, ['/api/v1/auth/me']);
  await readBrowserJson(f.handle.page, `/api/v1/browser/scans/${scanId}`, [scanId]);
  assert.deepEqual(f.state.getPaths, ['/api/v1/auth/me', `/api/v1/browser/scans/${scanId}`]);
  f.book.record('fresh_login', 'PASS', 'VERIFIED', result.meta);
  assert.equal(f.book.evidence().freshLoginScope, 'fresh-owner-ui-login-and-report-not-anonymous401');
  assert.equal(f.book.evidence().cases.fresh_login.preAuthScanProbe, false);
  assert.ok(evidenceDocuments(f.book)[1].includes('it does not qualify anonymous401'));
  const code = source();
  const flow = code.slice(code.indexOf("const loginOk = await step('fresh_login'"), code.indexOf("if (qualification === 'full') await step('history_fresh_login'"));
  assert.ok(flow.includes('await own.context.close(); own = await newPage(true)'));
  assert.ok(flow.includes("() => auth(own, owner, 'login')"));
  for (const forbidden of ['http(', '.status, 401', 'addCookies', 'storageState', 'force:', 'permit(']) assert.equal(flow.includes(forbidden), false);
  assert.ok(code.includes('return account.subject;'));
  assert.ok(code.includes('account.subject = assertAuthUser(me.value, account.email, account.subject)'));
  assert.ok(code.includes('assert.deepEqual(current.history, savedHistory)'));
  assert.ok(code.includes('if (!loginOk || !selected || !canRunTranslation(book))'));
});

test('fresh owner login rejects reused/nonempty/wrong-owner contexts and changed sessions without scan/provider submission', async () => {
  for (const change of [f => { f.state.cookieCount = 1; }, f => { f.state.url = `${ORIGIN}/account`; },
    f => { f.handle.aiOwner = false; }, f => { f.state.active = false; }]) {
    const f = freshLoginFixture(); change(f); let authCalls = 0;
    await assert.rejects(completeFreshOwnerLogin(f.book, f.handle, f.subject, async () => { authCalls++; }, () => f.state.active));
    assert.equal(authCalls, 0); assert.deepEqual(f.state.getPaths, []); assert.deepEqual(f.state.navigation, []);
  }
  const wrong = freshLoginFixture();
  await assert.rejects(completeFreshOwnerLogin(wrong.book, wrong.handle, wrong.subject, async () => {
    wrong.state.url = `${ORIGIN}/account`; return 'f'.repeat(32);
  }, () => true), error => error instanceof Fault && error.message === 'CONTEXT_CHANGED' && error.meta.ownerIdentityVerified === false);
  assert.equal(wrong.state.navigation.length, 0); assert.equal(wrong.state.authPosts, 0);
  const changed = freshLoginFixture();
  const pending = completeFreshOwnerLogin(changed.book, changed.handle, changed.subject, changed.authenticate, () => true);
  changed.releaseHydration(); await new Promise(setImmediate);
  changed.handle.readSession++; changed.releaseReport();
  await assert.rejects(pending, error => error instanceof BrowserReadError && error.meta.readCause === 'authority-changed');
  assert.equal(changed.state.authPosts, 1); assert.deepEqual(changed.state.getPaths, ['/api/v1/auth/me']);
});

test('actual completed-reply JSX heading matches all three exact native heading locators', () => {
  const require = createRequire(new URL('../server/api/package.json', import.meta.url));
  const ts = require('typescript');
  const uiText = readFileSync(new URL('../src/features/scans/ScanChatPanel.tsx', import.meta.url), 'utf8');
  const ui = ts.createSourceFile('ScanChatPanel.tsx', uiText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const headings = [];
  const findHeading = node => {
    if (ts.isJsxElement(node) && node.openingElement.tagName.getText(ui) === 'h5') headings.push(node);
    ts.forEachChild(node, findHeading);
  };
  const findCompletedBranch = node => {
    if (ts.isConditionalExpression(node) && node.condition.getText(ui) === "turn.state === 'completed'") findHeading(node.whenTrue);
    else ts.forEachChild(node, findCompletedBranch);
  };
  findCompletedBranch(ui);
  assert.equal(headings.length, 1, 'Exactly one real h5 belongs to the completed-turn branch');
  const heading = headings[0];
  assert.ok(heading.children.every(ts.isJsxText)); // No arbitrary nearby text or dynamic expression can satisfy this contract.
  const name = heading.children.map(child => child.text).join('').trim();
  assert.equal(name, 'Ответ ИИ · требует проверки');
  const jsx = ts.createPrinter().printNode(ts.EmitHint.Unspecified, heading, ui);
  const js = ts.transpileModule(`exports.Heading = () => (${jsx});`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  new Function('require', 'module', 'exports', js)(require, module, module.exports);
  const { createElement } = require('react'); const { renderToStaticMarkup } = require('react-dom/server');
  assert.equal(renderToStaticMarkup(createElement(module.exports.Heading)), `<h5>${name}</h5>`);

  const runner = ts.createSourceFile('public-ai-translation-live.mjs', source(), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const locators = [];
  const findLocator = node => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'getByRole' &&
        ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === 'heading') {
      const options = node.arguments[1]; assert.ok(options && ts.isObjectLiteralExpression(options));
      const field = key => options.properties.find(prop => ts.isPropertyAssignment(prop) && prop.name.getText(runner) === key)?.initializer;
      const label = field('name'); assert.ok(label && ts.isStringLiteral(label));
      assert.equal(field('exact')?.kind, ts.SyntaxKind.TrueKeyword);
      locators.push(label.text);
    }
    ts.forEachChild(node, findLocator);
  };
  findLocator(runner);
  assert.deepEqual(locators, [name, name, name]);
});

test('schema/render success never asserts semantic accuracy or authorizes retries', () => {
  const book = new ResultBook(scanId);
  for (const name of CASES) book.record(name, 'PASS', 'VERIFIED');
  assert.equal(book.evidence().semanticAccuracy, 'unverified');
  assert.ok(evidenceDocuments(book)[1].includes('Semantic accuracy is unverified'));
  assert.ok(evidenceDocuments(book)[1].includes('not permission to retry or refund'));
});

test('every individual case must pass; blocked/fail outcomes are not success and FAIL is sticky', () => {
  const book = new ResultBook(); assert.equal(exitCode(book), 2);
  for (const name of CASES) book.record(name, 'PASS', 'VERIFIED');
  assert.equal(exitCode(book), 0);
  book.record('translation', 'BLOCKED', 'READINESS_BLOCKED'); assert.equal(exitCode(book), 2);
  book.record('translation', 'FAIL', 'ASSERTION_FAILED'); book.record('translation', 'PASS', 'VERIFIED'); assert.equal(exitCode(book), 1);
  assert.throws(() => book.record('extra', 'PASS', 'VERIFIED'));
  assert.throws(() => book.record('chat_1', 'PASS', 'raw HTTP message'));
  const independent = new ResultBook();
  for (const name of ['native_scan', 'report', 'deployed_ui', 'readiness', 'fresh_login']) independent.record(name, 'PASS', 'VERIFIED');
  recordFailure(independent, 'chat_1', new Fault('LLM_HTTP_ERROR', { httpStatus: 200, errorCode: 'LLM_UNAVAILABLE', deliveryKind: 'ndjson-error' }));
  independent.record('chat_2', 'BLOCKED', 'PREREQUISITE_UNAVAILABLE');
  assert.equal(canRunTranslation(independent), true);
  independent.record('chat_2', 'FAIL', 'ASSERTION_FAILED');
  assert.equal(canRunTranslation(independent), false);
});

test('evidence writing is impossible before actual contact; afterward both locked exclusive files use mode 0600', async () => {
  const book = new ResultBook(), paths = [], written = [];
  const writer = async (path, flags, mode) => {
    paths.push(path); assert.equal(flags, 'wx'); assert.equal(mode, 0o600);
    return { writeFile: async text => written.push(text), sync: async () => {}, close: async () => {} };
  };
  await assert.rejects(writeEvidence(book, writer)); assert.equal(paths.length, 0);
  book.actual = true; await writeEvidence(book, writer);
  assert.deepEqual(paths, EVIDENCE_PATHS);
  assert.deepEqual(paths.map(path => path.split('/').at(-1)), ['public-ai-live-20261022.json', 'public-ai-live-20261022.md']);
  assert.equal(written.length, 2); assert.equal(JSON.parse(written[1]).actuallyRun, true);
  paths.length = 0; written.length = 0;
  const attempt2 = new ResultBook('attempt2'); attempt2.actual = true;
  await writeEvidence(attempt2, writer);
  assert.deepEqual(paths.map(path => path.split('/').at(-1)), ['public-ai-live-20261022.attempt2.json', 'public-ai-live-20261022.attempt2.md']);
  assert.ok(paths.every(path => !EVIDENCE_PATHS.includes(path)));
  assert.equal(JSON.parse(written[1]).attempt, 'attempt2');
  paths.length = 0; written.length = 0;
  const attempt3 = new ResultBook('attempt3'); attempt3.actual = true;
  await writeEvidence(attempt3, writer);
  assert.deepEqual(paths.map(path => path.split('/').at(-1)), ['public-ai-live-20261022.attempt3.json', 'public-ai-live-20261022.attempt3.md']);
  assert.ok(paths.every(path => !EVIDENCE_PATHS.includes(path) && !evidencePaths('attempt2').includes(path)));
  assert.equal(JSON.parse(written[1]).attempt, 'attempt3');
  let opens = 0, writes = 0;
  await assert.rejects(writeEvidence(attempt2, async () => {
    if (++opens === 2) throw new Error('exclusive collision');
    return { writeFile: async () => { writes++; }, sync: async () => {}, close: async () => {} };
  }));
  assert.equal(writes, 0);
});

test('eligible assessment excludes redacted/omitted/missing text and obvious unsafe destinations', () => {
  const text = { state: 'available', value: 'Safe source description', redacted: false };
  assert.ok(eligibleAssessment({ title: text, description: { ...text, value: null, state: 'missing' } }));
  assert.ok(eligibleAssessment({ title: { ...text, state: 'truncated' } }));
  for (const change of [{ redacted: true }, { value: null }, { value: '' }, { state: 'omitted' }, { state: 'redacted' },
    { value: 'https://example.invalid' }, { value: 'See example.com' }, { value: 'See sub.example.technology' },
    { value: 'See host.xyz' }, { value: 'Contact mailto:operator' }, { value: 'See 192.0.2.1' }])
    assert.equal(eligibleAssessment({ title: { ...text, ...change } }), false);
  for (const state of ['available', 'truncated']) {
    assert.equal(eligibleAssessment({ title: { ...text, state, value: 'я'.repeat(256) } }), true);
    assert.equal(eligibleAssessment({ title: { ...text, state, value: 'я'.repeat(257) } }), false);
    assert.equal(eligibleAssessment({ description: { ...text, state, value: 'я'.repeat(2048) } }), true);
    assert.equal(eligibleAssessment({ description: { ...text, state, value: 'я'.repeat(2049) } }), false);
    assert.equal(eligibleAssessment({ title: text, description: { ...text, state, value: 'я'.repeat(2049) } }), true);
  }
});

test('UI reply check follows every substantive response token in order, despite inert Markdown decorations or copy labels', () => {
  assert.ok(renderedReplyMatches('**Проверьте** источник.', 'Проверьте источник. Скопировать текст'));
  assert.ok(renderedReplyMatches('1. Проверьте источник.\n2. Сохраните отчёт.', 'Проверьте источник. Сохраните отчёт. Скопировать текст'));
  assert.equal(renderedReplyMatches('Проверьте источник целиком.', 'Проверьте источник.'), false);
  assert.equal(renderedReplyMatches('Сначала источник потом отчёт.', 'Сначала отчёт потом источник.'), false);
  assert.equal(renderedReplyMatches('###', 'Скопировать текст'), false);
});

test('workflow has real sequential UI consent, fresh-login durability, foreign GET-only denial and original-only toggle without another POST', () => {
  const code = source();
  for (const forbidden of ['route.fulfill', 'route.fetch', 'addCookies(', 'storageState(', 'screenshot(', 'tracing.start', 'recordHar',
    'context.request', 'dotenv', 'openrouter.env', 'readFile(', 'console.error(', 'console.warn(']) assert.equal(code.includes(forbidden), false, forbidden);
  assert.ok(code.includes('for (const [index, question] of QUESTIONS.entries())'));
  assert.ok(code.indexOf('assertInitialUsage(usageBefore, before.context)') < code.indexOf("await panel.getByRole('textbox', { name: 'Вопрос чату'"));
  assert.ok(code.includes("book.record('readiness', 'PASS', 'VERIFIED', { ...book.cases.readiness, initialUsageZero: true })"));
  assert.ok(code.includes('index === 1 && book.cases.chat_1.status'));
  const chat = code.slice(code.indexOf('for (const [index, question] of QUESTIONS.entries())'), code.indexOf("await step('history_reload'"));
  assert.equal(chat.includes('checkbox'), false); assert.equal(chat.includes('consent.check'), false);
  assert.ok(chat.includes("await expect(submit).toHaveAttribute('aria-describedby', 'scan-chat-send-help')"));
  assert.equal((chat.match(/await submit.click\(/g) ?? []).length, 1);
  assert.ok(chat.includes('assert.equal(stats.chatPosts, index)'));
  assert.ok(chat.includes('assert.equal(stats.chatPosts, index + 1)'));
  assert.ok(code.includes('createChatFrameParser(before.context'));
  assert.ok(code.includes('assert.deepEqual(turn.reply, delivered.reply)'));
  assert.ok(code.includes("own = await newPage(true)"));
  assert.ok(code.includes("const other = await newPage(false)"));
  assert.ok(code.includes("assertDeniedReply(await http(other.page, translationPath()), 404)"));
  assert.ok(code.includes('assert.notEqual(translationContext.policyVersion, chatPin)'));
  assert.ok(code.includes('assert.equal(stats.translationPosts, before)'));
  assert.ok(code.includes('args: [...BROWSER_ARGS]'));
});

test('finite guard telemetry distinguishes three genuine denials from three validated read aborts without storing private routes or relaxing admission', () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  const eligibility = `${ORIGIN}/api/v1/browser/scans/images/eligibility`;
  const abortedReads = new GuardLedger();
  for (let index = 0; index < 3; index++) abortedReads.record(guardAbortReason({ approvedRead: true, closing: false, aborted: true }), eligibility, 'POST');
  assert.equal(abortedReads.blockedRequests, 0);
  assert.equal(abortedReads.benignAborts, 3);
  assert.deepEqual(abortedReads.evidence().events, [{ reason: 'cancelled-local-read', routeCategory: 'eligibility', method: 'POST', count: 3 }]);
  const genuine = new GuardLedger();
  genuine.record('external-request', `https://outside.invalid/${marker}?token=${marker}`, 'GET');
  genuine.record('mutation-shape', `${ORIGIN}/api/v1/browser/scans/${scanId}/llm/chat?token=${marker}`, 'POST');
  genuine.record('api-get-not-allowed', `${ORIGIN}/api/v1/private/${marker}`, marker);
  assert.equal(genuine.blockedRequests, 3);
  genuine.record(guardAbortReason({ approvedRead: true, closing: true, aborted: false }), `${ORIGIN}/api/v1/browser/scans/${scanId}/events`, 'GET');
  assert.equal(genuine.blockedRequests, 3);
  assert.equal(genuine.benignAborts, 1);
  assert.equal(guardAbortReason({ approvedRead: false, closing: true, aborted: true }), 'handler-error');
  assert.equal(guardAbortReason({ approvedRead: true, closing: false, aborted: false }), 'handler-error');
  assert.equal(routeCategory(`${ORIGIN}/api/v1/browser/scans/${scanId}/llm/chat?secret=${marker}`), 'llm-chat');
  assert.equal(routeCategory(`${ORIGIN}/unknown/${marker}`), 'otherlocal');
  assert.equal(routeCategory(`http://127.0.0.1:8080/${marker}`), 'external');
  assert.equal(routeCategory(`${ORIGIN}/api/v1/browser/scans/${scanId}/llm/translation`), 'translation');
  assert.equal(allowedApiGet(`${ORIGIN}/api/v1/private/${marker}`, [scanId]), false);
  assert.equal(allowedApiGet(`${ORIGIN}/api/v1/browser/scans/${scanId}/llm/chat?secret=${marker}`, [scanId]), false);
  const book = new ResultBook('attempt2'); book.guard = genuine;
  book.record('safety', 'FAIL', 'REQUEST_GUARD', { blockedRequests: genuine.blockedRequests });
  assert.equal(exitCode(book), 1);
  assert.ok(evidenceDocuments(book).every(text => !text.includes(marker)));
  const bounded = new GuardLedger();
  for (const reason of ['external-request', 'mutation-shape', 'api-get-not-allowed', 'handler-error', 'redirect'])
    for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) bounded.record(reason, ORIGIN + '/unknown', method);
  assert.equal(bounded.blockedRequests, 35);
  assert.equal(bounded.evidence().events.length, 32);
  assert.equal(bounded.evidence().overflow, 3);
  assert.throws(() => bounded.record(marker, ORIGIN, 'GET'));
  const code = source();
  assert.ok(code.includes('approvedRead = true;'));
  assert.ok(code.includes("request.failure()?.errorText === 'net::ERR_ABORTED'"));
  assert.ok(code.includes('if (!approvedRead) return deny(\'api-get-not-allowed\')'));
  assert.ok(code.includes("own.closing = true; await own.context.close()"));
  assert.ok(code.includes('recordFailure(book, currentCase, error, fatal)'));
  assert.ok(code.includes('allowedApiGet(input, knownIds, method)'));
  assert.ok(code.includes('runtimeProbeRead(response.url(), response.request().method())'));
  assert.ok(code.includes('assertRuntimeOffReply(response.url(), response.request().method(), response.status())'));
  assert.ok(code.includes("book.record('safety', 'FAIL', 'RUNTIME_NOT_OFF'"));
});

test('independent translation has no chat prerequisite or dispatch and cannot qualify chat', () => {
  const book = new ResultBook(scanId, 'translation');
  assert.deepEqual(book.requiredCases, qualificationCases('translation'));
  for (const name of book.requiredCases) book.record(name, 'PASS', 'VERIFIED');
  assert.equal(exitCode(book), 0);
  for (const name of ['readiness', 'chat_1', 'chat_2', 'history_reload', 'history_fresh_login']) {
    assert.equal(book.cases[name].code, 'NOT_RUN');
    assert.equal(book.requiredCases.includes(name), false);
  }
  assert.equal(canRunTranslation(book), true);
  const state = { aiOwner: true, permit: { context, question, used: false }, chatPosts: 0, translationPosts: 0 };
  assert.equal(canDispatch(state, `/api/v1/browser/scans/${scanId}/llm/chat`, body(), 'translation'), false);
  assert.equal(canDispatch(state, `/api/v1/browser/scans/${scanId}/llm/translation`, translationBody(context), 'translation'), true);
  assert.equal(canDispatch(state, `/api/v1/browser/scans/${scanId}/llm/translation`, translationBody(context), 'unknown'), false);
  book.record('translation', 'BLOCKED', 'LLM_HTTP_ERROR', { httpStatus: 429 });
  assert.equal(exitCode(book), 2);
  const full = new ResultBook(scanId);
  for (const name of book.requiredCases) full.record(name, 'PASS', 'VERIFIED');
  assert.equal(exitCode(full), 2);
  const code = source();
  const translation = code.slice(code.indexOf("const contextOk = await step('translation_context'"), code.indexOf("const translatedOk ="));
  assert.equal(translation.includes('readChat('), false);
  assert.match(code, /if \(qualification === 'full'\) \{\s*const readyOk/);
});

test('new AI evidence destinations are UUID-scoped, exclusive and separate from attempts 1/2/3', async () => {
  const finalPaths = evidencePaths(scanId);
  const historical = [...EVIDENCE_PATHS, ...evidencePaths('attempt2'), ...evidencePaths('attempt3')];
  assert.ok(finalPaths.every(path => path.includes(`/docs/public-final-${scanId}-ai-translation.`) && !historical.includes(path)));
  const book = new ResultBook(scanId, 'translation'), opened = [];
  await assert.rejects(writeEvidence(book, async () => { throw new Error('must not open'); }));
  book.actual = true;
  await writeEvidence(book, async (path, flags, mode) => {
    opened.push(path); assert.equal(flags, 'wx'); assert.equal(mode, 0o600);
    return { writeFile: async () => {}, sync: async () => {}, close: async () => {} };
  });
  assert.deepEqual(opened, finalPaths);
  assert.equal(book.evidence().qualification, 'translation');
  assert.ok(evidenceDocuments(book)[1].includes('Chat generation is NOT qualified or attempted'));
});

test('loads the actual frontend wire decoders/translation schema entirely offline, without provider initialization', async () => {
  const contracts = await loadTranslationContracts();
  assert.equal(typeof contracts.decoder.parseCurrentStatus, 'function');
  assert.equal(typeof contracts.chat.createChatFrameParser, 'function');
  assert.equal(typeof contracts.translation.translationReplySchema.parse, 'function');
  assert.equal(typeof contracts.translation.translationContextSchema.parse, 'function');
});
