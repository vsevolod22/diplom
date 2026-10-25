// Offline guards only. Importing the runner does not launch a browser or contact a stand/provider.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import test from 'node:test';
import {
  ORIGIN, WORKER_MS, GLOBAL_MS, MODEL, ENDPOINT, CASES, EVIDENCE_PATHS, evidencePaths, parseMode,
  projectMeta, llmFailureMeta, assertLlmSuccess, ResultBook, Fault, recordFailure, GuardLedger, routeCategory, guardAbortReason, canRunTranslation,
    exitCode, evidenceDocuments, writeEvidence, assertFixedPolicy, assertReady,
  qualificationCases, chatBodyMatches, translationBody, canDispatch, allowedApiGet, runtimeProbeRead, assertRuntimeOffReply, eligibleAssessment, assertInitialUsage, renderedReplyMatches, historyMetadata, loadTranslationContracts,
} from './public-ai-translation-live.mjs';

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
  assert.ok(code.includes("llmFailureMeta(result.status, result.value, 'http-error')"));
  assert.ok(code.includes("llmFailureMeta(200, delivered, 'ndjson-error')"));
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
  assert.ok(code.includes('await consent.check()'));
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
