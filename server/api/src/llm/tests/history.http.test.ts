import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../app.module.js';
import { AuthStore } from '../../auth/auth.store.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { HistoryStore } from '../history-store.js';
import { registerHistoryIngress } from '../history-ingress.js';
import { type BodySendGuard, type GuardedTransport } from '../openrouter-transport.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import { policyFromEnvironment } from '../policy.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';
import { fixtureEnv, fakeKey, digest } from './fixtures.js';
import { HISTORY, bytes, hashValue, historyProjection, reportBinding, type Decision, type HistoryHead, type Turn, type Pending } from '../history-contract.js';
import { ReportReader } from '../report-context.js';

const freePolicy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
  LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }
type PublicHistory = ReturnType<typeof historyProjection>;
function assertPublicHistory(visible: PublicHistory, stored: HistoryHead) {
  assert.ok(visible.turns.length > 0, 'no-leak checks require actual retained turns');
  assert.equal(visible.turns.length, stored.turns.length);
  for (let n = 0; n < visible.turns.length; n++) {
    const turn = visible.turns[n], saved = stored.turns[n];
    assert.deepEqual(Object.keys(turn).sort(), ['id', 'mutationId', 'state', 'question', 'report', 'createdAt',
      ...(saved.state === 'completed' ? ['reply'] : [])].sort());
    assert.deepEqual(turn, { id: saved.id, mutationId: saved.mutationId, state: saved.state, question: saved.question,
      report: saved.report, createdAt: saved.createdAt, ...(saved.state === 'completed' ? { reply: saved.reply } : {}) });
    for (const key of ['inputHash', 'consentPolicyVersion', 'requestHash'] as const) assert.match(saved[key], /^[a-f0-9]{64}$/);
  }
  assert.doesNotMatch(JSON.stringify(visible), /inputHash|consentPolicyVersion|requestHash|sessionId|generation|accessIncarnation|reservation|token_hash/);
}

test('actual cookie Nest → durable history → current report/cache → real adapter synthetic boundary → durable receipt and guarded completion', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'history-http-'));
  const names = ['AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = names.map(n => process.env[n]); const origin = 'http://127.0.0.1:8080';
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite'); process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin; process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true'; process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const app = await NestFactory.create(AppModule, { logger: false }); registerHistoryIngress(app);
  const history = new HistoryStore(join(dir, 'llm-history.sqlite'), true), quota = new FixtureQuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  const runtime = app.get(LlmRuntime), quotas = app.get(LlmQuotaRuntime), llm = app.get(LlmService);
  runtime.policy = () => freePolicy; quotas.ledger = () => quota; llm.history().runtime.store = () => history;
  let sends = 0, reads = 0, beforeSend: (() => Promise<void>) | undefined, afterSend: (() => Promise<void>) | undefined, badCitation = false;
  let lastWire = '', lastReserve = 0;
  // Explicit synthetic send boundary, not a production TLS or provider assertion.
  const synthetic = Object.assign((async () => assert.fail('NEW path must not call plain transport')) as typeof fetch, {
    sendGuarded: async (_url: string, init: RequestInit, guard: BodySendGuard) => {
      await beforeSend?.();
      let response!: Promise<Response>;
      guard(() => {
        sends++; lastWire = String(init.body);
        const wire = JSON.parse(lastWire), context = JSON.parse(wire.messages[1].content), report = context.report;
        assert.equal(wire.stream, false); assert.equal(wire.max_tokens, 256);
        assert.deepEqual(wire.provider.only, ['novita/bf16']); assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
        const held = quota.snapshot(context.__owner ?? activeOwner, report.scanId).scan.held;
        lastReserve = held.input; assert.equal(lastReserve, Buffer.byteLength(lastWire) + 1024);
        response = (async () => {
          await afterSend?.();
          return new Response(JSON.stringify({ model: freePolicy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
            choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify({ scanId: report.scanId,
              digest: report.digest, platform: report.platform, reportVersion: report.reportVersion, text: 'This is a cited hypothesis, not a scanner fact.',
              citations: [badCitation ? 'foreign' : report.findings[0].findingId] }) } }] }), { headers: { 'content-type': 'application/json' } });
        })();
      });
      return response;
    },
  }) as GuardedTransport;
  runtime.provider = () => { reads++; return new OpenRouterProvider(fakeKey, synthetic); };
  let activeOwner = '';
  try {
    await app.listen(0, '127.0.0.1'); const base = `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1`;
    const credentials = { email: 'history-owner@example.com', password: 'temporary-history-password-1234' };
    const auth = async (route: string, body = credentials, cookie?: string) => fetch(`${base}/auth/${route}`, {
      method: 'POST', headers: { origin, 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
    const registered = await auth('register'); assert.equal(registered.status, 201);
    const owner = await registered.json() as { id: string }; activeOwner = owner.id;
    let cookie = registered.headers.get('set-cookie')!.split(';')[0];
    const other = await auth('register', { ...credentials, email: 'history-other@example.com' });
    const foreignCookie = other.headers.get('set-cookie')!.split(';')[0];
    const scans = app.get(LedgerStore).ledger!;
    const scan = (key: string) => {
      const id = scans.enqueue({ subject: owner.id, idempotencyKey: key, registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest as `sha256:${string}`,
        platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
      const job = scans.claim()!;
      assert.ok(scans.finishCombined(id, job.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [
        { findingId: 'secret-0-1', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' }] }])); return id;
    };
    const id = scan('history-x'), y = scan('history-y');
    const path = (endpoint: string, scanId = id) => `${base}/browser/scans/${scanId}/llm/${endpoint}`;
    const get = (endpoint: string, c = cookie, scanId = id) => fetch(path(endpoint, scanId), { headers: { cookie: c } });
    const post = (endpoint: string, body: unknown, c = cookie) => fetch(path(endpoint), { method: 'POST', headers: { cookie: c, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const context = async (c = cookie) => (await get('chat/context', c)).json() as Promise<{ epoch: string; revision: number; reportVersion: string; policyVersion: string }>;
    const request = async (c = cookie, question = 'Explain this finding safely.') => {
      const h = await context(c); return { epoch: h.epoch, revision: h.revision, reportVersion: h.reportVersion,
        mutationId: randomUUID(), question, consent: { accepted: true, policyVersion: h.policyVersion } };
    };
    assert.equal((await fetch(path('history'))).status, 401);
    const denied = await get('history', foreignCookie), missing = await get('history', foreignCookie, randomUUID());
    assert.equal(denied.status, 404); assert.equal(await denied.text(), await missing.text());
    assert.equal(llm.history().cache.lookups, 0); assert.equal(sends, 0); assert.equal(reads, 0);
    const h = await context();
    const pin = { epoch: h.epoch, revision: h.revision, reportVersion: h.reportVersion, mutationId: randomUUID(),
      text: 'Never change the deployment without approval.', findingIds: ['secret-0-1'] };
    assert.equal((await post('history/decision', pin)).status, 200); assert.equal(sends, 0);
    assert.equal((await post('history/decision', pin)).status, 200, 'durable decision dedup despite stale expected revision');
        assert.equal((await post('history/decision', { ...pin, text: 'Changed decision.' })).status, 409, 'changed replay refuses');
    const input = await request(), response = await post('chat', input); assert.equal(response.status, 200, await response.clone().text());
    assert.ok(Buffer.byteLength(await response.clone().text()) <= HISTORY.scopeBytes, 'ordinary actual HTTP completion response is bounded');
    const complete = await response.json() as { revision: number; turnId: string; deliveryMode: string; reply: { kind: string } };
    assert.equal(complete.deliveryMode, 'completed-response'); assert.equal(complete.reply.kind, 'hypothesis'); assert.equal(sends, 1);
    assert.ok(lastReserve > 1024); assert.match(lastWire, /Never change the deployment/);
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, 500);
    const storedComplete = history.snapshot(owner.id, id), hist = await (await get('history')).json() as PublicHistory;
    assert.equal(hist.turns[0].id, complete.turnId); assert.equal(hist.revision, 3); assertPublicHistory(hist, storedComplete);
    assert.deepEqual(history.snapshot(owner.id, id), storedComplete, 'HTTP projection does not change persisted identities');
    const decisionContext = await context();
    const decisionResponse = await post('history/decision', { ...pin, epoch: decisionContext.epoch, revision: decisionContext.revision, mutationId: randomUUID(),
      text: 'Keep the completed cited hypothesis for review.' });
    assert.equal(decisionResponse.status, 200);
    const decisionHistory = await decisionResponse.json() as PublicHistory;
    assertPublicHistory(decisionHistory, history.snapshot(owner.id, id));
    assert.equal(decisionHistory.decisions.length, 2); assert.deepEqual(history.snapshot(owner.id, id).turns, storedComplete.turns);
    assert.equal((await post('chat', input)).status, 200); assert.equal(sends, 1, 'duplicate never regenerates');
        assert.equal((await post('chat', { ...input, question: 'Changed question.' })).status, 409);
    assert.equal((await (await get('history', cookie, y)).json() as PublicHistory).turns.length, 0);
    const usage = await get('chat/usage'); assert.equal(usage.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await usage.json() as { admission: unknown }).admission, { status: 'unavailable' }); assert.equal(sends, 1);
    const independent = await auth('login'), s3 = independent.headers.get('set-cookie')!.split(';')[0];
    assert.equal((await (await get('history', s3)).json() as PublicHistory).turns[0].id, complete.turnId);
    const failed = await auth('login', { ...credentials, password: 'incorrect-history-password-1234' }, cookie);
    assert.equal(failed.status, 401); assert.equal((await get('history')).status, 200);
    const atBoundary = deferred(), resume = deferred(); beforeSend = async () => { atBoundary.resolve(); await resume.promise; };
    const beforeRotate = cookie, stalledInput = await request(), stalled = post('chat', stalledInput);
    await atBoundary.promise;
    const storedPending = history.snapshot(owner.id, id), pendingResponse = await get('history'); assert.equal(pendingResponse.status, 200);
    const pendingHistory = await pendingResponse.json() as PublicHistory;
    assert.equal(pendingHistory.turns.at(-1)!.state, 'pending'); assertPublicHistory(pendingHistory, storedPending);
    assert.deepEqual(pendingHistory.pending, { turnId: storedPending.pending!.id, state: 'pending' });
    assert.deepEqual(history.snapshot(owner.id, id), storedPending, 'pending projection preserves private identity/reservation');
    // A conflicting tab cannot get a second reserve/send while pending.
    const concurrent = await post('chat', { ...stalledInput, mutationId: randomUUID() }); assert.equal(concurrent.status, 409);
    const rotated = await auth('login', credentials, cookie); assert.equal(rotated.status, 200);
    cookie = rotated.headers.get('set-cookie')!.split(';')[0]; resume.resolve();
    assert.equal((await stalled).status, 502); assert.equal(sends, 1, 'presented rotation before synthetic body admission sends0');
    assert.equal(quota.snapshot(owner.id, id).scan.held.input, 0, 'still-reserved release');
    assert.equal((await get('history', beforeRotate)).status, 401); assert.equal((await get('history', s3)).status, 200);
    const terminalHistory = await (await get('history')).json() as PublicHistory;
        assert.equal(terminalHistory.turns[0].id, complete.turnId); assert.equal(terminalHistory.turns.at(-1)!.state, 'failed');
        assertPublicHistory(terminalHistory, history.snapshot(owner.id, id));
    beforeSend = undefined;
    const bodyStarted = deferred(), finish = deferred(); afterSend = async () => { bodyStarted.resolve(); await finish.promise; };
    const staleInput = await request(), staleReply = post('chat', staleInput); await bodyStarted.promise;
    app.get(AuthStore).revoke(cookie.slice('demo_session='.length)); finish.resolve();
    assert.equal((await staleReply).status, 503); assert.equal(sends, 2);
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, 1000, 'trusted receipt accounts despite revoked publication');
    assert.equal((await (await get('history', s3)).json() as PublicHistory).turns.filter(t => t.state === 'completed').length, 1);
    afterSend = undefined; cookie = s3; badCitation = true;
    assert.equal((await post('chat', await request())).status, 502); assert.equal(sends, 3);
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, 1500, 'invalid content cannot refund validated receipt');
    badCitation = false;
    assert.equal((await post('chat', { ...await request(), owner: foreignCookie })).status, 400);
    const tooLarge = await post('chat', { ...await request(), question: 'x'.repeat(8192) }); assert.equal(tooLarge.status, 413);
    assert.doesNotMatch(await tooLarge.text(), /xxxxx/); assert.equal(sends, 3);
    const questionTooLarge = await post('chat', { ...await request(), question: 'ю'.repeat(1025) }); assert.equal(questionTooLarge.status, 400);
    const secret = await post('chat', { ...await request(), question: 'CANARY-private-credential' }); assert.equal(secret.status, 400);
    assert.equal(sends, 3); assert.doesNotMatch(readFileSync(join(dir, 'llm-history.sqlite')).toString(), /CANARY|temporary-history-password|sk-or-/);
    // A fresh-policy race after cache lookup must refuse before pending/reservation/send.
    const raceInput = await request(), cache = llm.history().cache, originalGet = cache.get.bind(cache);
    const beforeRace = quota.snapshot(owner.id, id).scan;
    cache.get = (key, context) => { const value = originalGet(key, context); runtime.policy = () => ({ ...freePolicy, version: 'e'.repeat(64) }); return value; };
    assert.equal((await post('chat', raceInput)).status, 409); assert.equal(sends, 3);
    cache.get = originalGet; runtime.policy = () => freePolicy;
    assert.deepEqual(quota.snapshot(owner.id, id).scan, beforeRace);
    const normalFinish = history.finish.bind(history);
    history.finish = () => { throw new Error('synthetic completion disk fault'); };
    assert.equal((await post('chat', await request())).status, 503); assert.equal(sends, 4);
    history.finish = normalFinish;
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, 2000, 'receipt survives history completion failure');
    assert.equal((await (await get('history')).json() as PublicHistory).turns.filter(t => t.state === 'completed').length, 1);
    const remaining = quota.snapshot(owner.id, id).scan.remaining;
    const shortage = quota.reserve({ subject: owner.id, scanId: id, reportVersion: h.reportVersion, policyVersion: freePolicy.version, requestHash: 'f'.repeat(64) },
      { input: remaining.input - 100, output: 1, costMicros: 0 });
    const held = quota.snapshot(owner.id, id).scan.held;
    assert.equal((await post('chat', await request())).status, 429); assert.equal(sends, 4);
    assert.deepEqual(quota.snapshot(owner.id, id).scan.held, held, 'failed dual-scope admission adds no partial debit'); quota.release(shortage);
    // Real HTTP disconnect before body admission releases only the undispatched reserve.
    const preAbortBoundary = deferred(), preAbortResume = deferred(), preAbortController = new AbortController();
    beforeSend = async () => { preAbortBoundary.resolve(); await preAbortResume.promise; };
    const preAbortRequest = await request();
    const disconnected = fetch(path('chat'), { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
      body: JSON.stringify(preAbortRequest), signal: preAbortController.signal }).catch(error => error);
    await preAbortBoundary.promise; preAbortController.abort(); await disconnected;
    for (let n = 0; n < 100 && history.snapshot(owner.id, id).pending; n++) await new Promise(r => setTimeout(r, 5));
    preAbortResume.resolve(); beforeSend = undefined;
    assert.equal(history.snapshot(owner.id, id).pending, null); assert.equal(sends, 4);
    assert.equal(quota.snapshot(owner.id, id).scan.held.input, 0);
    const cancelledHistory = await (await get('history')).json() as PublicHistory;
    assert.equal(cancelledHistory.turns.at(-1)!.state, 'cancelled'); assertPublicHistory(cancelledHistory, history.snapshot(owner.id, id));
    const recoveryHead = history.snapshot(owner.id, y), recoveryReport = app.get(ReportReader).read({ subject: owner.id, scope: ['scan:read'] }, y);
    const interrupted: Turn = { id: randomUUID(), mutationId: randomUUID(), state: 'pending', question: 'Retain this interrupted request.',
      report: reportBinding(recoveryReport), createdAt: Date.now(), inputHash: 'a'.repeat(64), consentPolicyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) };
    history.begin(owner.id, y, recoveryHead.epoch, recoveryHead.revision, interrupted, { id: interrupted.id, sessionId: 'd'.repeat(32), generation: 1,
      accessIncarnation: 'e'.repeat(32), policyVersion: interrupted.consentPolicyVersion, requestHash: interrupted.requestHash, deadline: Date.now() - 1 });
    history.recoverExpired();
    const recovered = history.snapshot(owner.id, y); assert.deepEqual(recovered.turns[0], { ...interrupted, state: 'interrupted' });
    const recoveredResponse = await get('history', cookie, y); assert.equal(recoveredResponse.status, 200);
    const recoveredHistory = await recoveredResponse.json() as PublicHistory;
    assert.equal(recoveredHistory.turns[0].state, 'interrupted'); assertPublicHistory(recoveredHistory, recovered);
    assert.deepEqual(history.snapshot(owner.id, y), recovered, 'recovered HTTP projection preserves original private fingerprints');
    // Once body initiation happened, abort cannot invent a refund/receipt or completion.
    const abortBody = deferred(), abortFinish = deferred(), postAbortController = new AbortController();
    afterSend = async () => { abortBody.resolve(); await abortFinish.promise; };
    const postAbortRequest = await request();
    const afterDispatch = fetch(path('chat'), { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
      body: JSON.stringify(postAbortRequest), signal: postAbortController.signal }).catch(error => error);
    await abortBody.promise; postAbortController.abort(); await afterDispatch;
    for (let n = 0; n < 100 && history.snapshot(owner.id, id).pending; n++) await new Promise(r => setTimeout(r, 5));
    abortFinish.resolve(); afterSend = undefined;
    assert.equal(sends, 5); assert.equal(history.snapshot(owner.id, id).pending, null);
    assert.ok(quota.snapshot(owner.id, id).scan.held.input > 0, 'unknown dispatched usage remains held, not refunded');
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, 2000);
    assert.equal(history.snapshot(owner.id, id).turns.filter(t => t.state === 'completed').length, 1);
    // Old decisions remain mandatory even when optional context reduction cannot fit.
    const currentReport = app.get(ReportReader).read({ subject: owner.id, scope: ['scan:read'] }, id);
    for (let n = 0; n < 34; n++) {
      const current = history.snapshot(owner.id, id);
      history.decision(owner.id, id, current.epoch, current.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision',
        text: `Important retained decision ${n}: ${'x '.repeat(980)}`, report: reportBinding(currentReport), sources: [] });
    }
    const beforeOverflow = quota.snapshot(owner.id, id).scan;
    assert.equal((await post('chat', await request())).status, 409); assert.equal(sends, 5);
    assert.deepEqual(quota.snapshot(owner.id, id).scan, beforeOverflow, 'mandatory overflow refuses before reserve');
    // Missing storage never recreates an empty conversation or calls the model.
    llm.history().runtime.store = () => { throw new Error('PRIVATE-SQL-PATH'); };
    assert.equal((await get('history')).status, 503);
    assert.equal((await post('chat', await request(s3))).status, 400); // unavailable context cannot form valid request
    assert.equal(sends, 5);
  } finally {
    history.close(); quota.close(); await app.close(); rmSync(dir, { recursive: true, force: true });
    names.forEach((n, i) => { if (previous[i] === undefined) delete process.env[n]; else process.env[n] = previous[i]; });
  }
});

test('full HTTP history C/C+1 rollback, maximum completion, durable original replay and nullable policy final fences', { timeout: 30000 }, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'history-envelope-'));
  const names = ['AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = names.map(n => process.env[n]), origin = 'http://127.0.0.1:8080';
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite'); process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin; process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true'; process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const app = await NestFactory.create(AppModule, { logger: false }); registerHistoryIngress(app);
  const historyPath = join(dir, 'llm-history.sqlite');
  let history = new HistoryStore(historyPath, true);
  const quota = new FixtureQuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  const runtime = app.get(LlmRuntime), llm = app.get(LlmService);
  runtime.policy = () => freePolicy; app.get(LlmQuotaRuntime).ledger = () => quota; llm.history().runtime.store = () => history;
  let providerLookups = 0;
  runtime.provider = () => { providerLookups++; assert.fail('decision boundary must not request a provider'); };
  try {
    await app.listen(0, '127.0.0.1'); const base = `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1`;
    const registered = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'envelope@example.com', password: 'temporary-envelope-password-1234' }) });
    assert.equal(registered.status, 201);
    const owner = (await registered.json() as { id: string }).id, cookie = registered.headers.get('set-cookie')!.split(';')[0];
    const ledger = app.get(LedgerStore).ledger!;
    const scanId = ledger.enqueue({ subject: owner, idempotencyKey: 'envelope-boundary', registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: digest as `sha256:${string}`, platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
    const job = ledger.claim()!;
    assert.ok(ledger.finishCombined(scanId, job.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings:
      Array.from({ length: 32 }, (_, n) => ({ findingId: `secret-0-${n + 1}`, ruleId: 'rule-0123456789abcdef', line: n + 1, evidenceRef: `result-0-secret-${n + 1}` })) }]));
    const report = app.get(ReportReader).read({ subject: owner, scope: ['scan:read'] }, scanId), binding = reportBinding(report);
    const sources = report.findings.map(finding => ({ ...binding, finding })); assert.equal(sources.length, 32);
    assert.equal(bytes(historyProjection(history.snapshot(owner, scanId))), bytes(historyProjection(history.snapshot(owner, scanId), binding)),
      'supported actual ReportReader binding has identical canonical envelope byte overhead');
    const url = `${base}/browser/scans/${scanId}/llm`;
    const get = () => fetch(`${url}/history`, { headers: { cookie } });
    const post = (entry: Decision, head: HistoryHead) => fetch(`${url}/history/decision`, { method: 'POST',
      headers: { cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify({ epoch: head.epoch, revision: head.revision,
        mutationId: entry.mutationId, reportVersion: report.reportVersion, text: entry.text, findingIds: entry.sources.map(s => s.finding.findingId) }) });
    const entry = (): Decision => ({ id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Keep this constraint.', report: binding, sources });
    const candidate = (head: HistoryHead, d: Decision) => ({ ...head, revision: head.revision + 1, decisions: [...head.decisions, d] });
    // Fixture memory is written through the actual validated Store, not direct SQL/content injection.
    let head = history.snapshot(owner, scanId);
    for (;;) {
      const d = entry(), size = bytes(historyProjection(candidate(head, d), binding));
      if (size > HISTORY.scopeBytes - HISTORY.questionBytes) break;
      head = history.decision(owner, scanId, head.epoch, head.revision, d);
    }
    let final: Decision | undefined;
    for (let n = 0; n <= sources.length; n++) {
      const d = { ...entry(), text: 'x', sources: sources.slice(0, n) };
      const length = 1 + HISTORY.scopeBytes - bytes(historyProjection(candidate(head, d), binding));
      if (length >= 1 && length < HISTORY.questionBytes) { d.text = ('x '.repeat(1024)).slice(0, length); final = d; break; }
    }
    assert.ok(final, 'construct an exactly full supported HTTP envelope');
    assert.equal(bytes(historyProjection(candidate(head, final), binding)), HISTORY.scopeBytes);
    assert.ok(bytes(candidate(head, final)) <= HISTORY.scopeBytes, 'decision-only public C must also satisfy the independent stored cap');
    const before = await get(); assert.equal(before.status, 200); const beforeText = await before.text();
    const db = new Database(historyPath, { readonly: true });
    const row = () => db.prepare('SELECT epoch,revision,content,content_hash FROM history_head WHERE scope=?').get(hashValue([owner, scanId]));
    try {
      const saved = row(), overflow = await post({ ...final, text: final.text + ' ' }, head);
      assert.equal(overflow.status, 409, await overflow.clone().text());
      assert.equal((await overflow.json() as { errorCode: string }).errorCode, 'LLM_HISTORY_CAPACITY');
      assert.deepEqual(row(), saved, 'overflow rolls back epoch/revision/content/hash');
      const readable = await get(); assert.equal(readable.status, 200); assert.equal(await readable.text(), beforeText);
      assert.equal(history.snapshot(owner, scanId).decisions.some(d => d.mutationId === final.mutationId), false);
      const accepted = await post(final, head); assert.equal(accepted.status, 200, await accepted.clone().text());
      assert.equal(Buffer.byteLength(await accepted.text()), HISTORY.scopeBytes, 'measure actual serialized POST response');
      const full = await get(); assert.equal(full.status, 200); assert.equal(Buffer.byteLength(await full.text()), HISTORY.scopeBytes, 'measure actual serialized GET');
      assert.equal(providerLookups, 0);
    } finally { db.close(); }

    // Separate scope: large optional old explanations, NOT oversized mandatory user memory.
    const completionId = ledger.enqueue({ subject: owner, idempotencyKey: 'completion-envelope', registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: digest as `sha256:${string}`, platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
    const completionJob = ledger.claim()!;
    assert.ok(ledger.finishCombined(completionId, completionJob.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings:
      Array.from({ length: 32 }, (_, n) => ({ findingId: `secret-0-${n + 1}`, ruleId: 'rule-0123456789abcdef', line: n + 1, evidenceRef: `result-0-secret-${n + 1}` })) }]));
    const completionReport = app.get(ReportReader).read({ subject: owner, scope: ['scan:read'] }, completionId), cb = reportBinding(completionReport);
    const cs = completionReport.findings.map(finding => ({ ...cb, finding }));
    const chatUrl = `${base}/browser/scans/${completionId}/llm`;
    const getChat = (suffix: string) => fetch(`${chatUrl}/${suffix}`, { headers: { cookie } });
    const postChat = (body: unknown, suffix = 'chat') => fetch(`${chatUrl}/${suffix}`, { method: 'POST',
      headers: { cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const fixtureTurn = (): Turn => ({ id: randomUUID(), mutationId: randomUUID(), state: 'pending', question: 'Explain the retained finding.', report: cb,
      createdAt: Date.now(), inputHash: '1'.repeat(64), consentPolicyVersion: '2'.repeat(64), requestHash: '3'.repeat(64) });
    const fixturePending = (t: Turn): Pending => ({ id: t.id, sessionId: '4'.repeat(32), generation: 1, accessIncarnation: '5'.repeat(32),
      policyVersion: t.consentPolicyVersion, requestHash: t.requestHash, deadline: Date.now() + 40000 });
    const seed = (t: Turn, text: string) => {
      const h = history.snapshot(owner, completionId), p = history.begin(owner, completionId, h.epoch, h.revision, t, fixturePending(t));
      return history.finish(owner, completionId, p.epoch, p.revision, t.id, { ...cb, kind: 'hypothesis', text, sources: cs.slice(0, 1) });
    };
    const largeText = '"'.repeat(15000) + ' '.repeat(1384); assert.equal(Buffer.byteLength(largeText), HISTORY.replyBytes);
    for (let n = 0; n < 12; n++) seed(fixtureTurn(), largeText);
    const question = 'Explain the current findings.', prospective = { ...fixtureTurn(), question }, pp = fixturePending(prospective), filler = fixtureTurn();
    const beforeFiller = history.snapshot(owner, completionId);
    const afterFiller: HistoryHead = { ...beforeFiller, revision: beforeFiller.revision + 2, turns: [...beforeFiller.turns,
      { ...filler, state: 'completed', reply: { ...cb, kind: 'hypothesis', text: '"', sources: cs.slice(0, 1) } }] };
    const withPending = (h: HistoryHead) => ({ ...h, revision: h.revision + 1, turns: [...h.turns, prospective], pending: pp });
    const growth = HISTORY.scopeBytes - HISTORY.completionReserve - Math.max(bytes(withPending(afterFiller)), bytes(historyProjection(withPending(afterFiller), cb)));
    assert.ok(growth > 0 && growth < 2 * HISTORY.replyBytes);
    const fillerText = '"'.repeat(1 + Math.floor(growth / 2)) + ' '.repeat(growth % 2);
    const seeded = seed(filler, fillerText);
    assert.equal(Math.max(bytes(withPending(seeded)), bytes(historyProjection(withPending(seeded), cb))) + HISTORY.completionReserve, HISTORY.scopeBytes);
    assert.ok(bytes(withPending(seeded)) > bytes(historyProjection(withPending(seeded), cb)), 'private pending identity makes stored bytes the active admission bound');
    let sends = 0;
    const transport = Object.assign((async () => assert.fail('guarded adapter required')) as typeof fetch, {
      sendGuarded: async (_url: string, init: RequestInit, guard: BodySendGuard) => {
        guard(() => { sends++; });
        const wire = JSON.parse(String(init.body)), context = JSON.parse(wire.messages[1].content);
        assert.equal(wire.stream, false); assert.deepEqual(wire.provider.only, ['novita/bf16']);
        assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
        assert.equal(context.omission.explanations, 13, 'only optional assistant explanations are reduced');
        assert.equal(context.history.userTurns.length, 13); assert.equal(context.report.findings.length, 32, 'all UNKNOWN remain mandatory');
        return new Response(JSON.stringify({ model: freePolicy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
          choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify({ ...cb, text: largeText,
            citations: cs.map(s => s.finding.findingId) }) } }] }), { headers: { 'content-type': 'application/json' } });
      },
    }) as GuardedTransport;
    runtime.provider = () => { providerLookups++; return new OpenRouterProvider(fakeKey, transport); };
    const chatContext = await (await getChat('chat/context')).json() as { epoch: string; revision: number; reportVersion: string; policyVersion: string };
    const input = { epoch: chatContext.epoch, revision: chatContext.revision, mutationId: randomUUID(), reportVersion: chatContext.reportVersion,
      question, consent: { accepted: true, policyVersion: chatContext.policyVersion } };
    const cdb = new Database(historyPath, { readonly: true });
    const cRow = () => cdb.prepare('SELECT epoch,revision,content,content_hash FROM history_head WHERE scope=?').get(hashValue([owner, completionId]));
    try {
      const saved = cRow(), before = await getChat('history'); assert.equal(before.status, 200); const savedGet = await before.text();
      const usageBefore = quota.snapshot(owner, completionId).scan;
      const refused = await postChat({ ...input, question: question + ' ' });
      assert.equal(refused.status, 409, await refused.clone().text()); assert.equal((await refused.json() as { errorCode: string }).errorCode, 'LLM_HISTORY_CAPACITY');
      assert.deepEqual(cRow(), saved); assert.deepEqual(quota.snapshot(owner, completionId).scan, usageBefore); assert.equal(sends, 0);
      const readable = await getChat('history'); assert.equal(readable.status, 200); assert.equal(await readable.text(), savedGet);
      const completed = await postChat(input); assert.equal(completed.status, 200, await completed.clone().text());
      const completionText = await completed.text(); assert.ok(Buffer.byteLength(completionText) <= HISTORY.scopeBytes);
      const reply = JSON.parse(completionText).reply; assert.equal(Buffer.byteLength(reply.text), HISTORY.replyBytes); assert.equal(reply.sources.length, HISTORY.citations);
      assert.equal(sends, 1); assert.equal(quota.snapshot(owner, completionId).scan.used.input, 500, 'actual adapter receipt persisted before completion');
      const after = await getChat('history'); assert.equal(after.status, 200); const completedGet = await after.text();
      assert.ok(Buffer.byteLength(completedGet) <= HISTORY.scopeBytes, 'actual maximum-text/32-source completion remains readable');
      assertPublicHistory(JSON.parse(completedGet) as PublicHistory, history.snapshot(owner, completionId));
      t.diagnostic(`decision HTTP C=${HISTORY.scopeBytes}, C+1 rejected409; chat full-pending+reserve=${HISTORY.scopeBytes}, C+1 rejected409; maximum completion POST=${Buffer.byteLength(completionText)}, GET=${Buffer.byteLength(completedGet)}`);
      const originalTurn = history.snapshot(owner, completionId).turns.at(-1)!;
      assert.equal(originalTurn.consentPolicyVersion, input.consent.policyVersion); assert.match(originalTurn.inputHash, /^[a-f0-9]{64}$/);
      assert.match(originalTurn.requestHash, /^[a-f0-9]{64}$/);
      history.close(); history = new HistoryStore(historyPath);
      assert.deepEqual(history.snapshot(owner, completionId).turns.at(-1), originalTurn, 'original identity survives reopen');
      const reopened = await getChat('history'); assert.equal(reopened.status, 200);
      assertPublicHistory(await reopened.json() as PublicHistory, history.snapshot(owner, completionId));
      const duplicate = await postChat(input); assert.equal(duplicate.status, 200);
      assert.deepEqual(await duplicate.json(), { duplicate: true, id: originalTurn.id, state: 'completed', epoch: input.epoch, revision: input.revision + 2 });
      assert.equal(sends, 1, 'identical original-revision retry status only, never resend');
      const unchanged = cRow();
      for (const changed of [{ ...input, revision: input.revision + 1 }, { ...input, question: question + ' changed' },
        { ...input, reportVersion: 'f'.repeat(64) }, { ...input, epoch: randomUUID() }]) assert.equal((await postChat(changed)).status, 409);
      assert.equal((await postChat({ epoch: input.epoch, revision: input.revision, mutationId: input.mutationId, reportVersion: input.reportVersion,
        text: question, findingIds: [] }, 'history/decision')).status, 409, 'changed mutation kind');
      runtime.policy = () => ({ ...freePolicy, version: 'e'.repeat(64) });
      const newPolicy = await (await getChat('chat/context')).json() as { policyVersion: string };
      assert.equal((await postChat({ ...input, consent: { accepted: true, policyVersion: newPolicy.policyVersion } })).status, 409, 'new valid consent cannot reuse original mutation');
      runtime.policy = () => freePolicy;
      assert.deepEqual(cRow(), unchanged); assert.equal(sends, 1); assert.equal(providerLookups, 2, 'only attempted admissions consult provider; duplicates/conflicts do not');
      const service = llm.history(), normalContext = service.context.bind(service);
      for (const enabled of [true, false]) {
        runtime.policy = () => enabled ? freePolicy : null;
        service.context = (...args) => { const result = normalContext(...args); runtime.policy = () => enabled ? null : freePolicy; return result; };
        const stale = await getChat('chat/context'); assert.equal(stale.status, 409);
        assert.equal((await stale.json() as { errorCode: string }).errorCode, 'LLM_STALE_POLICY');
      }
      service.context = normalContext; runtime.policy = () => null;
      assert.equal((await getChat('history')).status, 200, 'provider-disabled authorized history is still readable');
      const disabled = await getChat('chat/context'); assert.equal(disabled.status, 200); assert.equal((await disabled.json() as { enabled: boolean }).enabled, false);
      runtime.policy = () => freePolicy;
      history.rotateRestoredLineage(); history.close(); history = new HistoryStore(historyPath);
      assert.equal((await postChat(input)).status, 409, 'restored epoch cannot replay old mutation');
      assert.deepEqual(history.snapshot(owner, completionId).turns.at(-1), originalTurn); assert.equal(sends, 1);
      const restored = await getChat('history'); assert.equal(restored.status, 200);
      assertPublicHistory(await restored.json() as PublicHistory, history.snapshot(owner, completionId));

      // Retained internal fingerprints make storage the active bound for turn-containing history.
      const retainedTurns = history.snapshot(owner, completionId).turns;
      const storedCandidate = (h: HistoryHead, d: Decision): HistoryHead => ({ ...h, revision: h.revision + 1, decisions: [...h.decisions, d] });
      const decision = (): Decision => ({ ...entry(), report: cb, sources: cs });
      let turnHead = history.snapshot(owner, completionId);
      for (;;) {
        const d = decision(), next = storedCandidate(turnHead, d);
        if (Math.max(bytes(next), bytes(historyProjection(next, cb))) > HISTORY.scopeBytes - HISTORY.questionBytes) break;
        turnHead = history.decision(owner, completionId, turnHead.epoch, turnHead.revision, d);
      }
      let atStoredCap: Decision | undefined;
      for (let n = 0; n <= cs.length; n++) {
        const d = { ...decision(), text: 'x', sources: cs.slice(0, n) }, next = storedCandidate(turnHead, d);
        const length = 1 + HISTORY.scopeBytes - Math.max(bytes(next), bytes(historyProjection(next, cb)));
        if (length >= 1 && length < HISTORY.questionBytes) { d.text = ('x '.repeat(1024)).slice(0, length); atStoredCap = d; break; }
      }
      assert.ok(atStoredCap, 'construct exact active stored C with actual retained turns');
      const admitted = storedCandidate(turnHead, atStoredCap);
      assert.equal(bytes(admitted), HISTORY.scopeBytes); assert.ok(bytes(historyProjection(admitted, cb)) < HISTORY.scopeBytes);
      const postDecision = (d: Decision) => postChat({ epoch: turnHead.epoch, revision: turnHead.revision, mutationId: d.mutationId,
        reportVersion: cb.reportVersion, text: d.text, findingIds: d.sources.map(s => s.finding.findingId) }, 'history/decision');
      const savedRow = cRow(), prior = await getChat('history'); assert.equal(prior.status, 200); const priorText = await prior.text();
      const quotaAtCap = quota.snapshot(owner, completionId).scan, lookupsAtCap = providerLookups;
      const overflowCandidate = storedCandidate(turnHead, { ...atStoredCap, text: atStoredCap.text + ' ' });
      assert.equal(bytes(overflowCandidate), HISTORY.scopeBytes + 1);
      assert.ok(bytes(historyProjection(overflowCandidate, cb)) < HISTORY.scopeBytes, 'public bytes alone would incorrectly admit this write');
      const refusedDecision = await postDecision({ ...atStoredCap, text: atStoredCap.text + ' ' }); assert.equal(refusedDecision.status, 409);
      assert.equal((await refusedDecision.json() as { errorCode: string }).errorCode, 'LLM_HISTORY_CAPACITY');
      assert.deepEqual(cRow(), savedRow); assert.deepEqual(quota.snapshot(owner, completionId).scan, quotaAtCap);
      assert.equal(history.snapshot(owner, completionId).decisions.some(d => d.mutationId === atStoredCap.mutationId), false);
      const priorReadable = await getChat('history'); assert.equal(priorReadable.status, 200); assert.equal(await priorReadable.text(), priorText);
      const acceptedDecision = await postDecision(atStoredCap); assert.equal(acceptedDecision.status, 200);
      const acceptedText = await acceptedDecision.text(); assert.equal(Buffer.byteLength(acceptedText), bytes(historyProjection(admitted, cb)));
      const atCap = history.snapshot(owner, completionId); assert.equal(bytes(atCap), HISTORY.scopeBytes);
      assertPublicHistory(JSON.parse(acceptedText) as PublicHistory, atCap); assert.deepEqual(atCap.turns, retainedTurns);
      assert.deepEqual(quota.snapshot(owner, completionId).scan, quotaAtCap); assert.equal(sends, 1); assert.equal(providerLookups, lookupsAtCap);
      const capGet = await getChat('history'); assert.equal(capGet.status, 200); assert.equal(await capGet.text(), acceptedText);
      t.diagnostic(`turn-containing decision stored C=${bytes(atCap)}, sanitized HTTP=${Buffer.byteLength(acceptedText)}; stored C+1 refused409 despite public bytes below cap`);
    } finally { cdb.close(); }
  } finally {
    history.close(); quota.close(); await app.close(); rmSync(dir, { recursive: true, force: true });
    names.forEach((n, i) => { if (previous[i] === undefined) delete process.env[n]; else process.env[n] = previous[i]; });
  }
});

test('TASK16 R4 real cookie/service/controller admitted failure frames preserve JSON, durable receipt, lease and per-write authority', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'task16-framing-'));
  const names = ['AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = names.map(n => process.env[n]), origin = 'http://127.0.0.1:8080';
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite'); process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin; process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true'; process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const app = await NestFactory.create(AppModule, { logger: false }); registerHistoryIngress(app);
  const history = new HistoryStore(join(dir, 'llm-history.sqlite'), true), quotaPath = join(dir, 'llm-usage.sqlite');
  const quota = new FixtureQuotaLedger(quotaPath, quotaPolicy), receiptDb = new Database(quotaPath, { readonly: true });
  const runtime = app.get(LlmRuntime), llm = app.get(LlmService), service = llm.history();
  runtime.policy = () => freePolicy; app.get(LlmQuotaRuntime).ledger = () => quota; service.runtime.store = () => history;
  let sends = 0, invalid: false | 'script' | 'malformed' | 'missing-usage' = false, owner = '', scanId = '', afterWrite: ((n: number) => void) | undefined;
  let afterResult: (() => Promise<void>) | undefined;
  const synthetic = Object.assign((async () => assert.fail('no unguarded/provider network')) as typeof fetch, {
    sendGuarded: async (_url: string, init: RequestInit, guard: BodySendGuard) => {
      let response!: Response;
      guard(() => {
        sends++; const wire = JSON.parse(String(init.body)), report = JSON.parse(wire.messages[1].content).report;
        assert.equal(wire.stream, false); assert.ok(wire.max_tokens <= 2048); assert.deepEqual(wire.provider.only, ['novita/bf16']);
        assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
        response = new Response(JSON.stringify({ model: freePolicy.model, usage: invalid === 'missing-usage' ? {} : { prompt_tokens: 500, completion_tokens: 32, cost: 0 }, choices: [{ finish_reason: 'stop',
          message: { role: 'assistant', content: invalid === 'malformed' ? '{PRIVATE-attacker' : JSON.stringify({ ...reportBinding(report), text: invalid === 'script' ? '<script>attacker</script>' : '- ```js\n  Unfinished safe hypothesis', citations: [report.findings[0].findingId] }) } }] }), { headers: { 'content-type': 'application/json' } });
      }); return response;
    },
  }) as GuardedTransport;
  runtime.provider = () => new OpenRouterProvider(fakeKey, synthetic);
  const acquire = (llm as unknown as { acquire(owner: string): () => void }).acquire.bind(llm);
  const generate = service.generate.bind(service);
  service.generate = async (...args) => {
    const previousIds = new Set((receiptDb.prepare('SELECT id FROM quota_attempt').all() as { id: string }[]).map(row => row.id));
    const result = await generate(...args);
    if (result.delivery && result.delivery.outcome !== 'duplicate') {
      const delivery = result.delivery;
      assert.throws(() => acquire(owner), 'same shared owner lease still held after durable terminalization');
      const saved = history.snapshot(owner, scanId).turns.find(turn => turn.id === delivery.turnId)!;
      assert.equal(saved.state, delivery.outcome);
      const attempts = (receiptDb.prepare('SELECT id FROM quota_attempt').all() as { id: string }[]).filter(row => !previousIds.has(row.id));
      assert.equal(attempts.length, 1, 'receipt provenance is THIS attempt, not any earlier settled row');
      const write = result.write; let n = 0;
      result.write = action => {
        write(() => {
          const receipt = receiptDb.prepare('SELECT state,input,output,cost,receipt,request_hash FROM quota_attempt WHERE id=?').get(attempts[0].id) as { state: string; input: number; output: number; cost: number; receipt: string; request_hash: string };
          assert.equal(receipt.request_hash, saved.requestHash);
          if ('usage' in delivery) {
            assert.equal(receipt.state, 'settled'); assert.ok(receipt.receipt);
            assert.deepEqual([receipt.input, receipt.output, receipt.cost], [delivery.usage.input, delivery.usage.output, delivery.usage.costMicros], 'exact same-attempt receipt persisted BEFORE each actual write');
          } else assert.equal(delivery.receipt, 'unavailable');
          action();
        }); afterWrite?.(++n);
      };
      await afterResult?.();
    }
    return result;
  };
  try {
    await app.listen(0, '127.0.0.1'); const base = `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1`;
    const registered = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'task16@example.com', password: 'synthetic-task16-password-1234' }) });
    owner = (await registered.json() as { id: string }).id; let cookie = registered.headers.get('set-cookie')!.split(';')[0];
    const scans = app.get(LedgerStore).ledger!;
    scanId = scans.enqueue({ subject: owner, idempotencyKey: 'task16-delivery', registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
    const job = scans.claim()!; assert.ok(scans.finishCombined(scanId, job.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [{ findingId: 'secret-0-1', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' }] }]));
    const url = `${base}/browser/scans/${scanId}/llm`;
    const get = async (suffix: string) => (await fetch(`${url}/${suffix}`, { headers: { cookie } })).json() as Promise<{ epoch: string; revision: number; reportVersion: string; policyVersion: string }>;
    const input = async () => { const c = await get('chat/context'); return { epoch: c.epoch, revision: c.revision, reportVersion: c.reportVersion, mutationId: randomUUID(), question: 'Explain the current finding.', consent: { accepted: true, policyVersion: c.policyVersion } }; };
    const post = (body: unknown, accept = 'application/x-ndjson', signal?: AbortSignal, suffix = 'chat') => fetch(`${url}/${suffix}`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json', accept }, body: JSON.stringify(body), signal });
    const first = await input(), json = await post(first, 'application/json');
    assert.equal(json.status, 200); assert.match(json.headers.get('content-type')!, /^application\/json/);
    const complete = await json.json() as { deliveryMode: string; turnId: string };
    assert.equal(complete.deliveryMode, 'completed-response'); assert.equal(sends, 1); acquire(owner)();
    const framedInput = await input(), response = await post(framedInput);
    assert.equal(response.status, 200); assert.equal(response.headers.get('content-type'), 'application/x-ndjson; charset=utf-8');
    assert.equal(response.headers.get('cache-control'), 'no-store, no-transform');
    const raw = await response.text(); assert.ok(raw.endsWith('\n'));
    const frames = raw.trimEnd().split('\n').map(s => JSON.parse(s));
    assert.deepEqual(frames.map(f => f.type), ['usage', 'citation', 'delta', 'done']);
    assert.deepEqual(frames.map(f => f.seq), [0, 1, 2, 3]);
    assert.ok(frames.every(f => f.mutationId === framedInput.mutationId && f.nativeProviderStream === false));
    assert.equal(frames[2].text, history.snapshot(owner, scanId).turns.at(-1)!.reply!.text);
    assert.deepEqual(frames[1].source, history.snapshot(owner, scanId).turns.at(-1)!.reply!.sources[0]);
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 1000); acquire(owner)();
    const duplicate = (await (await post(framedInput)).text()).trimEnd().split('\n').map(s => JSON.parse(s));
    assert.equal(duplicate.length, 1); assert.equal(duplicate[0].outcome, 'duplicate'); assert.equal('usage' in duplicate[0], false); assert.equal(sends, 2);
    assert.equal((await post(await input(), 'text/event-stream')).status, 406); assert.equal(sends, 2);
    const summary = await post({}, 'application/x-ndjson', undefined, 'summary');
    assert.equal(summary.status, 400); assert.match(summary.headers.get('content-type')!, /^application\/json/); assert.equal(sends, 2);
    invalid = 'script'; const failedInput = await input(), bad = await post(failedInput);
    assert.equal(bad.status, 200); assert.equal(bad.headers.get('content-type'), 'application/x-ndjson; charset=utf-8');
    const failedRaw = await bad.text(), failedFrames = failedRaw.trimEnd().split('\n').map(line => JSON.parse(line));
    assert.ok(failedRaw.endsWith('\n')); assert.deepEqual(failedFrames.map(frame => frame.type), ['usage', 'error']);
    assert.deepEqual(failedFrames.map(frame => frame.seq), [0, 1]);
    assert.deepEqual(failedFrames[0].usage, { input: 500, output: 32, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' });
    assert.equal(failedFrames[1].errorCode, 'LLM_UNAVAILABLE'); assert.equal(failedFrames[1].receipt, 'accepted');
    const failedHead = history.snapshot(owner, scanId), failedTurn = failedHead.turns.at(-1)!;
    assert.equal(failedTurn.state, 'failed'); assert.equal(failedTurn.reply, undefined); assert.equal(failedHead.pending, null);
    assert.ok(failedFrames.every(frame => frame.turnId === failedTurn.id && frame.mutationId === failedInput.mutationId && frame.epoch === failedHead.epoch && frame.revision === failedHead.revision && frame.revision === failedInput.revision + 2));
    assert.doesNotMatch(failedRaw, /attacker|script|synthetic|PRIVATE|"citation"|"delta"|"done"|inputHash|requestHash|reservation/);
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 1500, 'invalid reply keeps accepted receipt'); acquire(owner)();
    const dispatches = sends, replay = await post(failedInput);
    const replayFrames = (await replay.text()).trimEnd().split('\n').map(line => JSON.parse(line));
    assert.equal(replayFrames.length, 1); assert.equal(replayFrames[0].outcome, 'duplicate'); assert.equal(replayFrames[0].state, 'failed');
    assert.equal('usage' in replayFrames[0], false); assert.equal(sends, dispatches, 'failed replay never resends or borrows receipt');
    const legacyBad = await post(await input(), 'application/json'); assert.equal(legacyBad.status, 502);
    assert.match(legacyBad.headers.get('content-type')!, /^application\/json/);
    assert.deepEqual(await legacyBad.json(), { errorCode: 'LLM_INVALID_RESPONSE' });
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 2000, 'legacy failure also cannot refund'); acquire(owner)();
    invalid = 'malformed'; const malformed = await post(await input());
    assert.equal(malformed.status, 200); const malformedRaw = await malformed.text();
    assert.deepEqual(malformedRaw.trimEnd().split('\n').map(line => JSON.parse(line).type), ['usage', 'error']);
    assert.doesNotMatch(malformedRaw, /PRIVATE|attacker|"citation"|"delta"|"done"/);
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 2500); acquire(owner)();
    invalid = 'script'; let failedWrites = 0;
    afterWrite = n => { failedWrites = n; if (n === 2) {
      const head = history.snapshot(owner, scanId), report = app.get(ReportReader).read({ subject: owner, scope: ['scan:read'] }, scanId);
      history.decision(owner, scanId, head.epoch, head.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Decision after failed usage.', report: reportBinding(report), sources: [] });
    } };
    await post(await input()).then(response => response.text().catch(() => ''), () => ''); afterWrite = undefined;
    assert.equal(failedWrites, 2, 'failed head invalidation after usage forbids stale error/end');
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 3000); acquire(owner)(); invalid = false;
    // Actual durable revision invalidation after usage write: next write must fail, no stale error frame.
    let written = 0;
    const race = await input(); afterWrite = n => { written = n; if (n === 2) {
      const head = history.snapshot(owner, scanId), report = app.get(ReportReader).read({ subject: owner, scope: ['scan:read'] }, scanId);
      history.decision(owner, scanId, head.epoch, head.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'New decision after receipt.', report: reportBinding(report), sources: [] });
    } };
    await post(race).then(r => r.text().catch(() => ''), () => ''); afterWrite = undefined;
    assert.equal(written, 2, 'head invalidation forbids citation/delta/done/error writes');
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 3500); assert.equal(history.snapshot(owner, scanId).turns.at(-1)!.state, 'completed'); acquire(owner)();
    // Report and cookie rotation independently use the same production write guard, never a boolean permission.
    const reader = app.get(ReportReader), read = reader.read.bind(reader); let stale = false;
    reader.read = (...args) => { const report = read(...args); return stale ? { ...report, reportVersion: 'e'.repeat(64) } : report; };
    written = 0; afterWrite = n => { written = n; if (n === 2) stale = true; };
    await post(await input()).then(r => r.text().catch(() => ''), () => ''); stale = false; afterWrite = undefined; reader.read = read;
    assert.equal(written, 2, 'changed report forbids further writes');
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 4000); acquire(owner)();
    written = 0; const sessionInput = await input(); afterWrite = n => { written = n; if (n === 2) app.get(AuthStore).revoke(cookie.slice('demo_session='.length)); };
    await post(sessionInput).then(r => r.text().catch(() => ''), () => ''); afterWrite = undefined;
    assert.equal(written, 2, 'revoked cookie forbids further writes');
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 4500); acquire(owner)();
    const login = await fetch(`${base}/auth/login`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'task16@example.com', password: 'synthetic-task16-password-1234' }) });
    cookie = login.headers.get('set-cookie')!.split(';')[0];
    const committed = deferred(), resume = deferred(), controller = new AbortController(); let deliverySignal: AbortSignal | undefined;
    afterResult = async () => { committed.resolve(); await resume.promise; };
    service.generate = async (...args) => { deliverySignal = args[3]; return (async () => { const result = await generate(...args); assert.throws(() => acquire(owner)); await afterResult?.(); return result; })(); };
    const disconnect = post(await input(), 'application/x-ndjson', controller.signal).catch(() => undefined);
    await committed.promise; controller.abort(); await disconnect;
    for (let n = 0; n < 100 && !deliverySignal?.aborted; n++) await new Promise(r => setTimeout(r, 5));
    assert.equal(deliverySignal?.aborted, true); resume.resolve(); afterResult = undefined;
    for (let n = 0; n < 100; n++) { try { acquire(owner)(); break; } catch { await new Promise(r => setTimeout(r, 5)); } }
    assert.equal(history.snapshot(owner, scanId).turns.at(-1)!.state, 'completed');
    assert.equal(quota.snapshot(owner, scanId).scan.used.input, 5000, 'disconnect cannot retract accepted receipt or committed reply'); acquire(owner)();
        service.generate = generate; invalid = 'missing-usage';
        const unknownReceipt = await post(await input()); assert.equal(unknownReceipt.status, 200);
        assert.equal(unknownReceipt.headers.get('content-type'), 'application/x-ndjson; charset=utf-8');
        const unavailable = (await unknownReceipt.text()).trimEnd().split('\n').map(line => JSON.parse(line));
        assert.equal(unavailable.length, 1); assert.equal(unavailable[0].type, 'error'); assert.equal(unavailable[0].seq, 0);
        assert.equal(unavailable[0].receipt, 'unavailable'); assert.equal('usage' in unavailable[0], false);
        assert.equal(quota.snapshot(owner, scanId).scan.used.input, 5000, 'earlier settled attempts do NOT establish the current receipt');
        assert.equal(history.snapshot(owner, scanId).turns.at(-1)!.state, 'failed'); acquire(owner)();
  } finally {
    receiptDb.close(); history.close(); quota.close(); await app.close(); rmSync(dir, { recursive: true, force: true });
    names.forEach((n, i) => { if (previous[i] === undefined) delete process.env[n]; else process.env[n] = previous[i]; });
  }
});

test('TASK16 R5 admitted unavailable receipt emits only guarded error; nonadmission and legacy JSON stay safe', { timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'task16-unavailable-'));
  const names = ['AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = names.map(name => process.env[name]), origin = 'http://127.0.0.1:8080';
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite'); process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin; process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true'; process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const app = await NestFactory.create(AppModule, { logger: false }); registerHistoryIngress(app);
  const history = new HistoryStore(join(dir, 'llm-history.sqlite'), true), quotaPath = join(dir, 'llm-usage.sqlite');
  const quota = new FixtureQuotaLedger(quotaPath, quotaPolicy), db = new Database(quotaPath, { readonly: true });
  const runtime = app.get(LlmRuntime), llm = app.get(LlmService), service = llm.history();
  runtime.policy = () => freePolicy; app.get(LlmQuotaRuntime).ledger = () => quota; service.runtime.store = () => history;
  let mode: 'reject' | 'valid' | 'missing' | 'fault' = 'reject', sends = 0, owner = '', scanId = '', reservation = '', writes = 0;
  let afterWrite: ((n: number) => void) | undefined, beforeFailure: (() => void) | undefined;
  const synthetic = Object.assign((async () => assert.fail('no actual provider or unguarded transport')) as typeof fetch, {
    sendGuarded: async (_url: string, init: RequestInit, guard: BodySendGuard) => {
      let response!: Response;
      guard(() => {
        sends++; reservation = history.snapshot(owner, scanId).pending!.reservation!;
        assert.equal((db.prepare('SELECT state FROM quota_attempt WHERE id=?').get(reservation) as { state: string }).state, 'dispatched');
        const wire = JSON.parse(String(init.body)), report = JSON.parse(wire.messages[1].content).report;
        assert.equal(wire.stream, false); assert.ok(wire.max_tokens <= 2048); assert.deepEqual(wire.provider.only, ['novita/bf16']);
        assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
        if (mode === 'reject') { beforeFailure?.(); throw new Error('PRIVATE-before-receipt'); }
        const usage = mode === 'missing' ? {} : { prompt_tokens: 500, completion_tokens: 32, cost: mode === 'fault' ? 0.01 : 0 };
        response = new Response(JSON.stringify({ model: freePolicy.model, usage, choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: mode === 'valid' ? JSON.stringify({ ...reportBinding(report), text: 'Safe hypothesis', citations: [report.findings[0].findingId] }) : '{PRIVATE-invalid-reply' } }] }), { headers: { 'content-type': 'application/json' } });
      }); return response;
    },
  }) as GuardedTransport;
  runtime.provider = () => new OpenRouterProvider(fakeKey, synthetic);
  const acquire = (llm as unknown as { acquire(owner: string): () => void }).acquire.bind(llm), generate = service.generate.bind(service);
  service.generate = async (...args) => {
    const result = await generate(...args), delivery = result.delivery;
    if (delivery && delivery.outcome !== 'duplicate') {
      const attempt = reservation, head = history.snapshot(owner, scanId), turn = head.turns.find(turn => turn.id === delivery.turnId)!;
      assert.equal(turn.state, delivery.outcome); assert.equal(head.revision, delivery.revision); assert.equal(head.pending, null);
      assert.throws(() => acquire(owner), 'same capacity lease held after durable terminalization');
      const write = result.write; writes = 0;
      result.write = action => {
        write(() => {
          assert.throws(() => acquire(owner));
          const row = db.prepare('SELECT state,request_hash FROM quota_attempt WHERE id=?').get(attempt) as { state: string; request_hash: string };
          assert.equal(row.request_hash, turn.requestHash);
          if ('usage' in delivery) assert.equal(row.state, 'settled');
          else { assert.equal(delivery.receipt, 'unavailable'); assert.notEqual(row.state, 'settled'); assert.equal(turn.reply, undefined); }
          action();
        }); writes++; afterWrite?.(writes);
      };
    }
    return result;
  };
  try {
    await app.listen(0, '127.0.0.1'); const base = `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1`;
    const registration = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'task16-r5@example.com', password: 'synthetic-r5-password-1234' }) });
    owner = (await registration.json() as { id: string }).id; let cookie = registration.headers.get('set-cookie')!.split(';')[0];
    const scans = app.get(LedgerStore).ledger!;
    scanId = scans.enqueue({ subject: owner, idempotencyKey: 'task16-r5', registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
    const job = scans.claim()!; assert.ok(scans.finishCombined(scanId, job.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [{ findingId: 'secret-0-1', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' }] }]));
    const url = `${base}/browser/scans/${scanId}/llm`;
    const input = async () => { const c = await (await fetch(`${url}/chat/context`, { headers: { cookie } })).json() as { epoch: string; revision: number; reportVersion: string; policyVersion: string }; return { epoch: c.epoch, revision: c.revision, reportVersion: c.reportVersion, mutationId: randomUUID(), question: 'Explain this finding.', consent: { accepted: true, policyVersion: c.policyVersion } }; };
    const post = (body: unknown, accept = 'application/x-ndjson') => fetch(`${url}/chat`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json', accept }, body: JSON.stringify(body) });
    const denial = await post({ ...await input(), consent: { accepted: false, policyVersion: 'invalid' } });
    assert.equal(denial.status, 403); assert.match(denial.headers.get('content-type')!, /^application\/json/);
    assert.deepEqual(await denial.json(), { errorCode: 'LLM_CONSENT_REQUIRED' });
    assert.equal(sends, 0); assert.equal(history.snapshot(owner, scanId).turns.length, 0);
    assert.equal((db.prepare('SELECT count(*) AS n FROM quota_attempt').get() as { n: number }).n, 0); acquire(owner)();
    const unavailable = async () => {
      const request = await input(), response = await post(request);
      assert.equal(response.status, 200); assert.equal(response.headers.get('content-type'), 'application/x-ndjson; charset=utf-8');
      const raw = await response.text(); assert.ok(raw.endsWith('\n'));
      const frames = raw.trimEnd().split('\n').map(line => JSON.parse(line)); assert.equal(frames.length, 1);
      const error = frames[0], head = history.snapshot(owner, scanId), turn = head.turns.at(-1)!;
      assert.equal(error.type, 'error'); assert.equal(error.seq, 0); assert.equal(error.receipt, 'unavailable'); assert.equal(error.errorCode, 'LLM_UNAVAILABLE');
      assert.equal(error.mutationId, request.mutationId); assert.equal(error.turnId, turn.id); assert.equal(error.epoch, head.epoch);
      assert.equal(error.revision, request.revision + 2); assert.equal(error.revision, head.revision); assert.equal(turn.state, 'failed'); assert.equal(turn.reply, undefined);
      assert.equal(error.nativeProviderStream, false); assert.doesNotMatch(raw, /PRIVATE|invalid-reply|"usage"|"citation"|"delta"|"done"|requestHash|reservation|inputHash/);
      assert.equal(writes, 3, 'guard at header/error/end'); acquire(owner)(); return request;
    };
    const rejected = await unavailable(); assert.equal(sends, 1);
    assert.equal((db.prepare('SELECT state FROM quota_attempt WHERE id=?').get(reservation) as { state: string }).state, 'dispatched');
    const replay = await post(rejected), duplicate = (await replay.text()).trimEnd().split('\n').map(line => JSON.parse(line));
    assert.equal(duplicate.length, 1); assert.equal(duplicate[0].outcome, 'duplicate'); assert.equal(duplicate[0].state, 'failed'); assert.equal(sends, 1);
    const legacy = await post(await input(), 'application/json'); assert.equal(legacy.status, 502);
    assert.match(legacy.headers.get('content-type')!, /^application\/json/); assert.deepEqual(await legacy.json(), { errorCode: 'LLM_PROVIDER_UNAVAILABLE' }); acquire(owner)();
    mode = 'valid'; const valid = await post(await input()); assert.equal(valid.status, 200); await valid.text(); acquire(owner)();
    assert.equal((db.prepare("SELECT count(*) AS n FROM quota_attempt WHERE state='settled'").get() as { n: number }).n, 1);
    mode = 'missing'; await unavailable();
    assert.equal((db.prepare('SELECT state,receipt FROM quota_attempt WHERE id=?').get(reservation) as { state: string; receipt: string | null }).receipt, null, 'earlier settled row cannot establish this receipt');
    mode = 'reject'; beforeFailure = () => { runtime.policy = () => null; };
    const unsealable = await post(await input()); beforeFailure = undefined; runtime.policy = () => freePolicy;
    assert.equal(unsealable.status, 502); assert.match(unsealable.headers.get('content-type')!, /^application\/json/); assert.doesNotMatch(await unsealable.text(), /PRIVATE|"usage"/); acquire(owner)();
    const reader = app.get(ReportReader), read = reader.read.bind(reader);
    for (const loss of ['head', 'policy', 'report', 'session']) {
      const request = await input(); writes = 0;
      afterWrite = n => { if (n !== 1) return;
        if (loss === 'head') { const head = history.snapshot(owner, scanId), report = read({ subject: owner, scope: ['scan:read'] }, scanId); history.decision(owner, scanId, head.epoch, head.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'After error headers.', report: reportBinding(report), sources: [] }); }
        if (loss === 'policy') runtime.policy = () => null;
        if (loss === 'report') reader.read = (...args) => ({ ...read(...args), reportVersion: 'e'.repeat(64) });
        if (loss === 'session') app.get(AuthStore).revoke(cookie.slice('demo_session='.length));
      };
      await post(request).then(response => response.text().catch(() => ''), () => '');
      afterWrite = undefined; runtime.policy = () => freePolicy; reader.read = read;
      assert.equal(writes, 1, `${loss} loss forbids the sole error write`); acquire(owner)();
      if (loss === 'session') { const login = await fetch(`${base}/auth/login`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'task16-r5@example.com', password: 'synthetic-r5-password-1234' }) }); cookie = login.headers.get('set-cookie')!.split(';')[0]; }
    }
    mode = 'fault'; await unavailable();
    assert.equal((db.prepare('SELECT state FROM quota_attempt WHERE id=?').get(reservation) as { state: string }).state, 'fault', 'invalid receipt retains existing fault accounting, never claims accepted usage');
    assert.equal((db.prepare("SELECT count(*) AS n FROM quota_attempt WHERE state='settled'").get() as { n: number }).n, 1);
  } finally {
    db.close(); history.close(); quota.close(); await app.close(); rmSync(dir, { recursive: true, force: true });
    names.forEach((name, n) => { if (previous[n] === undefined) delete process.env[name]; else process.env[name] = previous[n]; });
  }
});
