import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AuthStore } from '../../auth/auth.store.js';
import { HistoryStore } from '../history-store.js';
import { HistoryStore as Old4Store } from './reservation-v5-batch26-old4.fixture.js';
import { HistoryRuntime, HISTORY_AUTHORITY } from '../history-runtime.js';
import { HISTORY, hashValue, reportBinding, type Turn } from '../history-contract.js';
import { LlmService, LlmRuntime } from '../llm.service.js';
import { LlmController } from '../llm.controller.js';
import { BrowserIdentity } from '../browser-identity.js';
import type { ReportContext, ReportReader } from '../report-context.js';
import type { LlmQuotaRuntime } from '../quota-runtime.js';
import { QuotaLedger } from '../quota-ledger.js';
import { syntheticOpenAiKey, openAiEnvelope } from './openai-core.fixture.js';
import { fixture, provider, report, policy, value, capacity, unavailable, quotaPolicy, quotaContext, tableRows, fingerprint } from './reservation-v5-batch26.fixture.js';

async function serviceFixture(version: 4 | 5 = 5) {
  const f = fixture(version), origin = 'http://127.0.0.1:8081';
  assert.equal(provider.monetaryLimit, 'uncapped'); assert.equal(quotaPolicy.monetaryLimit, 'uncapped');
  assert.equal(provider.requestBudgetMicros, null); assert.equal(quotaPolicy.user.costMicros, null);
  const env = { AUTH_DB_PATH: join(f.directory, 'auth.sqlite'), AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    LLM_HISTORY_ENABLED: 'true', LLM_HISTORY_REVISION: HISTORY.version, LLM_HISTORY_AUTHORITY: HISTORY_AUTHORITY };
  const previous = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]])); Object.assign(process.env, env);
  const auth = new AuthStore(), history = new HistoryRuntime(f.path);
  const user = await auth.register('batch26-service@example.invalid', 'synthetic-batch26-password-1234'); assert.ok(user);
  const owner = user.id;
  let sends = 0, quotaOpens = 0, failure: 'none' | 'unknown' | 'invalid' = 'none', currentReport: ReportContext = report;
  let resume = () => {}, entered = () => {};
  let reached = new Promise<void>(resolve => { entered = resolve; });
  let barrier = new Promise<void>(resolve => { resume = resolve; });
  const events: string[] = [];
  const runtime = new LlmRuntime(true, { environment: () => ({ LLM_PROVIDER: 'openai' }), quotaPolicy: () => f.ledger.policy,
    configuration: () => ({ policy: provider, maxConcurrent: 2, accountingRevision: 'batch26-service',
      spending: { userBudgetMicros: quotaPolicy.user.costMicros, scanBudgetMicros: quotaPolicy.scan.costMicros } }),
    credential: () => syntheticOpenAiKey, credentialReady: () => true,
    transport: () => ({ async sendGuarded(_endpoint, _init, guard) {
      guard(() => { sends++; events.push('send'); return undefined; });
      entered(); await barrier;
      if (failure === 'unknown') throw new Error('synthetic unknown response');
      return new Response(JSON.stringify(openAiEnvelope(failure === 'invalid' ? { invalid: true } : undefined)),
        { headers: { 'content-type': 'application/json' } });
    } }),
  });
  const reports = { read: () => currentReport,
    withSummaryReport: <T>(_identity: unknown, _scanId: string, action: (report: ReportContext) => T) => action(currentReport),
  } as unknown as ReportReader;
  const quotas = { ledger: () => { quotaOpens++; events.push('quota');
    assert.equal((f.db.prepare("SELECT count(*) n FROM llm_summary WHERE json_extract(content,'$.id') IS NOT NULL").get() as { n: number }).n, 1,
      'reservation must already be durably visible before quota opens');
    return f.ledger;
  } } as unknown as LlmQuotaRuntime;
  const service = new LlmService(reports, runtime, quotas, auth, origin, history), snapshot = runtime.resolve()!;
  assert.ok(snapshot);
  const body = { reportVersion: report.reportVersion, consent: { accepted: true, policyVersion: snapshot.version } };
  const request = { headers: { cookie: `demo_session=${auth.createSession(owner)}`, origin,
    'content-type': 'application/json', 'content-length': String(Buffer.byteLength(JSON.stringify(body))) },
    socket: { remoteAddress: '127.0.0.1' } };
  const generate = (signal = new AbortController().signal) => service.summaryForBrowser(request, currentReport.scanId, body, signal);
  return { ...f, auth, history, owner, service, runtime, request, body, snapshot, events, generate,
    get sends() { return sends; }, get quotaOpens() { return quotaOpens; }, get reached() { return reached; },
    resume() { resume(); }, setFailure(next: typeof failure) { failure = next; }, setReport(next: ReportContext) { currentReport = next; },
    resetBarrier() { reached = new Promise<void>(resolve => { entered = resolve; }); barrier = new Promise<void>(resolve => { resume = resolve; }); },
    close() { resume(); service.onModuleDestroy(); history.close(); auth.onModuleDestroy(); f.close();
      for (const [key, entry] of Object.entries(previous)) { if (entry === undefined) delete process.env[key]; else process.env[key] = entry; } },
  };
}
const status = (code: number) => (error: unknown) => error instanceof HttpException && error.getStatus() === code;

for (const version of [4, 5] as const) {
  test(`batch26 actual summary service schema${version} admits only held v5 before quota/send and commits before return`, { timeout: 20000 }, async t => {
    const f = await serviceFixture(version);
    try {
      if (version === 4) {
        const old = new Old4Store(f.path);
        try { old.writeSummary(f.owner, report, f.snapshot.summaryPolicy, value); } finally { old.close(); }
        const before = tableRows(f.db), files = fingerprint([f.path, f.quotaPath]);
        await assert.rejects(f.generate(), unavailable);
        assert.equal(f.sends, 0); assert.equal(f.quotaOpens, 0);
        assert.deepEqual(tableRows(f.db), before); assert.deepEqual(fingerprint([f.path, f.quotaPath]), files);
        assert.equal(f.db.pragma('user_version', { simple: true }), 4);
        const stored = f.service.readSummary(f.request, report.scanId);
        stored.write(() => {}); assert.deepEqual(stored.value, value);
        return;
      }
      f.fillOwner(f.owner);
      const store = f.history.summaryStore(), originalWrite = store.writeSummary.bind(store);
      t.mock.method(store, 'writeSummary', (...args: Parameters<HistoryStore['writeSummary']>) => {
        const result = originalWrite(...args); f.events.push('commit');
        assert.deepEqual(f.competitor.readSummary(f.owner, report, f.snapshot.summaryPolicy), value);
        return result;
      });
      const completion = f.generate();
      await Promise.race([f.reached, completion.then(() => assert.fail('no provider barrier reached'))]);
      assert.deepEqual(f.events, ['quota', 'send']);
      assert.equal(f.sends, 1); assert.equal(f.quotaOpens, 1);
      await assert.rejects(f.generate(), status(429), 'owner slot stays held through provider await');
      const other = { ...report, scanId: randomUUID() };
      assert.throws(() => f.competitor.writeSummary(f.owner, other, policy, { ...value, scanId: other.scanId }), capacity);
      f.resume();
      const result = await completion;
      assert.deepEqual(f.events, ['quota', 'send', 'commit']);
      assert.deepEqual(result.value, value); result.write(() => f.events.push('publish'));
      assert.deepEqual(f.events, ['quota', 'send', 'commit', 'publish']);
      const quota = new Database(f.quotaPath, { readonly: true });
      try { assert.deepEqual(quota.prepare('SELECT state,input,output,cost FROM quota_attempt').all(),
        [{ state: 'settled', input: 20, output: 10, cost: 40 }]); } finally { quota.close(); }
      const before = tableRows(f.db), files = fingerprint([f.path, f.quotaPath]);
      const read = f.service.readSummary(f.request, report.scanId); read.write(() => {}); assert.deepEqual(read.value, value);
      f.history.close();
      const reload = f.service.readSummary(f.request, report.scanId); reload.write(() => {}); assert.deepEqual(reload.value, value);
      assert.equal(f.sends, 1); assert.equal(f.quotaOpens, 1);
      assert.deepEqual(tableRows(f.db), before); assert.deepEqual(fingerprint([f.path, f.quotaPath]), files);
      f.setReport(other);
      await assert.rejects(f.generate(), capacity);
      assert.equal(f.sends, 1); assert.equal(f.quotaOpens, 1, 'capacity failure cannot reserve quota');
    } finally { f.close(); }
  });
}

for (const failure of ['unknown', 'invalid', 'stale-report', 'stale-policy', 'revoked', 'abort', 'commit-failure'] as const) {
  test(`batch26 actual service ${failure} preserves prior summary and observed/unknown liability without refund`, { timeout: 20000 }, async t => {
    const f = await serviceFixture();
    try {
      f.store.writeSummary(f.owner, report, f.snapshot.summaryPolicy, value);
      const before = tableRows(f.db);
      if (failure === 'unknown' || failure === 'invalid') f.setFailure(failure);
      const controller = new AbortController(), completion = f.generate(controller.signal);
      const rejected = assert.rejects(completion, (error: unknown) => error instanceof HttpException);
      await f.reached;
      if (failure === 'stale-report') f.setReport({ ...report, reportVersion: 'd'.repeat(64) });
      if (failure === 'stale-policy') t.mock.method(f.runtime, 'resolve', () => ({ ...f.snapshot, version: 'd'.repeat(64) }));
      if (failure === 'revoked') f.auth.revoke(f.request.headers.cookie.slice('demo_session='.length));
      if (failure === 'commit-failure') f.db.exec(`CREATE TRIGGER batch26_commit_fail BEFORE UPDATE ON llm_summary
        WHEN json_extract(OLD.content,'$.version')='durable-summary-reservation-v1'
          AND json_extract(NEW.content,'$.version')='durable-summary-v1'
          AND length(CAST(NEW.content AS BLOB))=69632
        BEGIN SELECT RAISE(ABORT,'batch26 synthetic commit failure'); END`);
      if (failure === 'abort') controller.abort();
      f.resume(); await rejected;
      if (failure === 'commit-failure') f.db.exec('DROP TRIGGER batch26_commit_fail');
      assert.deepEqual(f.competitor.readSummary(f.owner, report, f.snapshot.summaryPolicy), value);
      assert.deepEqual(tableRows(f.db).slice(0, 3), before.slice(0, 3));
      const retained = f.db.prepare('SELECT content FROM llm_summary').get() as { content: string };
      const hold = JSON.parse(retained.content) as { version: string; previous: string; deadline: number };
      assert.equal(hold.version, 'durable-summary-reservation-v1', 'postdispatch failures retain the hold, not just its previous visible summary');
      assert.equal(hold.previous, (before[3][0] as { content: string }).content);
      const now = Date.now;
      try {
        Date.now = () => hold.deadline + 1;
        const next = f.store.reserveSummary(f.owner, report.scanId, Date.now() + 60000);
        f.store.releaseSummary(f.owner, report.scanId, next);
      } finally { Date.now = now; }
      assert.equal(hashValue(tableRows(f.db)), hashValue(before), 'only explicit same-scope expiry acquisition restores previous bytes');
      const quota = new Database(f.quotaPath, { readonly: true });
      try {
        const rows = quota.prepare('SELECT state,input,output,cost FROM quota_attempt').all();
        if (failure === 'unknown' || failure === 'abort') assert.equal((rows[0] as { state: string }).state, 'dispatched');
        else assert.deepEqual(rows, [{ state: 'settled', input: 20, output: 10, cost: 40 }]);
      } finally { quota.close(); }
      const reopened = new QuotaLedger(f.quotaPath, quotaPolicy);
      try {
        const usage = reopened.snapshotOpenAi(quotaContext(f.owner));
        if (failure === 'unknown' || failure === 'abort') assert.ok(usage.scan.held.input > 0);
        else assert.deepEqual(usage.scan.used, { input: 20, output: 10, costMicros: 40 });
      } finally { reopened.close(); }
      assert.equal(f.sends, 1, 'no retry, fallback or repair');
    } finally { f.close(); }
  });
}

test('batch26 quota-reserve failure releases only predispatch storage hold and sends nothing', { timeout: 20000 }, async t => {
  const f = await serviceFixture();
  try {
    f.store.writeSummary(f.owner, report, f.snapshot.summaryPolicy, value);
    const before = hashValue(tableRows(f.db));
    t.mock.method(f.ledger, 'reserveOpenAi', () => { throw new HttpException({ errorCode: 'LLM_QUOTA_UNAVAILABLE' }, 503); });
    await assert.rejects(f.generate(), status(503));
    assert.equal(f.sends, 0); assert.equal(f.quotaOpens, 1);
    assert.equal(hashValue(tableRows(f.db)), before, 'proven predispatch failure restores exact previous bytes');
    const db = new Database(f.quotaPath, { readonly: true });
    try { assert.equal((db.prepare('SELECT count(*) n FROM quota_attempt').get() as { n: number }).n, 0); }
    finally { db.close(); }
  } finally { f.close(); }
});

for (const stage of ['storage', 'quota'] as const) {
  test(`batch26 enclosing guard failure after ${stage} reservation releases predispatch holds`, { timeout: 20000 }, async t => {
    const f = await serviceFixture();
    try {
      f.store.writeSummary(f.owner, report, f.snapshot.summaryPolicy, value);
      const before = tableRows(f.db), store = f.history.summaryStore();
      let rejectAfterAction = false, failures = 0;
      if (stage === 'storage') {
        const reserve = store.reserveSummary.bind(store);
        t.mock.method(store, 'reserveSummary', (...args: Parameters<HistoryStore['reserveSummary']>) => {
          const reservation = reserve(...args);
          rejectAfterAction = true;
          return reservation;
        });
      } else {
        const reserve = f.ledger.reserveOpenAi.bind(f.ledger);
        t.mock.method(f.ledger, 'reserveOpenAi', (...args: Parameters<QuotaLedger['reserveOpenAi']>) => {
          const reservation = reserve(...args);
          rejectAfterAction = true;
          return reservation;
        });
      }
      const guard = f.auth.guardSession.bind(f.auth);
      t.mock.method(f.auth, 'guardSession', function<T>(snapshot: Parameters<AuthStore['guardSession']>[0], action: () => T, busyMs?: number): T {
        const result = guard(snapshot, action, busyMs);
        if (rejectAfterAction) {
          rejectAfterAction = false; failures++;
          throw new HttpException({ errorCode: 'AUTH_UNAVAILABLE' }, 503);
        }
        return result;
      });
      await assert.rejects(f.generate(), status(503));
      assert.equal(failures, 1, 'the enclosing guard rejects only after the reservation succeeds');
      assert.equal(f.sends, 0); assert.equal(f.quotaOpens, stage === 'quota' ? 1 : 0);
      assert.deepEqual(tableRows(f.db), before, 'cleanup restores the full original storage rows, not just the visible prior summary');
      assert.deepEqual(f.competitor.readSummary(f.owner, report, f.snapshot.summaryPolicy), value);
      const db = new Database(f.quotaPath, { readonly: true });
      try {
        assert.deepEqual(db.prepare('SELECT state,input,output,cost,receipt FROM quota_attempt').all(), stage === 'quota'
          ? [{ state: 'released', input: 0, output: 0, cost: 0, receipt: null }] : []);
      } finally { db.close(); }
    } finally { f.close(); }
  });
}

test('batch26 synchronous quota dispatch delay expires token before actual send; proven unsent holds are released', { timeout: 20000 }, async t => {
  const f = await serviceFixture();
  try {
    f.store.writeSummary(f.owner, report, f.snapshot.summaryPolicy, value);
    const before = tableRows(f.db);
    const dispatch = f.ledger.dispatchOpenAi.bind(f.ledger), start = Date.now();
    t.mock.method(f.ledger, 'dispatchOpenAi', (...args: Parameters<QuotaLedger['dispatchOpenAi']>) => {
      const result = dispatch(...args);
      t.mock.method(Date, 'now', () => start + provider.timeoutMs + 1000);
      return result;
    });
    await assert.rejects(f.generate(), (error: unknown) => error instanceof HttpException);
    assert.equal(f.sends, 0, 'post-accounting token/deadline fence prevents the real transport callback');
    const db = new Database(f.quotaPath, { readonly: true });
    try { assert.deepEqual(db.prepare('SELECT state,input,output,cost,receipt FROM quota_attempt').all(),
      [{ state: 'released', input: 0, output: 0, cost: 0, receipt: null }]); }
    finally { db.close(); }
    assert.deepEqual(tableRows(f.db), before, 'proven pre-send rejection restores the full original storage bytes');
    assert.deepEqual(f.competitor.readSummary(f.owner, report, f.snapshot.summaryPolicy), value);
  } finally { f.close(); }
});

test('batch26 publication guard denies stale report after durable commit without losing result or known receipt', { timeout: 20000 }, async () => {
  const f = await serviceFixture();
  try {
    const completion = f.generate(); await f.reached; f.resume(); const publication = await completion;
    f.setReport({ ...report, reportVersion: 'd'.repeat(64) });
    let published = false;
    assert.throws(() => publication.write(() => { published = true; }), status(409));
    assert.equal(published, false);
    assert.deepEqual(f.competitor.readSummary(f.owner, report, f.snapshot.summaryPolicy), value);
    const db = new Database(f.quotaPath, { readonly: true });
    try { assert.deepEqual(db.prepare('SELECT state,input,output,cost FROM quota_attempt').all(),
      [{ state: 'settled', input: 20, output: 10, cost: 40 }]); } finally { db.close(); }
    assert.equal(f.sends, 1);
  } finally { f.close(); }
});

test('batch26 cold/cached readiness, summary GET and reopen preserve expired own/foreign slots and chat padding', { timeout: 20000 }, async t => {
  const f = await serviceFixture();
  try {
    const now = Date.now(), foreign = 'b'.repeat(32);
    for (const subject of [f.owner, foreign]) {
      f.store.writeSummary(subject, report, f.snapshot.summaryPolicy, value);
      f.store.reserveSummary(subject, report.scanId, now + 1000);
      const head = f.store.readSnapshot(subject, report.scanId), id = randomUUID();
      const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question: 'Проверить вручную.',
        report: reportBinding(report), createdAt: now, inputHash: 'f'.repeat(64), consentPolicyVersion: policy.version, requestHash: 'e'.repeat(64) };
      f.store.begin(subject, report.scanId, head.epoch, head.revision, turn, { id, sessionId: 'c'.repeat(32), generation: 1,
        accessIncarnation: 'd'.repeat(32), policyVersion: policy.version, deadline: now - 1, requestHash: turn.requestHash });
      const binding = quotaContext(subject), attempt = f.ledger.reserveOpenAi(binding);
      assert.equal(f.ledger.dispatchOpenAi(attempt, binding), true);
    }
    t.mock.method(Date, 'now', () => now + 2000);
    let recoveries = 0;
    const original = HistoryStore.prototype.recoverExpired;
    t.mock.method(HistoryStore.prototype, 'recoverExpired', function (this: HistoryStore) { recoveries++; return original.call(this); });
    // Readiness legitimately reads quota without generation's reservation-before-quota assertion.
    const quotas = { ledger: () => f.ledger } as unknown as LlmQuotaRuntime;
    const reports = { read: () => report,
      withSummaryReport: <T>(_identity: unknown, _scanId: string, action: (report: ReportContext) => T) => action(report),
    } as unknown as ReportReader;
    const service = new LlmService(reports, f.runtime, quotas, f.auth, 'http://127.0.0.1:8081', f.history);
    class Batch26PassiveModule {}
    Module({ controllers: [LlmController], providers: [
      { provide: LlmService, useValue: service },
      { provide: BrowserIdentity, useValue: { resolve: () => ({ subject: f.owner, scope: ['scan:read'] }) } },
    ] })(Batch26PassiveModule);
    const app = await NestFactory.create(Batch26PassiveModule, { logger: false });
    const emptyScan = randomUUID(), empty = f.history.readStore().readSnapshot(f.owner, emptyScan);
    assert.equal(empty.revision, 0);
    const before = tableRows(f.db), files = fingerprint([f.path, f.quotaPath]);
    const quota = new Database(f.quotaPath, { readonly: true });
    try {
      await app.listen(0, '127.0.0.1');
      const port = (app.getHttpServer().address() as { port: number }).port;
      const url = `http://127.0.0.1:${port}/api/v1/browser/scans/${report.scanId}/llm`;
      const quotaBefore = quota.prepare('SELECT * FROM quota_attempt ORDER BY rowid').all();
      for (let i = 0; i < 3; i++) {
        const readiness = await fetch(url + '/readiness', { headers: { cookie: f.request.headers.cookie, origin: f.request.headers.origin } });
        assert.equal(readiness.status, 200); assert.equal(readiness.headers.get('cache-control'), 'no-store');
        const ready = await readiness.json() as { history: string };
        assert.equal(ready.history, 'available');
        const summary = await fetch(url + '/summary', { headers: { cookie: f.request.headers.cookie, origin: f.request.headers.origin } });
        assert.equal(summary.status, 200); assert.equal(summary.headers.get('cache-control'), 'no-store');
        assert.deepEqual(await summary.json(), value);
        assert.deepEqual(f.history.readStore().readSnapshot(f.owner, emptyScan), empty);
        assert.deepEqual(tableRows(f.db), before); assert.deepEqual(fingerprint([f.path, f.quotaPath]), files);
        assert.deepEqual(quota.prepare('SELECT * FROM quota_attempt ORDER BY rowid').all(), quotaBefore);
        if (i === 1) f.history.close();
      }
      assert.equal(recoveries, 0); assert.equal(f.sends, 0);
      assert.equal((f.db.prepare('SELECT count(*) n FROM history_completion_space').get() as { n: number }).n, 2);
      f.history.store();
      assert.equal(recoveries, 1);
      assert.equal((f.db.prepare('SELECT count(*) n FROM history_completion_space').get() as { n: number }).n, 0);
      assert.deepEqual(f.db.prepare('SELECT * FROM llm_summary ORDER BY scope').all(), before[3].map(row => {
        const { rowid, ...fields } = row as Record<string, unknown>; assert.ok(rowid); return fields;
      }).sort((a, b) => String(a.scope).localeCompare(String(b.scope))));
      assert.deepEqual(quota.prepare('SELECT * FROM quota_attempt ORDER BY rowid').all(), quotaBefore);
    } finally { await app.close(); quota.close(); }
  } finally { f.close(); }
});
