import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException, NotFoundException } from '@nestjs/common';
import { AuthStore } from '../../auth/auth.store.js';
import type { Identity } from '../../security/identity.js';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { HistoryStore } from '../history-store.js';
import { HistoryRuntime, HISTORY_AUTHORITY } from '../history-runtime.js';
import { HISTORY } from '../history-contract.js';
import { registerHistoryIngress } from '../history-ingress.js';
import { encodeDelivery } from '../history-delivery.js';
import { QuotaLedger } from '../quota-ledger.js';
import type { ReportContext, ReportReader } from '../report-context.js';
import { MODULEAPI_COST_BASIS } from '../moduleapi-accounting.js';
import { createOpenAiRuntime } from '../provider-runtime.js';
import { makeOpenAiPolicy, syntheticOpenAiKey, openAiResponse } from './openai-core.fixture.js';
import { OpenAiProvider } from '../openai-provider.js';
import { fixturePolicy } from './fixtures.js';
import { moduleApiBackendConfiguration as configuration, moduleApiBackendQuota as quota, moduleApiBackendKey as key,
  moduleApiBackendReport as report, moduleApiBackendResponse as response, moduleApiBackendDeferred as deferred } from './moduleapi-backend.fixture.js';

const error = (code: string) => (value: unknown) => value instanceof HttpException &&
  (value.getResponse() as { errorCode?: string }).errorCode === code;

async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'moduleapi-backend-service-')), origin = 'http://127.0.0.1:8081' as const;
  const path = join(dir, 'llm-history.sqlite'), quotaPath = join(dir, 'llm-usage.sqlite');
  const env = { AUTH_DB_PATH: join(dir, 'auth.sqlite'), SCAN_LEDGER_PATH: join(dir, 'scan-ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    LLM_HISTORY_ENABLED: 'true', LLM_HISTORY_REVISION: HISTORY.version, LLM_HISTORY_AUTHORITY: HISTORY_AUTHORITY,
    LLM_QUOTA_ENABLED: 'true' };
  const previous = Object.fromEntries(Object.keys(env).map(name => [name, process.env[name]])); Object.assign(process.env, env);
  new HistoryStore(path, true).close();
  const auth = new AuthStore(), ledger = new QuotaLedger(quotaPath, quota, Date.now, true);
  const db = new Database(path, { readonly: true }), quotaDb = new Database(quotaPath, { readonly: true });
  const owner = await auth.register('moduleapi-offline-owner@example.invalid', 'synthetic-moduleapi-password-1234'); assert.ok(owner);
  const foreign = await auth.register('moduleapi-offline-foreign@example.invalid', 'synthetic-moduleapi-password-5678'); assert.ok(foreign);
  const cookie = `demo_session=${auth.createSession(owner.id)}`;
  const foreignCookie = `demo_session=${auth.createSession(foreign.id)}`;
  let current = configuration(), currentReport = report;
  let sends = 0, credentialReads = 0, legacyLookups = 0;
  let mode: 'valid' | 'unknown' | 'invalid' = 'valid';
  let beforeGuard: (() => void) | undefined, afterSend: (() => void | Promise<void>) | undefined;
  const events: string[] = [];
  const rows = () => quotaDb.prepare('SELECT * FROM quota_attempt ORDER BY rowid').all() as
    { id: string; state: string; cost: number; reserve_cost: number; quota_policy: string }[];
  const stored = () => db.prepare('SELECT * FROM llm_summary ORDER BY scope').all();
  const heads = () => db.prepare('SELECT * FROM history_head ORDER BY scope').all();
  const runtime = new LlmRuntime(true, { environment: () => ({ LLM_PROVIDER: 'moduleapi', MODULEAPI_MONETARY_LIMIT: 'uncapped' }),
    moduleApiConfiguration: () => current, quotaPolicy: () => quota,
    moduleApiCredentialReady: () => true, moduleApiCredential: () => { credentialReads++; return key; },
    moduleApiTransport: () => ({ async sendGuarded(_endpoint, init, guard) {
      assert.equal(rows().at(-1)!.state, 'reserved');
      beforeGuard?.();
      guard(() => { assert.equal(rows().at(-1)!.state, 'dispatched'); sends++; events.push('send'); return undefined; });
      await afterSend?.();
      const input = JSON.parse(JSON.parse(String(init.body)).messages[1].content);
      return response(input.report ? 'chat' : 'summary', mode);
    } }),
  });
  runtime.provider = () => { legacyLookups++; assert.fail('ModuleAPI never uses OpenRouter/direct fallback'); };
  const read = (identity: Identity, scanId: string) => {
    if (identity.subject !== owner.id || scanId !== currentReport.scanId) throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    return currentReport;
  };
  const reports = { read, withSummaryReport: <T>(identity: Identity, scanId: string, action: (value: ReportContext) => T) =>
    action(read(identity, scanId)) } as unknown as ReportReader;
  const quotas = { ledger: () => ledger } as LlmQuotaRuntime;
  const historyRuntime = new HistoryRuntime(path);
  let service = new LlmService(reports, runtime, quotas, auth, origin, historyRuntime);
  const identity = { subject: owner.id, scope: ['scan:read'] };
  const summaryBody = () => ({ reportVersion: currentReport.reportVersion, consent: { accepted: true, policyVersion: runtime.resolve()!.version } });
  const summaryRequest = (token = cookie) => ({ headers: { cookie: token, origin, 'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(JSON.stringify(summaryBody()))) },
    socket: { remoteAddress: '127.0.0.1' } });
  const summary = (body: unknown = summaryBody(), signal = new AbortController().signal) =>
    service.summaryForBrowser(summaryRequest(), currentReport.scanId, body, signal);
  const chatRequest = (body: unknown, token = cookie) => {
    const data = Buffer.from(JSON.stringify(body));
    const request = Object.assign(new EventEmitter(), { method: 'POST', url: `/api/v1/browser/scans/${report.scanId}/llm/chat`,
      headers: { cookie: token, origin, 'content-type': 'application/json', 'content-length': String(data.length) },
      socket: { remoteAddress: '127.0.0.1' }, body: undefined as unknown });
    let ingress!: (req: unknown, res: unknown, next: () => void) => void;
    registerHistoryIngress({ use: (fn: typeof ingress) => { ingress = fn; } } as unknown as Parameters<typeof registerHistoryIngress>[0]);
    let parsed = false;
    ingress(request, { writeHead: () => assert.fail('synthetic ingress refused'), once() {}, end() {} }, () => { parsed = true; });
    request.emit('data', data); request.emit('end'); assert.equal(parsed, true);
    return request;
  };
  const chatBody = () => {
    const head = historyRuntime.readStore().readSnapshot(owner.id, report.scanId);
    return { reportVersion: report.reportVersion, epoch: head.epoch, revision: head.revision, mutationId: randomUUID(),
      question: 'Что проверить вручную?', consent: { accepted: true, policyVersion: runtime.resolve()!.chatVersion } };
  };
  return { dir, path, ledger, db, auth, owner, identity, cookie, foreignCookie, rows, stored, heads, runtime, historyRuntime,
    get service() { return service; }, events, summary, summaryBody, summaryRequest, chatRequest,
    chatBody,
    get sends() { return sends; }, get credentialReads() { return credentialReads; }, get legacyLookups() { return legacyLookups; },
    setMode(value: typeof mode) { mode = value; }, setBeforeGuard(action?: () => void) { beforeGuard = action; },
    setAfterSend(action?: () => void | Promise<void>) { afterSend = action; },
    rotate() { current = configuration('moduleapi-backend-new-policy'); }, setReport(value: ReportContext) { currentReport = value; },
    reopen() { service.onModuleDestroy(); service = new LlmService(reports, runtime, quotas, auth, origin, historyRuntime); },
    close() { service.onModuleDestroy(); auth.onModuleDestroy(); db.close(); quotaDb.close(); ledger.close();
      for (const [name, value] of Object.entries(previous)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
      rmSync(dir, { recursive: true, force: true }); },
  };
}

test('ModuleAPI service summary/chat commit before JSON/NDJSON publication; metadata/read/reload never dispatch', { timeout: 20000 }, async t => {
  const f = await fixture();
  try {
    const baseline = { summary: f.stored(), heads: f.heads(), quota: f.rows() };
    const context = f.service.context(f.identity, report.scanId);
    assert.equal(context.disclosure?.provider, 'ModuleAPI');
    const readiness = f.service.readiness(f.identity, report.scanId);
    assert.equal(readiness.localReady, true); assert.equal('name' in readiness.provider && readiness.provider.name, 'ModuleAPI');
    assert.equal(readiness.generationVerified, false);
    const usage = f.service.usage(f.identity, report.scanId);
    assert.equal(usage.available, true); assert.equal('monetaryLimit' in usage && usage.monetaryLimit, 'uncapped');
    assert.equal('lifetimeBudget' in usage && usage.lifetimeBudget?.limitMicros, 5000000);
    assert.equal(f.credentialReads, 0); assert.equal(f.sends, 0);
    assert.deepEqual({ summary: f.stored(), heads: f.heads(), quota: f.rows() }, baseline);
    const observe = f.ledger.observeModuleApi.bind(f.ledger);
    t.mock.method(f.ledger, 'observeModuleApi', (...args: Parameters<QuotaLedger['observeModuleApi']>) => {
      const accepted = observe(...args); if (accepted) { assert.equal(f.rows().at(-1)!.state, 'settled'); f.events.push('receipt'); } return accepted;
    });
    const store = f.historyRuntime.summaryStore(), write = store.writeSummary.bind(store);
    t.mock.method(store, 'writeSummary', (...args: Parameters<HistoryStore['writeSummary']>) => {
      assert.equal(f.rows().at(-1)!.state, 'settled'); const value = write(...args);
      assert.equal(f.stored().length, 1, 'independent reader sees durable summary before service returns'); f.events.push('summary-commit'); return value;
    });
    const summary = await f.summary();
    summary.write(() => { assert.equal(f.stored().length, 1); f.events.push('summary-publish'); });
    assert.deepEqual(f.events, ['send', 'receipt', 'summary-commit', 'summary-publish']);
    const body = f.chatBody(), request = f.chatRequest(body);
    const finish = store.finish.bind(store);
    t.mock.method(store, 'finish', (...args: Parameters<HistoryStore['finish']>) => {
      assert.equal(f.rows().at(-1)!.state, 'settled'); const head = finish(...args);
      assert.equal(head.pending, null); assert.equal(head.turns.at(-1)!.state, 'completed'); f.events.push('chat-commit'); return head;
    });
    const chat = await f.service.history().generate(request, report.scanId, body, new AbortController().signal, 'ndjson');
    assert.ok(chat.delivery); assert.equal(chat.delivery.outcome, 'completed');
    const lines = encodeDelivery(chat.delivery, chat.outputTokens).lines.map(line => JSON.parse(line));
    assert.deepEqual(lines.find(line => line.type === 'usage').usage,
      { input: 20, output: 10, costMicros: 40, source: MODULEAPI_COST_BASIS });
    assert.equal(lines.at(-1).outcome, 'completed');
    chat.write(() => { assert.ok(f.heads().length); f.events.push('chat-publish'); }); chat.release?.();
    assert.deepEqual(f.events, ['send', 'receipt', 'summary-commit', 'summary-publish', 'send', 'receipt', 'chat-commit', 'chat-publish']);
    const committed = { summary: f.stored(), heads: f.heads(), quota: f.rows() };
    const read = f.service.readSummary(f.summaryRequest(), report.scanId); read.write(() => {}); assert.deepEqual(read.value, summary.value);
    const historyRead = f.service.history().read(request, report.scanId); historyRead.write(() => {});
    const historyUsage = f.service.history().usage(request, report.scanId); historyUsage.write(() => {});
    assert.equal((historyUsage.value as { monetaryLimit: string }).monetaryLimit, 'uncapped');
    f.reopen();
    const reload = f.service.readSummary(f.summaryRequest(), report.scanId); reload.write(() => {}); assert.deepEqual(reload.value, summary.value);
    const reloadHistory = f.service.history().read(request, report.scanId); reloadHistory.write(() => {});
    assert.deepEqual(reloadHistory.value, historyRead.value);
    assert.deepEqual({ summary: f.stored(), heads: f.heads(), quota: f.rows() }, committed);
    assert.deepEqual({ sends: f.sends, keys: f.credentialReads, fallback: f.legacyLookups }, { sends: 2, keys: 2, fallback: 0 });
  } finally { f.close(); }
});

test('ModuleAPI service rejects old free/OpenAI policy consent and foreign owner before key/reserve/send', { timeout: 20000 }, async () => {
  const f = await fixture();
  try {
    const directPolicy = makeOpenAiPolicy({ monetaryLimit: 'uncapped', requestBudgetMicros: null });
    const old = createOpenAiRuntime({ policy: directPolicy, maxConcurrent: 2, accountingRevision: 'historical-openai',
      spending: { userBudgetMicros: null, scanBudgetMicros: null } }, quota, () => assert.fail('metadata only'))!;
    for (const policyVersion of [old.version, fixturePolicy.version]) {
      await assert.rejects(f.summary({ ...f.summaryBody(), consent: { accepted: true, policyVersion } }), error('LLM_STALE_POLICY'));
    }
    for (const policyVersion of [old.chatVersion, fixturePolicy.version]) {
      const body = { ...f.chatBody(), consent: { accepted: true, policyVersion } };
      await assert.rejects(f.service.history().generate(f.chatRequest(body), report.scanId, body, new AbortController().signal), error('LLM_STALE_POLICY'));
    }
    assert.throws(() => f.service.readSummary(f.summaryRequest(f.foreignCookie), report.scanId), error('SCAN_NOT_FOUND'));
    await assert.rejects(f.service.summaryForBrowser(f.summaryRequest(f.foreignCookie), report.scanId, f.summaryBody(), new AbortController().signal), error('SCAN_NOT_FOUND'));
    assert.equal(f.credentialReads, 0); assert.equal(f.sends, 0); assert.deepEqual(f.rows(), []); assert.deepEqual(f.stored(), []);
  } finally { f.close(); }
});

for (const change of ['report', 'policy', 'session'] as const) {
  test(`ModuleAPI final ${change} fence rejects before actual send and releases only unsent quota`, { timeout: 20000 }, async () => {
    const f = await fixture();
    try {
      f.setBeforeGuard(() => {
        if (change === 'report') f.setReport({ ...report, reportVersion: 'd'.repeat(64) });
        if (change === 'policy') f.rotate();
        if (change === 'session') f.auth.revoke(f.cookie.slice('demo_session='.length));
      });
      await assert.rejects(f.summary(), (value: unknown) => value instanceof HttpException);
      assert.equal(f.credentialReads, 1, 'lazy key occurs only after initial fence; final fence is repeated at actual send');
      assert.equal(f.sends, 0); assert.equal(f.rows()[0].state, 'released'); assert.deepEqual(f.stored(), []);
      assert.equal(f.legacyLookups, 0);
    } finally { f.close(); }
  });
}

for (const mode of ['unknown', 'invalid'] as const) {
  test(`ModuleAPI ${mode} response never publishes/retries, retains truthful settled or unknown liability`, { timeout: 20000 }, async () => {
    const f = await fixture();
    try {
      f.setMode(mode);
      const body = f.chatBody(), request = f.chatRequest(body);
      const failed = await f.service.history().generate(request, report.scanId, body, new AbortController().signal, 'ndjson');
      assert.ok(failed.delivery); assert.equal(failed.delivery.outcome, 'failed');
      const lines = encodeDelivery(failed.delivery, failed.outputTokens).lines.map(line => JSON.parse(line));
      assert.equal(lines.at(-1).type, 'error');
      if (mode === 'unknown') {
        assert.equal(lines.at(-1).receipt, 'unavailable'); assert.equal(lines.some(line => line.type === 'usage'), false);
        assert.ok(f.rows()[0].state === 'fault' || f.rows()[0].state === 'dispatched');
        assert.ok(f.ledger.snapshot(f.owner.id, report.scanId).lifetimeBudget!.heldMicros > 0);
      } else {
        assert.equal(lines.find(line => line.type === 'usage').usage.source, MODULEAPI_COST_BASIS);
        assert.equal(f.rows()[0].state, 'settled'); assert.equal(f.rows()[0].cost, 40);
      }
      failed.write(() => {}); failed.release?.();
      assert.equal(f.sends, 1); assert.equal(f.legacyLookups, 0);
      const before = f.rows();
      f.service.history().read(request, report.scanId).write(() => {});
      assert.deepEqual(f.rows(), before); assert.equal(f.sends, 1);
    } finally { f.close(); }
  });
}

test('ModuleAPI postdispatch report/policy rotation suppresses publication but preserves old bound receipt', { timeout: 20000 }, async () => {
  const f = await fixture(), sent = deferred(), barrier = deferred();
  try {
    f.setAfterSend(async () => { sent.resolve(); await barrier.promise; });
    const completion = f.summary(), refused = assert.rejects(completion, error('LLM_STALE_POLICY'));
    await sent.promise; f.rotate(); barrier.resolve(); await refused;
    assert.equal(f.sends, 1); assert.equal(f.rows()[0].state, 'settled'); assert.equal(f.rows()[0].cost, 40);
    assert.equal(f.ledger.snapshot(f.owner.id, report.scanId).lifetimeBudget!.usedMicros, 40);
    assert.equal(f.legacyLookups, 0);
  } finally { barrier.resolve(); f.close(); }
});

test('ModuleAPI lifetime usage includes historical OpenAI settled cost and UNKNOWN held liability without relabeling', { timeout: 20000 }, async () => {
  const f = await fixture();
  try {
    const policy = makeOpenAiPolicy({ monetaryLimit: 'uncapped', requestBudgetMicros: null });
    let unknown = false;
    const old = createOpenAiRuntime({ policy, maxConcurrent: 2, accountingRevision: 'historical-openai',
      spending: { userBudgetMicros: null, scanBudgetMicros: null } }, quota,
    () => new OpenAiProvider(policy, syntheticOpenAiKey, { async sendGuarded(_endpoint, _init, guard) {
      guard(() => undefined); if (unknown) throw new Error('synthetic transport unknown'); return openAiResponse();
    } }))!;
    for (const unobserved of [false, true]) {
      unknown = unobserved;
      const prepared = old.prepareSummary(report), attempt = prepared.reserveAttempt(f.ledger, { subject: f.owner.id, scanId: report.scanId,
        reportVersion: report.reportVersion, policyVersion: old.providerPolicyVersion, requestHash: prepared.hash });
      const operation = attempt.generate(new AbortController().signal, send => send(), () => {});
      if (unobserved) await assert.rejects(operation); else await operation;
      attempt.release();
    }
    const oldRows = f.rows(), oldHold = oldRows[1].reserve_cost;
    assert.equal(JSON.parse(oldRows[0].quota_policy).paidAccounting.provider, 'OpenAI');
    await f.summary();
    const usage = f.service.usage(f.identity, report.scanId);
    assert.ok(usage.available && 'lifetimeBudget' in usage && usage.lifetimeBudget);
    assert.deepEqual(usage.lifetimeBudget, { limitMicros: 5000000, usedMicros: 80, heldMicros: oldHold, remainingMicros: 5000000 - 80 - oldHold });
    assert.deepEqual(f.rows().slice(0, 2), oldRows);
    assert.equal(JSON.parse(f.rows()[2].quota_policy).paidAccounting.provider, 'ModuleAPI');
    assert.equal(f.sends, 1, 'only the explicitly requested ModuleAPI summary uses selected transport');
  } finally { f.close(); }
});
