import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException } from '@nestjs/common';
import { LlmRuntime } from '../llm.service.js';
import { ModuleApiRuntimeResolver, PaidProviderAdmission, OpenAiRuntimeResolver, createModuleApiRuntime, selectedProvider } from '../provider-runtime.js';
import { ModuleApiProvider } from '../moduleapi-provider.js';
import { MODULEAPI_MODEL } from '../moduleapi-policy.js';
import { MODULEAPI_COST_BASIS } from '../moduleapi-accounting.js';
import { moduleApiDisclosure, validChatReceipt, MODULEAPI_ESTIMATE_SOURCE, OPENAI_ESTIMATE_SOURCE, OPENROUTER_RECEIPT_SOURCE,
  PUBLIC_SCANNER_DATA, LEGACY_SCANNER_DATA } from '../provider-browser-contract.js';
import { moduleApiReadiness } from '../public-readiness.js';
import { QuotaLedger } from '../quota-ledger.js';

import { HistoryStore } from '../history-store.js';
import { validateStoredSummary } from '../summary-record.js';
import { createOpenAiRuntime } from '../provider-runtime.js';
import { OpenAiProvider } from '../openai-provider.js';
import { makeOpenAiPolicy, syntheticOpenAiKey } from './openai-core.fixture.js';
import { PUBLIC_IMAGE_PROFILE } from '../../oci/public-image-policy.js';
import { moduleApiBackendConfiguration as configuration, moduleApiBackendQuota as quota, moduleApiBackendKey as key,
  moduleApiBackendReport as report, moduleApiBackendHistory as history, moduleApiBackendResponse as response,
  moduleApiBackendDeferred as deferred } from './moduleapi-backend.fixture.js';

const error = (code: string) => (value: unknown) => value instanceof HttpException &&
  (value.getResponse() as { errorCode?: string }).errorCode === code;
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'moduleapi-backend-runtime-')), path = join(dir, 'llm-usage.sqlite');
  const ledger = new QuotaLedger(path, quota, Date.now, true), db = new Database(path, { readonly: true });
  return { dir, ledger, db, rows: () => db.prepare('SELECT * FROM quota_attempt ORDER BY rowid').all() as
    { id: string; state: string; input: number; output: number; cost: number; reserve_cost: number; quota_policy: string }[],
  close() { db.close(); ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
}
const binding = (runtime: NonNullable<ReturnType<LlmRuntime['resolve']>>, prepared: { hash: string }, subject = 'a'.repeat(32)) => ({
  subject, scanId: report.scanId, reportVersion: report.reportVersion, policyVersion: runtime.providerPolicyVersion, requestHash: prepared.hash,
});

// No fetch, listener, default transport, environment credential or live store access in this file.
test('ModuleAPI exact selection is additive, explicit, disabled/fail-closed and never falls back', () => {
  for (const [value, expected] of [[undefined, 'openrouter'], ['openrouter', 'openrouter'], ['openai', 'openai'],
    ['moduleapi', 'moduleapi'], ['ModuleAPI', null], ['', null], [' moduleapi', null]] as const)
    assert.equal(selectedProvider({ LLM_PROVIDER: value }), expected);
  let legacy = 0, direct = 0;
  const runtime = new LlmRuntime(true, { environment: () => ({ LLM_PROVIDER: 'moduleapi' }),
    moduleApiConfiguration: () => null, configuration: () => { direct++; assert.fail('must not inspect OpenAI'); } });
  runtime.policy = () => { legacy++; assert.fail('must not fall back'); };
  runtime.provider = () => assert.fail('must not construct fallback');
  assert.equal(runtime.resolve(), null);
  assert.equal(legacy, 0); assert.equal(direct, 0);
  const privateRuntime = new LlmRuntime(false, { environment: () => { assert.fail('private runtime selection unchanged'); } });
  privateRuntime.policy = () => null;
  assert.equal(privateRuntime.resolve(), null);
});

test('ModuleAPI disclosure and readiness truthfully preserve unknown tariff/privacy and lifetime cap', () => {
  const config = configuration();
  for (const publicReport of [false, true]) {
    const value = moduleApiDisclosure(config.policy, quota, publicReport);
    assert.deepEqual(value, { provider: 'ModuleAPI', model: MODULEAPI_MODEL, retention: 'unknown', operatorApprovedRouting: true,
      providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false, tariffVerified: false,
      costBasis: MODULEAPI_COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1000000, output: 2000000 },
      data: publicReport ? PUBLIC_SCANNER_DATA : LEGACY_SCANNER_DATA, lifetimeUserCostMicros: 5000000,
      monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null });
  }
  let credential = 0, transport = 0;
  const resolver = new ModuleApiRuntimeResolver({ environment: () => ({ LLM_PROVIDER: 'moduleapi' }),
    moduleApiConfiguration: () => config, quotaPolicy: () => quota, moduleApiCredentialReady: () => true,
    moduleApiCredential: () => { credential++; return key; }, moduleApiTransport: () => { transport++; assert.fail('readiness must not construct transport'); } });
  const value = moduleApiReadiness(resolver, true, true);
  assert.equal(value.localReady, true); assert.equal(value.generationVerified, false);
  assert.deepEqual(value.provider, { name: 'ModuleAPI', model: MODULEAPI_MODEL, status: 'configured-unprobed', liveVerified: false,
    retention: 'unknown', operatorApprovedRouting: true, zeroDataRetentionVerified: false, tariffVerified: false });
  assert.equal(value.costBasis, MODULEAPI_COST_BASIS); assert.deepEqual(value.blockers, []);
  assert.deepEqual({ credential, transport }, { credential: 0, transport: 0 });
  const missing = moduleApiReadiness(new ModuleApiRuntimeResolver({ moduleApiConfiguration: () => null,
    moduleApiCredentialReady: () => false }), false, false);
  assert.equal(missing.provider.name, 'ModuleAPI'); assert.equal(missing.provider.model, null); assert.equal(missing.localReady, false);
  assert.deepEqual(missing.blockers, ['configuration-required', 'environment-key-required', 'accounting-configuration-required',
    'quota-store-unavailable', 'history-store-unavailable']);
});

test('ModuleAPI paid receipts use only distinct estimate provenance; historical receipt meanings stay intact', () => {
  const receipt = { input: 20, output: 10, costMicros: 40, source: MODULEAPI_ESTIMATE_SOURCE };
  assert.equal(validChatReceipt(receipt), true);
  for (const source of [OPENAI_ESTIMATE_SOURCE, OPENROUTER_RECEIPT_SOURCE]) {
    assert.equal(validChatReceipt({ ...receipt, source, costMicros: source === OPENROUTER_RECEIPT_SOURCE ? 0 : 40 }), true);
  }
  for (const changed of [{ input: 0 }, { output: 4097 }, { costMicros: 0 }, { source: 'provider-invoice' },
    { extra: true }, { costMicros: Number.NaN }]) assert.equal(validChatReceipt({ ...receipt, ...changed }), false);
});

test('ModuleAPI runtime requires explicit matching accounting and monetary configuration', () => {
  const config = configuration();
  const noProvider = () => assert.fail('configuration must never construct provider');
  assert.ok(createModuleApiRuntime(config, quota, noProvider));
  assert.equal(createModuleApiRuntime({ ...config, accountingRevision: '' }, quota, noProvider), null);
  assert.equal(createModuleApiRuntime({ ...config, spending: { userBudgetMicros: 1, scanBudgetMicros: null } }, quota, noProvider), null);
  assert.equal(createModuleApiRuntime(config, { ...quota, version: 'f'.repeat(64) }, noProvider), null);
});

test('ModuleAPI resolver caches only four immutable snapshots without opening credentials or rebuilding old authority', () => {
  let current = configuration('first'), reads = 0;
  const resolver = new ModuleApiRuntimeResolver({ environment: () => ({ LLM_PROVIDER: 'moduleapi' }),
    moduleApiConfiguration: () => current, quotaPolicy: () => quota, moduleApiCredential: () => { reads++; return key; } });
  const first = resolver.inspect(); assert.ok(first.runtime);
  assert.equal(resolver.inspect(), first);
  for (const revision of ['second', 'third', 'fourth']) {
    current = configuration(revision); assert.ok(resolver.inspect().runtime);
  }
  current = configuration('fifth'); assert.equal(resolver.inspect().runtime, null);
  current = first.configuration!; assert.equal(resolver.inspect(), first); assert.equal(reads, 0);
  assert.equal(first.runtime.provider, 'ModuleAPI'); assert.equal(Object.isFrozen(first.runtime), true);
  const direct = makeOpenAiPolicy({ monetaryLimit: 'uncapped', requestBudgetMicros: null });
  const openai = createOpenAiRuntime({ policy: direct, maxConcurrent: 2, accountingRevision: 'moduleapi-backend-estimates-approved',
    spending: { userBudgetMicros: null, scanBudgetMicros: null } }, quota, noDirectProvider)!;
  function noDirectProvider(): OpenAiProvider { return assert.fail('metadata only'); }
  assert.notEqual(first.runtime.version, openai.version); assert.notEqual(first.runtime.chatVersion, openai.chatVersion);
});

test('ModuleAPI summary/chat immutable producer accounts before selection with its own billing/source and same lifetime', async () => {
  const f = fixture();
  try {
    const config = configuration(); let sends = 0;
    const runtime = createModuleApiRuntime(config, quota, () => new ModuleApiProvider(config.policy, key, {
      async sendGuarded(_endpoint, init, guard) {
        const row = f.rows().at(-1)!; assert.equal(row.state, 'reserved');
        const stored = JSON.parse(row.quota_policy).paidAccounting;
        assert.equal(stored.provider, 'ModuleAPI'); assert.equal(stored.billing, 'estimate-only-effective-tariff-not-verified');
        assert.equal(stored.costBasis, MODULEAPI_COST_BASIS);
        guard(() => { assert.equal(f.rows().at(-1)!.state, 'dispatched'); sends++; return undefined; });
        const body = JSON.parse(String(init.body)), payload = JSON.parse(body.messages[1].content);
        assert.equal(body.model, MODULEAPI_MODEL);
        return response(payload.report ? 'chat' : 'summary');
      },
    }))!;
    assert.ok(runtime);
    for (const operation of [runtime.prepareSummary(report), runtime.prepareChat(history)]) {
      const attempt = operation.reserveAttempt(f.ledger, binding(runtime, operation));
      let observed = false;
      const result = await attempt.generate(new AbortController().signal, send => send(), receipt => {
        assert.equal(f.rows().at(-1)!.state, 'settled');
        assert.deepEqual(receipt, { input: 20, output: 10, costMicros: 40, source: MODULEAPI_COST_BASIS }); observed = true;
      });
      assert.ok(result); assert.equal(observed, true); attempt.release();
    }
    assert.equal(sends, 2); assert.deepEqual(f.rows().map(row => row.state), ['settled', 'settled']);
    const usage = f.ledger.snapshot('a'.repeat(32), report.scanId);
    assert.equal(usage.lifetimeBudget?.limitMicros, 5000000);
  } finally { f.close(); }
});

test('ModuleAPI shared admission retains low active limits across rotations and provider switches before lazy key', async () => {
  const f = fixture(), barrier = deferred(), entered = deferred();
  try {
    let current = configuration('low', 1), reads = 0, sends = 0, selected = 'moduleapi';
    const pool = new PaidProviderAdmission();
    const options = { environment: () => ({ LLM_PROVIDER: selected }), moduleApiConfiguration: () => current, quotaPolicy: () => quota,
      moduleApiCredential: () => { reads++; return key; },
      moduleApiTransport: () => ({ async sendGuarded(_endpoint: string, _init: RequestInit, guard: (send: () => undefined) => void) {
        guard(() => { sends++; entered.resolve(); return undefined; }); await barrier.promise; return response();
      } }) };
    const resolver = new ModuleApiRuntimeResolver(options, pool), first = resolver.inspect().runtime!;
    const prepared = first.prepareSummary(report), attempt = prepared.reserveAttempt(f.ledger, binding(first, prepared));
    const pending = attempt.generate(new AbortController().signal, send => send(), () => {});
    await entered.promise; assert.equal(reads, 1); assert.equal(sends, 1);
    current = configuration('high', 8);
    const second = resolver.inspect().runtime!, next = second.prepareSummary(report);
    const refused = next.reserveAttempt(f.ledger, binding(second, next, 'b'.repeat(32)));
    await assert.rejects(refused.generate(new AbortController().signal, send => send(), () => {}), error('LLM_CAPACITY'));
    refused.release(); assert.equal(reads, 1); assert.equal(sends, 1);
    selected = 'openai';
    const direct = makeOpenAiPolicy({ monetaryLimit: 'uncapped', requestBudgetMicros: null });
    const openai = new OpenAiRuntimeResolver({ environment: options.environment, quotaPolicy: () => quota,
      configuration: () => ({ policy: direct, maxConcurrent: 8, accountingRevision: 'cross-provider-test', spending: { userBudgetMicros: null, scanBudgetMicros: null } }),
      credential: () => assert.fail('shared active pool must refuse before OpenAI key'),
      transport: () => assert.fail('shared active pool must refuse before transport') }, pool).inspect().runtime!;
    const other = openai.prepareSummary(report), cross = other.reserveAttempt(f.ledger, binding(openai, other, 'c'.repeat(32)));
    await assert.rejects(cross.generate(new AbortController().signal, send => send(), () => {}), error('LLM_CAPACITY')); cross.release();
    barrier.resolve(); await pending; attempt.release();
    assert.equal(f.rows()[0].state, 'settled', 'old bound receipt remains valid after provider selection changes');
  } finally { barrier.resolve(); f.close(); }
});

test('ModuleAPI rejected final fence or changed selection never reaches lazy credential/send', async () => {
  const f = fixture();
  try {
    let selected = 'moduleapi', reads = 0;
    const resolver = new ModuleApiRuntimeResolver({ environment: () => ({ LLM_PROVIDER: selected }),
      moduleApiConfiguration: () => configuration(), quotaPolicy: () => quota, moduleApiCredential: () => { reads++; return key; } });
    const runtime = resolver.inspect().runtime!, prepared = runtime.prepareSummary(report);
    const attempt = prepared.reserveAttempt(f.ledger, binding(runtime, prepared));
    selected = 'openai';
    await assert.rejects(attempt.generate(new AbortController().signal, send => send(), () => {}), error('LLM_CONFIGURATION_UNAVAILABLE'));
    attempt.release(); assert.equal(reads, 0); assert.equal(f.rows()[0].state, 'released');
    selected = 'moduleapi';
    const second = runtime.prepareSummary(report), denied = second.reserveAttempt(f.ledger, binding(runtime, second));
    await assert.rejects(denied.generate(new AbortController().signal, () => { throw new HttpException({ errorCode: 'LLM_STALE_POLICY' }, 409); }, () => {}),
      error('LLM_STALE_POLICY'));
    denied.release(); assert.equal(reads, 0); assert.equal(f.rows()[1].state, 'released');
  } finally { f.close(); }
});

test('ModuleAPI durable summaries require their own branded current policy and never relabel old records', async () => {
  const f = fixture(); const storePath = join(f.dir, 'llm-history.sqlite'), store = new HistoryStore(storePath, true);
  try {
    const config = configuration(), runtime = createModuleApiRuntime(config, quota,
      () => new ModuleApiProvider(config.policy, key, { async sendGuarded(_endpoint, _init, guard) {
        guard(() => undefined); return response();
      } }))!;
    const prepared = runtime.prepareSummary(report), attempt = prepared.reserveAttempt(f.ledger, binding(runtime, prepared));
    const value = await attempt.generate(new AbortController().signal, send => send(), () => {}); attempt.release();
    store.writeSummary('a'.repeat(32), report, runtime.summaryPolicy, value);
    const db = new Database(storePath, { readonly: true });
    try {
      const before = db.prepare('SELECT * FROM llm_summary').all();
      const directPolicy = makeOpenAiPolicy({ monetaryLimit: 'uncapped', requestBudgetMicros: null });
      const openai = createOpenAiRuntime({ policy: directPolicy, maxConcurrent: 2, accountingRevision: 'historical',
        spending: { userBudgetMicros: null, scanBudgetMicros: null } }, quota, () => new OpenAiProvider(directPolicy, syntheticOpenAiKey,
        { async sendGuarded() { assert.fail('stored GET never generates'); } }))!;
      assert.equal(store.readSummary('a'.repeat(32), report, openai.summaryPolicy), undefined);
      assert.equal(store.readSummary('b'.repeat(32), report, runtime.summaryPolicy), undefined);
      assert.equal(store.readSummary('a'.repeat(32), { ...report, reportVersion: 'd'.repeat(64) }, runtime.summaryPolicy), undefined);
      assert.deepEqual(store.readSummary('a'.repeat(32), report, runtime.summaryPolicy), value);
      if (!('provider' in runtime.summaryPolicy) || runtime.summaryPolicy.provider !== 'ModuleAPI') assert.fail('exact paid policy');
      const unbranded = { ...runtime.summaryPolicy, policy: { ...config.policy } };
      assert.throws(() => validateStoredSummary(value, report, unbranded), error('LLM_HISTORY_UNAVAILABLE'));
      assert.deepEqual(db.prepare('SELECT * FROM llm_summary').all(), before);
    } finally { db.close(); }
    const publicReport = { ...report, profile: PUBLIC_IMAGE_PROFILE } as const;
    assert.equal(runtime.disclosure(publicReport).provider, 'ModuleAPI');
  } finally { store.close(); f.close(); }
});
