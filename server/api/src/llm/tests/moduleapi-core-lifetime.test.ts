import assert from 'node:assert/strict';
import test from 'node:test';
import { fork } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { createModuleApiPolicy, checkedModuleApiPolicy, MODULEAPI_MODEL } from '../moduleapi-policy.js';
import { createModuleApiAccountingPolicy, createModuleApiQuotaContext, MODULEAPI_BILLING, MODULEAPI_COST_BASIS } from '../moduleapi-accounting.js';
import { prepareModuleApiSummary } from '../moduleapi-prepared-request.js';
import { observeModuleApiUsage } from '../moduleapi-usage.js';
import { createOpenAiPolicy, checkedOpenAiPolicy } from '../openai-policy.js';
import { createOpenAiAccountingPolicy, createOpenAiQuotaContext, OPENAI_COST_BASIS } from '../openai-accounting.js';
import { prepareOpenAiSummary } from '../openai-prepared-request.js';
import { observeOpenAiUsage } from '../openai-usage.js';
import { QuotaLedger } from '../quota-ledger.js';
import { DAY, quotaPolicyFromEnvironment } from '../quota-policy.js';
import { openAiPrompts, openAiReport, openAiSettings } from './openai-core.fixture.js';
import { quotaEnv } from './quota-fixtures.js';

const NOW = 40 * DAY;
const quota = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_MONETARY_LIMIT: 'uncapped',
  LLM_QUOTA_USER_COST_USD: undefined, LLM_QUOTA_SCAN_COST_USD: undefined, LLM_QUOTA_OBSERVATION_COST_USD: undefined,
  LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000', LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000',
  LLM_QUOTA_USER_INPUT: '1', LLM_QUOTA_USER_OUTPUT: '1', LLM_QUOTA_SCAN_INPUT: '1', LLM_QUOTA_SCAN_OUTPUT: '1' })!;
const settings = { ...openAiSettings, monetaryLimit: 'uncapped', requestBudgetMicros: null,
  inputPriceMicrosPerMillion: 1, outputPriceMicrosPerMillion: 999_999_000, outputTokens: 1000 };
const moduleProvider = createModuleApiPolicy({ ...settings, model: MODULEAPI_MODEL, retention: 'unknown' }, openAiPrompts)!;
const oldProvider = createOpenAiPolicy(settings, openAiPrompts)!;
const approvalConfig = { enabled: true, revision: 'moduleapi-cross-provider-test', monetaryLimit: 'uncapped', quotaPolicyVersion: quota.version };
const moduleConfig = { ...approvalConfig, providerPolicyVersion: moduleProvider.version, billing: MODULEAPI_BILLING, costBasis: MODULEAPI_COST_BASIS };
const moduleApproval = createModuleApiAccountingPolicy(moduleConfig, moduleProvider, quota)!;
const oldApproval = createOpenAiAccountingPolicy({ ...approvalConfig, providerPolicyVersion: oldProvider.version,
  billing: 'text-tokens-only-no-additional-fees', costBasis: OPENAI_COST_BASIS }, oldProvider, quota)!;
const moduleRequest = prepareModuleApiSummary(openAiReport, moduleProvider);
const oldRequest = prepareOpenAiSummary(openAiReport, oldProvider);
const binding = (policyVersion: string, requestHash: string, scanId = 'scan', subject = 'shared-owner') =>
  ({ subject, scanId, reportVersion: openAiReport.reportVersion, policyVersion, requestHash });
const moduleContext = (scan = 'new-scan', owner = 'shared-owner') => createModuleApiQuotaContext(
  binding(moduleProvider.version, moduleRequest.hash, scan, owner), moduleRequest, moduleProvider, moduleApproval);
const oldContext = (scan = 'old-scan') => createOpenAiQuotaContext(
  binding(oldProvider.version, oldRequest.hash, scan), oldRequest, oldProvider, oldApproval);
const moduleUsage = (context = moduleContext(), input = context.reserve.input, output = context.reserve.output) =>
  observeModuleApiUsage({ prompt_tokens: input, completion_tokens: output, total_tokens: input + output }, context.reserve, moduleProvider);
const oldUsage = (context = oldContext()) => observeOpenAiUsage({ prompt_tokens: context.reserve.input,
  completion_tokens: context.reserve.output, total_tokens: context.reserve.input + context.reserve.output }, context.reserve, oldProvider);

function storage() {
  const dir = mkdtempSync(join(tmpdir(), 'moduleapi-core-lifetime-')), path = join(dir, 'llm-usage.sqlite');
  let now = NOW, ledger = new QuotaLedger(path, quota, () => now, true);
  return { path, get ledger() { return ledger; }, time(value: number) { now = value; },
    reopen() { ledger.close(); ledger = new QuotaLedger(path, quota, () => now); },
    inspect<T>(action: (db: Database.Database) => T) { const db = new Database(path); try { return action(db); } finally { db.close(); } },
    close() { ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function settleOld(ledger: QuotaLedger) {
  const context = oldContext(), id = ledger.reserveOpenAi(context);
  assert.equal(ledger.dispatchOpenAi(id, context), true);
  assert.equal(ledger.observeOpenAi(id, context, oldUsage(context)), true);
  return id;
}

if (process.argv[2] !== '--moduleapi-core-racer') {
test('ModuleAPI billing is an explicit estimate-only approval, never inherited OpenAI rates/brands/invoice semantics', () => {
  assert.ok(moduleProvider); assert.ok(oldProvider); assert.ok(moduleApproval); assert.ok(oldApproval);
  assert.equal(moduleApproval.billing, 'estimate-only-effective-tariff-not-verified');
  assert.equal(moduleApproval.costBasis, 'moduleapi-server-estimated-configured-rates-not-invoice');
  assert.notEqual(moduleProvider.version, oldProvider.version);
  for (const patch of [{ billing: 'text-tokens-only-no-additional-fees' }, { billing: undefined },
    { costBasis: OPENAI_COST_BASIS }, { revision: undefined }, { monetaryLimit: undefined }, { enabled: false }])
    assert.equal(createModuleApiAccountingPolicy({ ...moduleConfig, ...patch }, moduleProvider, quota), null);
  // Only adversarial tests cast foreign objects: production never converts provider brands.
  assert.throws(() => checkedModuleApiPolicy(oldProvider as unknown as typeof moduleProvider));
  assert.throws(() => checkedOpenAiPolicy(moduleProvider as unknown as typeof oldProvider));
  assert.equal(createModuleApiAccountingPolicy(moduleConfig, oldProvider as unknown as typeof moduleProvider, quota), null);
  assert.throws(() => createModuleApiQuotaContext(moduleContext().binding, oldRequest, moduleProvider, moduleApproval));
});

test('old OpenAI settled/reserved/UNKNOWN and ModuleAPI spend share exactly $5 for all time; old metadata survives rollover/reopen/cleanup', () => {
  const f = storage(), old = oldContext(), current = moduleContext();
  try {
    assert.equal(current.reserve.costMicros, 1_000_000);
    const settled = settleOld(f.ledger);
    const reserved = f.ledger.reserveOpenAi(old), unknown = f.ledger.reserveOpenAi(old);
    assert.equal(f.ledger.dispatchOpenAi(unknown, old), true);
    assert.equal(f.ledger.observeOpenAi(unknown, old, observeOpenAiUsage(undefined, old.reserve, oldProvider)), false);
    const original = f.inspect(db => db.prepare('SELECT * FROM quota_attempt ORDER BY id').all());
    const metadata = f.inspect(db => db.prepare('SELECT quota_policy FROM quota_attempt WHERE id=?').get(settled)) as { quota_policy: string };
    assert.equal(JSON.parse(metadata.quota_policy).paidAccounting.provider, 'OpenAI');
    assert.equal(JSON.parse(metadata.quota_policy).paidAccounting.billing, 'text-tokens-only-no-additional-fees');
    f.time(NOW + 30 * DAY); f.reopen();
    assert.deepEqual(f.ledger.snapshotModuleApi(current).lifetimeBudget,
      { limitMicros: 5_000_000, usedMicros: 1_000_000, heldMicros: 2_000_000, remainingMicros: 2_000_000 });
    const id = f.ledger.reserveModuleApi(current);
    assert.equal(f.ledger.dispatchModuleApi(id, current), true);
    assert.equal(f.ledger.observeModuleApi(id, current, moduleUsage(current)), true);
    assert.equal(f.ledger.observeModuleApi(id, current, moduleUsage(current)), true);
    const final = f.ledger.reserveModuleApi(current);
    assert.deepEqual(f.ledger.snapshotModuleApi(current).lifetimeBudget,
      { limitMicros: 5_000_000, usedMicros: 2_000_000, heldMicros: 3_000_000, remainingMicros: 0 });
    assert.throws(() => f.ledger.reserveOpenAi(old));
    assert.throws(() => f.ledger.reserveModuleApi(current));
    assert.equal(f.ledger.snapshotModuleApi(moduleContext('other-scan')).lifetimeBudget?.remainingMicros, 0);
    assert.equal(f.ledger.snapshotModuleApi(moduleContext('other-scan', 'other-owner')).lifetimeBudget?.remainingMicros, 5_000_000);
    for (const row of original as { id: string }[]) assert.deepEqual(f.inspect(db => db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(row.id)), row);
    assert.equal(f.ledger.releaseModuleApi(unknown, current), false);
    assert.equal(f.ledger.releaseModuleApi(reserved, current), false);
    assert.equal(f.ledger.release(final), false);
    assert.throws(() => f.ledger.dispatchModuleApi(unknown, old as unknown as typeof current));
  } finally { f.close(); }
});

test('ModuleAPI rejected usage overage is a durable cross-provider fault; unknown and late receipts never refund liability', () => {
  const f = storage(), context = moduleContext();
  try {
    const id = f.ledger.reserveModuleApi(context);
    assert.equal(f.ledger.dispatchModuleApi(id, context), true);
    const usage = moduleUsage(context, context.reserve.input, 1001);
    assert.equal(usage.normal, false);
    assert.equal(f.ledger.observeModuleApi(id, context, usage), false);
    f.time(NOW + 30 * DAY); f.reopen();
    assert.equal(f.ledger.snapshotModuleApi(context).reason, 'policy_fault');
    assert.equal(f.ledger.snapshotOpenAi(oldContext()).reason, 'policy_fault');
    assert.equal(f.ledger.snapshotOpenAi(oldContext()).lifetimeBudget?.heldMicros, usage.costMicros);
    assert.equal(f.ledger.observeModuleApi(id, context, moduleUsage(context)), false);
    assert.equal(f.ledger.releaseModuleApi(id, context), false);
    assert.throws(() => f.ledger.reserveOpenAi(oldContext()));
  } finally { f.close(); }
});

test('new paid entrypoints reject foreign contexts/usage; no structural cloning or old free entrypoint bypass', () => {
  const f = storage(), current = moduleContext(), old = oldContext();
  try {
    assert.throws(() => f.ledger.reserveModuleApi(old as unknown as typeof current));
    assert.throws(() => f.ledger.reserveOpenAi(current as unknown as typeof old));
    assert.throws(() => f.ledger.reserveModuleApi({ ...current }));
    const id = f.ledger.reserveModuleApi(current);
    assert.equal(f.ledger.dispatch(id), false); assert.equal(f.ledger.release(id), false);
    assert.equal(f.ledger.observe(id, { normal: true, input: 1, output: 0, costMicros: 0 }), false);
    assert.equal(f.ledger.dispatchOpenAi(id, old), false);
    assert.equal(f.ledger.releaseOpenAi(id, old), false);
    assert.equal(f.ledger.dispatchModuleApi(id, current), true);
    assert.throws(() => f.ledger.observeModuleApi(id, current, oldUsage() as unknown as ReturnType<typeof moduleUsage>));
    assert.equal(f.ledger.observeOpenAi(id, old, oldUsage()), false);
    assert.equal(f.ledger.observeModuleApi(id, current, moduleUsage()), true);
  } finally { f.close(); }
});

}

// The two children race through independent native SQLite connections, not a mocked admission counter.
if (process.argv[2] === '--moduleapi-core-racer') {
  const ledger = new QuotaLedger(process.argv[3], quota, () => NOW);
  process.send?.({ ready: true });
  process.once('message', () => {
    let admitted = false;
    try {
      if (process.argv[4] === 'moduleapi') ledger.reserveModuleApi(moduleContext());
      else ledger.reserveOpenAi(oldContext());
      admitted = true;
    } catch { /* Only the finite admission result crosses IPC. */ }
    finally { ledger.close(); process.send?.({ admitted }); process.disconnect(); }
  });
} else {
  test('independent OpenAI/ModuleAPI processes serialize the last $1 at the shared $5 lifetime boundary', { timeout: 20_000 }, async () => {
    const f = storage();
    const children: ReturnType<typeof fork>[] = [], readyChildren = new Set<ReturnType<typeof fork>>();
    try {
      for (let i = 0; i < 4; i++) settleOld(f.ledger);
      const results = ['moduleapi', 'openai'].map(kind => new Promise<boolean>((resolve, reject) => {
        const child = fork(fileURLToPath(import.meta.url), ['--moduleapi-core-racer', f.path, kind],
          { execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'ignore', 'ipc'], env: {} });
        children.push(child);
        let ready = false, finished = false;
        child.on('error', reject);
        child.on('message', (value: { ready?: boolean; admitted?: boolean }) => {
          if (value.ready) {
            ready = true;
            readyChildren.add(child);
            if (readyChildren.size === 2) for (const peer of children) peer.send('go');
          } else if (ready && typeof value.admitted === 'boolean') { finished = true; resolve(value.admitted); }
        });
        child.on('exit', code => { if (!finished) reject(new Error(`Synthetic racer exited without result: ${code}`)); });
      }));
      const admitted = await Promise.all(results);
      assert.equal(admitted.filter(Boolean).length, 1);
      assert.deepEqual(f.ledger.snapshotModuleApi(moduleContext()).lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 4_000_000, heldMicros: 1_000_000, remainingMicros: 0 });
    } finally { for (const child of children) if (child.connected) child.kill(); f.close(); }
  });
}
