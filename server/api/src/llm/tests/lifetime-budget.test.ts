import assert from 'node:assert/strict';
import test from 'node:test';
import { fork } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createOpenAiPolicy } from '../openai-policy.js';
import { checkedOpenAiQuotaContext, createOpenAiAccountingPolicy, createOpenAiQuotaContext, OPENAI_COST_BASIS } from '../openai-accounting.js';
import { prepareOpenAiSummary } from '../openai-prepared-request.js';
import { observeOpenAiUsage, openAiReserve } from '../openai-usage.js';
import { QuotaLedger } from '../quota-ledger.js';
import { checkedQuotaMonetaryPolicy, DAY, quotaDenial, quotaPolicyFromEnvironment, usdMicros, type QuotaPolicy } from '../quota-policy.js';
import { openAiPrompts, openAiReport, openAiSettings } from './openai-core.fixture.js';
import { quotaEnv } from './quota-fixtures.js';

const NOW = Date.UTC(2026, 10, 7, 12);
const environment = { ...quotaEnv, LLM_QUOTA_MONETARY_LIMIT: 'uncapped', LLM_QUOTA_USER_COST_USD: undefined,
  LLM_QUOTA_SCAN_COST_USD: undefined, LLM_QUOTA_OBSERVATION_COST_USD: undefined,
  LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000', LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000',
  LLM_QUOTA_USER_INPUT: '1', LLM_QUOTA_USER_OUTPUT: '1', LLM_QUOTA_SCAN_INPUT: '1', LLM_QUOTA_SCAN_OUTPUT: '1' };

function contract(env: NodeJS.ProcessEnv = {}, subject = 'owner', scanId = 'scan-a') {
  // Synthetic integer prices make every full 1000-output reserve exactly $1:
  // 999999 micros for output plus a positive sub-micro input, rounded up once.
  const provider = createOpenAiPolicy({ ...openAiSettings, monetaryLimit: 'uncapped', requestBudgetMicros: null,
    inputPriceMicrosPerMillion: 1, outputPriceMicrosPerMillion: 999_999_000, outputTokens: 1000 }, openAiPrompts)!;
  const quota = quotaPolicyFromEnvironment({ ...environment, ...env })!;
  assert.ok(provider); assert.ok(quota);
  const config = { enabled: true, revision: 'lifetime-offline-test', monetaryLimit: 'uncapped',
    providerPolicyVersion: provider.version, quotaPolicyVersion: quota.version,
    billing: 'text-tokens-only-no-additional-fees', costBasis: OPENAI_COST_BASIS };
  const approval = createOpenAiAccountingPolicy(config, provider, quota);
  assert.ok(approval);
  const request = prepareOpenAiSummary(openAiReport, provider);
  const binding = { subject, scanId, reportVersion: openAiReport.reportVersion,
    policyVersion: provider.version, requestHash: request.hash };
  const context = createOpenAiQuotaContext(binding, request, provider, approval);
  assert.equal(context.reserve.costMicros, 1_000_000);
  return { provider, quota, config, approval, request, binding, context };
}
function storage(policy: QuotaPolicy, initialTime = NOW) {
  const dir = mkdtempSync(join(tmpdir(), 'lifetime-budget-')), path = join(dir, 'llm-usage.sqlite');
  let now = initialTime, ledger = new QuotaLedger(path, policy, () => now, true);
  return { path, get ledger() { return ledger; }, time(value: number) { now = value; },
    reopen(next: QuotaPolicy = policy) { ledger.close(); ledger = new QuotaLedger(path, next, () => now); },
    inspect<T>(action: (db: Database.Database) => T): T {
      const db = new Database(path);
      try { return action(db); } finally { db.close(); }
    },
    close() { ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function usage(c: ReturnType<typeof contract>, output = c.context.reserve.output) {
  return observeOpenAiUsage({ prompt_tokens: c.context.reserve.input, completion_tokens: output,
    total_tokens: c.context.reserve.input + output }, c.context.reserve, c.provider);
}
function settle(ledger: QuotaLedger, c: ReturnType<typeof contract>) {
  const id = ledger.reserveOpenAi(c.context);
  assert.equal(ledger.dispatchOpenAi(id, c.context), true);
  assert.equal(ledger.observeOpenAi(id, c.context, usage(c)), true);
  return id;
}
function historical(db: Database.Database, state: string, cost: number, owner = 'owner', window = NOW - 30 * DAY) {
  const hash = (value: string) => createHash('sha256').update(value).digest('hex');
  db.prepare(`INSERT INTO quota_attempt VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`).run(
    randomUUID(), hash(owner), hash(JSON.stringify([owner, `old-${state}`])), 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64),
    JSON.stringify({ revision: 'old-policy-without-lifetime', user: { costMicros: 1_000_000 } }),
    Math.floor(window / DAY) * DAY, window + 1000, state, 10, 10, cost, 10, 10, cost);
}

type RaceResult = { id?: string; denial?: ReturnType<typeof quotaDenial> };
async function race(path: string) {
  const children = ['scan-race-a', 'scan-race-b'].map(scan => fork(new URL(import.meta.url),
    ['--lifetime-race-child', path, scan], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
  const deadline = setTimeout(() => children.forEach(child => child.kill()), 10000);
  try {
    await Promise.all(children.map(child => new Promise<void>((resolve, reject) => {
      child.once('message', message => {
        try {
          assert.deepEqual(message, { ready: true, status: 'fits', remainingMicros: 1_000_000 }); resolve();
        } catch (error) { reject(error); }
      });
      child.once('error', reject);
      child.once('exit', code => reject(new Error(`lifetime race child exited before readiness: ${code}`)));
    })));
    return await Promise.all(children.map(child => new Promise<RaceResult>((resolve, reject) => {
      child.once('message', value => resolve(value as RaceResult));
      child.once('error', reject);
      child.once('exit', code => reject(new Error(`lifetime race child exited without result: ${code}`)));
      child.send('reserve');
    })));
  } finally {
    clearTimeout(deadline);
    children.forEach(child => { if (child.connected) child.disconnect(); child.kill(); });
  }
}

if (process.argv[2] === '--lifetime-race-child') {
  const c = contract({}, 'owner', process.argv[4]);
  const ledger = new QuotaLedger(process.argv[3], c.quota, () => NOW);
  const view = ledger.snapshotOpenAi(c.context);
  process.send?.({ ready: true, status: view.admission.status, remainingMicros: view.lifetimeBudget!.remainingMicros });
  process.once('message', () => {
    try { process.send?.({ id: ledger.reserveOpenAi(c.context) }); }
    catch (error) { process.send?.({ denial: quotaDenial(error) }); }
    finally { ledger.close(); process.disconnect(); }
  });
} else {
  test('lifetime micros are optional exact integers, uncapped-only, frozen and covered by quota/approval hashes', () => {
    const c = contract();
    assert.equal(c.quota.lifetimeUserCostMicros, 5_000_000);
    checkedQuotaMonetaryPolicy(c.quota);
    const absent = quotaPolicyFromEnvironment({ ...environment, LLM_QUOTA_LIFETIME_USER_COST_MICROS: undefined })!;
    assert.ok(absent); assert.equal(Object.hasOwn(absent, 'lifetimeUserCostMicros'), false);
    const { lifetimeUserCostMicros: _lifetime, version: _version, ...withoutLifetime } = c.quota;
    assert.equal(absent.version, createHash('sha256').update(JSON.stringify(withoutLifetime)).digest('hex'));
    assert.notEqual(c.quota.version, absent.version);
    assert.notEqual(contract({ LLM_QUOTA_LIFETIME_USER_COST_MICROS: '4999999' }).approval.version, c.approval.version);
    assert.ok(Object.isFrozen(c.quota)); assert.ok(Object.isFrozen(checkedOpenAiQuotaContext(c.context).quota));
    assert.equal(checkedOpenAiQuotaContext(c.context).quota.lifetimeUserCostMicros, 5_000_000);
    assert.throws(() => { (c.quota as { lifetimeUserCostMicros?: number }).lifetimeUserCostMicros = 1; });
    assert.equal(createOpenAiAccountingPolicy(c.config, c.provider, { ...c.quota, lifetimeUserCostMicros: 1 }), null);
    for (const value of ['1', '1000000000']) assert.equal(
      quotaPolicyFromEnvironment({ ...environment, LLM_QUOTA_LIFETIME_USER_COST_MICROS: value })?.lifetimeUserCostMicros, Number(value));
    for (const value of ['', '0', '-1', '1.5', '5.000000', '05', '5e6', ' 5000000', '5000000 ', 'NaN', 'Infinity', '1000000001'])
      assert.equal(quotaPolicyFromEnvironment({ ...environment, LLM_QUOTA_LIFETIME_USER_COST_MICROS: value }), null, value);
    for (const value of [0, -1, 0.5, NaN, Infinity, 1_000_000_001, null, '5000000'])
      assert.throws(() => checkedQuotaMonetaryPolicy({ ...c.quota, lifetimeUserCostMicros: value } as QuotaPolicy));
    for (const mode of [undefined, 'capped']) {
      const cappedEnv = { ...quotaEnv, LLM_QUOTA_MONETARY_LIMIT: mode, LLM_QUOTA_USER_COST_USD: '1', LLM_QUOTA_SCAN_COST_USD: '1' };
      assert.equal(quotaPolicyFromEnvironment({ ...cappedEnv, LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000' }), null);
      const capped = quotaPolicyFromEnvironment(cappedEnv)!;
      assert.ok(capped); assert.throws(() => checkedQuotaMonetaryPolicy({ ...capped, lifetimeUserCostMicros: 5_000_000 }));
      assert.equal(quotaPolicyFromEnvironment({ ...cappedEnv, LLM_QUOTA_USER_COST_USD: '5' }), null);
      assert.equal(quotaPolicyFromEnvironment({ ...cappedEnv, LLM_QUOTA_SCAN_COST_USD: '5' }), null);
    }
    assert.equal(usdMicros(5), undefined);
    assert.equal(createOpenAiPolicy({ ...openAiSettings, requestBudgetMicros: 5_000_000 }, openAiPrompts), null);
    assert.throws(() => openAiReserve(c.provider.inputTokens + 1, c.provider));
    assert.equal(createOpenAiPolicy({ ...openAiSettings, outputTokens: 4097 }, openAiPrompts), null);
  });

  test('daily tokens are counters only with lifetime enabled; warnings, exhaustion and one cost shortage track exactly $5', () => {
    const c = contract(), f = storage(c.quota);
    try {
      const empty = f.ledger.snapshotOpenAi(c.context);
      assert.equal(empty.admission.status, 'fits'); assert.equal(empty.reason, 'ready');
      assert.deepEqual(empty.lifetimeBudget, { limitMicros: 5_000_000, usedMicros: 0, heldMicros: 0, remainingMicros: 5_000_000 });
      assert.deepEqual(empty.window, { start: Math.floor(NOW / DAY) * DAY, end: (Math.floor(NOW / DAY) + 1) * DAY });
      for (let i = 1; i <= 5; i++) {
        f.ledger.reserveOpenAi(c.context);
        const view = f.ledger.snapshotOpenAi(c.context);
        for (const scope of [view.user, view.scan]) {
          assert.equal(scope.remaining.input, 0); assert.equal(scope.remaining.output, 0);
          assert.equal(scope.held.output, i * 1000); assert.equal(scope.limits.input, 1);
          assert.equal(scope.limits.costMicros, null); assert.equal(scope.remaining.costMicros, null);
          assert.equal(scope.exhausted, i === 5); assert.equal(scope.warning, i >= 4);
        }
        assert.equal(view.reason, i === 5 ? 'exhausted' : i === 4 ? 'warning' : 'ready');
        assert.deepEqual(view.signals, i < 4 ? [] : [{ scope: 'user', dimension: 'costMicros', reason: i === 5 ? 'exhausted' : 'warning' }]);
        assert.equal(view.admission.status, i === 5 ? 'insufficient' : 'fits');
      }
      const view = f.ledger.snapshotOpenAi(c.context);
      assert.deepEqual(JSON.parse(JSON.stringify(view)).lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 0, heldMicros: 5_000_000, remainingMicros: 0 });
      assert.throws(() => f.ledger.reserveOpenAi(c.context), error => {
        assert.deepEqual(quotaDenial(error), { status: 'insufficient', reserve: c.context.reserve,
          signals: [{ scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 1_000_000, remaining: 0 }] });
        return true;
      });
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context), view);
      const other = contract({}, 'another-owner', c.binding.scanId);
      assert.equal(f.ledger.snapshotOpenAi(other.context).lifetimeBudget!.remainingMicros, 5_000_000);
      assert.ok(f.ledger.reserveOpenAi(other.context));
      f.reopen(quotaPolicyFromEnvironment({ ...environment, LLM_QUOTA_LIFETIME_USER_COST_MICROS: undefined })!);
      const disabled = f.ledger.snapshot(c.binding.subject, c.binding.scanId);
      assert.equal(Object.hasOwn(disabled, 'lifetimeBudget'), false);
      assert.equal(disabled.scan.exhausted, true);
      assert.ok(disabled.signals.some(s => s.dimension === 'output'));
    } finally { f.close(); }
  });

  test('all old policies/windows/scans count retained settlements, expired reservations, unknown dispatches and faults by owner', () => {
    const c = contract(), f = storage(c.quota);
    try {
      f.inspect(db => {
        historical(db, 'settled', 1_000_000);
        historical(db, 'settled', 500_000, 'owner', NOW - DAY);
        historical(db, 'reserved', 200_000);
        historical(db, 'dispatched', 300_000);
        historical(db, 'released', 0);
        historical(db, 'settled', 5_000_000, 'another-owner');
        historical(db, 'dispatched', 5_000_000, 'another-owner');
      });
      const expected = { limitMicros: 5_000_000, usedMicros: 1_500_000, heldMicros: 500_000, remainingMicros: 3_000_000 };
      let view = f.ledger.snapshotOpenAi(c.context);
      assert.deepEqual(view.lifetimeBudget, expected); assert.equal(view.admission.status, 'fits');
      assert.equal(view.user.used.costMicros, 0); assert.equal(view.user.carried.costMicros, 500_000);
      assert.equal(view.scan.carried.costMicros, 0); assert.equal(view.reason, 'ready');
      f.time(NOW + 40 * DAY); f.reopen();
      view = f.ledger.snapshotOpenAi(c.context);
      assert.deepEqual(view.lifetimeBudget, expected);
      const id = f.ledger.reserveOpenAi(c.context); assert.equal(f.ledger.releaseOpenAi(id, c.context), true);
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context).lifetimeBudget, expected);
      f.inspect(db => historical(db, 'fault', 600_000)); f.reopen();
      view = f.ledger.snapshotOpenAi(c.context);
      assert.deepEqual(view.lifetimeBudget, { ...expected, heldMicros: 1_100_000, remainingMicros: 2_400_000 });
      assert.equal(view.reason, 'policy_fault'); assert.equal(view.admission.status, 'policy_fault');
      assert.equal(view.user.exhausted, false); assert.equal(view.scan.exhausted, false);
      assert.deepEqual(view.signals, [{ scope: 'user', dimension: 'all', reason: 'policy_fault' }]);
      assert.throws(() => f.ledger.reserveOpenAi(c.context));
    } finally { f.close(); }
  });

  test('positive lifetime remaining below full reserve has one authoritative user/cost signal, without partial debit', () => {
    const c = contract(), f = storage(c.quota);
    try {
      f.inspect(db => historical(db, 'settled', 4_500_000));
      const view = f.ledger.snapshotOpenAi(c.context);
      assert.equal(view.reason, 'warning'); assert.equal(view.user.exhausted, false); assert.equal(view.scan.exhausted, false);
      assert.deepEqual(view.admission, { status: 'insufficient', reserve: c.context.reserve,
        signals: [{ scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 1_000_000, remaining: 500_000 }] });
      assert.throws(() => f.ledger.reserveOpenAi(c.context), error => {
        assert.deepEqual(quotaDenial(error), view.admission); return true;
      });
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context), view);
    } finally { f.close(); }
  });

  test('cross-midnight late receipt uses original policy, moves hold to spend once and remains replayable after retention horizon', () => {
    const c = contract(), f = storage(c.quota, DAY - 1000);
    try {
      const id = f.ledger.reserveOpenAi(c.context);
      assert.equal(f.ledger.dispatchOpenAi(id, c.context), true);
      assert.equal(f.ledger.observeOpenAi(id, c.context, observeOpenAiUsage(undefined, c.context.reserve, c.provider)), false);
      f.time(DAY + 1000); f.reopen(contract({ LLM_QUOTA_REVISION: 'rotated-lifetime' }).quota);
      assert.deepEqual(f.ledger.snapshot('owner', 'scan-a').lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 0, heldMicros: 1_000_000, remainingMicros: 4_000_000 });
      const receipt = usage(c, 500); assert.equal(receipt.costMicros, 500_000);
      assert.equal(f.ledger.observeOpenAi(id, c.context, receipt), true);
      assert.equal(f.ledger.observeOpenAi(id, c.context, receipt), true);
      assert.equal(f.ledger.observeOpenAi(id, c.context, usage(c, 501)), false);
      const view = f.ledger.snapshot('owner', 'scan-a');
      assert.deepEqual(view.lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 500_000, heldMicros: 0, remainingMicros: 4_500_000 });
      assert.equal(view.user.used.costMicros, 0); assert.equal(view.user.carried.costMicros, 0);
      f.time(20 * DAY); f.reopen();
      const next = f.ledger.reserveOpenAi(c.context); assert.equal(f.ledger.releaseOpenAi(next, c.context), true);
      assert.equal(f.ledger.observeOpenAi(id, c.context, receipt), true);
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context).lifetimeBudget, view.lifetimeBudget);
      const expired = f.ledger.reserveOpenAi(c.context); assert.equal(f.ledger.dispatchOpenAi(expired, c.context), true);
      f.time(20 * DAY + c.quota.receiptMs + 1);
      assert.equal(f.ledger.observeOpenAi(expired, c.context, receipt), false);
      assert.equal(f.ledger.snapshotOpenAi(c.context).lifetimeBudget!.heldMicros, 1_000_000);
    } finally { f.close(); }
  });

  test('cleanup never deletes settled spend or zero settlements while disabled; enable/disable/re-enable cannot erase history', () => {
    const c = contract(), disabled = contract({ LLM_QUOTA_LIFETIME_USER_COST_MICROS: undefined,
      LLM_QUOTA_USER_INPUT: '1000000', LLM_QUOTA_SCAN_INPUT: '1000000', LLM_QUOTA_USER_OUTPUT: '1000000', LLM_QUOTA_SCAN_OUTPUT: '1000000' });
    const f = storage(disabled.quota);
    try {
      const beforeEnable = settle(f.ledger, disabled);
      f.reopen(c.quota);
      assert.equal(f.ledger.snapshotOpenAi(c.context).lifetimeBudget!.usedMicros, 1_000_000);
      const enabled = settle(f.ledger, c);
      f.reopen(disabled.quota);
      const whileDisabled = settle(f.ledger, disabled);
      f.reopen(quotaPolicyFromEnvironment(quotaEnv)!);
      const free = f.ledger.reserve(c.binding, { input: 10, output: 10, costMicros: 0 });
      assert.equal(f.ledger.dispatch(free), true);
      assert.equal(f.ledger.observe(free, { normal: true, input: 1, output: 1, costMicros: 0 }), true);
      const released = f.ledger.reserve(c.binding, { input: 10, output: 10, costMicros: 0 });
      assert.equal(f.ledger.release(released), true);
      f.time(NOW + 20 * DAY);
      const cleanup = f.ledger.reserve(c.binding, { input: 10, output: 10, costMicros: 0 }); f.ledger.release(cleanup);
      f.inspect(db => {
        assert.deepEqual((db.prepare("SELECT id FROM quota_attempt WHERE state='settled'").all() as { id: string }[])
          .map(row => row.id).sort(), [beforeEnable, enabled, whileDisabled, free].sort());
        assert.equal(db.prepare('SELECT id FROM quota_attempt WHERE id=?').get(released), undefined);
        assert.equal(db.pragma('user_version', { simple: true }), 1);
      });
      f.reopen(c.quota);
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context).lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 3_000_000, heldMicros: 0, remainingMicros: 2_000_000 });
      assert.equal(f.ledger.observeOpenAi(beforeEnable, disabled.context, usage(disabled)), true);
      f.reopen(c.quota);
      assert.equal(f.ledger.snapshotOpenAi(c.context).lifetimeBudget!.usedMicros, 3_000_000);
    } finally { f.close(); }
  });

  test('independent concurrent SQLite connections serialize the last $1 at the exact $5 lifetime boundary', { timeout: 15000 }, async () => {
    const c = contract(), f = storage(c.quota);
    try {
      for (let i = 0; i < 4; i++) settle(f.ledger, contract({}, 'owner', `settled-${i}`));
      const result = await race(f.path);
      assert.equal(result.filter(r => r.id).length, 1);
      const denial = result.find(r => r.denial)!.denial!;
      assert.equal(denial.status, 'insufficient');

      assert.deepEqual(denial.signals,
        [{ scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 1_000_000, remaining: 0 }]);
      f.reopen();
      assert.deepEqual(f.ledger.snapshotOpenAi(c.context).lifetimeBudget,
        { limitMicros: 5_000_000, usedMicros: 4_000_000, heldMicros: 1_000_000, remainingMicros: 0 });
      f.inspect(db => assert.equal((db.prepare('SELECT count(*) n FROM quota_attempt').get() as { n: number }).n, 5));
    } finally { f.close(); }
  });
}
