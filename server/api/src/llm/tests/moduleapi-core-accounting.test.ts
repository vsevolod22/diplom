import { openAiSettings as baseSettings, openAiPrompts as moduleApiPrompts, openAiReport as moduleApiReport } from './openai-core.fixture.js';
import { createModuleApiPolicy, MODULEAPI_MODEL, type ModuleApiSettings } from '../moduleapi-policy.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bindModuleApiAccounting, createModuleApiAccountingPolicy, createModuleApiQuotaContext, MODULEAPI_COST_BASIS } from '../moduleapi-accounting.js';
import { prepareModuleApiSummary } from '../moduleapi-prepared-request.js';
import { observeModuleApiUsage } from '../moduleapi-usage.js';
import { QuotaLedger } from '../quota-ledger.js';
import { DAY, quotaPolicyFromEnvironment } from '../quota-policy.js';
import { quotaEnv } from './quota-fixtures.js';

function fixture() {
  const provider = makeModuleApiPolicy();
  const quota = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_MONETARY_LIMIT: 'capped', LLM_QUOTA_USER_COST_USD: '1', LLM_QUOTA_SCAN_COST_USD: '1' })!;
  const config = { enabled: true, revision: 'independent-paid-test', monetaryLimit: 'capped', providerPolicyVersion: provider.version,
    quotaPolicyVersion: quota.version, billing: 'estimate-only-effective-tariff-not-verified', costBasis: MODULEAPI_COST_BASIS };
  const approval = createModuleApiAccountingPolicy(config, provider, quota);
  assert.ok(approval);
  const request = prepareModuleApiSummary(moduleApiReport, provider);
  const binding = { subject: 'offline-owner', scanId: moduleApiReport.scanId, reportVersion: moduleApiReport.reportVersion,
    policyVersion: provider.version, requestHash: request.hash };
  const context = createModuleApiQuotaContext(binding, request, provider, approval);
  const dir = mkdtempSync(join(tmpdir(), 'independent-moduleapi-paid-'));
  const path = join(dir, 'llm-usage.sqlite');
  let now = DAY - 1000;
  let ledger = new QuotaLedger(path, quota, () => now, true);
  return { provider, quota, config, approval, request, binding, context,
    get ledger() { return ledger; }, time(value: number) { now = value; },
    restart() { ledger.close(); ledger = new QuotaLedger(path, quota, () => now); },
    usage(input = 20, output = 10) { return observeModuleApiUsage({ prompt_tokens: input, completion_tokens: output,
      total_tokens: input + output }, context.reserve, provider); },
    close() { ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
}


const moduleApiSettings: ModuleApiSettings = { ...baseSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped', requestBudgetMicros: 100_000 };
const makeModuleApiPolicy = (overrides: Partial<ModuleApiSettings> = {}) => {
  const policy = createModuleApiPolicy({ ...moduleApiSettings, ...overrides }, moduleApiPrompts);
  if (!policy) throw new Error('Invalid synthetic ModuleAPI policy fixture');
  return policy;
};

test('paid bridge: reserve → dispatch → unknown → settle; exact replay survives restart without duplicate debit', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveModuleApi(f.context);
    const bridge = bindModuleApiAccounting(f.ledger, id, f.context);
    const binding = { operation: f.request.operation, policyVersion: f.provider.version, requestHash: f.request.hash, reserve: f.context.reserve };
    assert.equal(bridge.accounting.assertReserved(binding), true);
    assert.equal(f.ledger.observeModuleApi(id, f.context, f.usage()), false);
    assert.equal(bridge.dispatch({ ...binding, requestHash: 'a'.repeat(64) }), false);
    assert.equal(bridge.dispatch(binding), true);
    assert.equal(bridge.dispatch(binding), false);
    assert.equal(bridge.release(), false);
    assert.equal(bridge.accounting.observe(binding, observeModuleApiUsage(undefined, f.context.reserve, f.provider)), false);
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, f.context.reserve);
    assert.equal(bridge.accounting.observe(binding, f.usage()), true);
    f.restart();
    const restoredProvider = makeModuleApiPolicy();
    const restoredApproval = createModuleApiAccountingPolicy(f.config, restoredProvider, f.quota)!;
    const restoredRequest = prepareModuleApiSummary(moduleApiReport, restoredProvider);
    const restoredContext = createModuleApiQuotaContext(f.binding, restoredRequest, restoredProvider, restoredApproval);
    const restoredUsage = observeModuleApiUsage({ prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 }, restoredContext.reserve, restoredProvider);
    assert.equal(f.ledger.observeModuleApi(id, restoredContext, restoredUsage), true);
    assert.equal(f.ledger.observeModuleApi(id, f.context, f.usage(21)), false);
    const view = f.ledger.snapshotModuleApi(f.context);
    assert.deepEqual(view.scan.used, { input: 20, output: 10, costMicros: 40 });
    assert.deepEqual(view.scan.held, { input: 0, output: 0, costMicros: 0 });
    assert.equal(f.ledger.dispatchModuleApi(id, f.context), false);
  } finally { f.close(); }
});

test('paid context and usage provenance reject structural clones, altered owner, foreign reserve and forged zero cost', () => {
  const f = fixture();
  try {
    assert.throws(() => f.ledger.reserveModuleApi({ ...f.context }));
    assert.throws(() => createModuleApiQuotaContext(f.binding, { ...f.request }, f.provider, f.approval));
    assert.throws(() => createModuleApiQuotaContext(f.binding, f.request, f.provider, { ...f.approval }));
    const id = f.ledger.reserveModuleApi(f.context);
    assert.equal(f.ledger.dispatchModuleApi(id, f.context), true);
    for (const usage of [{ ...f.usage() }, { ...f.usage(), costMicros: 0 },
      observeModuleApiUsage({ prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 }, { ...f.context.reserve, input: f.context.reserve.input + 1 }, f.provider)])
      assert.throws(() => f.ledger.observeModuleApi(id, f.context, usage));
    const other = createModuleApiQuotaContext({ ...f.binding, subject: 'other-owner' }, f.request, f.provider, f.approval);
    assert.equal(f.ledger.observeModuleApi(id, other, f.usage()), false);
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, f.context.reserve);
  } finally { f.close(); }
});

test('paid and free attempts share user/scan counters but legacy writes cannot dispatch, release or settle paid rows', () => {
  const f = fixture();
  try {
    const paid = f.ledger.reserveModuleApi(f.context);
    assert.equal(f.ledger.dispatch(paid), false);
    assert.equal(f.ledger.release(paid), false);
    assert.equal(f.ledger.observe(paid, { normal: true, input: 1, output: 0, costMicros: 0 }), false);
    const freeReserve = { input: 100, output: 100, costMicros: 0 };
    const free = f.ledger.reserve({ ...f.binding, policyVersion: 'b'.repeat(64) }, freeReserve);
    const held = { input: f.context.reserve.input + 100, output: f.context.reserve.output + 100, costMicros: f.context.reserve.costMicros };
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, held);
    assert.deepEqual(f.ledger.snapshot(f.binding.subject, f.binding.scanId).user.held, held);
    assert.equal(f.ledger.dispatchModuleApi(free, f.context), false);
    assert.equal(f.ledger.releaseModuleApi(free, f.context), false);
    assert.equal(f.ledger.dispatch(free), true);
    assert.equal(f.ledger.observe(free, { normal: true, input: 50, output: 10, costMicros: 0 }), true);
    assert.equal(f.ledger.dispatchModuleApi(paid, f.context), true);
    assert.equal(f.ledger.observeModuleApi(paid, f.context, f.usage()), true);
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.used, { input: 70, output: 20, costMicros: 40 });
  } finally { f.close(); }
});

test('unknown liability carries across midnight/restart; late valid receipt settles only the original window', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveModuleApi(f.context);
    assert.equal(f.ledger.dispatchModuleApi(id, f.context), true);
    f.time(DAY + 1000); f.restart();
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.carried, f.context.reserve);
    assert.equal(f.ledger.observeModuleApi(id, f.context, f.usage()), true);
    const view = f.ledger.snapshotModuleApi(f.context);
    assert.deepEqual(view.scan.carried, { input: 0, output: 0, costMicros: 0 });
    assert.deepEqual(view.scan.used, { input: 0, output: 0, costMicros: 0 });
    assert.equal(f.ledger.observeModuleApi(id, f.context, f.usage()), true);
  } finally { f.close(); }
});

test('expiry never refunds dispatched unknown; expired un-dispatched reserve cannot send and can be released', () => {
  const f = fixture();
  try {
    const dispatched = f.ledger.reserveModuleApi(f.context), reserved = f.ledger.reserveModuleApi(f.context);
    assert.equal(f.ledger.dispatchModuleApi(dispatched, f.context), true);
    f.time(DAY + f.quota.receiptMs);
    assert.equal(f.ledger.assertModuleApiReserved(reserved, f.context), false);
    assert.equal(f.ledger.dispatchModuleApi(reserved, f.context), false);
    assert.equal(f.ledger.observeModuleApi(dispatched, f.context, f.usage()), false);
    assert.equal(f.ledger.releaseModuleApi(dispatched, f.context), false);
    assert.equal(f.ledger.releaseModuleApi(reserved, f.context), true);
    f.restart();
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.carried, f.context.reserve);
  } finally { f.close(); }
});

test('known overage above observation cost ceiling remains a durable fault, never a zero-cost settlement', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveModuleApi(f.context);
    assert.equal(f.ledger.dispatchModuleApi(id, f.context), true);
    const overage = f.usage(1_048_000, 500);
    assert.equal(overage.normal, false); assert.ok(overage.costMicros! > f.quota.observationCostMicros);
    assert.equal(f.ledger.observeModuleApi(id, f.context, overage), false);
    f.restart();
    const view = f.ledger.snapshotModuleApi(f.context);
    assert.equal(view.reason, 'policy_fault');
    assert.equal(view.scan.held.costMicros, overage.costMicros);
    assert.equal(view.user.held.input, 1_048_000);
    assert.equal(f.ledger.observeModuleApi(id, f.context, f.usage()), false);
    assert.throws(() => f.ledger.reserveModuleApi(f.context));
  } finally { f.close(); }
});

test('missing usage is not zero; missing/zero budget cannot silently approve paid accounting', () => {
  const f = fixture();
  try {
    for (const value of [undefined, null, {}, { prompt_tokens: 20 }]) {
      const usage = observeModuleApiUsage(value, f.context.reserve, f.provider);
      assert.equal(usage.normal, false); assert.equal(usage.costMicros, undefined);
    }
    assert.equal(f.usage().costMicros, 40);
    for (const cost of [undefined, '0']) {
      const quota = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_USER_COST_USD: cost });
      if (quota) assert.equal(createModuleApiAccountingPolicy({ ...f.config, quotaPolicyVersion: quota.version }, f.provider, quota), null);
      else assert.equal(quota, null);
    }
  } finally { f.close(); }
});

test('ModuleAPI dispatch commits before the synchronous send fence; only proven unsent rejection can release liability', () => {
  const f = fixture();
  try {
    for (const mode of ['throw', 'thenable'] as const) {
      const id = f.ledger.reserveModuleApi(f.context), bound = bindModuleApiAccounting(f.ledger, id, f.context);
      const binding = { operation: f.request.operation, policyVersion: f.provider.version, requestHash: f.request.hash, reserve: f.context.reserve };
      let sends = 0;
      assert.throws(() => bound.dispatchGuarded(binding, () => {
        assert.equal(bound.accounting.assertReserved(binding), false, 'dispatch already durably committed');
        if (mode === 'thenable') return Promise.reject(new Error('synthetic rejection'));
        throw new Error('synthetic rejected owner/report fence');
      }, () => { sends++; }));
      assert.equal(sends, 0); assert.equal(bound.release(), false);
      assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, { input: 0, output: 0, costMicros: 0 });
    }
    const id = f.ledger.reserveModuleApi(f.context), bound = bindModuleApiAccounting(f.ledger, id, f.context);
    const binding = { operation: f.request.operation, policyVersion: f.provider.version, requestHash: f.request.hash, reserve: f.context.reserve };
    assert.throws(() => bound.dispatchGuarded(binding, () => {}, () => { throw new Error('synthetic entered send'); }));
    assert.equal(bound.release(), false);
    assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, f.context.reserve);
    f.restart(); assert.deepEqual(f.ledger.snapshotModuleApi(f.context).scan.held, f.context.reserve);
  } finally { f.close(); }
});
