import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate as immediate } from 'node:timers/promises';
import Database from 'better-sqlite3';
import { bindOpenAiAccounting, createOpenAiAccountingPolicy, createOpenAiQuotaContext, OPENAI_COST_BASIS } from '../openai-accounting.js';
import { prepareOpenAiSummary } from '../openai-prepared-request.js';
import { OpenAiProvider, type OpenAiAccountingBinding, type OpenAiGuardedTransport } from '../openai-provider.js';
import { observeOpenAiUsage } from '../openai-usage.js';
import { createOpenAiRuntime } from '../provider-runtime.js';
import { QuotaLedger } from '../quota-ledger.js';
import { DAY, quotaPolicyFromEnvironment } from '../quota-policy.js';
import { makeOpenAiPolicy, openAiReport, openAiResponse, syntheticOpenAiKey } from './openai-core.fixture.js';
import { quotaEnv } from './quota-fixtures.js';

type AttemptRow = Record<string, unknown> & {
  state: string; input: number; output: number; cost: number; receipt: string | null;
};
const zero = { input: 0, output: 0, costMicros: 0 };

function fixture() {
  const policy = makeOpenAiPolicy();
  const quota = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_USER_COST_USD: '1', LLM_QUOTA_SCAN_COST_USD: '1' })!;
  const config = { enabled: true, revision: 'unsent-dispatch-test', providerPolicyVersion: policy.version,
    quotaPolicyVersion: quota.version, billing: 'text-tokens-only-no-additional-fees', costBasis: OPENAI_COST_BASIS };
  const approval = createOpenAiAccountingPolicy(config, policy, quota);
  assert.ok(approval);
  const request = prepareOpenAiSummary(openAiReport, policy);
  const binding = { subject: 'offline-unsent-owner', scanId: openAiReport.scanId, reportVersion: openAiReport.reportVersion,
    policyVersion: policy.version, requestHash: request.hash };
  const context = createOpenAiQuotaContext(binding, request, policy, approval);
  const accountingBinding: OpenAiAccountingBinding = { operation: request.operation, policyVersion: policy.version,
    requestHash: request.hash, reserve: request.reserve };
  const dir = mkdtempSync(join(tmpdir(), 'openai-unsent-dispatch-')), path = join(dir, 'llm-usage.sqlite');
  let now = DAY - 1000;
  let ledger = new QuotaLedger(path, quota, () => now, true);
  return { policy, quota, config, approval, request, binding, context, accountingBinding,
    get ledger() { return ledger; }, time(value: number) { now = value; },
    restart() { ledger.close(); ledger = new QuotaLedger(path, quota, () => now); },
    row(id: string) {
      const db = new Database(path, { readonly: true });
      try { return db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as AttemptRow | undefined; }
      finally { db.close(); }
    },
    execute(sql: string) {
      const db = new Database(path);
      try { db.exec(sql); } finally { db.close(); }
    },
    usage(input = 20, output = 10) {
      return observeOpenAiUsage({ prompt_tokens: input, completion_tokens: output, total_tokens: input + output }, request.reserve, policy);
    },
    runtime(transport: OpenAiGuardedTransport) {
      const runtime = createOpenAiRuntime({ policy, maxConcurrent: 1, accountingRevision: config.revision,
        spending: { userBudgetMicros: quota.user.costMicros, scanBudgetMicros: quota.scan.costMicros } }, quota,
      () => new OpenAiProvider(policy, syntheticOpenAiKey, transport));
      assert.ok(runtime);
      return runtime;
    },
    close() { ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test('guarded dispatch commits before both callbacks; successful send retains liability until ordinary accounting settles', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), bridge = bindOpenAiAccounting(f.ledger, id, f.context), events: string[] = [];
    assert.equal(bridge.dispatchGuarded(f.accountingBinding, () => {
      assert.equal(f.row(id)!.state, 'dispatched'); events.push('before');
    }, () => {
      assert.equal(f.row(id)!.state, 'dispatched'); events.push('send');
    }), true);
    assert.deepEqual(events, ['before', 'send']);
    assert.equal(bridge.release(), false);
    f.restart();
    assert.equal(f.row(id)!.state, 'dispatched');
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.held, f.request.reserve);
    const reopened = bindOpenAiAccounting(f.ledger, id, f.context);
    assert.equal(reopened.accounting.observe(f.accountingBinding, f.usage()), true);
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.used, { input: 20, output: 10, costMicros: 40 });
  } finally { f.close(); }
});

test('fresh pre-send rejection compensates durably, zeros active amounts, and retains every audit binding and reserve', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), original = f.row(id)!, rejection = new Error('synthetic pre-send rejection');
    let sends = 0;
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => {
      assert.equal(f.row(id)!.state, 'dispatched'); throw rejection;
    }, () => { sends++; }), error => error === rejection);
    assert.equal(sends, 0);
    f.restart();
    assert.deepEqual(f.row(id), { ...original, state: 'released', input: 0, output: 0, cost: 0 });
    for (const scope of ['user', 'scan'] as const) {
      const view = f.ledger.snapshotOpenAi(f.context)[scope];
      assert.deepEqual(view.used, zero); assert.deepEqual(view.held, zero); assert.deepEqual(view.carried, zero);
    }
    assert.equal(f.ledger.dispatchOpenAi(id, f.context), false);
    assert.equal(f.ledger.observeOpenAi(id, f.context, f.usage()), false);
  } finally { f.close(); }
});

for (const mode of ['throw', 'abort'] as const) test(`send entry followed by ${mode} remains dispatched/unknown after reopen and expiry`, () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), rejection = new Error('synthetic send rejection'), controller = new AbortController();
    let sends = 0;
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => {}, () => {
      sends++;
      if (mode === 'abort') controller.abort();
      throw rejection;
    }), error => error === rejection);
    assert.equal(sends, 1); assert.equal(controller.signal.aborted, mode === 'abort');
    assert.equal(f.ledger.releaseOpenAi(id, f.context), false);
    assert.equal(f.ledger.observeOpenAi(id, f.context, observeOpenAiUsage(undefined, f.request.reserve, f.policy)), false);
    f.time(DAY + f.quota.receiptMs); f.restart();
    assert.equal(f.row(id)!.state, 'dispatched'); assert.equal(f.row(id)!.receipt, null);
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.carried, f.request.reserve);
    assert.equal(f.ledger.observeOpenAi(id, f.context, f.usage()), false);
    assert.equal(f.ledger.releaseOpenAi(id, f.context), false);
  } finally { f.close(); }
});

test('abort after send entry without a throw still retains unknown liability', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), controller = new AbortController();
    assert.equal(f.ledger.dispatchOpenAiGuarded(id, f.context, () => {}, () => { controller.abort(); }), true);
    assert.equal(controller.signal.aborted, true);
    f.restart(); assert.equal(f.row(id)!.state, 'dispatched');
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.held, f.request.reserve);
    assert.equal(f.ledger.releaseOpenAi(id, f.context), false);
  } finally { f.close(); }
});

for (const state of ['dispatched', 'settled', 'fault', 'released', 'expired', 'missing'] as const)
  test(`nonfresh ${state} attempt never runs callbacks or changes its row`, () => {
    const f = fixture();
    try {
      const id = f.ledger.reserveOpenAi(f.context);
      if (state === 'dispatched' || state === 'settled' || state === 'fault') assert.equal(f.ledger.dispatchOpenAi(id, f.context), true);
      if (state === 'settled') assert.equal(f.ledger.observeOpenAi(id, f.context, f.usage()), true);
      if (state === 'fault') assert.equal(f.ledger.observeOpenAi(id, f.context, f.usage(1_048_000, 500)), false);
      if (state === 'released') assert.equal(f.ledger.releaseOpenAi(id, f.context), true);
      if (state === 'expired') f.time(DAY + f.quota.receiptMs);
      const original = f.row(id), target = state === 'missing' ? 'missing-attempt' : id;
      assert.equal(f.ledger.dispatchOpenAiGuarded(target, f.context, () => assert.fail('before-send must not run'),
        () => assert.fail('send must not run')), false);
      f.restart(); assert.deepEqual(f.row(id), original);
    } finally { f.close(); }
  });

test('foreign branded contexts and structural clones cannot dispatch or compensate another context row', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), original = f.row(id);
    const otherRequest = prepareOpenAiSummary({ ...openAiReport, attempt: openAiReport.attempt + 1 }, f.policy);
    const otherApproval = createOpenAiAccountingPolicy({ ...f.config, revision: 'foreign-accounting' }, f.policy, f.quota)!;
    const foreign = [
      createOpenAiQuotaContext({ ...f.binding, subject: 'foreign-owner' }, f.request, f.policy, f.approval),
      createOpenAiQuotaContext({ ...f.binding, scanId: 'foreign-scan' }, f.request, f.policy, f.approval),
      createOpenAiQuotaContext({ ...f.binding, reportVersion: 'a'.repeat(64) }, f.request, f.policy, f.approval),
      createOpenAiQuotaContext({ ...f.binding, requestHash: otherRequest.hash }, otherRequest, f.policy, f.approval),
      createOpenAiQuotaContext(f.binding, f.request, f.policy, otherApproval),
    ];
    for (const context of foreign) assert.equal(f.ledger.dispatchOpenAiGuarded(id, context,
      () => assert.fail('foreign before-send'), () => assert.fail('foreign send')), false);
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, { ...f.context },
      () => assert.fail('unbranded before-send'), () => assert.fail('unbranded send')));
    assert.deepEqual(f.row(id), original);
    assert.equal(f.ledger.dispatchOpenAi(id, f.context), true);
    for (const context of foreign) assert.equal(f.ledger.dispatchOpenAiGuarded(id, context,
      () => assert.fail('foreign compensation'), () => assert.fail('foreign send')), false);
    f.restart(); assert.equal(f.row(id)!.state, 'dispatched');
  } finally { f.close(); }
});

test('accounting bridge checks every binding dimension before guarded dispatch and preserves ordinary methods', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), bridge = bindOpenAiAccounting(f.ledger, id, f.context), original = f.row(id);
    const foreign: OpenAiAccountingBinding[] = [
      { ...f.accountingBinding, operation: 'chat' }, { ...f.accountingBinding, policyVersion: 'a'.repeat(64) },
      { ...f.accountingBinding, requestHash: 'b'.repeat(64) },
      ...(['input', 'output', 'costMicros'] as const).map(key => ({ ...f.accountingBinding,
        reserve: { ...f.request.reserve, [key]: f.request.reserve[key] + 1 } })),
    ];
    for (const binding of foreign) assert.equal(bridge.dispatchGuarded(binding,
      () => assert.fail('mismatched before-send'), () => assert.fail('mismatched send')), false);
    assert.deepEqual(f.row(id), original);
    assert.equal(bridge.accounting.assertReserved(f.accountingBinding), true);
    assert.equal(bridge.dispatch(f.accountingBinding), true);
    assert.equal(bridge.dispatchGuarded(f.accountingBinding, () => assert.fail('old dispatch'), () => assert.fail('old send')), false);
    assert.equal(bridge.release(), false);
    assert.equal(bridge.accounting.observe(f.accountingBinding, f.usage()), true);
  } finally { f.close(); }
});

for (const state of ['settled', 'fault', 'receipt-only'] as const)
  test(`pre-send rejection never compensates a fresh row that acquired ${state}`, () => {
    const f = fixture();
    try {
      const id = f.ledger.reserveOpenAi(f.context), rejection = new Error('synthetic rejection after receipt');
      let receipted: AttemptRow | undefined;
      assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => {
        if (state === 'receipt-only') f.execute("UPDATE quota_attempt SET receipt='synthetic-receipt' WHERE state='dispatched'");
        else assert.equal(f.ledger.observeOpenAi(id, f.context, state === 'settled' ? f.usage() : f.usage(1_048_000, 500)), state === 'settled');
        receipted = f.row(id); throw rejection;
      }, () => assert.fail('send after receipt rejection')), error => error === rejection);
      f.restart(); assert.deepEqual(f.row(id), receipted); assert.notEqual(f.row(id)!.receipt, null);
    } finally { f.close(); }
  });

test('compensation rechecks the exact row binding after the pre-send callback rejects', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), rejection = new Error('synthetic rejection after binding changed');
    let changed: AttemptRow | undefined;
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => {
      f.execute(`UPDATE quota_attempt SET request_hash='${'a'.repeat(64)}' WHERE state='dispatched'`);
      changed = f.row(id); throw rejection;
    }, () => assert.fail('send after binding changed')), error => error === rejection);
    f.restart(); assert.deepEqual(f.row(id), changed); assert.equal(f.row(id)!.state, 'dispatched');
  } finally { f.close(); }
});

test('compensation write failure preserves both committed liability and the original pre-send rejection', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), rejection = new Error('original pre-send rejection');
    f.execute(`CREATE TRIGGER reject_unsent_compensation BEFORE UPDATE OF state ON quota_attempt
      WHEN NEW.state='released' BEGIN SELECT RAISE(ABORT, 'synthetic compensation failure'); END`);
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => { throw rejection; },
      () => assert.fail('send after compensation failure')), error => error === rejection);
    f.restart(); assert.equal(f.row(id)!.state, 'dispatched');
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.held, f.request.reserve);
  } finally { f.close(); }
});

test('deadline crossing after fresh dispatch can release only a synchronously proven unsent attempt', () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context), original = f.row(id)!, controller = new AbortController();
    const rejection = new Error('synthetic deadline before send');
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, () => {
      f.time(DAY + f.quota.receiptMs); controller.abort(rejection); throw controller.signal.reason;
    }, () => assert.fail('send after pre-send deadline')), error => error === rejection);
    f.restart(); assert.deepEqual(f.row(id), { ...original, state: 'released', input: 0, output: 0, cost: 0 });
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.carried, zero);
  } finally { f.close(); }
});

const invalidReturns: Array<[string, () => unknown]> = [
  ['resolved promise', () => Promise.resolve()],
  ['rejected promise', () => Promise.reject(new Error('synthetic async rejection'))],
  ['rejecting thenable', () => ({ then(_resolve: unknown, reject: (reason: Error) => void) { reject(new Error('synthetic thenable rejection')); } })],
  ['throwing then getter', () => Object.defineProperty({}, 'then', { get() { throw new Error('synthetic getter rejection'); } })],
  ['poisoned catch', () => Object.defineProperty(Promise.reject(new Error('synthetic rejection')), 'catch',
    { value() { assert.fail('must not call untrusted catch'); } })],
  ['scalar', () => 1], ['null', () => null], ['object', () => ({})],
];
for (const [name, result] of invalidReturns) test(`before-send ${name} is rejected without sending or an unhandled rejection`, async () => {
  const f = fixture();
  try {
    const id = f.ledger.reserveOpenAi(f.context);
    assert.throws(() => f.ledger.dispatchOpenAiGuarded(id, f.context, result, () => assert.fail('send after invalid synchronous return')));
    await immediate(); f.restart(); assert.equal(f.row(id)!.state, 'released');
    assert.deepEqual(f.ledger.snapshotOpenAi(f.context).scan.held, zero);
  } finally { f.close(); }
});

for (const mode of ['pre-send-throw', 'pre-send-deadline', 'pre-send-async', 'send-throw', 'success'] as const)
  test(`runtime uses the guarded bridge for ${mode}, without a network transport`, async () => {
    const f = fixture();
    try {
      let sends = 0, observations = 0, notifications = 0, completedFences = 0;
      const controller = new AbortController(), rejection = new Error('synthetic runtime rejection');
      const runtime = f.runtime({ async sendGuarded(_endpoint, _init, guard) {
        guard(() => {
          sends++;
          if (mode === 'send-throw') throw rejection;
          return undefined;
        });
        return openAiResponse();
      } });
      const operation = runtime.prepareSummary(openAiReport), attempt = operation.reserveAttempt(f.ledger, f.binding);
      const original = f.row(attempt.id)!;
      const notification = () => {
        notifications++;
        assert.equal(f.row(attempt.id)!.state, 'dispatched');
        if (mode === 'pre-send-deadline') { f.time(DAY + f.quota.receiptMs); controller.abort(rejection); }
        if (mode === 'pre-send-throw' || mode === 'pre-send-deadline') throw rejection;
        if (mode === 'pre-send-async') return Promise.reject(rejection);
      };
      // The second fence is the final dispatch fence; the first only acquires the adapter.
      const pending = attempt.generate(controller.signal, action => { action(); completedFences++; }, () => { observations++; }, notification);
      if (mode === 'success') await pending;
      else await assert.rejects(pending);
      attempt.release(); f.restart();
      assert.equal(notifications, 1);
      assert.equal(sends, mode.startsWith('pre-send') ? 0 : 1);
      assert.equal(observations, mode === 'success' ? 1 : 0);
      assert.equal(completedFences, mode === 'success' ? 2 : 1);
      if (mode.startsWith('pre-send')) assert.deepEqual(f.row(attempt.id), { ...original, state: 'released', input: 0, output: 0, cost: 0 });
      else assert.equal(f.row(attempt.id)!.state, mode === 'success' ? 'settled' : 'dispatched');
    } finally { f.close(); }
  });
