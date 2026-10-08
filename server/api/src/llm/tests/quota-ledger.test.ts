import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { quotaPolicyFromEnvironment, quotaDenial } from '../quota-policy.js';

import { quotaEnv, quotaPolicy } from './quota-fixtures.js';
const bindings = { subject: 'alice', scanId: 'scan-a', reportVersion: 'a'.repeat(64), policyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) };
const reserve = { input: 1000, output: 200, costMicros: 0 };

test('explicit finite policy, zero caps and free cost; absent/invalid never unlimited', () => {
  assert.ok(quotaPolicy);
  assert.equal(quotaPolicyFromEnvironment({}), null);
  for (const key of Object.keys(quotaEnv)) assert.equal(quotaPolicyFromEnvironment({ ...quotaEnv, [key]: undefined }), null, key);
  for (const value of ['NaN', '-1', 'Infinity', '1.5']) assert.equal(quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_USER_INPUT: value }), null);
  assert.equal(quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_SCAN_OUTPUT: '0' })?.scan.output, 0);
});

test('atomic both-scope reserve, CAS release/dispatch, restart and terminal replay', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-'));
  const path = join(dir, 'llm-usage.sqlite');
  const now = () => Date.UTC(2026, 9, 8, 12);
  let ledger = new QuotaLedger(path, quotaPolicy, now);
  try {
    const id = ledger.reserve(bindings, reserve);
    assert.equal(ledger.snapshot('alice', 'scan-a').scan.held.input, 1000);
    assert.equal(ledger.release(id), true);
    assert.equal(ledger.dispatch(id), false);
    assert.equal(ledger.release(id), false);
    const next = ledger.reserve(bindings, reserve);
    assert.equal(ledger.dispatch(next), true);
    assert.equal(ledger.dispatch(next), false);
    assert.equal(ledger.release(next), false);
    ledger.close(); ledger = new QuotaLedger(path, quotaPolicy, now);
    assert.equal(ledger.snapshot('alice', 'scan-a').user.held.input, 1000);
    assert.equal(ledger.observe(next, { normal: true, input: 600, output: 80, costMicros: 0 }), true);
    assert.equal(ledger.observe(next, { normal: true, input: 600, output: 80, costMicros: 0 }), true);
    assert.equal(ledger.observe(next, { normal: true, input: 601, output: 80, costMicros: 0 }), false);
    const view = ledger.snapshot('alice', 'scan-a');
    assert.equal(view.user.used.input, 600); assert.equal(view.scan.used.output, 80);
    assert.equal(view.user.held.input, 0);
    assert.equal(view.user.remaining.input, quotaPolicy.user.input - 600);
    assert.doesNotMatch(readFileSync(path).toString(), /alice|CANARY|Bearer|prompt_tokens/);
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('calendar carry, original-window settlement, clock rollback, overage floors and fault across windows', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-window-'));
  let time = Date.UTC(2026, 9, 8, 23, 59, 59);
  const ledger = new QuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy, () => time);
  try {
    const id = ledger.reserve(bindings, reserve); ledger.dispatch(id);
    time += 2000;
    assert.equal(ledger.snapshot('alice', 'scan-a').user.carried.input, 1000);
    assert.equal(ledger.observe(id, { normal: true, input: 600, output: 80, costMicros: 0 }), true);
    assert.equal(ledger.snapshot('alice', 'scan-a').user.used.input, 0);
    assert.equal(ledger.snapshot('alice', 'scan-a').user.carried.input, 0);
    time -= 3000;
    assert.throws(() => ledger.reserve(bindings, reserve));
    time += 4000;
    const bad = ledger.reserve(bindings, reserve); ledger.dispatch(bad);
    ledger.observe(bad, { normal: false, input: 1500, output: 250, costMicros: 100 });
    const view = ledger.snapshot('alice', 'scan-a');
    assert.equal(view.reason, 'policy_fault'); assert.equal(view.scan.held.input, 1500);
    assert.equal(view.scan.held.costMicros, 100);
    assert.throws(() => ledger.reserve(bindings, reserve));
    time += 86400000;
    assert.equal(ledger.snapshot('alice', 'scan-a').user.carried.input, 1500);
    assert.throws(() => ledger.reserve(bindings, reserve));
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('positive remaining below full envelope identifies both scopes/dimensions without partial reservation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-envelope-'));
  const ledger = new QuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  const envelope = { input: 1000, output: 2048, costMicros: 0 };
  try {
    assert.equal(ledger.snapshot('alice', 'scan-a', envelope).admission.status, 'fits');
    for (let i = 0; i < 4; i++) {
      const id = ledger.reserve(bindings, envelope); assert.equal(ledger.dispatch(id), true);
      assert.equal(ledger.observe(id, { normal: true, input: 600, output: 1575, costMicros: 0 }), true);
    }
    const view = ledger.snapshot('alice', 'scan-a', envelope);
    assert.equal(view.reason, 'ready'); assert.equal(view.scan.used.output, 6300);
    assert.equal(view.scan.remaining.output, 1892);
    const expected = { status: 'insufficient', reserve: envelope,
      signals: [{ scope: 'scan', dimension: 'output', reason: 'insufficient', required: 2048, remaining: 1892 }] };
    assert.deepEqual(view.admission, expected);
    assert.throws(() => ledger.reserve(bindings, envelope), error => {
      assert.deepEqual(quotaDenial(error), expected); return true;
    });
    assert.deepEqual(ledger.snapshot('alice', 'scan-a', envelope), view);
    // Same authoritative check covers positive input/output shortages in both scopes.
    const other = new QuotaLedger(join(dir, 'llm-usage.sqlite'), { ...quotaPolicy,
      user: { input: 2500, output: 6400, costMicros: 0 }, scan: { input: 2500, output: 6400, costMicros: 0 } });
    try {
      const next = other.snapshot('alice', 'scan-a', envelope).admission;
      assert.equal(next.status, 'insufficient');
      assert.deepEqual(next.signals.map(s => [s.scope, s.dimension]),
        [['user', 'input'], ['user', 'output'], ['scan', 'input'], ['scan', 'output']]);
      assert.throws(() => other.reserve(bindings, envelope));
      assert.equal(other.snapshot('alice', 'scan-a').user.held.input, 0);
    } finally { other.close(); }
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('partial caps are atomic, unknown never timer-refunded, receipt expiry retains liability', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-cap-'));
  let time = Date.UTC(2026, 9, 8);
  const policy = { ...quotaPolicy, scan: { ...quotaPolicy.scan, output: 200 } };
  const ledger = new QuotaLedger(join(dir, 'llm-usage.sqlite'), policy, () => time);
  try {
    const id = ledger.reserve(bindings, reserve); ledger.dispatch(id);
    assert.throws(() => ledger.reserve(bindings, reserve));
    assert.equal(ledger.snapshot('alice', 'scan-a').user.held.input, 1000);
    time += policy.receiptMs + 1;
    assert.equal(ledger.observe(id, { normal: true, input: 1, output: 1, costMicros: 0 }), false);
    assert.equal(ledger.snapshot('alice', 'scan-a').scan.held.output, 200);
    assert.equal(ledger.release(id), false);
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});
