import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger, type PinnedTarget } from './ledger.js';

const target: PinnedTarget = { subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["secret"]', scope: 'image' };

test('safe result is atomically fenced, subject scoped, durable and idempotent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-result-'));
  const filename = join(dir, 'ledger.sqlite');
  try {
    let now = 1000;
    let db = new ScanLedger(filename, () => now);
    const { scanId } = db.enqueue(target);
    const first = db.claim(1000, 100)!;
    const findings = [{ findingId: 'secret-0-0', ruleId: 'test-rule', line: 3, evidenceRef: 'result-0-secret-0' }];
    assert.equal(db.finishWithResult(scanId, first.attempts + 1, findings, '0.69.3', first.leaseToken), false);
    assert.equal(db.result(scanId, 'alice'), undefined);
    now = 1100;
    const second = db.claim(now, 100)!;
    assert.equal(db.finishWithResult(scanId, first.attempts, findings, '0.69.3', first.leaseToken), false);
    assert.throws(() => db.finishWithResult(scanId, second.attempts, [{ ...findings[0], ruleId: 'https://canary' }], '0.69.3', second.leaseToken), TypeError);
    assert.equal(db.finishWithResult(scanId, second.attempts, findings, '0.69.3', second.leaseToken), true);
    assert.equal(db.finishWithResult(scanId, second.attempts, findings, '0.69.3', second.leaseToken), false);
    assert.equal(db.result(scanId, 'bob'), undefined);
    db.close();
    db = new ScanLedger(filename);
    assert.deepEqual(db.result(scanId, 'alice'), { findingCount: 1, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3' });
    assert.equal(db.state(scanId, 'alice'), 'completed');
    assert.deepEqual(db.findings(scanId, 'alice'), { findings, nextCursor: null });
    assert.deepEqual(db.findings(scanId, 'alice', 0, 1), { findings, nextCursor: null });
    assert.equal(db.findings(scanId, 'bob'), undefined);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('wrong checks roll back result, delivery and terminal state', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-result-reject-'));
  try {
    const db = new ScanLedger(join(dir, 'ledger.sqlite'));
    const { scanId } = db.enqueue({ ...target, checks: '["vuln"]' });
    const job = db.claim()!;
    assert.throws(() => db.finishWithResult(scanId, job.attempts, [], '0.69.3', job.leaseToken), /contract mismatch/);
    assert.equal(db.state(scanId, 'alice'), 'running');
    assert.equal(db.result(scanId, 'alice'), undefined);
    assert.equal(db.finish(scanId, job.attempts, 'failed', 'SCAN_TIMEOUT', job.leaseToken), true);
    // An unsupported check must not be misreported as secret coverage.
    assert.equal(db.result(scanId, 'alice'), undefined);
    assert.equal(db.state(scanId, 'alice'), 'failed');
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
