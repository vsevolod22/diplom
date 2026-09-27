import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { IdempotencyConflict, ScanLedger, type PinnedTarget } from './ledger.js';

const target: PinnedTarget = {
  subject: 'alice', idempotencyKey: 'request-1', registry: 'registry.lab.test',
  repository: 'demo', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
};

test('atomic idempotency + outbox persist across reopen; subjects isolated', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dip-ledger-'));
  const file = join(dir, 'scan.sqlite');
  try {
    const first = new ScanLedger(file);
    const created = first.enqueue(target);
    assert.equal(created.created, true);
    first.close();
    const reopened = new ScanLedger(file);
    assert.deepEqual(reopened.findByKey('alice', 'request-1'), {
      scanId: created.scanId, digest: target.digest, platform: target.platform, fingerprint: null,
    });
    assert.deepEqual(reopened.enqueue(target), { scanId: created.scanId, created: false });
    assert.deepEqual(reopened.pending(), [{ scanId: created.scanId, digest: target.digest, platform: target.platform }]);
    const secondHandle = new ScanLedger(file);
    assert.deepEqual(secondHandle.enqueue(target), { scanId: created.scanId, created: false });
    secondHandle.close();
    assert.notEqual(reopened.enqueue({ ...target, subject: 'bob' }).scanId, created.scanId);
    assert.equal(reopened.pending().length, 2);
    assert.throws(() => reopened.enqueue({ ...target, digest: `sha256:${'b'.repeat(64)}` }), IdempotencyConflict);
    assert.equal(reopened.pending().length, 2);
    reopened.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects unpinned targets before creating rows', () => {
  const ledger = new ScanLedger(':memory:');
  assert.throws(() => ledger.enqueue({ ...target, digest: 'sha256:bad' }), TypeError);
  assert.throws(() => ledger.enqueue({ ...target, platform: 'unknown' }), TypeError);
  assert.deepEqual(ledger.pending(), []);
  ledger.close();
});
