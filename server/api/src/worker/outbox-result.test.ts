import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';

test('worker persists only fenced count/coverage, not sensitive runner data', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'worker-result-'));
  try {
    const db = new ScanLedger(join(dir, 'ledger.sqlite'));
    const { scanId } = db.enqueue({ subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' });
    const processed = await consumeOne(db, { timeoutMs: 2000, dbDir: '/tmp/cache' }, async job => {
      assert.equal(job.checks, '["secret"]');
      assert.equal(job.digest, `sha256:${'a'.repeat(64)}`);
      return { ok: true, findings: [{ findingId: 'secret-0-0', ruleId: 'test', line: 4, evidenceRef: 'result-0-secret-0' }], scannerVersion: '0.69.3' };
    });
    assert.equal(processed, true);
    assert.deepEqual(db.result(scanId, 'alice'), { findingCount: 1, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3' });
    assert.equal(db.result(scanId, 'other'), undefined);
    assert.equal(await consumeOne(db, { timeoutMs: 2000, dbDir: '/tmp/cache' }), false);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
