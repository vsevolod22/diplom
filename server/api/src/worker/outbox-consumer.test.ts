import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';

test('consumer claims persisted digest only; unsupported coverage fails closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'consumer-'));
  try {
    const ledger = new ScanLedger(join(dir, 'ledger.sqlite'));
    const digest = `sha256:${'a'.repeat(64)}` as const;
    const { scanId } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'replay-key', registry: 'registry.example.com',
      repository: 'team/image', digest, platform: 'linux/amd64' });
    let seen = 0;
    assert.equal(await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/db' }, async job => {
      seen++;
      assert.equal(job.digest, digest);
      assert.equal(job.platform, 'linux/amd64');
      assert.equal(job.registry, 'registry.example.com');
      return { ok: true, findings: [], scannerVersion: '0.69.3' };
    }, 1000), true);
    assert.equal(ledger.state(scanId, 'alice'), 'failed');
    assert.equal(await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/db' }, async () => {
      throw Error('should not run');
    }, 2000), false);
    assert.equal(seen, 1);
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('runner exceptions cannot leak diagnostics or leave a false success', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'consumer-'));
  try {
    const ledger = new ScanLedger(join(dir, 'ledger.sqlite'));
    const { scanId } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'failure-key', registry: 'registry.example.com',
      repository: 'team/image', digest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64' });
    assert.equal(await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/db' }, async () => {
      throw Error('sensitive signed URL');
    }), true);
    assert.equal(ledger.state(scanId, 'alice'), 'failed');
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
