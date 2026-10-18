import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';

const options = { timeoutMs: 1000, dbDir: '/tmp/cache' };

test('consumer aborts active attempt on cancel and does not wait for an uncooperative runner', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cancel-worker-'));
  try {
    const db = new ScanLedger(join(dir, 'ledger.sqlite'));
    const id = db.enqueue({ subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    let started!: () => void;
    const ready = new Promise<void>(resolve => { started = resolve; });
    const work = consumeOne(db, options, async (_job, runOptions) => {
      started();
      await new Promise<void>(resolve => runOptions.signal?.addEventListener('abort', () => resolve(), { once: true }));
      return { ok: true as const, findings: [], scannerVersion: '0.69.3' as const };
    });
    await ready;
    assert.equal(db.cancel(id, 'alice'), 'cancelled');
    assert.equal(await work, true);
    assert.equal(db.state(id, 'alice'), 'cancelled');
    assert.equal(db.result(id, 'alice'), undefined);
    assert.equal(await consumeOne(db, options, async () => { throw Error('must not run'); }), false);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('old attempt cannot overwrite a replacement claim', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cancel-attempt-'));
  try {
    const db = new ScanLedger(join(dir, 'ledger.sqlite'), () => 1000);
    const id = db.enqueue({ subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    let started!: () => void;
    const ready = new Promise<void>(resolve => { started = resolve; });
    const first = consumeOne(db, options, async (_job, runOptions) => {
      started();
      await new Promise<void>(resolve => runOptions.signal?.addEventListener('abort', () => resolve(), { once: true }));
      return { ok: true as const, findings: [], scannerVersion: '0.69.3' as const };
    }, 1000);
    await ready;
    const second = db.claim(32_000, 1000)!;
    assert.equal(second.attempts, 2);
    assert.equal(await first, true);
    assert.equal(db.attemptActive(id, second.attempts, second.leaseToken), true);
    assert.equal(db.finishWithResult(id, second.attempts, [], '0.69.3', second.leaseToken), true);
    assert.equal(db.state(id, 'alice'), 'completed');
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
