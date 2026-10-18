import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from './ledger.js';

const target = (key: string) => ({ subject: 'alice', idempotencyKey: key, registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64', checks: '["secret"]' });

test('subject-scoped cancel atomically delivers queued and running work, fencing late results', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cancel-ledger-'));
  const file = join(dir, 'ledger.sqlite');
  try {
    const db = new ScanLedger(file);
    const queued = db.enqueue(target('queued')).scanId;
    assert.equal(db.cancel(queued, 'bob'), 'not_found');
    assert.equal(db.cancel('00000000-0000-0000-0000-000000000000', 'alice'), 'not_found');
    assert.equal(db.cancel(queued, 'alice'), 'cancelled');
    assert.equal(db.cancel(queued, 'alice'), 'already_cancelled');
    assert.equal(db.pending().some(row => row.scanId === queued), false);
    assert.equal(db.claim(), undefined);
    assert.equal(db.result(queued, 'alice'), undefined);
    assert.deepEqual(db.events(queued, 'alice', null)?.map(e => e.state), ['queued', 'cancelled']);
    const running = db.enqueue(target('running')).scanId;
    const job = db.claim()!;
    assert.equal(db.attemptActive(running, job.attempts, job.leaseToken), true);
    assert.equal(db.cancel(running, 'alice'), 'cancelled');
    assert.equal(db.attemptActive(running, job.attempts, job.leaseToken), false);
    assert.equal(db.retry(running, job.attempts, 0, job.leaseToken), false);
    assert.equal(db.finishWithResult(running, job.attempts, [], '0.69.3', job.leaseToken), false);
    assert.equal(db.finish(running, job.attempts, 'failed', undefined, job.leaseToken), false);
    assert.equal(db.state(running, 'alice'), 'cancelled');
    assert.equal(db.result(running, 'alice'), undefined);
    assert.equal(db.claim(), undefined);
    const complete = db.enqueue(target('complete')).scanId;
    const next = db.claim()!;
    assert.equal(db.finishWithResult(complete, next.attempts, [], '0.69.3', next.leaseToken), true);
    assert.equal(db.cancel(complete, 'alice'), 'conflict');
    const failed = db.enqueue(target('failed')).scanId;
    const last = db.claim()!;
    assert.equal(db.finish(failed, last.attempts, 'failed', undefined, last.leaseToken), true);
    assert.equal(db.cancel(failed, 'alice'), 'conflict');
    db.close();
    const reopened = new ScanLedger(file);
    assert.equal(reopened.state(queued, 'alice'), 'cancelled');
    assert.equal(reopened.state(running, 'alice'), 'cancelled');
    assert.equal(reopened.claim(), undefined);
    reopened.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
