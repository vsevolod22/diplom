import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
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

test('subject-scoped snapshots and paged list survive reopen without exposing keys or foreign rows', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dip-list-'));
  const file = join(dir, 'scan.sqlite');
  try {
    const ledger = new ScanLedger(file);
    const a = ledger.enqueue(target).scanId;
    const b = ledger.enqueue({ ...target, idempotencyKey: 'request-2' }).scanId;
    ledger.enqueue({ ...target, subject: 'bob' });
    ledger.close();
    const reopened = new ScanLedger(file);
    assert.deepEqual(reopened.snapshot(a, 'alice'), { state: 'queued', digest: target.digest, platform: target.platform });
    assert.equal(reopened.snapshot(a, 'bob'), undefined);
    assert.deepEqual(reopened.list('bob').scans.map(row => row.scanId).length, 1);
    assert.deepEqual(reopened.list('nobody'), { scans: [], nextCursor: null });
    const first = reopened.list('alice', undefined, 1);
    assert.equal(first.scans.length, 1);
    assert.match(first.nextCursor!, /^[1-9]\d*:[1-9]\d*$/);
    reopened.enqueue({ ...target, idempotencyKey: 'request-3' });
    const second = reopened.list('alice', first.nextCursor!, 1);
    assert.equal(second.nextCursor, null);
    assert.equal(reopened.list('alice').scans.length, 3);
    assert.deepEqual(new Set([first.scans[0].scanId, second.scans[0].scanId]), new Set([a, b]));
    assert.equal(first.scans[0].targetLabel, `registry.lab.test/demo@${target.digest}`);
    assert.equal(JSON.stringify(first).includes('idempotencyKey'), false);
    assert.throws(() => reopened.list('alice', '-1', 1), TypeError);
    reopened.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('list cursor excludes later scans even when prune permits scan rowid reuse', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dip-list-prune-'));
  const file = join(dir, 'scan.sqlite');
  try {
    const ledger = new ScanLedger(file);
    ledger.enqueue(target);
    ledger.enqueue({ ...target, idempotencyKey: 'a2' });
    const removedId = ledger.enqueue({ ...target, subject: 'bob' }).scanId;
    const removedTop = ledger.enqueue({ ...target, idempotencyKey: 'a3' }).scanId;
    const first = ledger.list('alice', undefined, 1);
    ledger.close();
    const db = new Database(file);
    db.prepare("UPDATE scans SET state = 'completed', terminal_at = '2000-01-01' WHERE id IN (?, ?)").run(removedId, removedTop);
    db.close();
    const reopened = new ScanLedger(file);
    assert.equal(reopened.prune(), 2);
    const freshId = reopened.enqueue({ ...target, idempotencyKey: 'a5' }).scanId;
    const next = reopened.list('alice', first.nextCursor!, 1);
    assert.equal(next.scans.length, 1);
    assert.notEqual(next.scans[0].scanId, freshId);
    assert.ok(next.nextCursor);
    assert.equal(reopened.list('alice', next.nextCursor!, 1).nextCursor, null);
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
