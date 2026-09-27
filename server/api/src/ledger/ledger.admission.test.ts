import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import { AdmissionLimited, ScanLedger } from './ledger.js';

const target = { subject: 'alice', registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64', checks: '["secret"]' };
test('global queue capacity is bounded even with distinct subjects and keys', () => {
  const dir = mkdtempSync(join(tmpdir(), 'admission-global-'));
  try {
    const file = join(dir, 'db.sqlite');
    const a = new ScanLedger(file);
    const b = new ScanLedger(file);
    for (let i = 0; i < 30; i++) (i % 2 ? a : b).enqueue({ ...target, subject: `user${i}`, idempotencyKey: `key${i}` });
    assert.throws(() => b.enqueue({ ...target, subject: 'other', idempotencyKey: 'key-new' }), AdmissionLimited);
    assert.equal(a.pending().length, 30);
    a.close(); b.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('capacity is atomic across connections, persisted across restart and replay does not spend a slot', () => {
  const dir = mkdtempSync(join(tmpdir(), 'admission-'));
  try {
    const file = join(dir, 'db.sqlite');
    const a = new ScanLedger(file);
    let b = new ScanLedger(file);
    const first = a.enqueue({ ...target, idempotencyKey: 'first-key' });
    b.enqueue({ ...target, idempotencyKey: 'second-key' });
    a.enqueue({ ...target, idempotencyKey: 'third-key' });
    assert.deepEqual(b.enqueue({ ...target, idempotencyKey: 'first-key' }), { ...first, created: false });
    assert.throws(() => b.enqueue({ ...target, idempotencyKey: 'fourth-key' }), AdmissionLimited);
    assert.equal(b.pending().length, 3);
    b.close(); b = new ScanLedger(file);
    assert.throws(() => b.checkAdmission('alice'), AdmissionLimited);
    assert.equal(b.checkAdmission('bob'), undefined);
    const firstJob = b.claim()!;
    assert.equal(a.finish(firstJob.scanId, firstJob.attempts, 'failed'), true);
    assert.equal(b.enqueue({ ...target, idempotencyKey: 'fourth-key' }).created, true);
    const db = new Database(file);
    for (let i = 0; i < 6; i++) a.reserveAttempt('alice', 60000);
    assert.throws(() => b.reserveAttempt('alice', 60000), AdmissionLimited);
    assert.equal((db.prepare('SELECT count AS n FROM admission_windows WHERE subject = ?').get('alice') as { n: number }).n, 6);
    assert.equal((db.prepare("SELECT count(*) AS n FROM scan_audit WHERE decision = 'accepted'").get() as { n: number }).n, 4);
    assert.throws(() => a.audit('alice', 'unknown', 'unknown', 'rejected', 'EGRESS', 'signed://canary'), TypeError);
    a.audit('anonymous', 'unknown', 'unknown', 'rejected', 'UNAUTHORIZED');
    assert.equal((db.prepare("SELECT count(*) AS n FROM scan_audit WHERE reason = 'UNAUTHORIZED'").get() as { n: number }).n, 1);
    db.close(); a.close(); b.close();
    const restarted = new ScanLedger(file);
    assert.throws(() => restarted.reserveAttempt('alice', 60000), AdmissionLimited);
    restarted.reserveAttempt('alice', 120000);
    restarted.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
