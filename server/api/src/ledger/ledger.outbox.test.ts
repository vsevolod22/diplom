import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import test from 'node:test';
import { IdempotencyConflict, ScanLedger, type PinnedTarget } from './ledger.js';

const target: PinnedTarget = { subject: 'alice', idempotencyKey: 'k', registry: 'registry.example.com',
  repository: 'org/app', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  fingerprint: 'b'.repeat(64), checks: '["vuln"]', scope: 'image' };

test('lease expiry, retry, stale ack, terminal replay and subject isolation survive restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-outbox-'));
  try {
    const filename = join(dir, 'ledger.sqlite');
    let ledger = new ScanLedger(filename);
    const first = ledger.enqueue(target);
    const job = ledger.claim(1000, 100);
    assert.equal(job?.scanId, first.scanId);
    assert.equal(job?.digest, target.digest);
    assert.equal(ledger.claim(1050), undefined);
    ledger.close();
    ledger = new ScanLedger(filename);
    const recovered = ledger.claim(1100, 100);
    assert.equal(recovered?.attempts, 2);
    assert.equal(ledger.finish(first.scanId, 1, 'failed'), false);
    assert.equal(ledger.retry(first.scanId, 2, 2000), true);
    assert.equal(ledger.claim(1999), undefined);
    const final = ledger.claim(2000);
    assert.equal(final?.attempts, 3);
    assert.equal(ledger.finish(first.scanId, 3, 'failed'), true);
    assert.equal(ledger.finish(first.scanId, 3, 'failed'), false);
    assert.equal(ledger.claim(999999), undefined);
    assert.equal(ledger.state(first.scanId, 'alice'), 'failed');
    assert.equal(ledger.state(first.scanId, 'bob'), undefined);
    assert.deepEqual(ledger.enqueue(target), { ...first, created: false });
    assert.throws(() => ledger.enqueue({ ...target, fingerprint: 'c'.repeat(64) }), IdempotencyConflict);
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('migrates old schema atomically without losing queued scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-migrate-'));
  try {
    const filename = join(dir, 'ledger.sqlite');
    const db = new Database(filename);
    db.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
      state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(subject,idempotency_key));
      CREATE TABLE outbox (scan_id TEXT PRIMARY KEY REFERENCES scans(id), delivered_at TEXT);
      PRAGMA user_version = 1;`);
    db.prepare('INSERT INTO scans(id,subject,idempotency_key,registry,repository,digest,platform,state) VALUES(?,?,?,?,?,?,?,?)')
      .run('old-id', target.subject, target.idempotencyKey, target.registry, target.repository, target.digest, target.platform, 'queued');
    db.prepare('INSERT INTO outbox(scan_id) VALUES(?)').run('old-id');
    db.close();
    const ledger = new ScanLedger(filename);
    assert.equal(ledger.claim(100)?.scanId, 'old-id');
    ledger.close();
    const migrated = new Database(filename);
    assert.equal(migrated.pragma('user_version', { simple: true }), 13);
    migrated.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
