import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import test from 'node:test';
import { IdempotencyConflict, ScanLedger, type PinnedTarget } from './ledger.js';

const target: PinnedTarget = {
  subject: 'alice', idempotencyKey: 'key', registry: 'registry.example.com', repository: 'app',
  digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', fingerprint: 'b'.repeat(64),
  checks: '["vuln"]', scope: 'image',
};

function fixture(file: string, version: 1 | 2): void {
  const db = new Database(file);
  try {
    db.exec(`CREATE TABLE scans (
      id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(subject,idempotency_key)
    );
    CREATE TABLE outbox (scan_id TEXT PRIMARY KEY REFERENCES scans(id), delivered_at TEXT);`);
    if (version === 2) db.exec(`ALTER TABLE scans ADD COLUMN fingerprint TEXT;
      ALTER TABLE scans ADD COLUMN checks TEXT NOT NULL DEFAULT '[]';
      ALTER TABLE scans ADD COLUMN scope TEXT NOT NULL DEFAULT 'image';
      ALTER TABLE scans ADD COLUMN terminal_at TEXT;
      ALTER TABLE outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE outbox ADD COLUMN lease_until INTEGER;
      ALTER TABLE outbox ADD COLUMN next_run_at INTEGER NOT NULL DEFAULT 0;`);
    db.prepare(`INSERT INTO scans(id,subject,idempotency_key,registry,repository,digest,platform,state)
      VALUES ('existing','alice','key',?,?,?,?, 'queued')`).run(target.registry, target.repository, target.digest, target.platform);
    db.prepare("INSERT INTO outbox(scan_id) VALUES ('existing')").run();
    db.pragma(`user_version = ${version}`);
  } finally { db.close(); }
}

test('fresh v0 initializes once and enforces foreign keys on every ledger connection', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-fresh-'));
  try {
    const file = join(dir, 'ledger.sqlite');
    const ledger = new ScanLedger(file);
    const second = new ScanLedger(file);
    const created = ledger.enqueue(target);
    assert.equal(second.state(created.scanId, target.subject), 'queued');
    const db = new Database(file);
    try {
      assert.equal(db.pragma('user_version', { simple: true }), 2);
      assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
      assert.deepEqual(db.pragma('foreign_key_check'), []);
      // An external connection must opt in separately; the ledger opts in at construction.
      db.pragma('foreign_keys = ON');
      assert.throws(() => db.prepare("INSERT INTO outbox(scan_id) VALUES ('missing')").run(), /FOREIGN KEY constraint failed/);
    } finally { db.close(); second.close(); ledger.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('v1 and v2 fixtures retain rows, defaults, uniqueness, FK and version after reopen', () => {
  for (const version of [1, 2] as const) {
    const dir = mkdtempSync(join(tmpdir(), 'ledger-version-'));
    try {
      const file = join(dir, 'ledger.sqlite');
      fixture(file, version);
      const ledger = new ScanLedger(file);
      assert.deepEqual(ledger.findByKey('alice', 'key'), { scanId: 'existing', digest: target.digest, platform: target.platform, fingerprint: null });
      assert.deepEqual(ledger.enqueue({ ...target, fingerprint: undefined }), { scanId: 'existing', created: false });
      ledger.close();
      const reopened = new ScanLedger(file);
      assert.deepEqual(reopened.pending(), [{ scanId: 'existing', digest: target.digest, platform: target.platform }]);
      reopened.close();
      const db = new Database(file);
      try {
        assert.equal(db.pragma('user_version', { simple: true }), 2);
        assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
        assert.deepEqual(db.pragma('foreign_key_check'), []);
        assert.equal((db.prepare('SELECT count(*) AS n FROM scans').get() as { n: number }).n, 1);
        assert.deepEqual(db.prepare('SELECT attempts, next_run_at, delivered_at FROM outbox').get(),
          { attempts: 0, next_run_at: 0, delivered_at: null });
        assert.deepEqual(db.prepare('SELECT checks, scope, terminal_at FROM scans').get(),
          { checks: '[]', scope: 'image', terminal_at: null });
        assert.throws(() => db.prepare(`INSERT INTO scans (id,subject,idempotency_key,registry,repository,digest,platform,state)
          VALUES ('duplicate','alice','key',?,?,?,?, 'queued')`).run(target.registry, target.repository, target.digest, target.platform),
          /UNIQUE constraint failed/);
      } finally { db.close(); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test('failed upgrade rolls back DDL and version; future and ambiguous v0 fail closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-failure-'));
  try {
    const file = join(dir, 'ledger.sqlite');
    fixture(file, 1);
    const db = new Database(file);
    db.exec('ALTER TABLE scans ADD COLUMN fingerprint TEXT'); // simulate interrupted/manual partial upgrade
    db.close();
    assert.throws(() => new ScanLedger(file), /duplicate column name/);
    const after = new Database(file);
    assert.equal(after.pragma('user_version', { simple: true }), 1);
    assert.equal((after.prepare('SELECT count(*) AS n FROM scans').get() as { n: number }).n, 1);
    assert.equal((after.prepare("SELECT count(*) AS n FROM pragma_table_info('scans') WHERE name = 'checks'").get() as { n: number }).n, 0);
    after.pragma('user_version = 3');
    after.close();
    assert.throws(() => new ScanLedger(file), /Unsupported ledger version/);
    const unversioned = join(dir, 'ambiguous.sqlite');
    const legacy = new Database(unversioned);
    legacy.exec('CREATE TABLE scans(id TEXT)');
    legacy.close();
    assert.throws(() => new ScanLedger(unversioned), /Unversioned ledger/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('online SQLite backup includes committed WAL rows and restores a functional ledger', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-backup-'));
  try {
    const file = join(dir, 'ledger.sqlite');
    const backup = join(dir, 'backup.sqlite');
    const ledger = new ScanLedger(file);
    const created = ledger.enqueue(target);
    const reader = new Database(file);
    try { await reader.backup(backup); } finally { reader.close(); ledger.close(); }
    const restored = new ScanLedger(backup);
    assert.deepEqual(restored.findByKey('alice', 'key'), { scanId: created.scanId, digest: target.digest, platform: target.platform, fingerprint: target.fingerprint });
    assert.equal(restored.pending().length, 1);
    restored.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('outbox insertion failure rolls back the scan and permits a later retry', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-rollback-'));
  try {
    const file = join(dir, 'ledger.sqlite');
    const ledger = new ScanLedger(file);
    const db = new Database(file);
    try {
      db.exec(`CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'outbox unavailable'); END`);
      assert.throws(() => ledger.enqueue(target), /outbox unavailable/);
      assert.equal(ledger.findByKey('alice', 'key'), undefined);
      assert.deepEqual(ledger.pending(), []);
      db.exec('DROP TRIGGER reject_outbox');
      assert.equal(ledger.enqueue(target).created, true);
      assert.equal(ledger.pending().length, 1);
    } finally { db.close(); ledger.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('two connections serialize keys and claims; expired owner cannot retry or ack', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-connections-'));
  try {
    const file = join(dir, 'ledger.sqlite');
    const a = new ScanLedger(file);
    const b = new ScanLedger(file);
    try {
      const created = a.enqueue(target);
      assert.deepEqual(b.enqueue(target), { scanId: created.scanId, created: false });
      assert.throws(() => b.enqueue({ ...target, digest: `sha256:${'c'.repeat(64)}` }), IdempotencyConflict);
      assert.equal(b.pending().length, 1);
      const first = a.claim(1000, 100);
      assert.equal(first?.attempts, 1);
      assert.equal(b.claim(1099), undefined);
      const second = b.claim(1100, 100);
      assert.equal(second?.scanId, created.scanId);
      assert.equal(second?.attempts, 2);
      assert.equal(a.retry(created.scanId, 1, 3000), false);
      assert.equal(a.finish(created.scanId, 1, 'failed'), false);
      assert.equal(b.retry(created.scanId, 2, 2000), true);
      assert.equal(a.claim(1999), undefined);
      assert.equal(a.claim(2000)?.attempts, 3);
      assert.equal(b.finish(created.scanId, 2, 'failed'), false);
      assert.equal(a.finish(created.scanId, 3, 'completed'), true);
      assert.equal(b.finish(created.scanId, 3, 'failed'), false);
      assert.equal(b.state(created.scanId, 'alice'), 'completed');
    } finally { a.close(); b.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
