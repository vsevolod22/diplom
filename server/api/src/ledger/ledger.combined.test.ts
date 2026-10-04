import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import test from 'node:test';
import { ScanLedger, type CombinedOutcome, type PinnedTarget } from './ledger.js';

const target: PinnedTarget = { subject: 'alice', idempotencyKey: 'combined', registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["secret","sbom","vuln"]', scope: 'image' };
const image = `${target.registry}/${target.repository}@${target.digest}`;
const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3',
  findings: [{ findingId: 'secret-0-0', ruleId: 'test-rule', evidenceRef: 'result-0-secret-0', line: 1 }] };
const sbom: CombinedOutcome = { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3',
  sbom: { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' },
    components: [{ ecosystem: 'apk', name: 'busybox', version: '1.2-r0' }] } };
const provenanceRef = `target-${'b'.repeat(64)}`;
const key = JSON.stringify(['apk', provenanceRef, 'CVE-2025-1234', 'busybox', '1.2-r0']);
const vuln: CombinedOutcome = { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3', image,
  findings: [{ findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`,
    cveId: 'CVE-2025-1234', ecosystem: 'apk', packageName: 'busybox', installedVersion: '1.2-r0',
    severity: 'HIGH', severitySources: ['alpine', 'nvd'], provenanceRef, fixedVersion: null }] };
const fail = (check: 'secret' | 'sbom' | 'vuln'): CombinedOutcome =>
  ({ check, outcome: 'failed', errorCode: 'SCAN_TIMEOUT' });
function fixture(fn: (file: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-combined-'));
  try { fn(join(dir, 'ledger.sqlite')); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function count(db: Database.Database, table: string, scanId: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table} WHERE scan_id = ?`).get(scanId) as { n: number }).n;
}

test('v8 to v9 migration preserves rows, FKs, events, outbox and legacy secret result; partial survives reopen', () => fixture(file => {
  let ledger = new ScanLedger(file);
  const oldId = ledger.enqueue({ ...target, idempotencyKey: 'old', checks: '["secret"]' }).scanId;
  const oldJob = ledger.claim()!;
  assert.equal(ledger.finishWithResult(oldId, oldJob.attempts, secret.outcome === 'checked' ? secret.findings : [], '0.69.3'), true);
  const queued = ledger.enqueue({ ...target, idempotencyKey: 'queued' }).scanId;
  ledger.close();
  const raw = new Database(file);
  // Restore the actual v8 state CHECK while retaining the FK-linked rows.
  raw.pragma('foreign_keys = OFF');
  raw.exec(`BEGIN IMMEDIATE;
    CREATE TABLE scans_v8 (
      id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, fingerprint TEXT,
      checks TEXT NOT NULL DEFAULT '[]', scope TEXT NOT NULL DEFAULT 'image', terminal_at TEXT,
      UNIQUE(subject,idempotency_key)
    );
    INSERT INTO scans_v8 SELECT * FROM scans;
    DROP TABLE scans; ALTER TABLE scans_v8 RENAME TO scans;
    PRAGMA user_version = 8;
    COMMIT;`);
  raw.pragma('foreign_keys = ON');
  assert.deepEqual(raw.pragma('foreign_key_check'), []);
  assert.throws(() => raw.prepare("UPDATE scans SET state = 'partial' WHERE id = ?").run(queued), /CHECK constraint/);
  raw.close();
  ledger = new ScanLedger(file);
  assert.equal(ledger.result(oldId, 'alice')?.findingCount, 1);
  assert.equal(ledger.state(queued, 'alice'), 'queued');
  const job = ledger.claim()!;
  assert.equal(job.scanId, queued);
  assert.equal(ledger.finishCombined(queued, job.attempts, [secret, sbom, fail('vuln')]), true);
  assert.equal(ledger.state(queued, 'alice'), 'partial');
  ledger.close(); ledger = new ScanLedger(file);
  assert.equal(ledger.state(queued, 'alice'), 'partial');
  assert.deepEqual(ledger.events(queued, 'alice', null)?.map(e => e.state), ['queued','running','partial']);
  assert.equal(ledger.result(queued, 'alice')?.findingCount, 1);
  assert.equal(ledger.sbom(queued, 'alice')?.outcome, 'checked');
  assert.deepEqual(ledger.vuln(queued, 'alice'), { outcome: 'failed', coverage: 'image',
    errorCode: 'SCAN_TIMEOUT', findings: [], nextCursor: null });
  assert.equal(ledger.result(queued, 'bob'), undefined);
  assert.equal(ledger.sbom(queued, 'bob'), undefined);
  assert.equal(ledger.vuln(queued, 'bob'), undefined);
  ledger.close();
  const db = new Database(file);
  assert.equal(db.pragma('user_version', { simple: true }), 9);
  db.pragma('foreign_keys = ON');
  assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  assert.equal(count(db, 'outbox', queued), 1);
  assert.equal(count(db, 'scan_events', oldId), 3);
  assert.throws(() => db.prepare("INSERT INTO scan_events(scan_id,state) VALUES ('missing','running')").run(), /FOREIGN KEY/);
  db.close();
}));

test('all checked, all failed, mixed secret failure, two-check and single-check subsets produce exact terminal states', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const cases: Array<[string, CombinedOutcome[], string]> = [
    ['["secret","sbom","vuln"]', [secret, sbom, vuln], 'completed'],
    ['["secret","sbom","vuln"]', [fail('secret'), fail('sbom'), fail('vuln')], 'failed'],
    ['["secret","sbom"]', [fail('secret'), sbom], 'partial'],
    ['["secret","vuln"]', [secret, fail('vuln')], 'partial'],
    ['["sbom","vuln"]', [fail('sbom'), vuln], 'partial'],
    ['["vuln"]', [vuln], 'completed'],
  ];
  for (const [i, [checks, outcomes, expected]] of cases.entries()) {
    const scanId = ledger.enqueue({ ...target, idempotencyKey: `case-${i}`, checks }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    assert.equal(ledger.finishCombined(scanId, job.attempts, outcomes), true);
    assert.equal(ledger.finishCombined(scanId, job.attempts, outcomes), false);
    assert.equal(ledger.state(scanId, 'alice'), expected);
    assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued','running',expected]);
    assert.equal(ledger.result(scanId, 'alice')?.outcome, checks.includes('secret') ? outcomes[0].outcome : undefined);
    if (outcomes[0].check === 'secret' && outcomes[0].outcome === 'failed') {
      assert.equal(ledger.result(scanId, 'alice')?.findingCount, null);
      assert.deepEqual(ledger.findings(scanId, 'alice')?.findings, []);
      const raw = new Database(file);
      assert.equal((raw.prepare('SELECT finding_count FROM scan_results WHERE scan_id = ?')
        .get(scanId) as { finding_count: number | null }).finding_count, null);
      raw.close();
    }
    assert.equal(ledger.sbom(scanId, 'alice')?.outcome, checks.includes('sbom') ? outcomes.find(o => o.check === 'sbom')?.outcome : undefined);
    assert.equal(ledger.vuln(scanId, 'alice')?.outcome, checks.includes('vuln') ? outcomes.find(o => o.check === 'vuln')?.outcome : undefined);
  }
  ledger.close();
}));

test('invalid sets, unbound images, malformed payloads and duplicate findings cannot deliver', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const invalid: unknown[] = [[], [secret, secret], [sbom, secret, vuln], [secret, sbom],
    [secret, sbom, fail('vuln'), vuln],
    [secret, { ...sbom, sbom: { ...('sbom' in sbom ? sbom.sbom : {}), image: image.replace('a'.repeat(64), 'b'.repeat(64)) } }, vuln],
    [secret, sbom, { ...vuln, image: image.replace('a'.repeat(64), 'b'.repeat(64)) }],
    [{ ...secret, findings: [secret.outcome === 'checked' ? secret.findings[0] : {}, secret.outcome === 'checked' ? secret.findings[0] : {}] }, sbom, vuln],
    [secret, { ...sbom, sbom: { ...('sbom' in sbom ? sbom.sbom : {}), components: [] } }, vuln],
    [secret, sbom, { ...vuln, findings: [{ ...('findings' in vuln ? vuln.findings[0] : {}), severitySources: ['raw-url'] }] }],
    [secret, sbom, { ...vuln, findings: Array(1001).fill('findings' in vuln ? vuln.findings[0] : {}) }],
    [fail('secret'), fail('sbom'), { ...fail('vuln'), errorCode: 'RAW' }],
    [{ ...secret, scannerVersion: 'untrusted' }, sbom, vuln],
    [{ ...secret, raw: 'secret' }, sbom, vuln],
  ];
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  for (const value of invalid) assert.throws(() => ledger.finishCombined(scanId, job.attempts, value as CombinedOutcome[]));
  assert.equal(ledger.state(scanId, 'alice'), 'running');
  const db = new Database(file);
  for (const table of ['scan_results','scan_sbom_results','scan_vuln_results']) assert.equal(count(db, table, scanId), 0);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued','running']);
  assert.equal(ledger.finishCombined(scanId, job.attempts, [secret, sbom, vuln]), true);
  db.close(); ledger.close();
}));

test('stale and cancelled attempts cannot publish; write failure rolls back every check and outbox', () => fixture(file => {
  const a = new ScanLedger(file); const b = new ScanLedger(file);
  const staleId = a.enqueue({ ...target, idempotencyKey: 'stale' }).scanId;
  const first = a.claim(1000, 100)!; const second = b.claim(1100, 100)!;
  assert.equal(a.finishCombined(staleId, first.attempts, [secret, sbom, vuln]), false);
  assert.equal(a.cancel(staleId, 'alice'), 'cancelled');
  assert.equal(b.finishCombined(staleId, second.attempts, [secret, sbom, vuln]), false);
  const scanId = a.enqueue({ ...target, idempotencyKey: 'rollback' }).scanId;
  const job = a.claim()!;
  const db = new Database(file);
  db.exec(`CREATE TRIGGER reject_vuln BEFORE INSERT ON scan_vuln_results
    BEGIN SELECT RAISE(ABORT, 'vuln unavailable'); END`);
  assert.throws(() => a.finishCombined(scanId, job.attempts, [secret, sbom, fail('vuln')]), /vuln unavailable/);
  assert.equal(a.state(scanId, 'alice'), 'running');
  for (const table of ['scan_results','scan_findings','scan_sbom_results','scan_sbom_components','scan_vuln_results'])
    assert.equal(count(db, table, scanId), 0);
  assert.equal((db.prepare('SELECT delivered_at FROM outbox WHERE scan_id = ?').get(scanId) as { delivered_at: string | null }).delivered_at, null);
  assert.deepEqual(a.events(scanId, 'alice', null)?.map(e => e.state), ['queued','running']);
  db.exec('DROP TRIGGER reject_vuln');
  assert.equal(a.finishCombined(scanId, job.attempts, [secret, sbom, fail('vuln')]), true);
  db.close(); a.close(); b.close();
}));

test('failed v9 migration restores v8 schema, FK-linked rows and version', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  ledger.close();
  const db = new Database(file);
  db.exec('PRAGMA user_version = 8; CREATE TABLE scans_v9 (sentinel TEXT);');
  db.close();
  assert.throws(() => new ScanLedger(file), /already exists/);
  const after = new Database(file);
  assert.equal(after.pragma('user_version', { simple: true }), 8);
  assert.equal((after.prepare('SELECT state FROM scans WHERE id = ?').get(scanId) as { state: string }).state, 'queued');
  assert.equal((after.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'scans_v9'")
    .get() as { n: number }).n, 1);
  assert.deepEqual(after.pragma('foreign_key_check'), []);
  assert.equal(after.pragma('integrity_check', { simple: true }), 'ok');
  after.close();
}));
