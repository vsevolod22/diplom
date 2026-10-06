import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import test from 'node:test';
import { ScanLedger, type PinnedTarget } from './ledger.js';
import type { VulnFinding } from '../worker/vuln-findings.js';

const target: PinnedTarget = { subject: 'alice', idempotencyKey: 'vuln', registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["vuln"]', scope: 'image' };
const image = `${target.registry}/${target.repository}@${target.digest}`;
function finding(cveId: string): VulnFinding {
  const ecosystem = 'apk';
  const provenanceRef = `target-${'b'.repeat(64)}`;
  const packageName = 'busybox';
  const installedVersion = '1.2-r0';
  const key = JSON.stringify([ecosystem, provenanceRef, cveId, packageName, installedVersion]);
  return { findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`, cveId, ecosystem,
    provenanceRef, packageName, installedVersion, fixedVersion: null, severity: 'HIGH',
    severitySources: ['alpine', 'nvd'] };
}
const findings = [finding('CVE-2025-1234'), finding('CVE-2025-5678')];
function fixture(fn: (file: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-vuln-'));
  try { fn(join(dir, 'ledger.sqlite')); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function count(db: Database.Database, table: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

test('v7 upgrades forward through v8/v9 without modifying legacy rows, and results survive reopen with owner pagination', () => fixture(file => {
  let ledger = new ScanLedger(file);
  const legacy = ledger.enqueue({ ...target, checks: '["secret"]', idempotencyKey: 'legacy' }).scanId;
  ledger.close();
  const raw = new Database(file);
  raw.exec('DROP TABLE scan_check_results; DROP TABLE scan_vuln_findings; DROP TABLE scan_vuln_results; PRAGMA user_version = 7;');
  raw.close();
  ledger = new ScanLedger(file);
  assert.equal(ledger.state(legacy, 'alice'), 'queued');
  const old = ledger.claim()!;
  assert.equal(ledger.finishWithResult(legacy, old.attempts, [], '0.69.3'), true);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  assert.equal(job.scanId, scanId);
  assert.equal(ledger.finishWithVuln(scanId, job.attempts, image, findings, '0.69.3'), true);
  assert.equal(ledger.finishWithVuln(scanId, job.attempts, image, findings, '0.69.3'), false);
  ledger.close();
  ledger = new ScanLedger(file);
  const page = ledger.vuln(scanId, 'alice', 0, 1)!;
  assert.equal(page.outcome, 'checked');
  if (page.outcome !== 'checked') throw new Error('Expected checked result');
  assert.deepEqual({ image: page.image, platform: page.platform, findingCount: page.findingCount,
    coverage: page.coverage, scannerVersion: page.scannerVersion, findings: page.findings, nextCursor: page.nextCursor },
  { image, platform: 'linux/amd64', findingCount: 2, coverage: 'image', scannerVersion: '0.69.3',
    findings: [findings[0]], nextCursor: 1 });
  assert.ok(page.checkedAt);
  assert.deepEqual(ledger.vuln(scanId, 'alice', 1, 1)?.findings, [findings[1]]);
  assert.equal(ledger.vuln(scanId, 'alice', 1, 1)?.nextCursor, null);
  assert.deepEqual(ledger.vuln(scanId, 'alice', 2)?.findings, []);
  assert.equal(ledger.vuln(scanId, 'bob'), undefined);
  assert.equal(ledger.vuln('missing', 'alice'), undefined);
  assert.equal(ledger.vuln(legacy, 'alice'), undefined);
  assert.equal(ledger.result(scanId, 'alice'), undefined);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'completed']);
  ledger.close();
  const db = new Database(file);
  assert.equal(db.pragma('user_version', { simple: true }), 11);
  assert.equal(count(db, 'scan_vuln_results'), 1);
  assert.equal(count(db, 'scan_vuln_findings'), 2);
  assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  db.close();
}));

test('wrong image, digest, checks or scope rolls back delivery and events', () => fixture(file => {
  const ledger = new ScanLedger(file);
  for (const [i, changes, reportImage] of [
    [0, {}, image.replace('a'.repeat(64), 'b'.repeat(64))],
    [1, { digest: `sha256:${'b'.repeat(64)}` }, image],
    [2, { checks: '["sbom"]' }, image],
    [3, { checks: '["secret","vuln"]' }, image],
    [4, { scope: 'repository' }, image],
  ] as const) {
    const scanId = ledger.enqueue({ ...target, ...changes, idempotencyKey: `wrong-${i}` }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    assert.throws(() => ledger.finishWithVuln(scanId, job.attempts, reportImage, findings, '0.69.3'));
    assert.equal(ledger.state(scanId, 'alice'), 'running');
    assert.equal(ledger.vuln(scanId, 'alice'), undefined);
    assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
    assert.equal(ledger.cancel(scanId, 'alice'), 'cancelled');
  }
  ledger.close();
  const db = new Database(file);
  assert.equal(count(db, 'scan_vuln_results'), 0);
  assert.equal(count(db, 'scan_vuln_findings'), 0);
  db.close();
}));

test('stale and cancelled attempts cannot publish findings', () => fixture(file => {
  const a = new ScanLedger(file);
  const b = new ScanLedger(file);
  const scanId = a.enqueue(target).scanId;
  const first = a.claim(1000, 100)!;
  const second = b.claim(1100, 100)!;
  assert.equal(a.finishWithVuln(scanId, first.attempts, image, findings, '0.69.3'), false);
  assert.equal(b.cancel(scanId, 'bob'), 'not_found');
  assert.equal(b.cancel(scanId, 'alice'), 'cancelled');
  assert.equal(a.finishWithVuln(scanId, second.attempts, image, findings, '0.69.3'), false);
  assert.equal(a.vuln(scanId, 'alice'), undefined);
  a.close(); b.close();
}));

test('invalid or duplicate bounded findings and pagination reject; insertion failure rolls back transaction', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  const bad: unknown[] = [null, Array(1001).fill(findings[0]), [findings[0], findings[0]],
    [{ ...findings[0], cveId: 'CVE-2025-9999' }], [{ ...findings[0], severitySources: ['nvd', 'nvd'] }],
    [{ ...findings[0], severitySources: ['https://secret'] }],
    [{ ...findings[0], fixedVersion: 'x'.repeat(81) }], [{ ...findings[0], raw: 'secret' }]];
  for (const value of bad) assert.throws(() => ledger.finishWithVuln(scanId, job.attempts, image,
    value as VulnFinding[], '0.69.3'), TypeError);
  assert.throws(() => ledger.finishWithVuln(scanId, job.attempts, image, findings, 'untrusted'), TypeError);
  for (const [cursor, limit] of [[-1, 1], [0, 0], [0, 101], [1.5, 1]])
    assert.throws(() => ledger.vuln(scanId, 'alice', cursor, limit), TypeError);
  const db = new Database(file);
  db.exec(`CREATE TRIGGER reject_finding BEFORE INSERT ON scan_vuln_findings
    BEGIN SELECT RAISE(ABORT, 'finding unavailable'); END`);
  assert.throws(() => ledger.finishWithVuln(scanId, job.attempts, image, findings, '0.69.3'), /finding unavailable/);
  assert.equal(ledger.state(scanId, 'alice'), 'running');
  assert.equal(ledger.vuln(scanId, 'alice'), undefined);
  assert.equal(count(db, 'scan_vuln_results'), 0);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
  db.exec('DROP TRIGGER reject_finding');
  assert.equal(ledger.finishWithVuln(scanId, job.attempts, image, [], '0.69.3'), true);
  const zero = ledger.vuln(scanId, 'alice');
  assert.equal(zero?.outcome, 'checked');
  if (zero?.outcome !== 'checked') throw new Error('Expected checked result');
  assert.equal(zero.findingCount, 0);
  db.close(); ledger.close();
}));

test('standalone vuln failure records failed coverage, never a false zero or secret result', () => fixture(file => {
  let ledger = new ScanLedger(file);
  for (const [i, code] of (['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE'] as const).entries()) {
    const scanId = ledger.enqueue({ ...target, idempotencyKey: `failure-${i}` }).scanId;
    const job = ledger.claim()!;
    assert.equal(ledger.finish(scanId, job.attempts, 'failed', code), true);
    assert.equal(ledger.finish(scanId, job.attempts, 'failed', code), false);
    assert.equal(ledger.result(scanId, 'alice'), undefined);
    assert.deepEqual(ledger.vuln(scanId, 'alice'), { coverage: 'image', outcome: 'failed',
      errorCode: code, findings: [], nextCursor: null });
    assert.equal(ledger.vuln(scanId, 'bob'), undefined);
    assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'failed']);
  }
  ledger.close(); ledger = new ScanLedger(file);
  const db = new Database(file);
  assert.equal(count(db, 'scan_vuln_results'), 3);
  assert.equal(count(db, 'scan_vuln_findings'), 0);
  assert.deepEqual(db.prepare('SELECT finding_count,scanner_version,checked_at FROM scan_vuln_results').all(),
    Array(3).fill({ finding_count: null, scanner_version: null, checked_at: null }));
  db.close(); ledger.close();
}));

test('failure-result insertion abort rolls back outbox, terminal state and event', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  const db = new Database(file);
  db.exec(`CREATE TRIGGER reject_failure BEFORE INSERT ON scan_vuln_results
    BEGIN SELECT RAISE(ABORT, 'result unavailable'); END`);
  assert.throws(() => ledger.finish(scanId, job.attempts, 'failed', 'SCAN_TIMEOUT'), /result unavailable/);
  assert.equal(ledger.state(scanId, 'alice'), 'running');
  assert.equal(ledger.vuln(scanId, 'alice'), undefined);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
  db.exec('DROP TRIGGER reject_failure');
  assert.equal(ledger.finish(scanId, job.attempts, 'failed', 'SCAN_TIMEOUT'), true);
  db.close(); ledger.close();
}));

test('v8 migration failure rolls back schema and version', () => fixture(file => {
  const ledger = new ScanLedger(file);
  ledger.close();
  const raw = new Database(file);
  raw.exec('DROP TABLE scan_check_results; DROP TABLE scan_vuln_findings; DROP TABLE scan_vuln_results; PRAGMA user_version = 7; CREATE TABLE scan_vuln_findings (sentinel TEXT);');
  raw.close();
  assert.throws(() => new ScanLedger(file), /already exists/);
  const after = new Database(file);
  assert.equal(after.pragma('user_version', { simple: true }), 7);
  assert.equal((after.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'scan_vuln_results'").get() as { n: number }).n, 0);
  assert.equal(after.pragma('integrity_check', { simple: true }), 'ok');
  after.close();
}));
