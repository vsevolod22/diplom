import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import test from 'node:test';
import { ScanLedger, type PinnedTarget } from './ledger.js';
import type { ImageSbom } from '../worker/cyclonedx-components.js';

const target: PinnedTarget = { subject: 'alice', idempotencyKey: 'sbom', registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["sbom"]', scope: 'image' };
const image = `${target.registry}/${target.repository}@${target.digest}`;
const sbom: ImageSbom = { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' },
  components: [{ ecosystem: 'apk', name: 'alpine-baselayout', version: '3.6.8-r1' },
    { ecosystem: 'npm', name: '@org/module', version: '1.2.3' }] };

function fixture(fn: (file: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-sbom-'));
  try { fn(join(dir, 'ledger.sqlite')); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function count(db: Database.Database, table: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

test('v6 upgrades forward once; legacy rows stay untouched and SBOM survives reopen', () => fixture(file => {
  let ledger = new ScanLedger(file);
  const legacy = ledger.enqueue({ ...target, checks: '["secret"]', idempotencyKey: 'legacy' }).scanId;
  ledger.close();
  const raw = new Database(file);
  raw.exec('DROP TABLE scan_execution_profiles; DROP TABLE scan_check_results; DROP TABLE scan_vuln_findings; DROP TABLE scan_vuln_results; DROP TABLE scan_sbom_components; DROP TABLE scan_sbom_results; PRAGMA user_version = 6;');
  raw.close();
  ledger = new ScanLedger(file);
  assert.equal(ledger.state(legacy, 'alice'), 'queued');
  assert.equal(ledger.sbom(legacy, 'alice'), undefined);
  // Finish the legacy job before enqueueing SBOM so ordering is deterministic.
  const old = ledger.claim()!;
  assert.equal(old.scanId, legacy);
  assert.equal(ledger.finishWithResult(legacy, old.attempts, [], '0.69.3'), true);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  assert.equal(job.scanId, scanId);
  assert.equal(ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), true);
  ledger.close();
  ledger = new ScanLedger(file);
  const page = ledger.sbom(scanId, 'alice', 0, 1)!;
  assert.equal(page.outcome, 'checked');
  if (page.outcome !== 'checked') throw new Error('Expected checked SBOM');
  assert.deepEqual({ image: page.image, platform: page.platform, os: page.os,
    componentCount: page.componentCount, coverage: page.coverage, outcome: page.outcome,
    scannerVersion: page.scannerVersion, components: page.components, nextCursor: page.nextCursor },
  { image, platform: 'linux/amd64', os: sbom.os, componentCount: 2, coverage: 'image',
    outcome: 'checked', scannerVersion: '0.69.3', components: [sbom.components[0]], nextCursor: 1 });
  assert.ok(page.checkedAt);
  assert.deepEqual(ledger.sbom(scanId, 'alice', 1, 1)?.components, [sbom.components[1]]);
  assert.equal(ledger.sbom(scanId, 'alice', 1, 1)?.nextCursor, null);
  assert.deepEqual(ledger.sbom(scanId, 'alice', 2)?.components, []);
  assert.equal(ledger.sbom(scanId, 'bob'), undefined);
  assert.equal(ledger.sbom('missing', 'alice'), undefined);
  assert.equal(ledger.sbom(legacy, 'alice'), undefined);
  assert.equal(ledger.result(legacy, 'alice')?.check, 'secret');
  assert.equal(ledger.result(scanId, 'alice'), undefined);
  assert.equal(ledger.state(scanId, 'alice'), 'completed');
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'completed']);
  assert.equal(ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), false);
  ledger.close();
  const db = new Database(file);
  assert.equal(db.pragma('user_version', { simple: true }), 12);
  assert.equal(count(db, 'scan_sbom_results'), 1);
  assert.equal(count(db, 'scan_sbom_components'), 2);
  assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  db.close();
}));

test('wrong target, checks and scope roll back delivery, coverage and event', () => fixture(file => {
  const ledger = new ScanLedger(file);
  for (const [i, changes, report] of [
    [0, {}, { ...sbom, image: image.replace('a'.repeat(64), 'b'.repeat(64)) }],
    [1, { checks: '["vuln"]' }, sbom],
    [2, { scope: 'repository' }, sbom],
  ] as const) {
    const scanId = ledger.enqueue({ ...target, ...changes, idempotencyKey: `wrong-${i}` }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    assert.throws(() => ledger.finishWithSbom(scanId, job.attempts, report, '0.69.3'));
    assert.equal(ledger.state(scanId, 'alice'), 'running');
    assert.equal(ledger.sbom(scanId, 'alice'), undefined);
    assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
    assert.equal(ledger.cancel(scanId, 'alice'), 'cancelled');
  }
  ledger.close();
  const db = new Database(file);
  assert.equal(count(db, 'scan_sbom_results'), 0);
  assert.equal(count(db, 'scan_sbom_components'), 0);
  db.close();
}));

test('stale attempt and cancel cannot publish or duplicate SBOM', () => fixture(file => {
  const a = new ScanLedger(file);
  const b = new ScanLedger(file);
  const scanId = a.enqueue(target).scanId;
  const first = a.claim(1000, 100)!;
  const second = b.claim(1100, 100)!;
  assert.equal(a.finishWithSbom(scanId, first.attempts, sbom, '0.69.3'), false);
  assert.equal(b.cancel(scanId, 'bob'), 'not_found');
  assert.equal(b.cancel(scanId, 'alice'), 'cancelled');
  assert.equal(a.finishWithSbom(scanId, second.attempts, sbom, '0.69.3'), false);
  assert.equal(a.sbom(scanId, 'alice'), undefined);
  a.close();
  b.close();
}));

test('malformed inputs and pagination fail closed; insert failure rolls back atomically', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  const bad: unknown[] = [null, { ...sbom, components: [] }, { ...sbom, components: Array(1001).fill(sbom.components[0]) },
    { ...sbom, components: [sbom.components[0], sbom.components[0]] },
    { ...sbom, components: [{ ...sbom.components[0], name: 'secret=value' }] },
    { ...sbom, components: [{ ...sbom.components[0], purl: 'raw-secret' }] },
    { ...sbom, os: { name: 'ubuntu', version: '1' } }, { ...sbom, raw: 'secret' }];
  for (const value of bad) assert.throws(() => ledger.finishWithSbom(scanId, job.attempts, value as ImageSbom, '0.69.3'), TypeError);
  assert.throws(() => ledger.finishWithSbom(scanId, job.attempts, sbom, 'untrusted'), TypeError);
  for (const [cursor, limit] of [[-1, 1], [0, 0], [0, 101], [1.5, 1]])
    assert.throws(() => ledger.sbom(scanId, 'alice', cursor, limit), TypeError);
  const db = new Database(file);
  db.exec(`CREATE TRIGGER reject_component BEFORE INSERT ON scan_sbom_components
    BEGIN SELECT RAISE(ABORT, 'component unavailable'); END`);
  assert.throws(() => ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), /component unavailable/);
  assert.equal(ledger.state(scanId, 'alice'), 'running');
  assert.equal(ledger.sbom(scanId, 'alice'), undefined);
  assert.equal(count(db, 'scan_sbom_results'), 0);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
  db.exec('DROP TRIGGER reject_component');
  assert.equal(ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), true);
  assert.equal(ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), false);
  assert.equal(count(db, 'scan_sbom_components'), 2);
  db.close();
  ledger.close();
}));

test('SBOM failures survive reopen with subject-scoped coverage, not secret findings or invented checks', () => fixture(file => {
  let ledger = new ScanLedger(file);
  for (const [i, code] of (['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE'] as const).entries()) {
    const scanId = ledger.enqueue({ ...target, idempotencyKey: `failure-${i}` }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    assert.equal(ledger.finish(scanId, job.attempts, 'failed', code), true);
    assert.equal(ledger.finish(scanId, job.attempts, 'failed', code), false);
    assert.equal(ledger.state(scanId, 'alice'), 'failed');
    assert.equal(ledger.result(scanId, 'alice'), undefined);
    assert.deepEqual(ledger.sbom(scanId, 'alice'), { coverage: 'image', outcome: 'failed',
      errorCode: code, components: [], nextCursor: null });
    assert.equal(ledger.sbom(scanId, 'bob'), undefined);
    assert.equal(ledger.sbom('missing', 'alice'), undefined);
    assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'failed']);
  }
  ledger.close();
  ledger = new ScanLedger(file);
  const db = new Database(file);
  assert.equal(db.pragma('user_version', { simple: true }), 12);
  assert.equal(count(db, 'scan_sbom_results'), 3);
  assert.equal(count(db, 'scan_sbom_components'), 0);
  assert.equal(count(db, 'scan_results'), 0);
  assert.deepEqual(db.prepare(`SELECT outcome,error_code,image,platform,os_name,os_version,
    component_count,scanner_version,checked_at FROM scan_sbom_results ORDER BY error_code`).all(),
  ['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE'].map(code => ({ outcome: 'failed', error_code: code,
    image: null, platform: null, os_name: null, os_version: null, component_count: null,
    scanner_version: null, checked_at: null })));
  assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  db.close();
  ledger.close();
}));

test('v6 migration persists failed SBOM coverage across reopen', () => fixture(file => {
  let ledger = new ScanLedger(file);
  ledger.close();
  const old = new Database(file);
  old.exec('DROP TABLE scan_execution_profiles; DROP TABLE scan_check_results; DROP TABLE scan_vuln_findings; DROP TABLE scan_vuln_results; DROP TABLE scan_sbom_components; DROP TABLE scan_sbom_results; PRAGMA user_version = 6;');
  old.close();
  ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  assert.equal(ledger.finish(scanId, job.attempts, 'failed', 'SCAN_UNAVAILABLE'), true);
  ledger.close();
  ledger = new ScanLedger(file);
  assert.deepEqual(ledger.sbom(scanId, 'alice'), { coverage: 'image', outcome: 'failed',
    errorCode: 'SCAN_UNAVAILABLE', components: [], nextCursor: null });
  assert.equal(ledger.result(scanId, 'alice'), undefined);
  const db = new Database(file);
  assert.equal(db.pragma('user_version', { simple: true }), 12);
  assert.equal(count(db, 'scan_sbom_results'), 1);
  assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
  db.close();
  ledger.close();
}));

test('stale and cancelled attempts cannot persist SBOM failures', () => fixture(file => {
  const a = new ScanLedger(file);
  const b = new ScanLedger(file);
  const scanId = a.enqueue(target).scanId;
  const first = a.claim(1000, 100)!;
  const second = b.claim(1100, 100)!;
  assert.equal(a.finish(scanId, first.attempts, 'failed', 'SCAN_TIMEOUT'), false);
  assert.equal(b.cancel(scanId, 'alice'), 'cancelled');
  assert.equal(b.finish(scanId, second.attempts, 'failed', 'SCAN_FAILED'), false);
  assert.equal(a.sbom(scanId, 'alice'), undefined);
  assert.equal(a.result(scanId, 'alice'), undefined);
  const db = new Database(file);
  assert.equal(count(db, 'scan_sbom_results'), 0);
  assert.equal(count(db, 'scan_results'), 0);
  assert.deepEqual(a.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'running', 'cancelled']);
  db.close();
  a.close();
  b.close();
}));

test('unsupported checks fail without falsely claiming coverage; invalid scope and inserts roll back', () => fixture(file => {
  const ledger = new ScanLedger(file);
  for (const [i, changes] of [
    { checks: '[]' }, { checks: '["vuln"]' }, { checks: '["sbom","secret"]' },
    { checks: '["sbom"]', scope: 'repository' }, { checks: '["secret"]', scope: 'repository' },
  ].entries()) {
    const scanId = ledger.enqueue({ ...target, ...changes, idempotencyKey: `unsupported-${i}` }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    if (i < 3) {
      assert.equal(ledger.finish(scanId, job.attempts, 'failed'), true);
      assert.equal(ledger.state(scanId, 'alice'), 'failed');
      assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running', 'failed']);
    } else {
      assert.throws(() => ledger.finish(scanId, job.attempts, 'failed'), /contract mismatch/);
      assert.equal(ledger.state(scanId, 'alice'), 'running');
      assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
      assert.equal(ledger.cancel(scanId, 'alice'), 'cancelled');
    }
    assert.equal(ledger.sbom(scanId, 'alice'), undefined);
    assert.equal(ledger.result(scanId, 'alice'), undefined);
  }
  const scanId = ledger.enqueue({ ...target, idempotencyKey: 'rollback' }).scanId;
  const job = ledger.claim()!;
  assert.throws(() => ledger.finish(scanId, job.attempts, 'failed', 'raw-secret' as 'SCAN_FAILED'), /constraint|Invalid failure code/);
  const db = new Database(file);
  db.exec(`CREATE TRIGGER reject_sbom_failure BEFORE INSERT ON scan_sbom_results
    BEGIN SELECT RAISE(ABORT, 'sbom unavailable'); END`);
  assert.throws(() => ledger.finish(scanId, job.attempts, 'failed'), /sbom unavailable/);
  assert.equal(ledger.state(scanId, 'alice'), 'running');
  assert.equal(ledger.sbom(scanId, 'alice'), undefined);
  assert.equal(count(db, 'scan_sbom_results'), 0);
  assert.equal(count(db, 'scan_results'), 0);
  assert.deepEqual(ledger.events(scanId, 'alice', null)?.map(e => e.state), ['queued', 'running']);
  db.exec('DROP TRIGGER reject_sbom_failure');
  assert.equal(ledger.finish(scanId, job.attempts, 'failed'), true);
  db.close();
  ledger.close();
}));

test('prune removes SBOM metadata and components with terminal scan', () => fixture(file => {
  const ledger = new ScanLedger(file);
  const scanId = ledger.enqueue(target).scanId;
  const job = ledger.claim()!;
  assert.equal(ledger.finishWithSbom(scanId, job.attempts, sbom, '0.69.3'), true);
  const db = new Database(file);
  db.prepare("UPDATE scans SET terminal_at = datetime('now', '-40 days') WHERE id = ?").run(scanId);
  assert.equal(ledger.prune(30), 1);
  assert.equal(ledger.sbom(scanId, 'alice'), undefined);
  assert.equal(count(db, 'scan_sbom_results'), 0);
  assert.equal(count(db, 'scan_sbom_components'), 0);
  db.close();
  ledger.close();
}));
