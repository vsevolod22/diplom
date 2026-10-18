import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger, type CombinedOutcome } from './ledger.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';
import { runImageConfig } from '../worker/image-config-runner.js';

const target = { subject: 'alice', idempotencyKey: 'partial', registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64', checks: '["secret","sbom","vuln"]' };
const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3',
  findings: [{ findingId: 'secret-0-0', ruleId: 'test-rule', line: 1, evidenceRef: 'result-0-secret-0' }] };
const sbom: CombinedOutcome = { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3', sbom: {
  image: `${target.registry}/${target.repository}@${target.digest}`, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' },
  components: [{ ecosystem: 'apk', name: 'busybox', version: '1.0' }] } };
function setup(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'partial-checkpoint-')), file = join(dir, 'ledger.sqlite');
  let now = Date.now(), ledger = new ScanLedger(file, () => now);
  const raw = new Database(file);
  t.after(() => { raw.close(); ledger.close(); rmSync(dir, { recursive: true, force: true }); });
  return { get ledger() { return ledger; }, raw, file, get now() { return now; }, advance(ms: number) { now += ms; },
    reopen() { ledger.close(); ledger = new ScanLedger(file, () => now); return ledger; } };
}
function archive(at: number): ArchiveScanReport {
  return { receipt: { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
    archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1', resourcePolicyVersion: 'nginx-archive-resources-v1',
    checksVersion: 'trivy-0.69.3-archive-v1' }, scannerVersion: '0.69.3', checkedAt: at,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1,
      archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 }, secret: { outcome: 'checked', findings: [] } };
}
function dbIdentity(at: number) {
  return { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`, manifestDigest: `sha256:${'d'.repeat(64)}`,
    artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
    updatedAt: new Date(at - 60_000).toISOString(), downloadedAt: new Date(at - 30_000).toISOString(),
    nextUpdate: new Date(at + 1000).toISOString() };
}

test('checkpoint commits before cancel, survives crash/reopen, projects existing contracts only at cancel', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  assert.equal(f.ledger.checkpointCombined(job, secret), true);
  assert.equal(f.ledger.checkpointCombined(job, secret), false, 'immutable first result');
  assert.equal(f.ledger.result(id, 'alice'), undefined, 'not a running public report');
  f.reopen();
  assert.equal(f.ledger.cancel(id, 'bob'), 'not_found');
  assert.equal(f.ledger.result(id, 'alice'), undefined);
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  const verify = () => {
    assert.equal(f.ledger.state(id, 'alice'), 'cancelled');
    assert.deepEqual(f.ledger.secretDataset(id, 'alice')?.findings, secret.outcome === 'checked' ? secret.findings : []);
    assert.equal(f.ledger.secretDataset(id, 'bob'), undefined);
    assert.equal(f.ledger.sbomDataset(id, 'alice'), undefined);
    assert.equal(f.ledger.vulnDataset(id, 'alice'), undefined);
    assert.equal(f.ledger.configResult(id, 'alice'), undefined);
    assert.deepEqual(f.ledger.events(id, 'alice', null)?.map(e => e.state), ['queued', 'running', 'cancelled']);
    assert.deepEqual(f.raw.prepare('SELECT lease_until,lease_token FROM outbox WHERE scan_id=?').get(id), { lease_until: null, lease_token: null });
    assert.equal(f.ledger.claim(f.now), undefined);
  };
  verify(); f.reopen(); verify();
  assert.equal(f.ledger.checkpointCombined(job, sbom), false);
  assert.equal(f.ledger.finishCombined(id, job.attempts, [secret, sbom, { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_FAILED' }], undefined, job.leaseToken), false);
  assert.equal(f.ledger.cancel(id, 'alice'), 'already_cancelled');
});

test('separate writer connections serialize checkpoint/cancel and cancel/finalize races', t => {
  const f = setup(t), other = new ScanLedger(f.file, () => f.now);
  try {
    const first = f.ledger.enqueue({ ...target, checks: '["secret"]' }).scanId, job = f.ledger.claim(f.now)!;
    assert.equal(f.ledger.checkpointCombined(job, secret), true);
    assert.equal(other.cancel(first, 'alice'), 'cancelled');
    assert.equal(f.ledger.finishCombined(first, job.attempts, [secret], undefined, job.leaseToken), false);
    assert.equal(f.ledger.result(first, 'alice')?.findingCount, 1);
    const second = f.ledger.enqueue({ ...target, idempotencyKey: 'cancel-first', checks: '["secret"]' }).scanId;
    const next = f.ledger.claim(f.now)!;
    assert.equal(other.cancel(second, 'alice'), 'cancelled');
    assert.equal(f.ledger.checkpointCombined(next, secret), false);
    assert.equal(f.ledger.result(second, 'alice'), undefined);
  } finally { other.close(); }
});

test('cancel before checkpoint and crash before any checkpoint remain unknown, not checked zero', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.reopen();
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.equal(f.ledger.checkpointCombined(job, secret), false);
  assert.equal(f.ledger.secretDataset(id, 'alice'), undefined);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
});

for (const mode of ['retry', 'replacement', 'expiry', 'token', 'target', 'check'] as const) {
  test(`checkpoint authority rejects ${mode} without mixing attempts`, t => {
    const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now, 100)!;
    assert.equal(f.ledger.checkpointCombined(job, secret), true);
    if (mode === 'retry') assert.equal(f.ledger.retry(id, job.attempts, f.now + 1000, job.leaseToken), true);
    if (mode === 'expiry' || mode === 'replacement') f.advance(100);
    if (mode === 'replacement') {
      const next = f.ledger.claim(f.now)!;
      assert.equal(f.ledger.checkpointCombined(next, sbom), true);
    }
    const stale = { ...job, ...(mode === 'token' ? { leaseToken: 'wrong' } : {}),
      ...(mode === 'target' ? { digest: `sha256:${'b'.repeat(64)}` } : {}), ...(mode === 'check' ? { checks: '["sbom"]' } : {}) };
    assert.equal(f.ledger.checkpointCombined(stale, sbom), false);
    if (mode === 'retry' || mode === 'expiry') assert.equal(f.ledger.finishCombined(id, job.attempts,
      [secret, sbom, { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_FAILED' }], undefined, job.leaseToken), false);
    assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
    assert.equal(f.ledger.result(id, 'alice')?.outcome, mode === 'retry' || mode === 'replacement' ? undefined : 'checked');
    assert.equal(f.ledger.sbom(id, 'alice')?.outcome, mode === 'replacement' ? 'checked' : undefined);
  });
}

test('strict sanitization, identity and bounds reject before checkpoint bytes reach SQLite', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  const invalid = [ { ...secret, raw: 'SECRET_CANARY' }, { ...secret, scannerVersion: 'future' },
    { ...secret, findings: [{ findingId: 'secret-0-0', ruleId: 'rule', line: 1, evidenceRef: 'result-0-secret-0', Match: 'SECRET_CANARY' }] },
    { ...secret, findings: Array.from({ length: 1001 }, () => (secret as Extract<CombinedOutcome, { check: 'secret'; outcome: 'checked' }>).findings[0]) },
    { ...sbom, sbom: { ...(sbom as Extract<CombinedOutcome, { check: 'sbom'; outcome: 'checked' }>).sbom, image: 'wrong' } } ];
  for (const item of invalid) assert.throws(() => f.ledger.checkpointCombined(job, item as CombinedOutcome));
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.equal(f.ledger.result(id, 'alice'), undefined);
});

for (const [table, action] of [['scan_findings', 'INSERT'], ['scan_check_results', 'INSERT'], ['outbox', 'UPDATE'], ['scans', 'UPDATE'], ['scan_events', 'INSERT']] as const) {
  test(`cancel snapshot, config, siblings and event roll back together on ${table} failure`, async t => {
    const f = setup(t), bytes = configBytes(), id = f.ledger.enqueue({ ...target, digest: bytes.digest, checks: '["secret","config"]' }).scanId;
    const job = f.ledger.claim(f.now)!;
    const config = await runImageConfig(f.ledger, job, new AbortController().signal, fixtureLoader(bytes));
    assert.equal(f.ledger.checkpointConfig(job, config), true);
    assert.equal(f.ledger.checkpointCombined(job, secret), true);
    f.raw.exec(`CREATE TRIGGER reject_cancel BEFORE ${action} ON ${table} BEGIN SELECT RAISE(ABORT,'cancel rollback'); END`);
    assert.throws(() => f.ledger.cancel(id, 'alice'), /cancel rollback/);
    assert.equal(f.ledger.state(id, 'alice'), 'running');
    assert.equal(f.ledger.result(id, 'alice'), undefined); assert.equal(f.ledger.configResult(id, 'alice'), undefined);
    assert.equal(f.ledger.checkpointActive(job), true);
    assert.deepEqual(f.ledger.events(id, 'alice', null)?.map(e => e.state), ['queued', 'running']);
    f.raw.exec('DROP TRIGGER reject_cancel');
    assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
    assert.equal(f.ledger.result(id, 'alice')?.findingCount, 1);
    assert.deepEqual(f.ledger.configResult(id, 'alice'), config);
  });
}

test('final completion winning first is immutable and emits one terminal event', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret"]' }).scanId, job = f.ledger.claim(f.now)!;
  assert.equal(f.ledger.checkpointCombined(job, secret), true);
  assert.equal(f.ledger.finishCombined(id, job.attempts, [secret], undefined, job.leaseToken), true);
  assert.equal(f.ledger.cancel(id, 'alice'), 'conflict');
  assert.equal(f.ledger.checkpointCombined(job, secret), false);
  assert.deepEqual(f.ledger.events(id, 'alice', null)?.map(e => e.state), ['queued', 'running', 'completed']);
});

for (const kind of ['ordinary', 'archive'] as const) {
  test(`${kind} CVE receipt is validated/frozen at checkpoint, never refreshed at cancellation/reopen`, t => {
    const f = setup(t), db = dbIdentity(f.now);
    const pinned = kind === 'ordinary' ? target : { ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}` };
    const id = f.ledger.enqueue({ ...pinned, checks: '["secret","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
    const job = f.ledger.claim(f.now)!;
    const checkedAt = f.now, dbPolicy = evaluateDbPolicy(db, CURRENT_DB_POLICY, checkedAt)!;
    if (kind === 'ordinary') {
      const value: CombinedOutcome = { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3', image: `${job.registry}/${job.repository}@${job.digest}`,
        findings: [], dbEvidence: { db, checkedAt, dbPolicy } };
      assert.throws(() => f.ledger.checkpointCombined(job, { ...value, dbEvidence: undefined }));
      assert.equal(f.ledger.checkpointCombined(job, value), true);
    } else {
      const base = archive(checkedAt);
            delete base.secret;
      const value: ArchiveScanReport = { ...base, vuln: { outcome: 'checked', findings: [], db, dbPolicy,
        os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } } };
      assert.throws(() => f.ledger.checkpointArchive(job, 'vuln', { ...value, vuln: { ...value.vuln!, dbPolicy: undefined } }));
      assert.equal(f.ledger.checkpointArchive(job, 'vuln', value), true);
    }
    f.advance(30 * 86400_000); // Lease and DB expired, but durable evidence was committed while both were valid.
    assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
    const verify = () => {
      if (kind === 'ordinary') {
        const result = f.ledger.vulnDataset(id, 'alice'); assert.equal(result?.outcome, 'checked');
        if (result?.outcome !== 'checked') throw Error('fixture');
        assert.deepEqual(result.dbEvidence, { db, checkedAt, dbPolicy });
        assert.equal(f.ledger.result(id, 'alice'), undefined);
      } else {
        const result = f.ledger.archiveResult(id, 'alice')!; assert.equal(result.vuln?.outcome, 'checked');
        assert.equal(result.checkedAt, checkedAt); assert.equal(result.secret, undefined);
        assert.deepEqual(result.vuln?.dbPolicy, dbPolicy); assert.equal(f.ledger.archiveResult(id, 'bob'), undefined);
      }
    };
    verify(); f.reopen(); verify();
  });
}

test('CVE expiry at the checkpoint fence becomes a failed check without erasing independent results', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
  const job = f.ledger.claim(f.now)!, updated = f.now - 14 * 86400_000 - 1;
  const db = { ...dbIdentity(f.now), updatedAt: new Date(updated).toISOString(), downloadedAt: new Date(updated + 1000).toISOString(),
    nextUpdate: new Date(updated + 86400_000).toISOString() };
  const checkedAt = f.now - 1;
  const value: CombinedOutcome = { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3', findings: [],
    image: `${job.registry}/${job.repository}@${job.digest}`, dbEvidence: { db, checkedAt, dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY, checkedAt)! } };
  f.ledger.checkpointCombined(job, secret);
  assert.equal(f.ledger.checkpointCombined(job, value), true);
  f.ledger.cancel(id, 'alice');
  assert.equal(f.ledger.result(id, 'alice')?.findingCount, 1);
  assert.deepEqual(f.ledger.vulnDataset(id, 'alice'), { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_UNAVAILABLE', findings: [] });
});

test('archive checkpoints retain exact receipt, reject mixed identity and expose only completed subset', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}` }).scanId;
  const job = f.ledger.claim(f.now)!, first = archive(f.now);
  assert.equal(f.ledger.checkpointArchive(job, 'secret', first), true);
  const base = { ...first };
    delete base.secret;
  const second: ArchiveScanReport = { ...base, sbom: { outcome: 'failed', reason: 'SCAN_FAILED' } };
  assert.throws(() => f.ledger.checkpointArchive(job, 'sbom', { ...second, receipt: { ...second.receipt, archiveSha256: `sha256:${'e'.repeat(64)}` } }), /Mixed archive/);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', second), true);
  f.reopen(); assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.deepEqual(f.ledger.archiveResult(id, 'alice'), { ...first, sbom: second.sbom });
  assert.equal(f.ledger.archiveResult(id, 'alice')?.vuln, undefined);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', second), false);
});

test('tampered checkpoint fails closed and cancel cannot partially publish siblings', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  assert.equal(f.ledger.checkpointCombined(job, secret), true);
  assert.equal(f.ledger.checkpointCombined(job, sbom), true);
  f.raw.prepare("UPDATE scan_checkpoints SET body='{}' WHERE check_name='secret'").run();
  assert.throws(() => f.ledger.cancel(id, 'alice'), /Invalid stored checkpoint/);
  assert.equal(f.ledger.state(id, 'alice'), 'running'); assert.equal(f.ledger.sbom(id, 'alice'), undefined);
  assert.equal(f.ledger.result(id, 'alice'), undefined);
});

test('owner identity is ledger-derived and stored-owner corruption cannot reassign preserved findings', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.checkpointCombined(job, secret);
  f.raw.prepare('UPDATE scans SET subject=? WHERE id=?').run('bob', id);
  assert.equal(f.ledger.cancel(id, 'alice'), 'not_found');
  assert.throws(() => f.ledger.cancel(id, 'bob'), /Invalid stored checkpoint identity/);
  assert.equal(f.ledger.secretDataset(id, 'bob'), undefined);
});

test('committed WAL checkpoint survives abrupt worker death before cancellation', { timeout: 10000 }, t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    `import { ScanLedger } from ${JSON.stringify(new URL('./ledger.ts', import.meta.url).href)};
     const ledger = new ScanLedger(${JSON.stringify(f.file)});
     const job = ledger.claim();
     if (!ledger.checkpointCombined(job, ${JSON.stringify(secret)})) process.exit(2);
     process.kill(process.pid, 'SIGKILL');`], { timeout: 5000, encoding: 'utf8', maxBuffer: 4096 });
  assert.equal(child.error, undefined); assert.equal(child.signal, 'SIGKILL', child.stderr);
  f.reopen();
  assert.equal(f.ledger.result(id, 'alice'), undefined);
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.equal(f.ledger.result(id, 'alice')?.findingCount, 1);
});

test('v14 to v15 preserves historical report bytes, adds no invented coverage, and reopens idempotently', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret"]' }).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.finishCombined(id, job.attempts, [secret], undefined, job.leaseToken);
  const history = f.raw.prepare('SELECT * FROM scan_results').all();
  f.raw.exec('DROP TABLE scan_checkpoints; ALTER TABLE outbox DROP COLUMN lease_token; PRAGMA user_version=14');
  f.reopen();
  assert.equal(f.raw.pragma('user_version', { simple: true }), 15);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_results').all(), history);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
  assert.equal(f.ledger.cancel(id, 'alice'), 'conflict');
  f.reopen();
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_results').all(), history);
  assert.deepEqual(f.raw.pragma('foreign_key_check'), []);
});

test('failed v15 forward migration rolls back new column and version, leaving v14 rows untouched', t => {
  const f = setup(t); f.ledger.enqueue(target);
  f.raw.exec('DROP TABLE scan_checkpoints; ALTER TABLE outbox DROP COLUMN lease_token; CREATE TABLE scan_checkpoints(sentinel TEXT); PRAGMA user_version=14');
  const before = f.raw.prepare('SELECT * FROM outbox').all();
  assert.throws(() => new ScanLedger(f.file), /already exists/);
  assert.equal(f.raw.pragma('user_version', { simple: true }), 14);
  assert.deepEqual(f.raw.prepare('SELECT * FROM outbox').all(), before);
  assert.deepEqual(f.raw.prepare("SELECT * FROM pragma_table_info('outbox') WHERE name='lease_token'").all(), []);
});

test('retention removes checkpoints with terminal evidence, not active checkpoints', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.checkpointCombined(job, secret); assert.equal(f.ledger.prune(), 0);
  f.ledger.cancel(id, 'alice');
  f.raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id);
  assert.equal(f.ledger.prune(), 1); assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
  assert.deepEqual(f.raw.pragma('foreign_key_check'), []);
});
