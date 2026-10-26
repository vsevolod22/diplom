import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger, type CombinedOutcome } from './ledger.js';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';
import { runImageConfig } from '../worker/image-config-runner.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_RESOURCE_POLICY } from '../oci/public-image-policy.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';

const target = { subject: 'alice', idempotencyKey: 'progress', registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64', checks: '["secret","sbom","vuln","config"]' };
const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3',
  findings: [{ findingId: 'secret-0-0', ruleId: 'private-rule', line: 1, evidenceRef: 'result-0-secret-0' }] };
const failed: CombinedOutcome = { check: 'sbom', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' };
function setup(t: TestContext) {
  const directory = mkdtempSync(join(tmpdir(), 'ledger-progress-')), file = join(directory, 'ledger.sqlite');
  let now = Date.now(), ledger = new ScanLedger(file, () => now);
  const raw = new Database(file);
  t.after(() => { raw.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  return { get ledger() { return ledger; }, raw, file, get now() { return now; }, advance(ms: number) { now += ms; },
    reopen() { ledger.close(); ledger = new ScanLedger(file, () => now); } };
}
const empty = { basis: 'durable-outcomes-v1', requestedChecks: ['secret', 'sbom', 'vuln', 'config'],
  outcomes: { secret: null, sbom: null, vuln: null, config: null }, resolvedChecks: 0, checkedChecks: 0 };

test('owner metadata reflects accepted outcomes without publishing running results or writing any table', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId;
  assert.deepEqual(f.ledger.progress(id, 'alice'), empty);
  const job = f.ledger.claim(f.now)!;
  assert.deepEqual(f.ledger.progress(id, 'alice'), empty);
  assert.equal(f.ledger.checkpointCombined(job, secret), true);
  assert.equal(f.ledger.checkpointCombined(job, failed), true);
  const before = f.raw.serialize();
  const expected = { ...empty, outcomes: { ...empty.outcomes, secret: 'checked', sbom: 'failed' }, resolvedChecks: 2, checkedChecks: 1 };
  for (let i = 0; i < 3; i++) assert.deepEqual(f.ledger.progress(id, 'alice'), expected);
  assert.equal(f.ledger.progress(id, 'bob'), undefined);
  assert.equal(f.ledger.progress('missing', 'alice'), undefined);
  assert.equal(f.ledger.result(id, 'alice'), undefined);
  assert.equal(f.ledger.sbom(id, 'alice'), undefined);
  assert.equal(f.ledger.vuln(id, 'alice'), undefined);
  assert.equal(f.ledger.configResult(id, 'alice'), undefined);
  assert.equal(f.ledger.archiveResult(id, 'alice'), undefined);
  assert.deepEqual(f.raw.serialize(), before, 'schema/outbox/events/checkpoints and every result remain unchanged');
  assert.equal(JSON.stringify(expected).includes('private-rule'), false);
  assert.equal(JSON.stringify(expected).includes('SCAN_TIMEOUT'), false);
  f.advance(365 * 86400_000); f.reopen();
  assert.deepEqual(f.ledger.progress(id, 'alice'), expected, 'expired current claim retains accepted metadata after reopen');
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.deepEqual(f.ledger.progress(id, 'alice'), expected, 'cancel now reads the same published subset');
});

test('GET is DEFERRED and succeeds while another connection holds an IMMEDIATE writer reservation', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.checkpointCombined(job, secret);
  f.raw.exec('BEGIN IMMEDIATE');
  try { assert.equal(f.ledger.progress(id, 'alice')?.resolvedChecks, 1); }
  finally { f.raw.exec('ROLLBACK'); }
});

for (const mode of ['retry', 'replacement', 'token', 'attempt'] as const) test(`current claim only: ${mode} does not mix outcomes`, t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now, 100)!;
  f.ledger.checkpointCombined(job, secret);
  if (mode === 'retry') assert.equal(f.ledger.retry(id, job.attempts, f.now + 1000, job.leaseToken), true);
  if (mode === 'replacement') {
    f.advance(32_000);
    const next = f.ledger.claim(f.now)!;
    assert.equal(f.ledger.checkpointCombined(next, failed), true);
  }
  if (mode === 'token') f.raw.prepare('UPDATE outbox SET lease_token=? WHERE scan_id=?').run('replacement-token', id);
  if (mode === 'attempt') f.raw.prepare('UPDATE outbox SET attempts=attempts+1 WHERE scan_id=?').run(id);
  assert.deepEqual(f.ledger.progress(id, 'alice'), mode === 'replacement'
    ? { ...empty, outcomes: { ...empty.outcomes, sbom: 'failed' }, resolvedChecks: 1 } : empty);
});

for (const mode of ['hash', 'identity', 'payload'] as const) test(`corrupt ${mode} fails closed; foreign denial precedes checkpoint access`, t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.checkpointCombined(job, secret);
  if (mode === 'hash') f.raw.exec("UPDATE scan_checkpoints SET evidence_hash='bad'");
  else {
    const row = f.raw.prepare('SELECT identity,body,committed_at AS at FROM scan_checkpoints').get() as { identity: string; body: string; at: number };
    const identity = mode === 'identity' ? JSON.stringify({ ...JSON.parse(row.identity), subject: 'bob' }) : row.identity;
    const body = mode === 'payload' ? JSON.stringify({ ...secret, raw: 'PRIVATE_CANARY' }) : row.body;
    const hash = createHash('sha256').update(JSON.stringify([identity, 'secret', 'combined', row.at, body])).digest('hex');
    f.raw.prepare('UPDATE scan_checkpoints SET identity=?,body=?,evidence_hash=?').run(identity, body, hash);
  }
  const internals = f.ledger as unknown as { checkpointRows: (id: string) => unknown[] };
  const spy = t.mock.method(internals, 'checkpointRows');
  assert.equal(f.ledger.progress(id, 'bob'), undefined); assert.equal(spy.mock.callCount(), 0);
  const before = f.raw.serialize();
  assert.throws(() => f.ledger.progress(id, 'alice'), TypeError);
  assert.deepEqual(f.raw.serialize(), before);
  assert.equal(f.ledger.result(id, 'alice'), undefined);
});

for (const outcome of ['checked', 'unsupported', 'failed'] as const) test(`selected config ${outcome} counts as resolved, only checked counts as checked`, async t => {
  const f = setup(t), bytes = configBytes(outcome === 'unsupported' ? 'named-user' : '0');
  const id = f.ledger.enqueue({ ...target, digest: bytes.digest, checks: '["config"]' }).scanId, job = f.ledger.claim(f.now)!;
  const report = await runImageConfig(f.ledger, job, new AbortController().signal,
    outcome === 'failed' ? async () => { throw new Error('synthetic failure'); } : fixtureLoader(bytes));
  assert.equal(report.config.outcome, outcome);
  assert.equal(f.ledger.checkpointConfig(job, report), true);
  assert.deepEqual(f.ledger.progress(id, 'alice'), { basis: 'durable-outcomes-v1', requestedChecks: ['config'],
    outcomes: { config: outcome }, resolvedChecks: 1, checkedChecks: outcome === 'checked' ? 1 : 0 });
  assert.equal(f.ledger.configResult(id, 'alice'), undefined);
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.equal(f.ledger.progress(id, 'alice')?.outcomes.config, outcome);
});

test('public archive metadata includes checked/unsupported/failed independently, without report fields', t => {
  const f = setup(t), pinned = { ...target, repository: 'example/application', checks: '["secret","sbom","vuln"]' };
  const id = f.ledger.enqueue(pinned).scanId, job = f.ledger.claim(f.now)!;
  const base: ArchiveScanReport = { receipt: { registry: pinned.registry, repository: pinned.repository, digest: pinned.digest,
    configDigest: `sha256:${'b'.repeat(64)}`, platform: pinned.platform, layerDigests: [`sha256:${'c'.repeat(64)}`],
    diffIds: [`sha256:${'d'.repeat(64)}`], archiveSha256: `sha256:${'e'.repeat(64)}`, profileVersion: PUBLIC_IMAGE_PROFILE,
    resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION }, scannerVersion: '0.69.3', checkedAt: f.now,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 } };
  assert.equal(f.ledger.checkpointArchive(job, 'secret', { ...base, secret: { outcome: 'checked', findings: [] } }), true);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', { ...base, sbom: { outcome: 'failed', reason: 'SCAN_TIMEOUT' } }), true);
  const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`, manifestDigest: `sha256:${'d'.repeat(64)}`,
    artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
    updatedAt: new Date(f.now - 60_000).toISOString(), downloadedAt: new Date(f.now - 30_000).toISOString(), nextUpdate: new Date(f.now + 60_000).toISOString() };
  assert.equal(f.ledger.checkpointArchive(job, 'vuln', { ...base, vuln: { outcome: 'unsupported', reason: 'OS_UNKNOWN', db,
    os: { outcome: 'unsupported', reason: 'OS_UNKNOWN' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } } }), true);
  const expected = { basis: 'durable-outcomes-v1', requestedChecks: ['secret', 'sbom', 'vuln'],
    outcomes: { secret: 'checked', sbom: 'failed', vuln: 'unsupported' }, resolvedChecks: 3, checkedChecks: 1 };
  assert.deepEqual(f.ledger.progress(id, 'alice'), expected);
  assert.equal(f.ledger.archiveResult(id, 'alice'), undefined);
  f.ledger.cancel(id, 'alice'); f.reopen();
  assert.deepEqual(f.ledger.progress(id, 'alice'), expected);
});

test('accepted CVE metadata is historical even after DB and lease expire; GET never reevaluates or rewrites it', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId, job = f.ledger.claim(f.now)!;
  const at = f.now, db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`, manifestDigest: `sha256:${'d'.repeat(64)}`,
    artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
    updatedAt: new Date(at - 60_000).toISOString(), downloadedAt: new Date(at - 30_000).toISOString(), nextUpdate: new Date(at + 60_000).toISOString() };
  f.ledger.checkpointCombined(job, { check: 'vuln', outcome: 'checked', findings: [], scannerVersion: '0.69.3',
    image: `${target.registry}/${target.repository}@${target.digest}`, dbEvidence: { db, checkedAt: at, dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY, at)! } });
  const expected = f.ledger.progress(id, 'alice'), before = f.raw.serialize();
  f.advance(30 * 86400_000);
  assert.deepEqual(f.ledger.progress(id, 'alice'), expected); assert.equal(expected?.checkedChecks, 1);
  assert.deepEqual(f.raw.serialize(), before);
});

for (const terminal of ['completed', 'partial', 'failed', 'cancelled'] as const) test(`${terminal} progress uses published outcomes, never synthesizes interrupted checks`, t => {
  const f = setup(t), checks = terminal === 'completed' ? '["secret"]' : '["secret","sbom"]';
  const id = f.ledger.enqueue({ ...target, checks }).scanId, job = f.ledger.claim(f.now)!;
  if (terminal === 'completed') f.ledger.finishCombined(id, job.attempts, [secret], undefined, job.leaseToken);
  if (terminal === 'partial') f.ledger.finishCombined(id, job.attempts, [secret, failed], undefined, job.leaseToken);
  if (terminal === 'failed') f.ledger.finishCombined(id, job.attempts, [{ ...failed, check: 'secret' }, failed], undefined, job.leaseToken);
  if (terminal === 'cancelled') { f.ledger.checkpointCombined(job, secret); f.ledger.cancel(id, 'alice'); }
  assert.equal(f.ledger.state(id, 'alice'), terminal);
  assert.equal(f.ledger.progress(id, 'alice')?.outcomes.secret, terminal === 'failed' ? 'failed' : 'checked');
  assert.equal(f.ledger.progress(id, 'alice')?.outcomes.sbom, terminal === 'completed' ? undefined : terminal === 'cancelled' ? null : 'failed');
  assert.equal(f.ledger.progress(id, 'alice')?.checkedChecks, terminal === 'failed' ? 0 : 1);
});

test('one DEFERRED read snapshot keeps old state, identity and progress together when cancel commits between reads', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!;
  f.ledger.checkpointCombined(job, secret);
  const writer = new ScanLedger(f.file, () => f.now);
  try {
    f.ledger.readReportSnapshot(() => {
      const snapshot = f.ledger.snapshot(id, 'alice');
      assert.equal(writer.cancel(id, 'alice'), 'cancelled');
      assert.equal(snapshot?.state, 'running');
      assert.equal(f.ledger.progress(id, 'alice')?.checkedChecks, 1);
      assert.equal(f.ledger.result(id, 'alice'), undefined);
      assert.equal(f.ledger.pinnedTarget(id, 'alice')?.digest, snapshot?.digest);
    });
    assert.equal(f.ledger.snapshot(id, 'alice')?.state, 'cancelled');
    assert.equal(f.ledger.result(id, 'alice')?.outcome, 'checked');
  } finally { writer.close(); }
});
