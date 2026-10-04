import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { ScanLedger } from './ledger.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
const target = { ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}`, subject: 'alice',
  idempotencyKey: 'archive-qualification', checks: '["secret","sbom","vuln"]', scope: 'image', fingerprint: 'a'.repeat(64) };
function report(): ArchiveScanReport {
  return { receipt: { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
    archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1',
    resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
    scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
      expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
    secret: { outcome: 'checked', findings: [] },
    sbom: { outcome: 'checked', sbom: { image: `${target.registry}/${target.repository}@${target.digest}`, platform: 'linux/amd64',
      os: { name: 'alpine', version: '3.20.6' }, components: [{ ecosystem: 'apk', name: 'busybox', version: '1.0' }] } },
    vuln: { outcome: 'failed', reason: 'DB_UNAVAILABLE' } };
}
function dbIdentity(nextUpdate: string) {
  return { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`,
    schemaVersion: 2, manifestDigest: `sha256:${'d'.repeat(64)}`, artifactSha256: 'a'.repeat(64),
    metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64), updatedAt: new Date(Date.now() - 60_000).toISOString(),
    downloadedAt: new Date(Date.now() - 30_000).toISOString(), nextUpdate };
}
function fixture(run: (ledger: ScanLedger, file: string) => void) {
  const directory = mkdtempSync(`${tmpdir()}/archive-ledger-`), file = `${directory}/ledger.sqlite`;
  const ledger = new ScanLedger(file);
  try { run(ledger, file); } finally { ledger.close(); rmSync(directory, { recursive: true, force: true }); }
}
test('archive result is atomically fenced, partial, scoped and replayed without duplicate evidence', () => fixture((ledger, file) => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  const value = report();
  assert.equal(ledger.finishArchive(id, job.attempts + 1, value), false);
  assert.equal(ledger.finishArchive(id, job.attempts, value), true);
  assert.equal(ledger.finishArchive(id, job.attempts, value), false);
  assert.equal(ledger.state(id, 'alice'), 'partial');
  assert.deepEqual(ledger.archiveResult(id, 'alice'), value);
  assert.equal(ledger.archiveResult(id, 'bob'), undefined);
  assert.equal(ledger.enqueue(target).scanId, id);
  assert.deepEqual(ledger.events(id, 'alice', null)?.map(item => item.state), ['queued', 'running', 'partial']);
  const reopened = new ScanLedger(file);
  try { assert.deepEqual(reopened.archiveResult(id, 'alice'), value); } finally { reopened.close(); }
  const db = new Database(file);
  db.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id); db.close();
  assert.equal(ledger.prune(), 1); assert.equal(ledger.archiveResult(id, 'alice'), undefined);
}));
test('cancelled/reclaimed attempts cannot write and invalid payload never reaches SQLite', () => fixture(ledger => {
  const id = ledger.enqueue(target).scanId, old = ledger.claim(100, 10)!;
  const current = ledger.claim(111, 100)!;
  assert.equal(ledger.finishArchive(id, old.attempts, report()), false);
  const unsafe = report(); (unsafe.secret as unknown as Record<string, unknown>).raw = 'SECRET_CANARY';
  assert.throws(() => ledger.finishArchive(id, current.attempts, unsafe));
  assert.equal(ledger.archiveResult(id, 'alice'), undefined);
  ledger.cancel(id, 'alice'); assert.equal(ledger.finishArchive(id, current.attempts, report()), false);
}));
test('DB expiry at the write boundary cannot persist coverage and rolls back terminal evidence', () => fixture(ledger => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  const value = report();
  value.vuln = { outcome: 'unsupported', reason: 'OS_EOL', db: dbIdentity(new Date(Date.now() - 1).toISOString()),
    os: { outcome: 'unsupported', reason: 'OS_EOL' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } };
  assert.throws(() => ledger.finishArchive(id, job.attempts, value));
  assert.equal(ledger.state(id, 'alice'), 'running');
  assert.equal(ledger.archiveResult(id, 'alice'), undefined);
  assert.deepEqual(ledger.events(id, 'alice', null)?.map(item => item.state), ['queued', 'running']);
  value.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
  assert.equal(ledger.finishArchive(id, job.attempts, value), true);
  assert.equal(ledger.state(id, 'alice'), 'partial');
}));
test('receipt/check mismatch rolls back all terminal writes', () => fixture(ledger => {
  const id = ledger.enqueue({ ...target, repository: 'library/alpine' }).scanId, job = ledger.claim()!;
  assert.throws(() => ledger.finishArchive(id, job.attempts, report()), /Archive job mismatch/);
  assert.equal(ledger.state(id, 'alice'), 'running'); assert.equal(ledger.archiveResult(id, 'alice'), undefined);
}));
