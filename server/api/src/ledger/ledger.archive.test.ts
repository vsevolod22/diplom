import test from 'node:test';
import { createHash } from 'node:crypto';
import { allocateAdvisoryBudget, normalizeAdvisory, jsonBytes } from '../worker/vuln-advisory.js';
import type { VulnFinding } from '../worker/vuln-findings.js';
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

function advisoryReport(count = 1): ArchiveScanReport {
  const value = report();
  const image = `${target.registry}/${target.repository}@${target.digest}`;
  const provenanceRef = `target-${'b'.repeat(64)}`;
  const findings: VulnFinding[] = Array.from({ length: count }, (_, i) => {
    const cveId = `CVE-2025-${String(i).padStart(4, '0')}`, packageName = 'x'.repeat(128), installedVersion = '1'.repeat(80);
    const key = JSON.stringify([image, 'linux/amd64', 'vuln', 'apk', provenanceRef, cveId, packageName, installedVersion]);
    return { findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`, cveId, ecosystem: 'apk', packageName, installedVersion,
      fixedVersion: '2'.repeat(80), severity: 'HIGH', severitySources: ['alpine'], provenanceRef,
      advisory: normalizeAdvisory({ DataSource: { ID: 'alpine' }, Title: 'Safe', Description: '界'.repeat(1365), Severity: 'HIGH', SeveritySource: 'alpine' }, provenanceRef, cveId) };
  });
  value.vuln = { outcome: 'checked', findings: allocateAdvisoryBudget(findings), db: dbIdentity(new Date(Date.now() + 60_000).toISOString()),
    os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } };
  return value;
}
test('embedded advisory roundtrip rejects stored injection and never rechecks historical freshness against now', () => fixture((ledger, file) => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!, value = advisoryReport();
  assert.equal(ledger.finishArchive(id, job.attempts, value), true);
  const now = Date.now; Date.now = () => now() + 365 * 86400_000;
  try { assert.deepEqual(ledger.archiveResult(id, 'alice'), value); } finally { Date.now = now; }
  const raw = new Database(file);
  const malformed = structuredClone(value);
  if (malformed.vuln?.outcome !== 'checked') throw new Error('fixture');
  malformed.vuln.findings[0].advisory!.references[0].url = 'https://evil.test/?token=CANARY';
  raw.prepare('UPDATE scan_archive_results SET report=? WHERE scan_id=?').run(JSON.stringify(malformed), id);
  assert.equal(ledger.archiveResult(id, 'bob'), undefined);
  assert.throws(() => ledger.archiveResult(id, 'alice'), /Invalid vulnerability advisory/);
  raw.prepare('UPDATE scan_archive_results SET report=? WHERE scan_id=?').run(JSON.stringify({ ...value, raw: 'CANARY' }), id);
  assert.throws(() => ledger.archiveResult(id, 'alice'), /Invalid archive result/);
  raw.close();
}));
test('archive report budget omits metadata before commit and preserves core N/IDs under two million bytes', () => fixture((ledger, file) => {
  const value = advisoryReport(1000);
  value.secret = { outcome: 'checked', findings: Array.from({ length: 1000 }, (_, i) => ({ findingId: `secret-${i}-0`, ruleId: 'r'.repeat(80), line: i, evidenceRef: `result-${i}-secret-0` })) };
  if (value.sbom?.outcome !== 'checked' || value.vuln?.outcome !== 'checked') throw new Error('fixture');
  value.sbom.sbom.components = Array.from({ length: 1000 }, (_, i) => ({ ecosystem: 'apk', name: `p${i}`.padEnd(128, 'x'), version: '1'.repeat(80) }));
  assert.ok(jsonBytes(value) > 2_000_000, `fixture must cross cap: ${jsonBytes(value)}`);
  const ids = value.vuln.findings.map(f => f.findingId);
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  assert.equal(ledger.finishArchive(id, job.attempts, value), true);
  const saved = ledger.archiveResult(id, 'alice');
  if (saved?.vuln?.outcome !== 'checked') throw new Error('checked expected');
  assert.equal(saved.vuln.findings.length, 1000); assert.deepEqual(saved.vuln.findings.map(f => f.findingId), ids);
  assert.ok(saved.vuln.findings.some(f => f.advisory?.limitations.includes('report_budget')));
  assert.ok(jsonBytes(saved) <= 2_000_000);
  const reopened = new ScanLedger(file);
  try { assert.deepEqual(reopened.archiveResult(id, 'alice'), saved); } finally { reopened.close(); }
}));
test('embedded aggregate metadata limit is enforced both before write and on stored read', () => fixture((ledger, file) => {
  const value = advisoryReport(300), excessive = structuredClone(value);
  if (value.vuln?.outcome !== 'checked' || excessive.vuln?.outcome !== 'checked') throw new Error('fixture');
  for (const f of excessive.vuln.findings) f.advisory = normalizeAdvisory({ Title: 'Title', Description: 'x'.repeat(4096) }, f.provenanceRef, f.cveId);
  assert.ok(jsonBytes(excessive) < 2_000_000);
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  assert.throws(() => ledger.finishArchive(id, job.attempts, excessive), /Invalid vulnerability advisory/);
  assert.equal(ledger.state(id, 'alice'), 'running');
  assert.equal(ledger.finishArchive(id, job.attempts, value), true);
  const raw = new Database(file);
  raw.prepare('UPDATE scan_archive_results SET report=? WHERE scan_id=?').run(JSON.stringify(excessive), id);
  assert.throws(() => ledger.archiveResult(id, 'alice'), /Invalid vulnerability advisory/);
  raw.close();
}));
