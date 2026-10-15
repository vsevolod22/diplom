import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { ScanLedger } from './ledger.js';
import type { VulnFinding } from '../worker/vuln-findings.js';
import type Database from 'better-sqlite3';

// SOURCE ONLY: these seams require the native storage module. Not authorized for
// execution/import under the current pure-query/page validation permission.
const target = { subject: 'synthetic-owner', idempotencyKey: 'synthetic-report-dataset',
  registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}` as `sha256:${string}`,
  platform: 'linux/amd64', checks: '["secret","sbom","vuln"]', scope: 'image' };
const image = `${target.registry}/${target.repository}@${target.digest}`;
const provenanceRef = `target-${'b'.repeat(64)}`;
function findings(count: number): VulnFinding[] {
  return Array.from({ length: count }, (_, i) => {
    const cveId = `CVE-2026-${String(i).padStart(4, '0')}`;
    const key = JSON.stringify(['apk', provenanceRef, cveId, 'busybox', '1.2-r0']);
    return { findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`, cveId,
      ecosystem: 'apk', provenanceRef, packageName: 'busybox', installedVersion: '1.2-r0',
      fixedVersion: null, severity: 'HIGH', severitySources: ['unknown'] };
  });
}

test('source-only complete bounded datasets are owner scoped and legacy page limits stay intact', () => {
  const ledger = new ScanLedger(':memory:');
  try {
    const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
    const vuln = findings(1000);
    const components = Array.from({ length: 1000 }, (_, i) => ({ ecosystem: 'apk' as const, name: `pkg-${i}`, version: '1' }));
    const secrets = Array.from({ length: 1000 }, (_, i) => ({ findingId: `secret-${i}-0`, ruleId: 'opaque-rule', line: i === 0 ? null : i,
      evidenceRef: `result-${i}-secret-0` }));
    assert.equal(ledger.finishCombined(id, job.attempts, [
      { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: secrets },
      { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3', sbom: { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.20' }, components } },
      { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3', image, findings: vuln },
    ]), true);
    const before = ledger.snapshot(id, target.subject);
    const datasets = ledger.readReportSnapshot(() => ({ vuln: ledger.vulnDataset(id, target.subject),
      sbom: ledger.sbomDataset(id, target.subject), secret: ledger.secretDataset(id, target.subject) }));
    assert.deepEqual(datasets.vuln?.findings, vuln);
    assert.deepEqual(datasets.sbom?.components, components);
    assert.equal(datasets.secret?.findings.length, 1000);
    assert.deepEqual(ledger.snapshot(id, target.subject), before);
    assert.equal(ledger.vulnDataset(id, 'foreign'), undefined);
    assert.equal(ledger.sbomDataset(id, 'foreign'), undefined);
    assert.equal(ledger.secretDataset(id, 'foreign'), undefined);
    assert.equal(ledger.vuln(id, target.subject, 0, 1)?.nextCursor, 1);
    assert.equal(ledger.sbom(id, target.subject, 0, 1)?.nextCursor, 1);
    assert.equal(ledger.findings(id, target.subject, 0, 1)?.nextCursor, 1);
    assert.throws(() => ledger.vuln(id, target.subject, 0, 1000), /Invalid pagination/);
    assert.throws(() => ledger.sbom(id, target.subject, 0, 1000), /Invalid pagination/);
    assert.throws(() => ledger.findings(id, target.subject, 0, 1000), /Invalid pagination/);
    // Synthetic corruption beyond page one must not disappear behind a filter.
    const raw = (ledger as unknown as { db: Database.Database }).db;
    raw.prepare('UPDATE scan_sbom_components SET name=? WHERE scan_id=? AND ordinal=999').run('invalid/path!', id);
    assert.throws(() => ledger.sbomDataset(id, target.subject), /Invalid SBOM component/);
    raw.prepare('UPDATE scan_findings SET rule_id=? WHERE scan_id=? AND finding_id=?').run('invalid/path', id, 'secret-999-0');
    assert.throws(() => ledger.secretDataset(id, target.subject), /Invalid secret finding/);
    raw.prepare('UPDATE scan_vuln_findings SET severity_sources=? WHERE scan_id=? AND ordinal=999').run('["unrecognized"]', id);
    assert.throws(() => ledger.vulnDataset(id, target.subject), /Invalid vulnerability finding/);
    assert.throws(() => ledger.vuln(id, target.subject, 0, 1), /Invalid vulnerability finding/);
  } finally { ledger.close(); }
});

test('source-only missing/failed datasets retain unknown outcomes without invented rows', () => {
  const ledger = new ScanLedger(':memory:');
  try {
    const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
    assert.equal(ledger.vulnDataset(id, target.subject), undefined);
    assert.equal(ledger.sbomDataset(id, target.subject), undefined);
    assert.equal(ledger.secretDataset(id, target.subject), undefined);
    assert.equal(ledger.finishCombined(id, job.attempts, [
      { check: 'secret', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' },
      { check: 'sbom', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' },
      { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' },
    ]), true);
    assert.deepEqual(ledger.vulnDataset(id, target.subject), { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_TIMEOUT', findings: [] });
    assert.equal(ledger.sbomDataset(id, target.subject)?.outcome, 'failed');
    assert.equal(ledger.secretDataset(id, target.subject)?.coverage.findingCount, null);
    assert.deepEqual(ledger.secretDataset(id, target.subject)?.findings, []);
  } finally { ledger.close(); }
});
