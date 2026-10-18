import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger } from './ledger.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import type { VulnFinding } from '../worker/vuln-findings.js';
import { normalizeAdvisory } from '../worker/vuln-advisory.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION } from '../oci/public-image-policy.js';
import { PUBLIC_ECOSYSTEMS } from '../worker/public-image-evidence.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';

// Synthetic identities/count-shape fixtures, not copies of native scanner output or published scan evidence.
const digest = (char: string) => `sha256:${char.repeat(64)}` as const;
const publicTarget = { registry: 'registry-1.docker.io', repository: 'library/debian', digest: digest('a'), configDigest: digest('b'), platform: 'linux/amd64' };
function findingHash(finding: VulnFinding, image: string, archive = true): string {
  const key = JSON.stringify([...(archive ? [image, 'linux/amd64', 'vuln'] : []), finding.ecosystem, finding.provenanceRef,
    finding.cveId, finding.packageName, finding.installedVersion]);
  return `vuln-${createHash('sha256').update(key).digest('hex')}`;
}
function fixtureReport(at: number, legacy = false): ArchiveScanReport {
  const target = legacy ? NGINX_ARCHIVE_TARGET : publicTarget, image = `${target.registry}/${target.repository}@${target.digest}`;
  const ecosystem = legacy ? 'apk' : 'deb';
  const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@${digest('f')}`, manifestDigest: digest('f'), artifactSha256: 'a'.repeat(64),
    metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64), updatedAt: new Date(at - 60_000).toISOString(),
    downloadedAt: new Date(at - 30_000).toISOString(), nextUpdate: new Date(at + 3_600_000).toISOString() };
  const findings: VulnFinding[] = Array.from({ length: 241 }, (_, index) => {
    const cveId = index < 236 ? `CVE-2026-${1000 + index}` : `TEMP-${1000000 + index}-A1B2C3`;
    const finding: VulnFinding = { findingId: '', cveId, ecosystem, packageName: `package-${index % 88}`, installedVersion: legacy ? '1.0' : '1:2.36-9+deb12u10',
      fixedVersion: null, severity: 'HIGH', severitySources: ['nvd'], provenanceRef: `target-${'b'.repeat(64)}`,
      ...(index >= 236 ? { advisory: normalizeAdvisory({ Title: 'Temporary Debian advisory' }, `target-${'b'.repeat(64)}`, cveId) } : {}) };
    finding.findingId = findingHash(finding, image);
    return finding;
  });
  return { receipt: { ...target, layerDigests: [digest('c')], diffIds: [digest('d')], archiveSha256: digest('e'),
    profileVersion: legacy ? 'nginx-alpine-amd64-v1' : PUBLIC_IMAGE_PROFILE,
    resourcePolicyVersion: legacy ? 'nginx-archive-resources-v1' : PUBLIC_IMAGE_RESOURCE_POLICY,
    checksVersion: legacy ? 'trivy-0.69.3-archive-v1' : PUBLIC_IMAGE_CHECKS_VERSION }, scannerVersion: '0.69.3', checkedAt: at,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
    sbom: { outcome: 'checked', sbom: { image, platform: 'linux/amd64', os: { name: legacy ? 'alpine' : 'debian', version: '12.12' },
      components: Array.from({ length: 88 }, (_, index) => ({ ecosystem, name: `package-${index}`, version: legacy ? '1.0' : '1:2.36-9+deb12u10' })) } },
    vuln: { outcome: 'checked', findings, db, dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY, at)!, os: { outcome: 'checked' },
      node: { outcome: 'unsupported', reason: legacy ? 'NODE_INVENTORY_ABSENT' : 'NODE_INVENTORY_UNKNOWN' } } };
}
function setup(t: TestContext, legacy = false) {
  const directory = mkdtempSync(join(tmpdir(), 'ledger-debian-temp-')), file = join(directory, 'ledger.sqlite');
  let now = Date.now(), ledger = new ScanLedger(file, () => now);
  const raw = new Database(file), value = fixtureReport(now, legacy);
  const target = { subject: 'alice', idempotencyKey: 'debian-temp', registry: value.receipt.registry, repository: value.receipt.repository,
    digest: value.receipt.digest as `sha256:${string}`, platform: value.receipt.platform, checks: '["sbom","vuln"]', scope: 'image', cvePolicy: CURRENT_DB_POLICY };
  const id = ledger.enqueue(target).scanId, job = ledger.claim(now, 627_000)!;
  t.after(() => { raw.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  return { get ledger() { return ledger; }, raw, target, id, job, value, get now() { return now; }, advance(ms: number) { now += ms; },
    reopen() { ledger.close(); ledger = new ScanLedger(file, () => now); } };
}
type Fixture = ReturnType<typeof setup>;
function checkedVuln(value: ArchiveScanReport) {
  if (value.vuln?.outcome !== 'checked') throw new Error('fixture');
  return value.vuln;
}
function temporary(value: ArchiveScanReport) { return checkedVuln(value).findings[236]; }
function imageOf(value: ArchiveScanReport) { return `${value.receipt.registry}/${value.receipt.repository}@${value.receipt.digest}`; }
function subset(value: ArchiveScanReport, check: 'sbom' | 'vuln') {
  const { sbom, vuln, ...base } = value;
  return { ...base, [check]: { sbom, vuln }[check] };
}
function state(f: Fixture) {
  return ['scans', 'outbox', 'scan_archive_results', 'scan_checkpoints', 'scan_events'].map(table => f.raw.prepare(`SELECT * FROM ${table}`).all());
}
function ordinaryTablesEmpty(f: Fixture) {
  for (const table of ['scan_results', 'scan_findings', 'scan_sbom_results', 'scan_sbom_components', 'scan_vuln_results', 'scan_vuln_findings'])
    assert.deepEqual(f.raw.prepare(`SELECT * FROM ${table}`).all(), []);
}
function assertPartition(value: ArchiveScanReport) {
  const findings = checkedVuln(value).findings;
  assert.equal(findings.length, 241);
  assert.deepEqual({ cve: findings.filter(f => f.cveId.startsWith('CVE-')).length, debianTemp: findings.filter(f => f.cveId.startsWith('TEMP-')).length },
    { cve: 236, debianTemp: 5 });
  for (const finding of findings) {
    assert.equal(finding.findingId, findingHash(finding, imageOf(value)), 'identity includes the exact source identifier');
    if (finding.cveId.startsWith('TEMP-')) assert.deepEqual(finding.advisory?.references, []);
  }
}

test('public JSON retains 236 CVEs plus 5 exact Debian TEMP IDs, with no fabricated links, replay/reopen/retention', t => {
  const f = setup(t), ids = checkedVuln(f.value).findings.map(finding => finding.cveId);
  assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), true);
  const saved = f.ledger.archiveResult(f.id, 'alice')!;
  assertPartition(saved); assert.deepEqual(checkedVuln(saved).findings.map(finding => finding.cveId), ids);
  assert.equal(saved.sbom?.outcome === 'checked' && saved.sbom.sbom.components.length, 88);
  assert.equal(f.ledger.archiveResult(f.id, 'other'), undefined); ordinaryTablesEmpty(f);
  assert.equal(f.ledger.enqueue(f.target).scanId, f.id);
  const before = state(f); assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), false);
  assert.deepEqual(state(f), before);
  f.advance(365 * 86400_000); f.reopen(); assert.deepEqual(f.ledger.archiveResult(f.id, 'alice'), saved);
  // Paging belongs to the API; retaining the complete ordered dataset must not lose the last five source IDs at a page boundary.
  const replayed = checkedVuln(f.ledger.archiveResult(f.id, 'alice')!).findings;
  assert.deepEqual([...replayed.slice(0, 236), ...replayed.slice(236)].map(finding => finding.cveId), ids);
  f.raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(f.id);
  assert.equal(f.ledger.prune(), 1); assert.equal(f.ledger.archiveResult(f.id, 'alice'), undefined);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []);
});

test('public TEMP dedup identity retains one source ID affecting two distinct packages', t => {
  const f = setup(t), finding = structuredClone(temporary(f.value));
  finding.packageName = 'package-0'; finding.findingId = findingHash(finding, imageOf(f.value));
  checkedVuln(f.value).findings.push(finding);
  assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), true);
  const saved = checkedVuln(f.ledger.archiveResult(f.id, 'alice')!).findings;
  assert.equal(saved.length, 242);
  const sameSource = saved.filter(value => value.cveId === finding.cveId);
  assert.equal(sameSource.length, 2); assert.equal(new Set(sameSource.map(value => value.findingId)).size, 2);
  assert.deepEqual(sameSource.map(value => value.packageName), ['package-60', 'package-0']);
});

test('public TEMP checkpoints survive reopen/cancellation and cannot be changed by a valid rehashed final', t => {
  const f = setup(t);
  assert.equal(f.ledger.checkpointArchive(f.job, 'sbom', subset(f.value, 'sbom')), true);
  assert.equal(f.ledger.checkpointArchive(f.job, 'vuln', subset(f.value, 'vuln')), true);
  const changed = structuredClone(f.value); temporary(changed).cveId = 'TEMP-9999999-ABCDEF';
  temporary(changed).findingId = findingHash(temporary(changed), imageOf(changed));
  const before = state(f);
  assert.throws(() => f.ledger.finishArchive(f.id, f.job.attempts, changed, undefined, f.job.leaseToken), /Archive checkpoint outcome mismatch/);
  assert.deepEqual(state(f), before);
  f.reopen(); assert.equal(f.ledger.cancel(f.id, 'other'), 'not_found'); assert.equal(f.ledger.cancel(f.id, 'alice'), 'cancelled');
  const saved = f.ledger.archiveResult(f.id, 'alice')!; assertPartition(saved); assert.deepEqual(saved, f.value);
  f.reopen(); assert.deepEqual(f.ledger.archiveResult(f.id, 'alice'), saved);
  assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), false);
  f.raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(f.id);
  assert.equal(f.ledger.prune(), 1); assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []); ordinaryTablesEmpty(f);
});

const badIdentifiers: Array<[string, unknown]> = [
  ['unknown namespace', 'GHSA-abcd-efgh-ijkl'], ['unknown TEMP prefix', 'DEBIAN-TEMP-1234567-A1B2C3'],
  ['short decimal', 'TEMP-123456-A1B2C3'], ['long decimal', 'TEMP-12345678-A1B2C3'], ['lowercase hex', 'TEMP-1234567-a1b2c3'],
  ['nonhex suffix', 'TEMP-1234567-GHIJKL'], ['long suffix', 'TEMP-1234567-A1B2C3D'], ['leading space', ' TEMP-1234567-A1B2C3'],
  ['trailing space', 'TEMP-1234567-A1B2C3 '], ['raw identifier', 'TEMP-1234567-A1B2C3\nRAW_ID_CANARY'],
  ['object identifier', { id: 'TEMP-1234567-A1B2C3', raw: 'RAW_ID_CANARY' }], ['array identifier', ['TEMP-1234567-A1B2C3']],
  ['null identifier', null], ['oversized identifier', 'TEMP-' + '1'.repeat(4096)],
];
type Mutation = (value: ArchiveScanReport) => void;
const malformed: Array<[string, Mutation]> = badIdentifiers.map(([name, id]) => [name, value => {
  const finding = temporary(value); finding.cveId = id as string; finding.findingId = findingHash(finding, imageOf(value));
}]);
for (const ecosystem of PUBLIC_ECOSYSTEMS.filter(value => value !== 'deb')) malformed.push([`wrong ecosystem ${ecosystem}`, value => {
  const finding = temporary(value); finding.ecosystem = ecosystem; finding.findingId = findingHash(finding, imageOf(value));
}]);
malformed.push(
  ['unknown ecosystem', value => { const finding = temporary(value); finding.ecosystem = 'unknown' as VulnFinding['ecosystem']; finding.findingId = findingHash(finding, imageOf(value)); }],
  ['hash for rewritten source ID', value => { temporary(value).cveId = 'TEMP-9999999-ABCDEF'; }],
  ['duplicate TEMP finding', value => { checkedVuln(value).findings.push(structuredClone(temporary(value))); }],
  ['raw extra identifier field', value => { Object.assign(temporary(value), { vulnerabilityId: { raw: 'RAW_ID_CANARY' } }); }],
  ['fabricated CVE link', value => { temporary(value).advisory!.references = [{ kind: 'canonical', authority: 'cve', url: 'https://www.cve.org/CVERecord?id=CVE-2026-1234' }]; }],
  ['fabricated NVD link', value => { temporary(value).advisory!.references = [{ kind: 'canonical', authority: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234' }]; }],
  ['TEMP as CVE URL', value => { const finding = temporary(value); finding.advisory!.references = [{ kind: 'canonical', authority: 'cve', url: `https://www.cve.org/CVERecord?id=${finding.cveId}` }]; }],
);
for (const [name, mutate] of malformed) for (const phase of ['checkpoint', 'finalize', 'read'] as const) {
  test(`public TEMP rejects ${name} at ${phase}`, t => {
    const f = setup(t); mutate(f.value);
    if (phase === 'read') {
      f.raw.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(f.id, f.job.attempts, JSON.stringify(f.value));
      assert.equal(f.ledger.archiveResult(f.id, 'other'), undefined);
      assert.throws(() => f.ledger.archiveResult(f.id, 'alice'), TypeError);
    } else {
      const before = state(f);
      assert.throws(() => phase === 'checkpoint' ? f.ledger.checkpointArchive(f.job, 'vuln', subset(f.value, 'vuln')) :
        f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), TypeError);
      assert.deepEqual(state(f), before); assert.equal(f.ledger.checkpointActive(f.job), true);
    }
    ordinaryTablesEmpty(f);
  });
}

for (const phase of ['checkpoint', 'finalize', 'read'] as const) test(`legacy archive never accepts TEMP identifiers at ${phase}`, t => {
  const f = setup(t, true);
  if (phase === 'read') {
    f.raw.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(f.id, f.job.attempts, JSON.stringify(f.value));
    assert.throws(() => f.ledger.archiveResult(f.id, 'alice'), /Invalid vulnerability finding/);
  } else {
    const before = state(f);
    assert.throws(() => phase === 'checkpoint' ? f.ledger.checkpointArchive(f.job, 'vuln', subset(f.value, 'vuln')) :
      f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, f.job.leaseToken), /Invalid vulnerability finding/);
    assert.deepEqual(state(f), before);
  }
});

test('ordinary legacy Alpine vulnerability writes remain CVE-only', () => {
  const ledger = new ScanLedger(':memory:');
  try {
    const target = { subject: 'alice', idempotencyKey: 'ordinary-temp', registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: digest('a'), platform: 'linux/amd64', checks: '["vuln"]', scope: 'image' };
    const id = ledger.enqueue(target).scanId, job = ledger.claim()!, image = `${target.registry}/${target.repository}@${target.digest}`;
    const finding = structuredClone(temporary(fixtureReport(Date.now(), true))); finding.findingId = findingHash(finding, image, false);
    assert.throws(() => ledger.finishWithVuln(id, job.attempts, image, [finding], '0.69.3', job.leaseToken), /Invalid vulnerability finding/);
    assert.throws(() => ledger.finishCombined(id, job.attempts, [{ check: 'vuln', outcome: 'checked', image, findings: [finding], scannerVersion: '0.69.3' }],
      undefined, job.leaseToken), /Invalid vulnerability finding/);
    assert.equal(ledger.vulnDataset(id, 'alice'), undefined); assert.equal(ledger.checkpointActive(job), true);
  } finally { ledger.close(); }
});

for (const authority of ['wrong', 'missing', 'expired', 'retry', 'replacement', 'cancelled'] as const) {
  test(`public valid TEMP report with ${authority} token authority cannot write`, t => {
    const f = setup(t);
    if (authority === 'expired' || authority === 'replacement') f.advance(627_000);
    if (authority === 'replacement') f.ledger.claim(f.now, 1000);
    if (authority === 'retry') f.ledger.retry(f.id, f.job.attempts, f.now + 1000, f.job.leaseToken);
    if (authority === 'cancelled') f.ledger.cancel(f.id, 'alice');
    const token = authority === 'wrong' ? 'wrong-token' : authority === 'missing' ? undefined : f.job.leaseToken, before = state(f);
    assert.equal(f.ledger.checkpointArchive({ ...f.job, leaseToken: token }, 'vuln', subset(f.value, 'vuln')), false);
    assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, f.value, undefined, token), false);
    assert.deepEqual(state(f), before); ordinaryTablesEmpty(f);
  });
}
