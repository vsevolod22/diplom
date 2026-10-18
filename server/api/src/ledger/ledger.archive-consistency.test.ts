import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger } from './ledger.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION } from '../oci/public-image-policy.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';
import { normalizeAdvisory, omittedAdvisory } from '../worker/vuln-advisory.js';

type Profile = 'legacy' | 'public';
type Check = 'secret' | 'sbom' | 'vuln';
const digest = (char: string) => `sha256:${char.repeat(64)}` as const;
function fixtureReport(profile: Profile, at: number, current: boolean): ArchiveScanReport {
  const target = profile === 'legacy' ? NGINX_ARCHIVE_TARGET : {
    registry: 'registry-1.docker.io', repository: 'example/application', digest: digest('a'), configDigest: digest('b'), platform: 'linux/amd64',
  };
  const image = `${target.registry}/${target.repository}@${target.digest}`, ecosystem = profile === 'legacy' ? 'apk' : 'deb';
  const provenanceRef = `target-${'b'.repeat(64)}`, cveId = 'CVE-2026-1234', packageName = 'package', installedVersion = '1.0';
  const key = JSON.stringify([image, 'linux/amd64', 'vuln', ecosystem, provenanceRef, cveId, packageName, installedVersion]);
  const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@${digest('f')}`, manifestDigest: digest('f'), artifactSha256: 'a'.repeat(64),
    metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64), updatedAt: new Date(at - 60_000).toISOString(),
    downloadedAt: new Date(at - 30_000).toISOString(), nextUpdate: new Date(at + 3_600_000).toISOString() };
  return { receipt: { ...target, layerDigests: [digest('c'), digest('d')], diffIds: [digest('d'), digest('c')], archiveSha256: digest('e'),
    profileVersion: profile === 'public' ? PUBLIC_IMAGE_PROFILE : 'nginx-alpine-amd64-v1',
    resourcePolicyVersion: profile === 'public' ? PUBLIC_IMAGE_RESOURCE_POLICY : 'nginx-archive-resources-v1',
    checksVersion: profile === 'public' ? PUBLIC_IMAGE_CHECKS_VERSION : 'trivy-0.69.3-archive-v1' },
    scannerVersion: '0.69.3', checkedAt: at,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
    secret: { outcome: 'checked', findings: [{ findingId: 'secret-0-0', ruleId: `rule-${'a'.repeat(16)}`, line: 7, evidenceRef: 'result-0-secret-0' }] },
    sbom: { outcome: 'checked', sbom: { image, platform: 'linux/amd64', os: { name: profile === 'legacy' ? 'alpine' : 'debian', version: '12' },
      components: [{ ecosystem, name: packageName, version: installedVersion }] } },
    vuln: { outcome: 'checked', db, ...(current ? { dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY, at)! } : {}),
      os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: profile === 'legacy' ? 'NODE_INVENTORY_ABSENT' : 'NODE_INVENTORY_UNKNOWN' },
      findings: [{ findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`, cveId, ecosystem, packageName, installedVersion,
        fixedVersion: '2.0', severity: 'HIGH', severitySources: ['nvd'], provenanceRef,
        advisory: normalizeAdvisory({ Title: 'Original assessment', Severity: 'HIGH', SeveritySource: 'nvd' }, provenanceRef, cveId) }] } };
}
function subset(value: ArchiveScanReport, check: Check): ArchiveScanReport {
  const { secret, sbom, vuln, ...base } = value;
  return { ...base, [check]: { secret, sbom, vuln }[check] };
}
function setup(t: TestContext, profile: Profile, current = false) {
  const directory = mkdtempSync(join(tmpdir(), 'archive-consistency-')), file = join(directory, 'ledger.sqlite');
  let now = Date.now(), ledger = new ScanLedger(file, () => now);
  const raw = new Database(file), value = fixtureReport(profile, now, current);
  const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'consistency', registry: value.receipt.registry, repository: value.receipt.repository,
    digest: value.receipt.digest as `sha256:${string}`, platform: value.receipt.platform, checks: '["secret","sbom","vuln"]', scope: 'image',
    ...(current ? { cvePolicy: CURRENT_DB_POLICY } : {}) }).scanId;
  const job = ledger.claim(now, 627_000)!;
  t.after(() => { raw.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  return { get ledger() { return ledger; }, get now() { return now; }, advance(ms: number) { now += ms; },
    reopen() { ledger.close(); ledger = new ScanLedger(file, () => now); }, raw, value, id, job };
}
type Fixture = ReturnType<typeof setup>;
function evidence(f: Fixture) {
  return ['scans', 'outbox', 'scan_checkpoints', 'scan_archive_results', 'scan_check_results', 'scan_events']
    .map(table => f.raw.prepare(`SELECT * FROM ${table}`).all());
}
function checkpointAll(f: Fixture) {
  for (const check of ['secret', 'sbom', 'vuln'] as const) assert.equal(f.ledger.checkpointArchive(f.job, check, subset(f.value, check)), true);
}
function rejectsWithoutWrites(f: Fixture, value: ArchiveScanReport, message: RegExp = /Archive checkpoint outcome mismatch/) {
  const before = evidence(f);
  assert.throws(() => f.ledger.finishArchive(f.id, f.job.attempts, value, undefined, f.job.leaseToken), message);
  assert.deepEqual(evidence(f), before, 'outbox, results, checkpoints, state and events are unchanged');
  assert.equal(f.ledger.checkpointActive(f.job), true);
}

for (const profile of ['legacy', 'public'] as const) {
  for (const check of ['secret', 'sbom'] as const) for (const mutation of ['failed', 'changed', 'cleared'] as const) {
    test(`${profile} accepted positive ${check} cannot be ${mutation} by a valid final report`, t => {
      const f = setup(t, profile); checkpointAll(f);
      const final = structuredClone(f.value);
      if (mutation === 'failed') final[check] = { outcome: 'failed', reason: 'SCAN_FAILED' };
      else if (check === 'secret' && final.secret?.outcome === 'checked') {
        if (mutation === 'cleared') final.secret.findings = [];
        else final.secret.findings[0].line = 8;
      } else if (final.sbom?.outcome === 'checked') {
        if (mutation === 'cleared') final.sbom.sbom.components = [{ ecosystem: profile === 'legacy' ? 'apk' : 'deb', name: 'other', version: '2.0' }];
        else final.sbom.sbom.components[0].version = '2.0';
      }
      rejectsWithoutWrites(f, final);
      f.reopen(); assert.equal(f.ledger.cancel(f.id, 'alice'), 'cancelled');
      const saved = f.ledger.archiveResult(f.id, 'alice')!;
      assert.deepEqual(saved.secret, f.value.secret); assert.deepEqual(saved.sbom, f.value.sbom);
      assert.deepEqual(saved.vuln, f.value.vuln); assert.equal(f.ledger.archiveResult(f.id, 'other'), undefined);
      f.reopen(); assert.deepEqual(f.ledger.archiveResult(f.id, 'alice'), saved);
    });
  }

  test(`${profile} unchanged accepted Secrets survives an independently failed unfinished SBOM`, t => {
    const f = setup(t, profile);
    assert.equal(f.ledger.checkpointArchive(f.job, 'secret', subset(f.value, 'secret')), true);
    const final = structuredClone(f.value); final.sbom = { outcome: 'failed', reason: 'SCAN_FAILED' };
    final.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
    final.checkedAt++; final.metrics.scratchPeak++;
    assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, final, undefined, f.job.leaseToken), true);
    assert.equal(f.ledger.state(f.id, 'alice'), 'partial');
    f.reopen(); assert.deepEqual(f.ledger.archiveResult(f.id, 'alice'), final);
  });

  for (const mutation of ['archive-hash', 'diffID-order', 'layer-order'] as const) test(`${profile} final cannot mix checkpoint receipt ${mutation}`, t => {
    const f = setup(t, profile); checkpointAll(f);
    const final = structuredClone(f.value);
    if (mutation === 'archive-hash') final.receipt.archiveSha256 = digest('f');
    if (mutation === 'diffID-order') final.receipt.diffIds.reverse();
    if (mutation === 'layer-order') final.receipt.layerDigests.reverse();
    rejectsWithoutWrites(f, final, /Archive checkpoint receipt mismatch/);
    assert.equal(f.ledger.cancel(f.id, 'alice'), 'cancelled'); assert.deepEqual(f.ledger.archiveResult(f.id, 'alice')?.receipt, f.value.receipt);
  });

  for (const mutation of ['arbitrary-failure', 'invented-DB-expiry', 'changed-finding', 'changed-DB', 'changed-advisory'] as const) {
    test(`${profile} current CVE checkpoint rejects ${mutation}`, t => {
      const f = setup(t, profile, true); checkpointAll(f);
      const final = structuredClone(f.value);
      if (mutation === 'arbitrary-failure') final.vuln = { outcome: 'failed', reason: 'SCAN_FAILED' };
      else if (mutation === 'invented-DB-expiry') final.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
      else if (final.vuln?.outcome === 'checked') {
        if (mutation === 'changed-finding') final.vuln.findings[0].severity = 'LOW';
        if (mutation === 'changed-DB') final.vuln.db = { ...final.vuln.db, dbSha256: 'f'.repeat(64) };
        if (mutation === 'changed-advisory') {
          const finding = final.vuln.findings[0];
          finding.advisory = normalizeAdvisory({ Title: 'Different valid assessment', Severity: 'HIGH', SeveritySource: 'nvd' }, finding.provenanceRef, finding.cveId);
        }
      }
      rejectsWithoutWrites(f, final);
      assert.equal(f.ledger.cancel(f.id, 'alice'), 'cancelled');
      assert.deepEqual(f.ledger.archiveResult(f.id, 'alice')?.vuln, f.value.vuln);
    });
  }

  test(`${profile} current policy reevaluation and later completion time preserve accepted findings`, t => {
    const f = setup(t, profile, true); checkpointAll(f); f.advance(100);
    const final = structuredClone(f.value); final.checkedAt = f.now; final.metrics.scratchPeak++;
    if (final.vuln?.outcome !== 'checked') throw new Error('fixture');
    final.vuln.dbPolicy = evaluateDbPolicy(final.vuln.db, CURRENT_DB_POLICY, final.checkedAt)!;
    assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, final, undefined, f.job.leaseToken), true);
    const saved = f.ledger.archiveResult(f.id, 'alice')!;
    assert.deepEqual(saved.secret, f.value.secret); assert.deepEqual(saved.sbom, f.value.sbom);
    assert.equal(saved.vuln?.dbPolicy?.evaluatedAt, f.now); assert.equal(saved.checkedAt, f.now);
  });

  for (const downgrade of ['ledger', 'returned'] as const) test(`${profile} genuine current DB ${downgrade} downgrade cannot erase unrelated checkpoints`, t => {
    const f = setup(t, profile, true);
    if (f.value.vuln?.outcome !== 'checked') throw new Error('fixture');
    const updated = f.now - 14 * 86400_000 + 100;
    f.value.vuln.db = { ...f.value.vuln.db, updatedAt: new Date(updated).toISOString(), downloadedAt: new Date(updated + 1).toISOString(),
      nextUpdate: new Date(updated + 86400_000).toISOString() };
    f.value.vuln.dbPolicy = evaluateDbPolicy(f.value.vuln.db, CURRENT_DB_POLICY, f.now)!;
    checkpointAll(f); f.advance(101);
    const final = structuredClone(f.value);
    if (downgrade === 'returned') final.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
    for (const check of ['secret', 'sbom'] as const) {
      const contradictory = structuredClone(final); contradictory[check] = { outcome: 'failed', reason: 'SCAN_FAILED' };
      rejectsWithoutWrites(f, contradictory);
    }
    assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, final, undefined, f.job.leaseToken), true);
    assert.equal(f.ledger.state(f.id, 'alice'), 'partial'); f.reopen();
    const saved = f.ledger.archiveResult(f.id, 'alice')!;
    assert.deepEqual(saved.secret, f.value.secret); assert.deepEqual(saved.sbom, f.value.sbom);
    assert.deepEqual(saved.vuln, { outcome: 'failed', reason: 'DB_UNAVAILABLE' });
  });

  for (const omission of ['checkpoint', 'final'] as const) test(`${profile} CVE optional report-budget omission retains all accepted core findings: ${omission}`, t => {
    const f = setup(t, profile, true), final = structuredClone(f.value);
    const value = omission === 'checkpoint' ? f.value : final;
    if (value.vuln?.outcome !== 'checked') throw new Error('fixture');
    value.vuln.findings[0].advisory = omittedAdvisory('report_budget');
    checkpointAll(f);
    assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, final, undefined, f.job.leaseToken), true);
    const saved = f.ledger.archiveResult(f.id, 'alice')!;
    assert.equal(saved.vuln?.outcome, 'checked'); assert.deepEqual(saved.secret, f.value.secret); assert.deepEqual(saved.sbom, f.value.sbom);
  });

  for (const authority of ['wrong', 'missing', 'expired', 'retry', 'replacement', 'cancelled'] as const) {
    test(`${profile} contradictory final with ${authority} authority makes no writes`, t => {
      const f = setup(t, profile); checkpointAll(f);
      const final = structuredClone(f.value); final.secret = { outcome: 'failed', reason: 'SCAN_FAILED' };
      if (authority === 'expired' || authority === 'replacement') f.advance(627_000);
      if (authority === 'replacement') f.ledger.claim(f.now, 1000);
      if (authority === 'retry') f.ledger.retry(f.id, f.job.attempts, f.now + 1000, f.job.leaseToken);
      if (authority === 'cancelled') f.ledger.cancel(f.id, 'alice');
      const token = authority === 'wrong' ? 'wrong-token' : authority === 'missing' ? undefined : f.job.leaseToken;
      const before = evidence(f);
      assert.equal(f.ledger.finishArchive(f.id, f.job.attempts, final, undefined, token), false);
      assert.deepEqual(evidence(f), before);
    });
  }

  test(`${profile} corrupt accepted checkpoint cannot be bypassed by consistent final output`, t => {
    const f = setup(t, profile); checkpointAll(f);
    f.raw.prepare("UPDATE scan_checkpoints SET evidence_hash=? WHERE check_name='secret'").run('0'.repeat(64));
    rejectsWithoutWrites(f, f.value, /Invalid stored checkpoint/);
  });
}
