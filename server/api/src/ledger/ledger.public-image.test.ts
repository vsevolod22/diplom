import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger, type CombinedOutcome } from './ledger.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { PUBLIC_ECOSYSTEMS, PUBLIC_OS_ECOSYSTEMS } from '../worker/public-image-evidence.js';
import { PUBLIC_VULN_SOURCES } from '../worker/vuln-findings.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_LIMITS } from '../oci/public-image-policy.js';
import { NGINX_SUPPORTED_CANDIDATE } from '../oci/bounded-image-archive.js';
import { NGINX_LOCAL_BINDING } from '../oci/nginx-local-policy.js';
import { admittedConfigTarget, CONFIG_LOAD_MS } from '../oci/pinned-image-config.js';
import { buildResult } from '../image-config/result.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';
import { consumeOne } from '../worker/outbox-consumer.js';

// Synthetic normalized output only; no registry, scanner, Docker or live DB access.
const digest = (char: string) => `sha256:${char.repeat(64)}` as const;
const target = { subject: 'alice', idempotencyKey: 'public', registry: 'registry-1.docker.io', repository: 'example/application',
  digest: digest('a'), platform: 'linux/amd64', checks: '["secret","sbom","vuln"]', scope: 'image' };
const image = `${target.registry}/${target.repository}@${target.digest}`;
const names = { apk: 'busybox', deb: 'libc6', rpm: 'glibc', npm: '@example/lib', pypi: 'Example_Pkg', gem: 'example-gem',
  gomod: 'github.com/Example/lib', cargo: 'example-crate', maven: 'org.example:lib', composer: 'example/lib', nuget: 'Example.Package' };
function report(at: number, current = false): ArchiveScanReport {
  const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
    source: `ghcr.io/aquasecurity/trivy-db@${digest('f')}`, manifestDigest: digest('f'), artifactSha256: 'a'.repeat(64),
    metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64), updatedAt: new Date(at - 60_000).toISOString(),
    downloadedAt: new Date(at - 30_000).toISOString(), nextUpdate: new Date(at + 3_600_000).toISOString() };
  return { receipt: { registry: target.registry, repository: target.repository, digest: target.digest, configDigest: digest('b'), platform: target.platform,
    layerDigests: [digest('c')], diffIds: [digest('d')], archiveSha256: digest('e'), profileVersion: PUBLIC_IMAGE_PROFILE,
    resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION }, scannerVersion: '0.69.3', checkedAt: at,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
    secret: { outcome: 'checked', findings: [{ findingId: 'secret-0-0', ruleId: `rule-${'a'.repeat(16)}`, line: 1, evidenceRef: 'result-0-secret-0' }] },
    sbom: { outcome: 'checked', sbom: { image, platform: 'linux/amd64', os: { name: 'debian', version: '12.12' },
      components: PUBLIC_ECOSYSTEMS.map(ecosystem => ({ ecosystem, name: names[ecosystem], version: '1!2.0,3' })) } },
    vuln: { outcome: 'checked', findings: PUBLIC_ECOSYSTEMS.map(ecosystem => {
      const packageName = names[ecosystem], installedVersion = '1!2.0,3', provenanceRef = `target-${'b'.repeat(64)}`, cveId = 'CVE-2026-1234';
      const key = JSON.stringify([image, 'linux/amd64', 'vuln', ecosystem, provenanceRef, cveId, packageName, installedVersion]);
      return { findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`, ecosystem, packageName, installedVersion, provenanceRef,
        cveId, severity: 'HIGH', severitySources: [...PUBLIC_VULN_SOURCES].sort(), fixedVersion: '2!3,4' };
    }), db, ...(current ? { dbPolicy: evaluateDbPolicy(db, CURRENT_DB_POLICY, at)! } : {}),
    os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } } };
}
function setup(t: TestContext) {
  const directory = mkdtempSync(join(tmpdir(), 'public-ledger-')), file = join(directory, 'ledger.sqlite');
  let now = Date.now(), ledger = new ScanLedger(file, () => now);
  const raw = new Database(file);
  t.after(() => { raw.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  return { get ledger() { return ledger; }, raw, get now() { return now; }, advance(ms: number) { now += ms; },
    reopen() { ledger.close(); ledger = new ScanLedger(file, () => now); } };
}
function subset(value: ArchiveScanReport, check: 'secret' | 'sbom' | 'vuln'): ArchiveScanReport {
  const { secret, sbom, vuln, ...base } = value;
  return { ...base, [check]: { secret, sbom, vuln }[check] };
}
function noOrdinaryCoverage(raw: Database.Database) {
  for (const table of ['scan_results', 'scan_findings', 'scan_sbom_results', 'scan_sbom_components', 'scan_vuln_results', 'scan_vuln_findings'])
    assert.deepEqual(raw.prepare(`SELECT * FROM ${table}`).all(), [], table);
}

test('public eleven-ecosystem final report is owner scoped, archive-only, immutable, reopened and retained historically', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, cvePolicy: CURRENT_DB_POLICY }).scanId;
  assert.deepEqual(f.ledger.pinnedTarget(id, 'alice'), { registry: target.registry, repository: target.repository, digest: target.digest, platform: target.platform });
  assert.equal(f.ledger.pinnedTarget(id, 'bob'), undefined); assert.equal(f.ledger.pinnedTarget('missing', 'alice'), undefined);
  const job = f.ledger.claim(f.now)!, value = report(f.now, true);
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), true);
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), false);
  assert.equal(f.ledger.state(id, 'alice'), 'completed');
  assert.deepEqual(f.ledger.archiveResult(id, 'alice'), value); assert.equal(f.ledger.archiveResult(id, 'bob'), undefined);
  noOrdinaryCoverage(f.raw);
  assert.equal(f.ledger.enqueue({ ...target, cvePolicy: CURRENT_DB_POLICY }).scanId, id);
  f.advance(365 * 86400_000); f.reopen();
  assert.deepEqual(f.ledger.archiveResult(id, 'alice'), value, 'read uses accepted DB evaluation, not present freshness');
  const active = f.ledger.enqueue({ ...target, idempotencyKey: 'active', checks: '["sbom"]' }).scanId;
  f.raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id);
  assert.equal(f.ledger.prune(), 1); assert.equal(f.ledger.archiveResult(id, 'alice'), undefined);
  assert.equal(f.ledger.pinnedTarget(id, 'alice'), undefined); assert.ok(f.ledger.pinnedTarget(active, 'alice'));
});

for (const family of Object.keys(PUBLIC_OS_ECOSYSTEMS)) test(`public supported ${family} SBOM accepts only numeric bounded release`, t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["sbom"]' }).scanId, job = f.ledger.claim(f.now)!;
  const value = subset(report(f.now), 'sbom');
  if (value.sbom?.outcome !== 'checked') throw new Error('fixture');
  value.sbom.sbom.os = { name: family, version: '1.2.3.4' };
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), true);
  assert.deepEqual(f.ledger.archiveResult(id, 'alice'), value);
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Adversarial fixtures deliberately add malformed fields outside the closed production report type.
type Mutation = (value: any) => void;
const malformed: Array<[string, Mutation]> = [
  ['root raw', v => { v.raw = 'RAW_CANARY'; }],
  ['receipt raw', v => { v.receipt.Env = ['RAW_CANARY']; }],
  ['profile alone', v => { v.receipt.resourcePolicyVersion = 'nginx-archive-resources-v1'; }],
  ['legacy checks version', v => { v.receipt.checksVersion = 'trivy-0.69.3-archive-v1'; }],
  ['extra check version', v => { v.sbom.scannerVersion = { Match: 'RAW_CANARY' }; }],
  ['shadow check', v => { v.secret.check = 'sbom'; }],
  ['secret raw nested', v => { v.secret.findings[0].Code = { Match: 'RAW_CANARY' }; }],
  ['secret unsanitized rule', v => { v.secret.findings[0].ruleId = 'raw-rule'; }],
  ['SBOM raw nested', v => { v.sbom.sbom.components[0].raw = { Match: 'RAW_CANARY' }; }],
  ['OS raw nested', v => { v.sbom.sbom.os.raw = 'RAW_CANARY'; }],
  ['unsupported OS', v => { v.sbom.sbom.os.name = 'windows'; }],
  ['malformed OS release', v => { v.sbom.sbom.os.version = 'bookworm'; }],
  ['unknown ecosystem', v => { v.sbom.sbom.components[0].ecosystem = 'arbitrary'; }],
  ['SBOM unsafe name', v => { v.sbom.sbom.components[0].name = '../../raw'; }],
  ['SBOM unsafe version', v => { v.sbom.sbom.components[0].version = '1 RAW_CANARY'; }],
  ['duplicate component', v => { v.sbom.sbom.components.push(v.sbom.sbom.components[0]); }],
  ['CVE nested raw', v => { v.vuln.findings[0].raw = { Match: 'RAW_CANARY' }; }],
  ['CVE bad hash', v => { v.vuln.findings[0].findingId = `vuln-${'0'.repeat(64)}`; }],
  ['CVE duplicate', v => { v.vuln.findings.push(v.vuln.findings[0]); }],
  ['CVE arbitrary source', v => { v.vuln.findings[0].severitySources = ['arbitrary']; }],
  ['CVE unordered sources', v => { v.vuln.findings[0].severitySources = ['nvd', 'debian']; }],
  ['CVE unsafe package', v => { v.vuln.findings[0].packageName = 'RAW CANARY'; }],
  ['CVE unsafe fixed version', v => { v.vuln.findings[0].fixedVersion = { raw: 'RAW_CANARY' }; }],
  ['legacy absence reason', v => { v.vuln.node.reason = 'NODE_INVENTORY_ABSENT'; }],
  ['node nested raw', v => { v.vuln.node.raw = 'RAW_CANARY'; }],
  ['invalid layer', v => { v.receipt.layerDigests[0] = 'sha256:bad'; }],
  ['too many layers', v => { v.receipt.layerDigests = Array(65).fill(digest('c')); v.receipt.diffIds = Array(65).fill(digest('d')); }],
  ['metric out of bounds', v => { v.metrics.scratchPeak = PUBLIC_IMAGE_LIMITS.scratchBytes + 1; }],
  ['metric raw', v => { v.metrics.raw = 'RAW_CANARY'; }],
  ['cross-target receipt', v => { v.receipt.repository = 'other/application'; v.sbom.sbom.image = `${v.receipt.registry}/${v.receipt.repository}@${v.receipt.digest}`;
    for (const finding of v.vuln.findings) finding.findingId = `vuln-${createHash('sha256').update(JSON.stringify([v.sbom.sbom.image, 'linux/amd64', 'vuln', finding.ecosystem, finding.provenanceRef, finding.cveId, finding.packageName, finding.installedVersion])).digest('hex')}`; }],
];
for (const [name, mutate] of malformed) for (const phase of ['checkpoint', 'finalize', 'read'] as const) {
  test(`public rejects ${name} at ${phase}`, t => {
    const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!, value = report(f.now);
    const before = structuredClone(value);
    mutate(value);
    const changedCheck = (['secret', 'sbom', 'vuln'] as const).find(check => JSON.stringify(value[check]) !== JSON.stringify(before[check])) ?? 'secret';
    if (phase === 'read') {
      f.raw.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(id, job.attempts, JSON.stringify(value));
      assert.equal(f.ledger.archiveResult(id, 'bob'), undefined);
      assert.throws(() => f.ledger.archiveResult(id, 'alice'), TypeError);
    } else {
      assert.throws(() => phase === 'finalize' ? f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken) :
        f.ledger.checkpointArchive(job, changedCheck, subset(value, changedCheck)), TypeError);
      assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []);
      assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
      assert.equal(f.ledger.state(id, 'alice'), 'running'); assert.equal(f.ledger.checkpointActive(job), true);
    }
    noOrdinaryCoverage(f.raw);
  });
}

for (const mode of ['wrong-token', 'missing-token', 'expired', 'replacement', 'retry', 'cancelled'] as const) {
  test(`public original claim fences checkpoint and finalization: ${mode}`, t => {
    const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now, 100)!, value = report(f.now);
    if (mode === 'expired' || mode === 'replacement') f.advance(100);
    if (mode === 'replacement') f.ledger.claim(f.now, 100);
    if (mode === 'retry') assert.equal(f.ledger.retry(id, job.attempts, f.now + 1000, job.leaseToken), true);
    if (mode === 'cancelled') assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
    const token = mode === 'wrong-token' ? 'other-token' : mode === 'missing-token' ? undefined : job.leaseToken;
    const before = f.raw.prepare('SELECT * FROM outbox').all(), events = f.ledger.events(id, 'alice', null);
    assert.equal(f.ledger.checkpointArchive({ ...job, leaseToken: token }, 'secret', subset(value, 'secret')), false);
    assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, token), false);
    assert.deepEqual(f.raw.prepare('SELECT * FROM outbox').all(), before); assert.deepEqual(f.ledger.events(id, 'alice', null), events);
    assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []);
  });
}

test('public checkpoints survive expiry/reopen/cancel, preserve exact completed subset and retention removes evidence', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, cvePolicy: CURRENT_DB_POLICY }).scanId, job = f.ledger.claim(f.now, 100)!, value = report(f.now, true);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', subset(value, 'sbom')), true);
  assert.equal(f.ledger.checkpointArchive(job, 'vuln', subset(value, 'vuln')), true);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', subset(value, 'sbom')), false);
  assert.equal(f.ledger.archiveResult(id, 'alice'), undefined);
  f.advance(365 * 86400_000); f.reopen();
  assert.equal(f.ledger.cancel(id, 'bob'), 'not_found');
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  const saved = f.ledger.archiveResult(id, 'alice')!;
  assert.equal(saved.secret, undefined); assert.deepEqual(saved.sbom, value.sbom); assert.deepEqual(saved.vuln, value.vuln);
  assert.deepEqual(saved.receipt, value.receipt); noOrdinaryCoverage(f.raw);
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), false);
  f.reopen(); assert.deepEqual(f.ledger.archiveResult(id, 'alice'), saved);
  f.raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id);
  assert.equal(f.ledger.prune(), 1); assert.deepEqual(f.raw.prepare('SELECT * FROM scan_checkpoints').all(), []);
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []);
});

test('public checkpoint identity cannot mix archive hashes, config digests or diffID order', t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!, value = report(f.now);
  assert.equal(f.ledger.checkpointArchive(job, 'secret', subset(value, 'secret')), true);
  for (const change of [{ archiveSha256: digest('f') }, { configDigest: digest('f') }, { diffIds: [digest('c')] }]) {
    const other = subset(value, 'sbom'); other.receipt = { ...other.receipt, ...change };
    assert.throws(() => f.ledger.checkpointArchive(job, 'sbom', other), /Mixed archive checkpoint identity/);
  }
  assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled'); assert.equal(f.ledger.archiveResult(id, 'alice')?.sbom, undefined);
});

for (const tamper of ['body', 'hash', 'owner'] as const) test(`public stored checkpoint ${tamper} tampering fails atomic cancellation`, t => {
  const f = setup(t), id = f.ledger.enqueue(target).scanId, job = f.ledger.claim(f.now)!, value = report(f.now);
  assert.equal(f.ledger.checkpointArchive(job, 'secret', subset(value, 'secret')), true);
  assert.equal(f.ledger.checkpointArchive(job, 'sbom', subset(value, 'sbom')), true);
  const row = f.raw.prepare("SELECT identity,body,committed_at AS at FROM scan_checkpoints WHERE scan_id=? AND check_name='sbom'").get(id) as { identity: string; body: string; at: number };
  if (tamper === 'body') f.raw.prepare("UPDATE scan_checkpoints SET body='{}' WHERE scan_id=? AND check_name='sbom'").run(id);
  if (tamper === 'hash') f.raw.prepare("UPDATE scan_checkpoints SET evidence_hash=? WHERE scan_id=? AND check_name='sbom'").run('0'.repeat(64), id);
  if (tamper === 'owner') {
    const identity = JSON.stringify({ ...JSON.parse(row.identity), subject: 'bob' });
    const hash = createHash('sha256').update(JSON.stringify([identity, 'sbom', 'archive', row.at, row.body])).digest('hex');
    f.raw.prepare("UPDATE scan_checkpoints SET identity=?,evidence_hash=? WHERE scan_id=? AND check_name='sbom'").run(identity, hash, id);
  }
  assert.throws(() => f.ledger.cancel(id, 'alice'), TypeError); assert.equal(f.ledger.state(id, 'alice'), 'running');
  assert.deepEqual(f.raw.prepare('SELECT * FROM scan_archive_results').all(), []); noOrdinaryCoverage(f.raw);
});

for (const phase of ['checkpoint', 'finalize', 'read'] as const) test(`public receipt never satisfies nginx execution profile at ${phase}`, t => {
  const f = setup(t), pinned = { ...target, ...NGINX_SUPPORTED_CANDIDATE, digest: NGINX_SUPPORTED_CANDIDATE.digest as `sha256:${string}`, checks: '["secret"]', executionProfile: NGINX_LOCAL_BINDING };
  const id = f.ledger.enqueue(pinned).scanId, job = f.ledger.claim(f.now)!;
  const value = subset(report(f.now), 'secret'); value.receipt = { ...value.receipt, ...NGINX_SUPPORTED_CANDIDATE };
  if (phase === 'checkpoint') assert.throws(() => f.ledger.checkpointArchive(job, 'secret', value), /Execution receipt mismatch/);
  if (phase === 'finalize') assert.throws(() => f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), /Execution receipt mismatch/);
  if (phase === 'read') {
    f.raw.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(id, job.attempts, JSON.stringify(value));
    assert.throws(() => f.ledger.archiveResult(id, 'alice'), /Execution receipt mismatch/);
  }
});

test('public resource profile alone admits 64 layers and larger metrics without legacy widening', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret"]' }).scanId, job = f.ledger.claim(f.now)!;
  const value = subset(report(f.now), 'secret'); value.receipt.layerDigests = Array(64).fill(digest('c')); value.receipt.diffIds = Array(64).fill(digest('d'));
  value.metrics = { wireBytes: PUBLIC_IMAGE_LIMITS.wireBytes, requests: PUBLIC_IMAGE_LIMITS.requests, compressedBytes: PUBLIC_IMAGE_LIMITS.compressedTotal,
    expandedBytes: PUBLIC_IMAGE_LIMITS.expandedTotal, entries: PUBLIC_IMAGE_LIMITS.entries, archiveBytes: PUBLIC_IMAGE_LIMITS.archiveBytes,
    reservationPeak: PUBLIC_IMAGE_LIMITS.scratchBytes, scratchPeak: PUBLIC_IMAGE_LIMITS.scratchBytes };
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), true);
  assert.deepEqual(f.ledger.archiveResult(id, 'alice'), value);
});

test('public config-only and config checkpoint cancellation use explicit safe target, not ordinary checked generic results', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["config"]' }).scanId, job = f.ledger.claim(f.now)!;
  assert.equal(admittedConfigTarget(job), false); assert.equal(admittedConfigTarget(job, true), true);
  const config = buildResult({ outcome: 'checked' }, { dockerfile: false, iac: false },
    { manifestDigest: job.digest, configDigest: digest('b'), platform: { os: 'linux', architecture: 'amd64' } }, 'DEFAULT_ROOT');
  assert.equal(f.ledger.checkpointConfig(job, config), true);
  assert.equal(f.ledger.finishCombined(id, job.attempts, [], config, 'wrong-token'), false);
  assert.equal(f.ledger.finishCombined(id, job.attempts, [], config, job.leaseToken), true);
  assert.equal(f.ledger.state(id, 'alice'), 'completed'); assert.deepEqual(f.ledger.configResult(id, 'alice'), config);
  assert.equal(f.ledger.configResult(id, 'bob'), undefined); assert.equal(f.ledger.archiveResult(id, 'alice'), undefined); noOrdinaryCoverage(f.raw);
  const next = f.ledger.enqueue({ ...target, idempotencyKey: 'config-cancel', checks: '["config"]' }).scanId, second = f.ledger.claim(f.now)!;
  assert.equal(f.ledger.checkpointConfig(second, config), true); f.reopen(); assert.equal(f.ledger.cancel(next, 'alice'), 'cancelled');
  assert.deepEqual(f.ledger.configResult(next, 'alice'), config);
  const generic = f.ledger.enqueue({ ...target, idempotencyKey: 'generic', checks: '["secret","config"]' }).scanId, third = f.ledger.claim(f.now)!;
  const checked: CombinedOutcome = { check: 'secret', outcome: 'checked', findings: [], scannerVersion: '0.69.3' };
  assert.throws(() => f.ledger.finishCombined(generic, third.attempts, [checked], config, third.leaseToken), /Scan combined contract mismatch/);
  assert.throws(() => f.ledger.checkpointCombined(third, checked), /Checkpoint image mismatch/);
  assert.equal(f.ledger.finishCombined(generic, third.attempts, [{ check: 'secret', outcome: 'failed', errorCode: 'SCAN_FAILED' }], config, third.leaseToken), true);
  assert.equal(f.ledger.state(generic, 'alice'), 'partial');
});

for (const change of [{ registry: 'evil.example' }, { repository: '../image' }, { platform: 'linux/arm64' }, { scope: 'container' }]) {
  test(`public config-only rejects unsafe target ${JSON.stringify(change)}`, t => {
    const f = setup(t), id = f.ledger.enqueue({ ...target, ...change, checks: '["config"]' }).scanId, job = f.ledger.claim(f.now)!;
    const config = buildResult({ outcome: 'checked' }, { dockerfile: false, iac: false });
    assert.throws(() => f.ledger.checkpointConfig(job, config), TypeError);
    assert.throws(() => f.ledger.finishCombined(id, job.attempts, [], config, job.leaseToken), /Scan combined contract mismatch/);
    assert.equal(f.ledger.state(id, 'alice'), 'running');
  });
}

test('explicit archive lease reserves 627s for non-Alpine and config budget, with no early replacement claim', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret","config"]' }).scanId;
  const job = f.ledger.claim(f.now, 30_000, 627_000)!;
  const lease = f.raw.prepare('SELECT lease_until AS until FROM outbox WHERE scan_id=?').get(id) as { until: number };
  assert.equal(lease.until, f.now + 627_000 + CONFIG_LOAD_MS + 1000);
  f.advance(627_000 + CONFIG_LOAD_MS + 999); assert.equal(f.ledger.checkpointActive(job), true); assert.equal(f.ledger.claim(f.now), undefined);
  f.advance(1); assert.equal(f.ledger.checkpointActive(job), false); assert.equal(f.ledger.claim(f.now)!.attempts, 2);
  f.ledger.cancel(id, 'alice');
  const alpine = f.ledger.enqueue({ ...target, repository: 'library/alpine', idempotencyKey: 'legacy', checks: '["secret"]' }).scanId;
  f.ledger.claim(f.now, 30_000, 627_000);
  assert.equal((f.raw.prepare('SELECT lease_until AS until FROM outbox WHERE scan_id=?').get(alpine) as { until: number }).until, f.now + 30_000);
});

for (const reason of ['OS_UNKNOWN', 'OS_EOL'] as const) test(`public ${reason} coverage preserves unknown Node inventory`, t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId, job = f.ledger.claim(f.now)!;
  const value = subset(report(f.now, true), 'vuln');
  if (value.vuln?.outcome !== 'checked') throw new Error('fixture');
  const { db, dbPolicy } = value.vuln;
  value.vuln = { outcome: 'unsupported', reason, db, dbPolicy, os: { outcome: 'unsupported', reason },
    node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } };
  assert.equal(f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), true);
  assert.equal(f.ledger.state(id, 'alice'), 'failed'); assert.deepEqual(f.ledger.archiveResult(id, 'alice'), value);
});

for (const phase of ['checkpoint', 'finalize'] as const) test(`public DB expiry at ${phase} preserves SBOM and fails CVE only`, t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["sbom","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId, job = f.ledger.claim(f.now)!;
  const value = report(f.now, true);
  if (value.vuln?.outcome !== 'checked') throw new Error('fixture');
  const updatedAt = f.now - 14 * 86400_000;
  value.vuln.db = { ...value.vuln.db, updatedAt: new Date(updatedAt).toISOString(),
    downloadedAt: new Date(updatedAt + 1000).toISOString(), nextUpdate: new Date(updatedAt + 86400_000).toISOString() };
  value.vuln.dbPolicy = evaluateDbPolicy(value.vuln.db, CURRENT_DB_POLICY, f.now)!;
  f.advance(2);
  if (phase === 'checkpoint') {
    assert.equal(f.ledger.checkpointArchive(job, 'sbom', subset(value, 'sbom')), true);
    assert.equal(f.ledger.checkpointArchive(job, 'vuln', subset(value, 'vuln')), true);
    assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  } else {
    const { secret, ...final } = value; void secret;
    assert.equal(f.ledger.finishArchive(id, job.attempts, final, undefined, job.leaseToken), true);
    assert.equal(f.ledger.state(id, 'alice'), 'partial');
  }
  const saved = f.ledger.archiveResult(id, 'alice')!;
  assert.deepEqual(saved.sbom, value.sbom); assert.deepEqual(saved.vuln, { outcome: 'failed', reason: 'DB_UNAVAILABLE' });
});

test('generic checked secret/SBOM/CVE cannot escape into ordinary legacy tables', t => {
  const f = setup(t), value = report(f.now);
  for (const check of ['secret', 'sbom', 'vuln'] as const) {
    const id = f.ledger.enqueue({ ...target, checks: JSON.stringify([check]), idempotencyKey: check }).scanId, job = f.ledger.claim(f.now)!;
    if (check === 'secret') assert.throws(() => f.ledger.finishWithResult(id, job.attempts, [], '0.69.3', job.leaseToken), /contract mismatch/);
    const sbom = value.sbom;
    if (check === 'sbom' && sbom?.outcome === 'checked') assert.throws(() => f.ledger.finishWithSbom(id, job.attempts, sbom.sbom, '0.69.3', job.leaseToken), TypeError);
    if (check === 'vuln') assert.throws(() => f.ledger.finishWithVuln(id, job.attempts, image, [], '0.69.3', job.leaseToken), TypeError);
    noOrdinaryCoverage(f.raw); assert.equal(f.ledger.state(id, 'alice'), 'running');
    assert.equal(f.ledger.checkpointActive(job), true); f.ledger.cancel(id, 'alice');
  }
});


test('public normalization never widens legacy archive profile or Alpine combined parser', t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, ...NGINX_SUPPORTED_CANDIDATE, digest: NGINX_SUPPORTED_CANDIDATE.digest as `sha256:${string}` }).scanId,
    job = f.ledger.claim(f.now)!, value = report(f.now);
  value.receipt = { ...value.receipt, ...NGINX_SUPPORTED_CANDIDATE, profileVersion: 'nginx-alpine-amd64-v2-candidate',
    resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
  if (value.sbom?.outcome !== 'checked' || value.vuln?.outcome !== 'checked') throw new Error('fixture');
  value.sbom.sbom.image = `${job.registry}/${job.repository}@${job.digest}`;
  value.vuln.node = { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' };
  assert.throws(() => f.ledger.finishArchive(id, job.attempts, value, undefined, job.leaseToken), /Invalid SBOM/);
  f.ledger.cancel(id, 'alice');
  const alpine = f.ledger.enqueue({ ...target, repository: 'library/alpine', idempotencyKey: 'alpine', checks: '["sbom"]' }).scanId,
    next = f.ledger.claim(f.now)!;
  const sbom = { ...value.sbom.sbom, image: `${next.registry}/${next.repository}@${next.digest}`, os: { name: 'alpine', version: '3.20' } };
  assert.throws(() => f.ledger.finishCombined(alpine, next.attempts, [{ check: 'sbom', outcome: 'checked', sbom, scannerVersion: '0.69.3' }], undefined, next.leaseToken), /Invalid SBOM component/);
  noOrdinaryCoverage(f.raw);
});

test('public consumer storage errors keep original failure and accepted sibling cancellable', async t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret","sbom"]' }).scanId, value = report(f.now);
  f.raw.exec("CREATE TRIGGER reject_public BEFORE INSERT ON scan_checkpoints WHEN NEW.check_name='sbom' BEGIN SELECT RAISE(ABORT,'public storage error'); END");
  let storageError: unknown;
  await assert.rejects(consumeOne(f.ledger, { timeoutMs: 1000, dbDir: '/unused', publicImagePolicy: true }, undefined, f.now,
    undefined, undefined, undefined, async (_checks, options) => {
      assert.equal(options.onCheckpoint!('secret', subset(value, 'secret')), true);
      try { options.onCheckpoint!('sbom', subset(value, 'sbom')); } catch (error) { storageError = error; }
      return new Promise(() => {});
    }), (error: unknown) => { assert.equal(error, storageError); return true; });
  assert.equal(f.ledger.state(id, 'alice'), 'running'); assert.equal(f.ledger.cancel(id, 'alice'), 'cancelled');
  assert.deepEqual(f.ledger.archiveResult(id, 'alice')?.secret, value.secret); assert.equal(f.ledger.archiveResult(id, 'alice')?.sbom, undefined);
});

test('public consumer checkpoints/finalizes original claimed job with the full archive lease', async t => {
  const f = setup(t), id = f.ledger.enqueue({ ...target, checks: '["secret","sbom"]' }).scanId;
  const value = report(f.now), { vuln, ...final } = value; void vuln;
  assert.equal(await consumeOne(f.ledger, { timeoutMs: 1000, dbDir: '/unused', publicImagePolicy: true }, undefined, f.now,
    undefined, undefined, undefined, async (_checks, options) => {
      f.advance(60_000); assert.equal(options.signal?.aborted, false);
      assert.equal(options.onCheckpoint!('secret', subset(value, 'secret')), true);
      assert.equal(options.onCheckpoint!('sbom', subset(value, 'sbom')), true);
      return final;
    }), true);
  assert.equal(f.ledger.state(id, 'alice'), 'completed'); assert.deepEqual(f.ledger.archiveResult(id, 'alice'), final);
});
