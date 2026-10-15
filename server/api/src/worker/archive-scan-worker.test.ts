import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion, type ArchiveReceipt } from '../oci/bounded-image-archive.js';
import { scanNginxArchive } from './archive-scan-worker.js';
import { auditArchiveScratch } from './archive-scratch.js';
import type { VulnScanOptions } from './vuln-worker.js';
import { CURRENT_DB_POLICY } from './cve-db-policy.mjs';

const target = NGINX_SUPPORTED_CANDIDATE;
const diffId = `sha256:${'b'.repeat(64)}`;
const archivePath = `/tmp/trivy/jobs/${randomUUID()}/image.tar`;
const receipt: ArchiveReceipt = { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [diffId],
  archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(target),
  resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
const metrics = { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1,
  archiveBytes: 7, reservationPeak: 4096 };
function raw() {
  return { SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: archivePath, Metadata: {
    ImageID: target.configDigest, DiffIDs: [diffId], Layers: [{ DiffID: diffId, Size: 2048 }],
    ImageConfig: { os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: [diffId] } },
    OS: { Family: 'alpine', Name: '3.23.3' } }, Results: [] as unknown[] };
}
function db() {
  return { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`,
    schemaVersion: 2, manifestDigest: `sha256:${'d'.repeat(64)}`, artifactSha256: 'a'.repeat(64),
    metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64), updatedAt: new Date(Date.now() - 60_000).toISOString(),
    downloadedAt: new Date(Date.now() - 30_000).toISOString(), nextUpdate: new Date(Date.now() + 3_600_000).toISOString() };
}
const vulnOptions: VulnScanOptions = { timeoutMs: 120_000, cacheDir: '/synthetic/cache', releaseDir: '/synthetic/release',
  trust: { trustedPublicKeyPem: '', expectedSigner: 'local-db-operator-v1', expectedSource: '', expectedSchemaVersion: 2,
    expectedArtifactSha256: 'a'.repeat(64), expectedManifestDigest: `sha256:${'d'.repeat(64)}` } };

// Actual runner/parsers/audits and SQLite; only archive acquisition, subprocess output
// and DB preflight are injected. These fixtures are not actual Trivy/DB qualification.
async function fixture(run: (directory: string, ledger: ScanLedger) => Promise<void>) {
  const directory = await mkdtemp(`${tmpdir()}/archive-runner-`);
  const ledger = new ScanLedger(`${directory}/ledger.sqlite`);
  try { await mkdir(`${directory}/attempt`); await writeFile(`${directory}/attempt/image.tar`, 'archive'); await run(directory, ledger); }
  finally { ledger.close(); await rm(directory, { recursive: true, force: true }); }
}
function lifecycle(directory: string, invoke: NonNullable<Parameters<typeof scanNginxArchive>[2]>['invoke'],
  audit = auditArchiveScratch) {
  const identity = db();
  return { requireScanner() {}, prepare: async () => ({ archivePath, directory: `${directory}/attempt`, receipt, metrics,
    cleanup: async () => rm(`${directory}/attempt`, { recursive: true, force: true }) }), invoke,
    verifiedDb: async (options: VulnScanOptions) => { void options; return identity; }, audit };
}
function persist(ledger: ScanLedger, checks: string[], report: Awaited<ReturnType<typeof scanNginxArchive>>) {
  const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: 'alice',
    idempotencyKey: randomUUID(), checks: JSON.stringify(checks), scope: 'image' }).scanId;
  const job = ledger.claim()!;
  assert.equal(ledger.finishArchive(id, job.attempts, report), true);
  assert.deepEqual(ledger.archiveResult(id, 'alice'), report);
  return ledger.state(id, 'alice');
}

test('empty/omitted/meaningless Secrets without layer inspection fail at runner -> durable ledger', async () => {
  for (const Results of [undefined, [], [{}], [{ Secrets: [] }], [null], [[]], [{ Secrets: 'invalid' }]]) {
    await fixture(async (directory, ledger) => {
      const value: Record<string, unknown> = raw();
      const metadata = { ...raw().Metadata } as Record<string, unknown>;
      delete metadata.Layers;
      value.Metadata = metadata; value.Results = Results;
      const report = await scanNginxArchive(['secret'], { target }, lifecycle(directory, async () => value));
      assert.deepEqual(report.secret, { outcome: 'failed', reason: 'SCAN_FAILED' });
      assert.equal(persist(ledger, ['secret'], report), 'failed');
    });
  }
});

test('genuine clean schema supports omitted/empty Results but mismatched/malformed layers do not', async () => {
  for (const Results of [undefined, []]) await fixture(async (directory, ledger) => {
    const report = await scanNginxArchive(['secret'], { target }, lifecycle(directory, async () => ({ ...raw(), Results })));
    assert.deepEqual(report.secret, { outcome: 'checked', findings: [] });
    assert.equal(persist(ledger, ['secret'], report), 'completed');
  });
  for (const Layers of [[], [{}], [null], [{ DiffID: `sha256:${'f'.repeat(64)}` }]]) {
    await fixture(async (directory, ledger) => {
      const value = raw(); value.Metadata = { ...value.Metadata, Layers } as typeof value.Metadata;
      const report = await scanNginxArchive(['secret'], { target }, lifecycle(directory, async () => value));
      assert.equal(report.secret?.outcome, 'failed');
      assert.equal(persist(ledger, ['secret'], report), 'failed');
    });
  }
});

test('runner retains clean Secrets and checked OS CVE during concurrent scanner cache cleanup', async () => fixture(async (directory, ledger) => {
  let audits = 0, stop = false;
  let churn: Promise<void> | undefined;
  const deps = lifecycle(directory, async (check, _binding, attempt, signal) => {
    if (check === 'secret') return raw();
    churn = (async () => {
      while (!stop) {
        await mkdir(`${attempt}/cache/temp`);
        await Promise.all(Array.from({ length: 16 }, (_, index) => writeFile(`${attempt}/cache/temp/${index}`, 'tmp')));
        await rm(`${attempt}/cache/temp`, { recursive: true });
      }
    })();
    try { await new Promise(resolve => setTimeout(resolve, 450)); assert.equal(signal.aborted, false); }
    finally { stop = true; await churn; }
    return { ...raw(), Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Packages: [{ Name: 'busybox', Version: '1' }] }] };
  }, async (...args) => { audits++; return auditArchiveScratch(...args); });
  const report = await scanNginxArchive(['secret', 'vuln'], { target, vuln: vulnOptions }, deps);
  assert.ok(audits >= 3);
  assert.equal(report.secret?.outcome, 'checked'); assert.equal(report.vuln?.outcome, 'checked');
  assert.equal(persist(ledger, ['secret', 'vuln'], report), 'completed');
}));

test('v2 archive runner retains overdue3day data, exact policy receipt and independent SBOM', async () => fixture(async (directory, ledger) => {
  const now = Date.now();
  const identity = { ...db(), updatedAt: new Date(now - 3 * 86400_000).toISOString(),
    downloadedAt: new Date(now - 3 * 86400_000 + 1000).toISOString(), nextUpdate: new Date(now - 2 * 86400_000).toISOString() };
  const deps = lifecycle(directory, async check => check === 'sbom'
    ? { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
        metadata: { component: { name: archivePath, type: 'container', properties: [
          { name: 'aquasecurity:trivy:ImageID', value: target.configDigest },
          { name: 'aquasecurity:trivy:DiffID', value: diffId },
          { name: 'aquasecurity:trivy:SchemaVersion', value: '2' },
          { name: 'aquasecurity:trivy:OS:Family', value: 'alpine' },
          { name: 'aquasecurity:trivy:OS:Name', value: '3.23.3' }] } },
        components: [{ type: 'operating-system', name: 'alpine', version: '3.23.3' },
          { type: 'library', name: 'busybox', version: '1', purl: 'pkg:apk/alpine/busybox@1?arch=x86_64&distro=3.23.3' }] }
    : { ...raw(), Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Packages: [{ Name: 'busybox', Version: '1' }] }] });
  let verifications = 0;
  deps.verifiedDb = async options => { verifications++; assert.equal(options.policy, CURRENT_DB_POLICY); return identity; };
  const report = await scanNginxArchive(['sbom', 'vuln'], { target, vuln: { ...vulnOptions, policy: CURRENT_DB_POLICY } }, deps);
  assert.equal(verifications, 2); assert.equal(report.vuln?.outcome, 'checked');
  assert.equal(report.sbom?.outcome, 'checked');
  if (report.vuln?.outcome !== 'checked') throw Error('fixture');
  assert.deepEqual(report.vuln.dbPolicy?.warnings, ['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE']);
  assert.equal(report.vuln.dbPolicy?.evaluatedAt, report.checkedAt);
  const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: 'alice',
    idempotencyKey: randomUUID(), checks: '["sbom","vuln"]', scope: 'image', cvePolicy: CURRENT_DB_POLICY }).scanId;
  const job = ledger.claim()!;
  assert.equal(ledger.finishArchive(id, job.attempts, report), true);
  assert.equal(ledger.archiveResult(id, 'alice')?.vuln?.outcome, 'checked');
  assert.equal(ledger.archiveResult(id, 'alice')?.sbom?.outcome, 'checked');
  assert.equal(ledger.archiveResult(id, 'alice')?.checkedAt, report.checkedAt);
}));

test('unexpected scratch symlink/real audit error fails closed as SCAN_FAILED, never false SCAN_TIMEOUT', async () => {
  for (const periodic of [true, false]) await fixture(async (directory, ledger) => {
    const deps = lifecycle(directory, async (_check, _binding, attempt) => {
      await symlink('/outside/SECRET_CANARY', `${attempt}/cache/foreign`);
      if (periodic) await new Promise(resolve => setTimeout(resolve, 250));
      return raw();
    });
    const report = await scanNginxArchive(['secret'], { target }, deps);
    assert.deepEqual(report.secret, { outcome: 'failed', reason: 'SCAN_FAILED' });
    assert.equal(persist(ledger, ['secret'], report), 'failed');
  });
});

test('real external cancellation remains timeout and own scratch is removed', async () => fixture(async (directory, ledger) => {
  const controller = new AbortController();
  const report = await scanNginxArchive(['secret'], { target, signal: controller.signal }, lifecycle(directory, async () => {
    controller.abort(); return raw();
  }));
  assert.deepEqual(report.secret, { outcome: 'failed', reason: 'SCAN_TIMEOUT' });
  assert.equal(persist(ledger, ['secret'], report), 'failed');
  await assert.rejects(auditArchiveScratch(`${directory}/attempt`), { code: 'ENOENT' });
}));

test('postscan DB rejection/identity change is DB_UNAVAILABLE, independent Secrets survive', async () => {
  for (const changed of [false, true]) for (const checks of [['vuln'], ['secret', 'vuln']] as Array<Array<'secret' | 'vuln'>>) {
    await fixture(async (directory, ledger) => {
      const deps = lifecycle(directory, async check => check === 'secret' ? raw() : { ...raw(),
        Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Packages: [{ Name: 'busybox', Version: '1' }] }] });
      const identity = db(); let calls = 0;
      deps.verifiedDb = async () => {
        if (++calls === 1) return identity;
        if (!changed) throw new Error('PRIVATE_DB_CANARY');
        return { ...identity, dbSha256: 'e'.repeat(64) };
      };
      const report = await scanNginxArchive(checks, { target, vuln: vulnOptions }, deps);
      assert.deepEqual(report.vuln, { outcome: 'failed', reason: 'DB_UNAVAILABLE' });
      if (checks.includes('secret')) assert.equal(report.secret?.outcome, 'checked');
      assert.equal(JSON.stringify(report).includes('PRIVATE_DB_CANARY'), false);
      assert.equal(persist(ledger, checks, report), checks.includes('secret') ? 'partial' : 'failed');
    });
  }
});

test('scanner/identity/malformed output is not relabelled as DB_UNAVAILABLE', async () => {
  for (const output of ['throw', {}, { ...raw(), Metadata: { ...raw().Metadata, ImageID: `sha256:${'e'.repeat(64)}` } }]) {
    await fixture(async (directory, ledger) => {
      const report = await scanNginxArchive(['secret', 'vuln'], { target, vuln: vulnOptions }, lifecycle(directory, async check => {
        if (check === 'secret') return raw();
        if (output === 'throw') throw new Error('SCANNER_SECRET_CANARY');
        return output;
      }));
      assert.deepEqual(report.vuln, { outcome: 'failed', reason: 'SCAN_FAILED' });
      assert.equal(report.secret?.outcome, 'checked');
      assert.equal(persist(ledger, ['secret', 'vuln'], report), 'partial');
    });
  }
});

test('missing/unknown/malformed OS fails, validated EOL is unsupported, EOSL false/omitted remains checked', async () => {
  for (const OS of [undefined, null, [], {}, { Family: 'unknown', Name: '3.23.3' }, { Family: 'alpine' },
    { Family: 'alpine', Name: 3233 }, { Family: 'alpine', Name: '3.23.3', EOSL: 'true' },
    { Family: 'alpine', Name: '3.23.3', EOSL: true }, { Family: 'alpine', Name: '3.23.3', EOSL: false },
    { Family: 'alpine', Name: '3.23.3' }]) {
    await fixture(async (directory, ledger) => {
      const report = await scanNginxArchive(['secret', 'vuln'], { target, vuln: vulnOptions }, lifecycle(directory, async check => {
        if (check === 'secret') return raw();
        return { ...raw(), Metadata: { ...raw().Metadata, OS },
          Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Packages: [{ Name: 'busybox', Version: '1' }] }] };
      }));
      assert.equal(report.secret?.outcome, 'checked');
      const valid = OS && !Array.isArray(OS) && OS.Family === 'alpine' && OS.Name === '3.23.3' &&
        (OS.EOSL === undefined || typeof OS.EOSL === 'boolean');
      const expected = valid ? (OS.EOSL ? 'unsupported' : 'checked') : 'failed';
      assert.equal(report.vuln?.outcome, expected);
      if (expected === 'failed') assert.deepEqual(report.vuln, { outcome: 'failed', reason: 'SCAN_FAILED' });
      if (expected === 'unsupported') assert.equal(report.vuln && 'reason' in report.vuln && report.vuln.reason, 'OS_EOL');
      assert.equal(persist(ledger, ['secret', 'vuln'], report), expected === 'checked' ? 'completed' : 'partial');
    });
  }
});
