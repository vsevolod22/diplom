import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { ScanLedger } from '../ledger/ledger.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import { parseVulnFindings } from '../worker/vuln-findings.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';

const origin = 'http://127.0.0.1:8080';
const ordinary = { registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64' };
const diffId = `sha256:${'b'.repeat(64)}`;
const receipt = { ...NGINX_SUPPORTED_CANDIDATE, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [diffId],
  archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(NGINX_SUPPORTED_CANDIDATE),
  resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
const binding = { receipt, archivePath: `/tmp/trivy/jobs/${randomUUID()}/image.tar` };
const encoded = Buffer.from('synthetic-user:PRIVATE_BASIC_PASSWORD').toString('base64');
const core = { VulnerabilityID: 'CVE-2026-1234', PkgName: 'busybox', InstalledVersion: '1.2',
  Severity: 'HIGH', SeveritySource: 'alpine', DataSource: { ID: 'alpine' } };
const cases: Array<{ name: string; metadata: Record<string, unknown> }> = [
  { name: 'safe control', metadata: { Title: 'Safe title', Description: 'Safe prose' } },
  { name: 'Basic in both fields', metadata: { Title: `Authorization: Basic ${encoded}`, Description: `Authorization: Basic ${encoded}` } },
  { name: 'case whitespace quoted Proxy-Authorization', metadata: { Title: `pRoXy-AuThOrIzAtIoN:\t bAsIc\t"${encoded}"`, Description: `Authorization: Basic '${encoded}'` } },
  { name: 'nested Markdown in both fields', metadata: { Title: '[[issue](doc)](outer)', Description: '[[issue](doc)](outer)' } },
  { name: 'exposed Basic and nested markup', metadata: { Title: `Basic\u0000 ${encoded}`, Description: `[[issue](doc)](outer) Authorization: Basic ${encoded}` } },
  { name: 'bounded normalization exhaustion', metadata: { Title: '['.repeat(32) + 'issue' + '](doc)'.repeat(32), Description: '['.repeat(32) + 'issue' + '](doc)'.repeat(32) } },
  { name: 'invalid optional metadata', metadata: { Title: {}, Description: [], CVSS: { nvd: { V3Score: 'invalid', V3Vector: 'invalid' } } } },
  { name: 'missing optional metadata', metadata: {} },
];
function source(kind: 'ordinary' | 'archive', metadata: Record<string, unknown>) {
  const target = kind === 'ordinary' ? ordinary : NGINX_SUPPORTED_CANDIDATE;
  const image = `${target.registry}/${target.repository}@${target.digest}`;
  const raw = { SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: kind === 'ordinary' ? image : binding.archivePath,
    Metadata: { ...(kind === 'ordinary' ? { RepoDigests: [image] } : { ImageID: NGINX_SUPPORTED_CANDIDATE.configDigest, DiffIDs: [diffId] }),
      ImageConfig: { os: 'linux', architecture: 'amd64', ...(kind === 'archive' ? { rootfs: { type: 'layers', diff_ids: [diffId] } } : {}) },
      OS: { Family: 'alpine', Name: '3.23.3' } },
    Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Packages: [{ Name: 'busybox', Version: '1.2' }], Vulnerabilities: [{ ...core, ...metadata }] }] };
  return parseVulnFindings(raw, image, target.platform, kind === 'archive' ? binding : undefined);
}

// Actual normalizer -> consumer -> on-disk SQLite -> real Nest cookie HTTP -> strict
// browser parser. Only scanner/acquisition/DB outputs are injected, NOT Trivy/Chromium E2E.
for (const kind of ['ordinary', 'archive'] as const) test(`${kind} consumer preserves CVEs and successful siblings with hostile optional advisory text`, async t => {
  const { parseCurrentVuln, parseCurrentStatus, parseCurrentResults, parseCurrentSbom } = await import(
    new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const directory = mkdtempSync(join(tmpdir(), 'advisory-consumer-http-'));
  const env = { SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_DB_PATH: join(directory, 'auth.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_JWT_SECRET: 'disposable-advisory-http-secret-not-production-12345', SCAN_JWT_ISSUER: 'advisory-test',
    SCAN_JWT_AUDIENCE: 'advisory-test', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'disposable-advisory-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('owner@example.com'), other = await register('other@example.com');
    const ledger = app.get(LedgerStore).ledger!;
    const target = kind === 'ordinary' ? ordinary : NGINX_SUPPORTED_CANDIDATE;
    const image = `${target.registry}/${target.repository}@${target.digest}`;
    const sbom = { image, platform: 'linux/amd64' as const, os: { name: 'alpine' as const, version: '3.23.3' },
      components: [{ ecosystem: 'apk' as const, name: 'busybox', version: '1.2' }] };
    const baselineId = source(kind, {}).map(finding => finding.findingId);
    for (const input of cases) await t.test(input.name, async () => {
      const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: owner.id,
        idempotencyKey: randomUUID(), checks: '["secret","sbom","vuln"]', scope: 'image' }).scanId;
      const findings = source(kind, input.metadata);
      assert.deepEqual(findings.map(finding => finding.findingId), baselineId);
      const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`,
        schemaVersion: 2, manifestDigest: `sha256:${'d'.repeat(64)}`, artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
        updatedAt: new Date(Date.now() - 60_000).toISOString(), downloadedAt: new Date(Date.now() - 30_000).toISOString(), nextUpdate: new Date(Date.now() + 3_600_000).toISOString() };
      const archiveReport: ArchiveScanReport = { receipt, scannerVersion: '0.69.3', checkedAt: Date.now(),
        metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1,
          archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
        secret: { outcome: 'checked', findings: [] }, sbom: { outcome: 'checked', sbom },
        vuln: { outcome: 'checked', findings, db, os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } } };
      assert.equal(await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/synthetic/cache', archivePolicy: 'proof',
        vuln: { cacheDir: '/synthetic/cache', releaseDir: '/synthetic/release', trust: { trustedPublicKeyPem: '',
          expectedSigner: 'local-db-operator-v1', expectedSource: '', expectedSchemaVersion: 2,
          expectedArtifactSha256: 'a'.repeat(64), expectedManifestDigest: `sha256:${'d'.repeat(64)}` } } },
      async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }), Date.now(),
      async () => ({ ok: true, sbom, scannerVersion: '0.69.3' }),
      async () => ({ ok: true, findings, scannerVersion: '0.69.3' }), async () => archiveReport), true);
      assert.equal(ledger.state(id, owner.id), 'completed');
      const path = `${base}/browser/scans/${id}`;
      const get = (suffix: string) => fetch(path + suffix, { headers: { cookie: owner.cookie } });
      const status = parseCurrentStatus(await (await get('')).json());
      assert.equal(status.state, 'completed');
      for (const check of ['secret', 'sbom', 'vuln']) assert.equal(status.perCheck?.[check]?.outcome, 'checked');
      const response = await get('/vuln');
      assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
      const wire = await response.json();
      const parsed = parseCurrentVuln(wire);
      assert.equal(parsed.findingCount, 1); assert.equal(parsed.outcome, 'checked');
      assert.deepEqual(parsed.findings, findings);
      assert.equal(parsed.image, image); assert.equal(parsed.scannerVersion, '0.69.3');
      assert.equal(parseCurrentResults(await (await get('/results')).json()).coverage[0].findingCount, 0);
      assert.equal(parseCurrentSbom(await (await get('/sbom')).json()).componentCount, 1);
      assert.deepEqual(parseCurrentVuln(await (await get('/vuln')).json()), parsed);
      assert.equal((await fetch(path + '/vuln')).status, 401);
      assert.equal((await fetch(path + '/vuln', { headers: { cookie: other.cookie } })).status, 404);
      const stored = new Database(env.SCAN_LEDGER_PATH, { readonly: true });
      try {
        const rows = stored.prepare(kind === 'ordinary' ? 'SELECT advisory FROM scan_vuln_findings WHERE scan_id=?' : 'SELECT report FROM scan_archive_results WHERE scan_id=?').all(id);
        assert.equal(rows.length, 1);
        for (const text of [JSON.stringify(rows), JSON.stringify(wire), JSON.stringify(parsed)]) {
          assert.ok(!text.includes(encoded)); assert.ok(!text.includes('PRIVATE_BASIC_PASSWORD'));
        }
      } finally { stored.close(); }
      const reopened = new ScanLedger(env.SCAN_LEDGER_PATH);
      try {
        assert.equal(reopened.state(id, owner.id), 'completed');
        if (kind === 'archive') assert.deepEqual(reopened.archiveResult(id, owner.id)?.vuln, archiveReport.vuln);
        else assert.deepEqual(reopened.vuln(id, owner.id)?.findings, findings);
      } finally { reopened.close(); }
    });
  } finally {
    await app.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
