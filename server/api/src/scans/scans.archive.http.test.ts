import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { normalizeAdvisory } from '../worker/vuln-advisory.js';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';


const origin = 'http://127.0.0.1:8080';
const target = NGINX_SUPPORTED_CANDIDATE;
// Synthetic persisted outcomes, real Nest/browser auth/service/JSON/strict UI parser.
// This is the failed-SBOM wire regression, not real scanner or public admission proof.
test('real browser HTTP failed/partial archive SBOM roundtrips through the actual strict browser parser', async () => {
  // Load the sibling UI source at test runtime; server-only Docker typecheck must
  // not require copying/bundling the browser workspace into production images.
  const browserModule = new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url);
  const { parseCurrentSbom, parseCurrentStatus, parseCurrentVuln, parseCurrentResults } = await import(browserModule.href);
  const directory = mkdtempSync(`${tmpdir()}/archive-http-`);
  const env = { SCAN_LEDGER_PATH: `${directory}/ledger.sqlite`, AUTH_DB_PATH: `${directory}/auth.sqlite`,
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_JWT_SECRET: 'disposable-test-secret-for-archive-http-only-1234', SCAN_JWT_ISSUER: 'archive-test',
    SCAN_JWT_AUDIENCE: 'archive-test', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'disposable-only-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('archive-owner@example.com'), other = await register('archive-other@example.com');
    const ledger = app.get(LedgerStore).ledger!;
    for (const reason of ['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE'] as const) {
      for (const partial of [true, false]) {
        const checks = partial ? ['secret', 'sbom'] : ['sbom'];
        const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: owner.id,
          idempotencyKey: `${reason}-${partial}`, checks: JSON.stringify(checks), scope: 'image' }).scanId;
        const job = ledger.claim()!;
        const report: ArchiveScanReport = { receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`],
          diffIds: [`sha256:${'b'.repeat(64)}`], archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(target),
          resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
          scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
            expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
          ...(partial ? { secret: { outcome: 'checked' as const, findings: [] } } : {}), sbom: { outcome: 'failed', reason } };
        assert.equal(ledger.finishArchive(id, job.attempts, report, undefined, job.leaseToken), true);
        const path = `${base}/browser/scans/${id}`;
        const status = parseCurrentStatus(await (await fetch(path, { headers: { cookie: owner.cookie } })).json());
        assert.equal(status.state, partial ? 'partial' : 'failed');
        if (partial) assert.equal(status.perCheck?.secret?.outcome, 'checked');
        const response = await fetch(`${path}/sbom`, { headers: { cookie: owner.cookie } });
        assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
        const wire = await response.json();
        const page = parseCurrentSbom(wire);
        assert.deepEqual(page, { outcome: 'failed', coverage: 'image', reason,
          errorCode: reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED', components: [], nextCursor: null });
        assert.throws(() => parseCurrentSbom({ ...wire, reason: 'SECRET_CANARY' }));
        assert.throws(() => parseCurrentSbom({ ...wire, raw: 'SECRET_CANARY' }));
        assert.equal((await fetch(`${path}/sbom`)).status, 401);
        assert.equal((await fetch(`${path}/sbom`, { headers: { cookie: other.cookie } })).status, 404);
      }
    }
    // Synthetic fenced archive outputs through real ordinary cookie auth/HTTP,
    // SQLite and the browser parser; not signed-DB, Trivy or Chromium proof.
    for (const secretChecked of [true, false]) {
      const image = `${target.registry}/${target.repository}@${target.digest}`;
      const provenanceRef = `target-${'b'.repeat(64)}`, cveId = 'CVE-2026-1234';
      const finding = { findingId: `vuln-${createHash('sha256').update(JSON.stringify([image, 'linux/amd64', 'vuln', 'apk', provenanceRef, cveId, 'busybox', '1.2'])).digest('hex')}`,
        cveId, ecosystem: 'apk' as const, packageName: 'busybox', installedVersion: '1.2', severity: 'HIGH' as const,
        severitySources: ['alpine'], provenanceRef, fixedVersion: null,
        advisory: normalizeAdvisory({ DataSource: { ID: 'alpine' }, Title: 'Archive package issue', Description: 'Safe {"password":"PRIVATE_SENTINEL words"} remainder',
          SeveritySource: 'alpine', Severity: 'HIGH', CVSS: { nvd: { V3Score: 0, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } } }, provenanceRef, cveId) };
      const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: owner.id,
        idempotencyKey: `advisory-${secretChecked}`, checks: '["secret","vuln"]', scope: 'image' }).scanId;
      const job = ledger.claim()!;
      const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`,
        schemaVersion: 2, manifestDigest: `sha256:${'d'.repeat(64)}`, artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
        updatedAt: new Date(Date.now() - 60_000).toISOString(), downloadedAt: new Date(Date.now() - 30_000).toISOString(), nextUpdate: new Date(Date.now() + 120_000).toISOString() };
      const report: ArchiveScanReport = { receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
        archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(target), resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
        scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
        secret: secretChecked ? { outcome: 'checked', findings: [] } : { outcome: 'failed', reason: 'SCAN_FAILED' },
        vuln: { outcome: 'checked', findings: [finding], db, os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } } };
      assert.equal(ledger.finishArchive(id, job.attempts, report, undefined, job.leaseToken), true);
      const path = `${base}/browser/scans/${id}`;
      const get = (suffix: string) => fetch(path + suffix, { headers: { cookie: owner.cookie } });
      const snapshot = parseCurrentStatus(await (await get('')).json());
      assert.equal(snapshot.state, secretChecked ? 'completed' : 'partial');
      const response = await get('/vuln');
      assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
      const parsed = parseCurrentVuln(await response.json());
      assert.equal(parsed.outcome, 'checked'); assert.deepEqual(parsed.findings, [finding]);
      assert.ok(!JSON.stringify(parsed).includes('PRIVATE_SENTINEL'));
      assert.deepEqual(parseCurrentVuln(await (await get('/vuln')).json()), parsed);
      const secrets = parseCurrentResults(await (await get('/results')).json());
      assert.equal(secrets.coverage[0].findingCount, secretChecked ? 0 : undefined);
      assert.equal((await fetch(path + '/vuln')).status, 401);
      assert.equal((await fetch(path + '/vuln', { headers: { cookie: other.cookie } })).status, 404);
    }
  } finally {
    await app.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
