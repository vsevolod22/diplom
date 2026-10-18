import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from '../oci/public-image.module.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION } from '../oci/public-image-policy.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import type { PinnedTarget } from '../ledger/ledger.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';

const origin = 'http://127.0.0.1:8081';
const secret = 'disposable-public-legacy-jwt-secret-1234';
const digest = (char: string) => `sha256:${char.repeat(64)}` as const;
type Target = Pick<PinnedTarget, 'registry' | 'repository' | 'digest' | 'platform'> & { configDigest: `sha256:${string}` };
const alpine: Target = { registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest('a'), configDigest: digest('b'), platform: 'linux/amd64' };
const nginx: Target = { ...NGINX_SUPPORTED_CANDIDATE, digest: NGINX_SUPPORTED_CANDIDATE.digest as `sha256:${string}` };
const publicTarget: Target = { ...alpine, repository: 'example/application', digest: digest('c') };
function token(subject: string) {
  const now = Math.floor(Date.now() / 1000);
  const body = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
    iss: 'public-legacy-test', aud: 'public-legacy-test', sub: subject, iat: now - 1, exp: now + 60, scope: 'scan:create',
  })).toString('base64url')}`;
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
}
function archive(target: Target, version: string, publicContract: boolean): ArchiveScanReport {
  return { receipt: { ...target, layerDigests: [digest('d')], diffIds: [digest('e')], archiveSha256: digest('f'),
    profileVersion: publicContract ? PUBLIC_IMAGE_PROFILE : archiveProfileVersion(NGINX_SUPPORTED_CANDIDATE),
    resourcePolicyVersion: publicContract ? PUBLIC_IMAGE_RESOURCE_POLICY : 'nginx-archive-resources-v1',
    checksVersion: publicContract ? PUBLIC_IMAGE_CHECKS_VERSION : 'trivy-0.69.3-archive-v1' },
    scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
      expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
    sbom: { outcome: 'checked', sbom: { image: `${target.registry}/${target.repository}@${target.digest}`, platform: 'linux/amd64',
      os: { name: 'alpine', version }, components: [{ ecosystem: 'apk', name: 'busybox', version: '1.37.0-r0' }] } } };
}

// Real Nest ingress/controllers/auth, actual owner-scoped SQLite publication/read,
// actual browser parsers. Persisted normalized SBOM fixtures are not live scanner evidence.
test('R2 public HTTP composition labels persisted evidence, not the endpoint; ordinary/report-v1 retain legacy release grammar', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'public-legacy-http-'));
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_JWT_SECRET: secret, SCAN_JWT_ISSUER: 'public-legacy-test', SCAN_JWT_AUDIENCE: 'public-legacy-test' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  const app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
  configurePublicImageIngress(app);
  try {
    const { parseCurrentSbom, parseCurrentStatus } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (name: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email: `${name}@example.com`, password: 'disposable-public-legacy-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('owner'), other = await register('other');
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = `${owner.id},${other.id}`;
    const ledger = app.get(LedgerStore).ledger!;
    const readers: Array<{ path: string; headers: Record<string, string> }> = [
      { path: `${base}/browser/scans`, headers: { cookie: owner.cookie } },
      { path: `${base}/scans`, headers: { authorization: `Bearer ${token(owner.id)}` } },
    ];
    const get = async (path: string, headers: Record<string, string>) => {
      const response = await fetch(path, { headers });
      assert.equal(response.status, 200, path);
      return response.json() as Promise<Record<string, unknown>>;
    };
    const query = { view: 'report-v1', limit: 5, sort: 'name:asc' } as const;
    const reportQuery = '?view=report-v1&limit=5&sort=name:asc';
    for (const [name, target, publicContract] of [
      ['legacy Alpine edge', alpine, false], ['legacy exact-nginx edge', nginx, false], ['public archive numeric Alpine', publicTarget, true],
      // A matching legacy target is not by itself the normalization contract.
      ['public receipt on exact-nginx target', nginx, true], ['public receipt on legacy Alpine target', alpine, true],
    ] as const) await t.test(name, async () => {
      const image = `${target.registry}/${target.repository}@${target.digest}`;
      const scanId = ledger.enqueue({ ...target, subject: owner.id, idempotencyKey: name, checks: '["sbom"]', scope: 'image' }).scanId;
      const job = ledger.claim()!; assert.equal(job.scanId, scanId);
      const version = publicContract ? '3.23.3' : 'edge';
      if (target === alpine && !publicContract) {
        assert.equal(ledger.finishCombined(scanId, job.attempts, [{ check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3',
          sbom: { image, platform: 'linux/amd64', os: { name: 'alpine', version }, components: [{ ecosystem: 'apk', name: 'busybox', version: '1.37.0-r0' }] },
        }], undefined, job.leaseToken), true);
        assert.equal(ledger.archiveResult(scanId, owner.id), undefined);
      } else assert.equal(ledger.finishArchive(scanId, job.attempts, archive(target, version, publicContract), undefined, job.leaseToken), true);
      for (const reader of readers) {
        const path = `${reader.path}/${scanId}`;
        const wire = await get(`${path}/sbom`, reader.headers);
        const parsed = parseCurrentSbom(wire);
        assert.equal(wire.profile, publicContract ? PUBLIC_IMAGE_PROFILE : undefined);
        assert.equal(parsed.os.version, version); assert.equal(parsed.image, image);
        const reportWire = await get(`${path}/sbom${reportQuery}`, reader.headers);
        const report = parseCurrentSbom(reportWire, query);
        assert.equal(reportWire.profile, wire.profile); assert.equal(report.os.version, version);
        assert.equal(report.page.totalCount, 1); assert.equal(report.page.returnedCount, 1);
        // Any history traversal is a regression: status must use the owner accessor.
        const list = ledger.list;
        ledger.list = () => { assert.fail('public status must not traverse scan history'); };
        let statusWire: Record<string, unknown>;
        try { statusWire = await get(path, reader.headers); } finally { ledger.list = list; }
        const status = parseCurrentStatus(statusWire);
        assert.equal(statusWire.profile, wire.profile); assert.equal(status.imageReference, image);
        if (publicContract) {
          assert.throws(() => parseCurrentSbom({ ...wire, os: { name: 'alpine', version: 'edge' } }));
          assert.throws(() => parseCurrentSbom({ ...reportWire, os: { name: 'alpine', version: 'edge' } }, query));
        } else {
          assert.equal(Object.hasOwn(wire, 'profile'), false); assert.equal(Object.hasOwn(reportWire, 'profile'), false);
          assert.equal(Object.hasOwn(statusWire, 'profile'), false);
          assert.throws(() => parseCurrentSbom({ ...wire, os: { name: 'debian', version: '12' } }));
        }
      }
      assert.equal((await fetch(`${base}/browser/scans/${scanId}`, { headers: { cookie: other.cookie } })).status, 404);
      assert.equal((await fetch(`${base}/browser/scans/${scanId}/sbom${reportQuery}`, { headers: { cookie: other.cookie } })).status, 404);
    });
    await t.test('queued public identity is owner scoped without a history lookup; legacy queued targets stay unmarked', async () => {
      const list = ledger.list;
      const pinnedTarget = ledger.pinnedTarget.bind(ledger);
      const reads: Array<[string, string]> = [];
      ledger.list = () => { assert.fail('public status must not traverse scan history'); };
      ledger.pinnedTarget = (scanId, subject) => { reads.push([scanId, subject]); return pinnedTarget(scanId, subject); };
      try {
        for (const [index, target] of [publicTarget, alpine, nginx].entries()) {
          const scanId = ledger.enqueue({ ...target, subject: owner.id, idempotencyKey: `queued-${index}`, checks: '["config"]', scope: 'image' }).scanId;
          const wire = await get(`${base}/browser/scans/${scanId}`, { cookie: owner.cookie });
          assert.equal(wire.profile, target === publicTarget ? PUBLIC_IMAGE_PROFILE : undefined);
          assert.equal(parseCurrentStatus(wire).imageReference, `${target.registry}/${target.repository}@${target.digest}`);
          assert.deepEqual(reads.at(-1), [scanId, owner.id]);
          assert.equal((await fetch(`${base}/browser/scans/${scanId}`, { headers: { cookie: other.cookie } })).status, 404);
          assert.equal(reads.some(([, subject]) => subject === other.id), false);
          assert.equal(ledger.cancel(scanId, owner.id), 'cancelled');
        }
      } finally { ledger.list = list; ledger.pinnedTarget = pinnedTarget; }
    });
    await t.test('genuine public receipt cannot persist a checked nonnumeric release', () => {
      const scanId = ledger.enqueue({ ...publicTarget, subject: owner.id, idempotencyKey: 'invalid-public-edge', checks: '["sbom"]', scope: 'image' }).scanId;
      const job = ledger.claim()!; assert.equal(job.scanId, scanId);
      assert.throws(() => ledger.finishArchive(scanId, job.attempts, archive(publicTarget, 'edge', true), undefined, job.leaseToken));
      assert.equal(ledger.archiveResult(scanId, owner.id), undefined);
      assert.equal(ledger.cancel(scanId, owner.id), 'cancelled');
    });
  } finally {
    await app.close(); Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
