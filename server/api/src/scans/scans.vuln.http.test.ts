import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { ScansService } from './scans.service.js';

const origin = 'http://127.0.0.1:8080';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const request = (checks: string[], idempotencyKey: string, scope = 'image') =>
  ({ imageReference: 'registry-1.docker.io/library/alpine:3.20', checks, scope, idempotencyKey });
function token(subject: string) {
  const now = Math.floor(Date.now() / 1000);
  const body = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'issuer.example', aud: 'scan-api', sub: subject, iat: now - 1, exp: now + 60, scope: 'scan:create' })).toString('base64url')}`;
  return `${body}.${createHmac('sha256', 'dedicated-test-secret-not-for-production-12345').update(body).digest('base64url')}`;
}

test('HTTP vulnerability admission fails closed; combined status and vuln pages remain subject scoped', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vuln-http-'));
  const keys = ['SCAN_LEDGER_PATH', 'SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE',
    'AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS',
    'SCAN_VULN_ENABLED', 'SCAN_VULN_RELEASE_DIR', 'SCAN_VULN_MANIFEST_DIGEST', 'SCAN_VULN_ARTIFACT_SHA256'];
  const previous = keys.map(key => process.env[key]);
  process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
  delete process.env.SCAN_VULN_ENABLED;
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    const service = app.get(ScansService);
    Object.defineProperty(service, 'readiness', { value: async () => true });
    const resolver = app.get(OciResolver);
    let resolutions = 0;
    resolver.resolvePublicAlpine = async () => {
      resolutions++;
      return { registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64' };
    };
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const path = `${base}/scans`;
    const auth = (subject: string) => ({ authorization: `Bearer ${token(subject)}` });
    const post = (subject: string, body: unknown) => fetch(path, { method: 'POST', headers: { ...auth(subject), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const ledger = app.get(LedgerStore).ledger!;
    for (const checks of [[], ['vuln', 'vuln'], ['vuln', 'secret'], ['secret', 'sbom', 'vuln', 'secret'], ['host'], ['sbom', 'secret']]) {
      assert.equal((await post('alice', request(checks, `invalid-${checks.join('-') || 'empty'}`))).status, 400);
    }
    assert.equal((await post('alice', request(['secret'], 'host-scope-key', 'host'))).status, 400);
    assert.equal((await post('alice', request(['vuln'], 'disabled-vuln'))).status, 503);
    process.env.SCAN_VULN_ENABLED = 'true';
    assert.equal((await post('alice', request(['vuln'], 'unconfigured-vuln'))).status, 503);
    process.env.SCAN_VULN_RELEASE_DIR = join(dir, 'missing-release');
    process.env.SCAN_VULN_MANIFEST_DIGEST = `sha256:${'b'.repeat(64)}`;
    process.env.SCAN_VULN_ARTIFACT_SHA256 = 'c'.repeat(64);
    assert.equal((await post('alice', request(['secret', 'sbom', 'vuln'], 'absent-db-key'))).status, 503);
    assert.equal(ledger.pending().length, 0);
    assert.equal(resolutions, 0);

    // Simulates a verified operator release for the success path only; the real
    // missing-DB rejection above exercises the production preflight unchanged.
    Object.defineProperty(service, 'vulnDbReady', { value: async () => true });
    const created = await post('alice', request(['secret', 'sbom', 'vuln'], 'combined-vuln-key'));
    assert.equal(created.status, 202);
    const { scanId } = await created.json() as { scanId: string };
    assert.equal((await post('alice', request(['secret', 'sbom', 'vuln'], 'combined-vuln-key'))).status, 202);
    assert.equal(resolutions, 1);
    assert.equal((await post('alice', request(['secret', 'vuln'], 'combined-vuln-key'))).status, 409);
    delete process.env.SCAN_VULN_ENABLED;
    assert.equal((await post('alice', request(['secret', 'sbom', 'vuln'], 'combined-vuln-key'))).status, 503);
    process.env.SCAN_VULN_ENABLED = 'true';
    const queued = await (await fetch(`${path}/${scanId}`, { headers: auth('alice') })).json() as Record<string, unknown>;
    assert.deepEqual(queued.checks, ['secret', 'sbom', 'vuln']);
    assert.deepEqual(queued.perCheck, { secret: null, sbom: null, vuln: null });
    assert.equal(queued.result, null);
    assert.equal((await fetch(`${path}/${scanId}/vuln`, { headers: auth('alice') })).status, 404);
    assert.equal((await fetch(`${path}/${scanId}/vuln`, { headers: auth('bob') })).status, 404);
    const job = ledger.claim()!;
    const cveId = 'CVE-2025-1234';
    const provenanceRef = `target-${'b'.repeat(64)}`;
    const findingId = `vuln-${createHash('sha256').update(JSON.stringify(['apk', provenanceRef, cveId, 'busybox', '1.2-r0'])).digest('hex')}`;
    const finding = { findingId, cveId, ecosystem: 'apk' as const, packageName: 'busybox',
      installedVersion: '1.2-r0', fixedVersion: null, severity: 'HIGH' as const,
      severitySources: ['alpine', 'nvd'], provenanceRef };
    assert.equal(ledger.finishCombined(scanId, job.attempts, [
      { check: 'secret', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' },
      { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3', sbom: { image,
        platform: 'linux/amd64', os: { name: 'alpine', version: '3.20' },
        components: [{ ecosystem: 'apk', name: 'busybox', version: '1.2-r0' }] } },
      { check: 'vuln', outcome: 'checked', image, scannerVersion: '0.69.3', findings: [finding] },
    ]), true);
    const status = await (await fetch(`${path}/${scanId}`, { headers: auth('alice') })).json() as Record<string, any>;
    assert.equal(status.state, 'partial');
    assert.equal(status.perCheck.secret.outcome, 'failed');
    assert.equal(status.perCheck.sbom.componentCount, 1);
    assert.equal(status.perCheck.vuln.findingCount, 1);
    assert.equal((await fetch(`${path}/${scanId}`, { headers: auth('bob') })).status, 404);
    const page = await (await fetch(`${path}/${scanId}/vuln?limit=1`, { headers: auth('alice') })).json() as Record<string, any>;
    assert.deepEqual(page.findings, [finding]);
    assert.equal(page.nextCursor, null);
    assert.equal(page.outcome, 'checked');
    for (const query of ['?cursor=-1', '?cursor=1.5', '?cursor=2', '?limit=0', '?limit=101'])
      assert.equal((await fetch(`${path}/${scanId}/vuln${query}`, { headers: auth('alice') })).status, 400);
    assert.equal((await fetch(`${path}/${scanId}/vuln`, { headers: auth('bob') })).status, 404);

    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'long-secret-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: (response.headers.get('set-cookie') ?? '').split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('vuln-owner@example.com');
    const other = await register('vuln-other@example.com');
    const browserId = ledger.enqueue({ subject: owner.id, idempotencyKey: 'browser-vuln', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', checks: '["vuln"]', scope: 'image' }).scanId;
    const browserJob = ledger.claim()!;
    assert.equal(ledger.finishWithVuln(browserId, browserJob.attempts, image, [finding], '0.69.3'), true);
    const browserPath = `${base}/browser/scans/${browserId}/vuln`;
    assert.equal((await fetch(browserPath)).status, 401);
    assert.equal((await fetch(browserPath, { headers: { cookie: other.cookie } })).status, 404);
    const browserReport = await fetch(`${browserPath}?limit=1`, { headers: { cookie: owner.cookie } });
    assert.equal(browserReport.status, 200);
    assert.equal(browserReport.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await browserReport.json() as { findings: unknown[] }).findings, [finding]);
    assert.equal((await fetch(`${base}/browser/scans/${scanId}/vuln`, { headers: { cookie: owner.cookie } })).status, 404);
  } finally {
    await app.close();
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
