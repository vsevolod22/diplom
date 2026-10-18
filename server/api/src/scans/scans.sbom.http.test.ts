import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
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
const request = (checks: string[], idempotencyKey: string) => ({
  imageReference: 'registry-1.docker.io/library/alpine:3.20', checks, scope: 'image', idempotencyKey,
});
function token(subject: string) {
  const now = Math.floor(Date.now() / 1000);
  const body = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'issuer.example', aud: 'scan-api', sub: subject, iat: now - 1, exp: now + 60, scope: 'scan:create' })).toString('base64url')}`;
  return `${body}.${createHmac('sha256', 'dedicated-test-secret-not-for-production-12345').update(body).digest('base64url')}`;
}

test('HTTP admits only standalone SBOM/secret, replays per subject and serves scoped paginated SBOM coverage', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-http-'));
  const keys = ['SCAN_LEDGER_PATH', 'SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE',
    'AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = keys.map(key => process.env[key]);
  process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
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
    assert.equal((await fetch(`${path}/00000000-0000-0000-0000-000000000000/sbom`)).status, 401);
    for (const checks of [['license'], ['sbom', 'secret'], ['sbom', 'sbom'], []]) {
      const response = await post('alice', request(checks, `bad-${checks.join('-') || 'empty'}-key`));
      assert.equal(response.status, 400, JSON.stringify(checks));
    }
    assert.equal((await post('alice', { ...request(['sbom'], 'wrong-repo-key'), imageReference: 'registry-1.docker.io/other/alpine:3.20' })).status, 400);
    assert.equal((await post('alice', request(['vuln'], 'disabled-vuln-key'))).status, 503);
    assert.equal((await post('alice', request(['secret', 'vuln'], 'disabled-combined-key'))).status, 503);
    assert.equal(ledger.pending().length, 0);
    assert.equal(resolutions, 0);

    const created = await post('alice', request(['sbom'], 'sbom-replay-key'));
    assert.equal(created.status, 202);
    const receipt = await created.json() as { scanId: string; statusUrl: string; eventsUrl: string };
    assert.equal(receipt.statusUrl, `/api/v1/scans/${receipt.scanId}`);
    const queuedStatus = await (await fetch(`${path}/${receipt.scanId}`, { headers: auth('alice') })).json() as Record<string, unknown>;
    assert.equal(queuedStatus.check, 'sbom');
    assert.equal(queuedStatus.result, null);
    assert.equal((await post('alice', request(['sbom'], 'sbom-replay-key'))).status, 202);
    assert.equal((await (await post('alice', request(['sbom'], 'sbom-replay-key'))).json() as { scanId: string }).scanId, receipt.scanId);
    assert.equal(resolutions, 1);
    assert.equal((await post('alice', request(['secret'], 'sbom-replay-key'))).status, 409);
    const bobReceipt = await (await post('bob', request(['sbom'], 'sbom-replay-key'))).json() as { scanId: string };
    const secretReceipt = await (await post('alice', request(['secret'], 'secret-only-key'))).json() as { scanId: string };
    assert.equal(ledger.pending().length, 3);
    assert.equal(ledger.cancel(bobReceipt.scanId, 'bob'), 'cancelled');
    assert.equal(ledger.cancel(secretReceipt.scanId, 'alice'), 'cancelled');
    assert.equal((await fetch(`${path}/${receipt.scanId}/sbom`, { headers: auth('alice') })).status, 404);
    assert.equal((await fetch(`${path}/${receipt.scanId}/sbom`, { headers: auth('bob') })).status, 404);
    const job = ledger.claim()!;
    assert.equal(job.scanId, receipt.scanId);
    const components = [{ ecosystem: 'apk' as const, name: 'alpine-baselayout', version: '3.6.8-r1' },
      { ecosystem: 'npm' as const, name: '@org/module', version: '1.2.3' }];
    assert.equal(ledger.finishWithSbom(job.scanId, job.attempts,
      { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.20' }, components }, '0.69.3', job.leaseToken), true);
    const first = await fetch(`${path}/${receipt.scanId}/sbom?limit=1`, { headers: auth('alice') });
    assert.equal(first.status, 200);
    const page = await first.json() as Record<string, unknown>;
    assert.deepEqual(page.components, [components[0]]);
    assert.equal(page.componentCount, 2);
    assert.equal(page.nextCursor, 1);
    assert.equal(page.outcome, 'checked');
    assert.equal(page.image, image);
    assert.equal(JSON.stringify(page).includes('bomFormat'), false);
    const second = await (await fetch(`${path}/${receipt.scanId}/sbom?cursor=1&limit=1`, { headers: auth('alice') })).json() as Record<string, unknown>;
    assert.deepEqual(second.components, [components[1]]);
    assert.equal(second.nextCursor, null);
    for (const query of ['?cursor=-1', '?cursor=1.5', '?cursor=3', '?limit=0', '?limit=101', '?limit=abc']) {
      assert.equal((await fetch(`${path}/${receipt.scanId}/sbom${query}`, { headers: auth('alice') })).status, 400);
    }
    assert.equal((await fetch(`${path}/${receipt.scanId}/sbom`, { headers: auth('bob') })).status, 404);
    const status = await (await fetch(`${path}/${receipt.scanId}`, { headers: auth('alice') })).json() as Record<string, unknown>;
    assert.equal(status.check, 'sbom');
    assert.deepEqual(status.result, { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 2,
      scannerVersion: '0.69.3', checkedAt: (page.checkedAt as string) });
    assert.equal(JSON.stringify(status).includes('CVE'), false);
    assert.equal(JSON.stringify(status).includes('components'), false);

    const failed = ledger.enqueue({ subject: 'alice', idempotencyKey: 'failed-sbom', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', checks: '["sbom"]', scope: 'image' }).scanId;
    const failedJob = ledger.claim()!;
    assert.equal(failedJob.scanId, failed);
    assert.equal(ledger.finish(failed, failedJob.attempts, 'failed', 'SCAN_TIMEOUT', failedJob.leaseToken), true);
    const failureStatus = await (await fetch(`${path}/${failed}`, { headers: auth('alice') })).json() as { result: unknown };
    assert.deepEqual(failureStatus.result, { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' });
    assert.deepEqual(await (await fetch(`${path}/${failed}/sbom`, { headers: auth('alice') })).json(),
      { coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null });

    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'long-secret-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: (response.headers.get('set-cookie') ?? '').split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const browser = await register('sbom-browser@example.com');
    const other = await register('sbom-other@example.com');
    const browserScan = ledger.enqueue({ subject: browser.id, idempotencyKey: 'browser-sbom', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', checks: '["sbom"]', scope: 'image' }).scanId;
    const browserPath = `${base}/browser/scans/${browserScan}/sbom`;
    assert.equal((await fetch(browserPath)).status, 401);
    assert.equal((await fetch(browserPath, { headers: { cookie: other.cookie } })).status, 404);
    assert.equal((await fetch(browserPath, { headers: { cookie: browser.cookie } })).status, 404); // no report yet
    const browserJob = ledger.claim()!;
    assert.equal(browserJob.scanId, browserScan);
    assert.equal(ledger.finishWithSbom(browserScan, browserJob.attempts,
      { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.20' }, components }, '0.69.3', browserJob.leaseToken), true);
    const browserReport = await fetch(`${browserPath}?limit=1`, { headers: { cookie: browser.cookie } });
    assert.equal(browserReport.status, 200);
    assert.equal(browserReport.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await browserReport.json() as { components: unknown[] }).components, [components[0]]);
    assert.equal((await fetch(browserPath, { headers: { cookie: other.cookie } })).status, 404);
    assert.equal((await fetch(`${base}/browser/scans/${receipt.scanId}/sbom`, { headers: { cookie: browser.cookie } })).status, 404);
    assert.equal((await fetch(browserPath, { headers: { cookie: browser.cookie, authorization: 'Bearer invalid' } })).status, 403);
  } finally {
    await app.close();
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
