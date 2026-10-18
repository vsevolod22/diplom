import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from '../app.module.js';
import { AuthStore } from '../auth/auth.store.js';
import { browserIdentity, BrowserIdentity, type BrowserScanLocalOrigin } from '../llm/browser-identity.js';
import { PublicImageModule, configurePublicImageIngress } from '../oci/public-image.module.js';
import { ScansService } from './scans.service.js';
import type { ImageReference } from './image-reference.js';

const publicOrigin = 'http://127.0.0.1:8081';
const legacyOrigin = 'http://127.0.0.1:8080';
const intent = { imageReference: 'registry-1.docker.io/library/node:22', checks: ['secret'] };

// Actual ephemeral HTTP/Nest/auth/SQLite, never the live 8081 stand.
// Only OCI inspection and worker readiness are controlled admission fixtures.
async function withHttp(publicComposition: boolean, run: (app: NestExpressApplication, base: string) => Promise<void>) {
  const directory = mkdtempSync(join(tmpdir(), 'public-origin-'));
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
    AUTH_ORIGIN: publicOrigin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  let app: NestExpressApplication | undefined;
  try {
    app = await NestFactory.create<NestExpressApplication>(publicComposition ? PublicImageModule : AppModule,
      { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
    await app.listen(0, '127.0.0.1');
    const port = (app.getHttpServer().address() as { port: number }).port;
    await run(app, `http://127.0.0.1:${port}/api/v1`);
  } finally {
    try { await app?.close(); } finally {
      Object.keys(env).forEach((key, index) => {
        if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index];
      });
      rmSync(directory, { recursive: true, force: true });
    }
  }
}

const request = (url: string, init: RequestInit = {}) => fetch(url, { ...init, signal: AbortSignal.timeout(5000) });
async function register(base: string, name: string) {
  const response = await request(`${base}/auth/register`, { method: 'POST',
    headers: { origin: publicOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ email: `${name}@example.com`, password: 'disposable-origin-1234' }) });
  assert.equal(response.status, 201);
  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  assert.ok(cookie);
  return { cookie, id: (await response.json() as { id: string }).id };
}
async function denied(response: Response, status: number, code: string) {
  assert.equal(response.status, status);
  assert.equal((await response.json() as { errorCode: string }).errorCode, code);
}

// Do not weaken the existing default-composition guard test to cover this opt-in.
test('public composition alone selects exact 8081 local-account trust; cookie, origin and enrollment guards remain', { timeout: 30000 }, () => withHttp(true, async (app, base) => {
  const service = app.get(ScansService);
  let inspections = 0;
  Object.defineProperty(service, 'readiness', { value: async () => true });
  Object.defineProperty(service, 'inspect', { value: async (ref: ImageReference) => {
    inspections++;
    return { registry: ref.registry, repository: ref.repository, digest: `sha256:${'a'.repeat(64)}`,
      configDigest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64',
      layers: [{ digest: `sha256:${'c'.repeat(64)}`, size: 100, mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' }] };
  } });
  const owner = await register(base, 'owner'), other = await register(base, 'other');
  const path = `${base}/browser/scans`;
  const get = (cookie = owner.cookie, headers = {}) => request(path, { headers: { cookie, ...headers } });
  const post = (origin = publicOrigin, body: unknown = intent, suffix = '/images/eligibility') => request(path + suffix,
    { method: 'POST', headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  assert.equal((await get()).status, 200);
  assert.equal((await get(other.cookie)).status, 200);
  const eligibility = await post();
  assert.equal(eligibility.status, 200);
  assert.equal((await eligibility.json() as { eligible: boolean }).eligible, true);
  assert.equal(inspections, 1);
  const creation = await post(publicOrigin, { ...intent, scope: 'image', idempotencyKey: 'public-origin-proof' }, '');
  assert.equal(creation.status, 202);
  const scanId = (await creation.json() as { scanId: string }).scanId;
  assert.equal(inspections, 2);
  assert.equal((await request(`${path}/${scanId}`, { headers: { cookie: owner.cookie } })).status, 200);
  assert.equal((await request(`${path}/${scanId}`, { headers: { cookie: other.cookie } })).status, 404);

  await denied(await request(path), 401, 'UNAUTHORIZED');
  await denied(await get(`demo_session=${'x'.repeat(43)}`), 401, 'UNAUTHORIZED');
  await denied(await get(owner.cookie, { authorization: 'Bearer invalid' }), 403, 'INVALID_BROWSER_REQUEST');
  await denied(await get(owner.cookie, { 'sec-fetch-site': 'cross-site' }), 403, 'INVALID_BROWSER_REQUEST');
  for (const origin of [legacyOrigin, 'http://localhost:8081', 'https://foreign.example'])
    assert.equal((await post(origin)).status, 403);
  assert.equal((await request(`${path}/images/eligibility`, { method: 'POST',
    headers: { cookie: owner.cookie, origin: publicOrigin, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
  assert.equal(inspections, 2); // rejected requests never reached the controlled inspector
  assert.equal((await request(`${base}/scans`, { headers: { cookie: owner.cookie } })).status, 401);

  const req = { headers: { cookie: owner.cookie }, socket: { remoteAddress: '127.0.0.1' } };
  const store = app.get(AuthStore);
  const accessDisabled = (error: unknown) => error instanceof HttpException && error.getStatus() === 403 &&
    (error.getResponse() as { errorCode: string }).errorCode === 'SCAN_ACCESS_DISABLED';
  assert.throws(() => new BrowserIdentity(store).resolve(req), accessDisabled); // LLM bridge keeps default 8080
  assert.throws(() => browserIdentity(store, req), accessDisabled);
  assert.throws(() => browserIdentity(store, req, false, 'https://foreign.example' as BrowserScanLocalOrigin), accessDisabled);

  // Neither arbitrary env origins nor a valid enrollment can rescue misconfigured all-local trust.
  process.env.SCAN_BROWSER_ALLOWED_USER_IDS = owner.id;
  for (const configured of [legacyOrigin, 'http://127.0.0.1:8082', 'http://localhost:8081', 'https://foreign.example']) {
    process.env.AUTH_ORIGIN = configured;
    await denied(await get(), 403, 'SCAN_ACCESS_DISABLED');
  }
  process.env.AUTH_ORIGIN = publicOrigin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'false';
  await denied(await get(), 403, 'SCAN_ACCESS_DISABLED');
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'false';
  assert.equal((await get()).status, 200);
  await denied(await get(other.cookie), 403, 'SCAN_ACCESS_DENIED');
  process.env.SCAN_BROWSER_ALLOWED_USER_IDS = '';
  await denied(await get(), 403, 'SCAN_ACCESS_DISABLED');
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const logout = await request(`${base}/auth/logout`, { method: 'POST',
    headers: { cookie: owner.cookie, origin: publicOrigin, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(logout.status, 204);
  await denied(await get(), 401, 'UNAUTHORIZED');
}));

test('unchanged AppModule rejects all-local 8081 while retaining exact default 8080', { timeout: 30000 }, () => withHttp(false, async (_app, base) => {
  const owner = await register(base, 'legacy-owner');
  const path = `${base}/browser/scans`;
  const get = () => request(path, { headers: { cookie: owner.cookie } });
  await denied(await get(), 403, 'SCAN_ACCESS_DISABLED');
  const response = await request(`${path}/images/eligibility`, { method: 'POST',
    headers: { cookie: owner.cookie, origin: publicOrigin, 'content-type': 'application/json' }, body: JSON.stringify(intent) });
  await denied(response, 403, 'SCAN_ACCESS_DISABLED');
  process.env.AUTH_ORIGIN = legacyOrigin;
  assert.equal((await get()).status, 200);
  await denied(await request(path), 401, 'UNAUTHORIZED');
  process.env.AUTH_ORIGIN = publicOrigin;
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'false';
  process.env.SCAN_BROWSER_ALLOWED_USER_IDS = owner.id;
  assert.equal((await get()).status, 200); // explicit enrollment is not the local-demo bypass
}));
