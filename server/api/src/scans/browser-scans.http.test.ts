import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';

const origin = 'http://127.0.0.1:8080';
const sample = { imageReference: 'registry-1.docker.io/library/alpine:3.20', checks: ['secret'], scope: 'image', idempotencyKey: 'browser-test' };

test('browser scans fail closed for anonymous, unlisted users, foreign origins and revoked sessions', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'browser-scan-'));
  const keys = ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_LEDGER_PATH', 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const previous = keys.map(key => process.env[key]);
  process.env.AUTH_DB_PATH = join(dir, 'accounts.sqlite');
  process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  delete process.env.SCAN_BROWSER_ALLOWED_USER_IDS;
  delete process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS;
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'long-secret-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: (response.headers.get('set-cookie') ?? '').split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const alice = await register('approved@example.com');
    const bob = await register('other@example.com');
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = alice.id;
    const path = `${base}/browser/scans`;
    const post = (cookie: string, requestOrigin = origin) => fetch(path, { method: 'POST', headers: { cookie, origin: requestOrigin, 'content-type': 'application/json' }, body: JSON.stringify(sample) });
        const discovery = `${path}/images?q=nginx&generation=gen`;
        assert.equal((await fetch(discovery)).status, 401);
        assert.equal((await fetch(discovery, { headers: { cookie: bob.cookie } })).status, 403);
        assert.equal((await fetch(`${discovery}&cursor=${'a'.repeat(48)}`, { headers: { cookie: alice.cookie } })).status, 410);
        assert.equal((await fetch(`${path}/images?q=nginx`, { headers: { cookie: alice.cookie } })).status, 400);
        assert.equal((await fetch(`${path}/images?q=https%3A%2F%2Fevil.example&generation=gen`, { headers: { cookie: alice.cookie } })).status, 400);
        const forged = await fetch(path, { method: 'POST', headers: { cookie: alice.cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify({ ...sample, imageReference: 'registry-1.docker.io/library/nginx:latest' }) });
        assert.equal(forged.status, 400);
    assert.equal((await fetch(path)).status, 401);
    assert.equal((await fetch(path, { headers: { cookie: bob.cookie } })).status, 403);
    assert.equal((await post(bob.cookie)).status, 403);
    assert.equal((await fetch(path, { headers: { cookie: alice.cookie, authorization: 'Bearer invalid' } })).status, 403);
    assert.equal((await fetch(path, { headers: { cookie: alice.cookie, 'sec-fetch-site': 'cross-site' } })).status, 403);
    assert.equal((await post(alice.cookie, 'http://evil.example')).status, 403);
    assert.equal((await fetch(path, { method: 'POST', headers: { cookie: alice.cookie, origin, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
    assert.equal((await fetch(path, { headers: { cookie: alice.cookie } })).status, 200);
    // Explicit local-demo opt-in admits any authenticated account, but never an anonymous one.
    process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
    const bobList = await fetch(path, { headers: { cookie: bob.cookie } });
    assert.equal(bobList.status, 200);
    assert.deepEqual((await bobList.json() as { scans: unknown[] }).scans, []);
    assert.equal((await fetch(path)).status, 401);
    assert.equal((await post(bob.cookie)).status, 503); // Permission passed; no worker/gateway in this HTTP test.
    assert.equal((await post(bob.cookie, 'http://evil.example')).status, 403);
    process.env.AUTH_ORIGIN = 'https://stand.example.org';
    assert.equal((await fetch(path, { headers: { cookie: bob.cookie } })).status, 403);
    assert.equal((await fetch(path, { headers: { cookie: alice.cookie } })).status, 403);
    process.env.AUTH_ORIGIN = origin;
    process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'false';
    assert.equal((await fetch(path, { headers: { cookie: bob.cookie } })).status, 403);
    process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
    delete process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS;
    assert.equal((await fetch(path, { headers: { cookie: bob.cookie } })).status, 403);
    // No worker/gateway heartbeat: a successful login must not fake a successful scan.
    assert.equal((await post(alice.cookie)).status, 503);
    assert.equal((await fetch(`${base}/scans`, { headers: { cookie: alice.cookie } })).status, 401);
    assert.equal((await fetch(`${path}/00000000-0000-0000-0000-000000000000`, { headers: { cookie: bob.cookie } })).status, 403);
    assert.equal((await fetch(`${path}/00000000-0000-0000-0000-000000000000`, { headers: { cookie: alice.cookie } })).status, 404);
    const logout = await fetch(`${base}/auth/logout`, { method: 'POST', headers: { cookie: alice.cookie, origin, 'content-type': 'application/json' }, body: '{}' });
    assert.equal(logout.status, 204);
    assert.equal((await fetch(path, { headers: { cookie: alice.cookie } })).status, 401);
    delete process.env.SCAN_BROWSER_ALLOWED_USER_IDS;
    assert.equal((await fetch(path, { headers: { cookie: bob.cookie } })).status, 403);
  } finally {
    await app.close();
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
