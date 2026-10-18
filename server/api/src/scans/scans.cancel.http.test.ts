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

const origin = 'http://127.0.0.1:8080';
test('browser cancel requires enrolled live session, origin and empty JSON; JWT requires cancel scope', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cancel-http-'));
  const keys = ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_LEDGER_PATH',
    'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE'];
  const previous = keys.map(key => process.env[key]);
  process.env.AUTH_DB_PATH = join(dir, 'accounts.sqlite');
  process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
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
    const alice = await register('alice-cancel@example.com');
    const bob = await register('bob-cancel@example.com');
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = `${alice.id},${bob.id}`;
    const ledger = app.get(LedgerStore).ledger!;
    const enqueue = (subject: string, key: string) => ledger.enqueue({ subject, idempotencyKey: key,
      registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`,
      platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    const id = enqueue(alice.id, 'browser');
    const browser = `${base}/browser/scans/${id}/cancel`;
    const post = (url: string, cookie: string, requestOrigin = origin, body = '{}', extra: Record<string, string> = {}) =>
      fetch(url, { method: 'POST', headers: { cookie, origin: requestOrigin, 'content-type': 'application/json', ...extra }, body });
    assert.equal((await post(browser, bob.cookie)).status, 404);
    assert.equal((await post(browser, alice.cookie, 'http://evil.example')).status, 403);
    assert.equal((await post(browser, alice.cookie, origin, '{"x":1}')).status, 400);
    assert.equal((await post(browser, alice.cookie, origin, '{}', { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await post(browser, alice.cookie, origin, `{}${' '.repeat(2048)}`)).status, 415);
    assert.equal((await post(browser, alice.cookie, origin, '{}', { authorization: 'Bearer token' })).status, 403);
    assert.equal((await post(browser, alice.cookie)).status, 200);
    assert.equal((await post(browser, alice.cookie)).status, 200);
    assert.equal(ledger.state(id, alice.id), 'cancelled');
    const completed = enqueue(alice.id, 'terminal');
    const job = ledger.claim()!;
    assert.equal(job.scanId, completed);
    assert.equal(ledger.finishWithResult(completed, job.attempts, [], '0.69.3', job.leaseToken), true);
    assert.equal((await post(`${base}/browser/scans/${completed}/cancel`, alice.cookie)).status, 409);
    const logout = await post(`${base}/auth/logout`, alice.cookie);
    assert.equal(logout.status, 204);
    assert.equal((await post(browser, alice.cookie)).status, 401);
    const jwt = (subject: string, scope: string) => {
      const payload = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
        iss: 'issuer.example', aud: 'scan-api', sub: subject, iat: Math.floor(Date.now() / 1000) - 1,
        exp: Math.floor(Date.now() / 1000) + 60, scope })).toString('base64url')}`;
      return `${payload}.${createHmac('sha256', process.env.SCAN_JWT_SECRET!).update(payload).digest('base64url')}`;
    };
    const internal = `${base}/scans/${enqueue('internal', 'jwt')}/cancel`;
    const bearer = (subject: string, scope: string) => fetch(internal, { method: 'POST', headers: {
      authorization: `Bearer ${jwt(subject, scope)}`, 'content-type': 'application/json' }, body: '{}' });
    assert.equal((await bearer('internal', 'scan:create')).status, 403);
    assert.equal((await bearer('other', 'scan:create scan:cancel')).status, 404);
    assert.equal((await fetch(internal, { method: 'POST', headers: { cookie: bob.cookie, 'content-type': 'application/json' }, body: '{}' })).status, 401);
    assert.equal((await bearer('internal', 'scan:create scan:cancel')).status, 200);
  } finally {
    await app.close();
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
