import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';

const origin = 'http://127.0.0.1:5173';
const credentials = { email: ' TEST@Example.com ', password: 'long-secret-1234' };

async function serve() {
  const app = await NestFactory.create(AppModule, { logger: false });
  await app.listen(0, '127.0.0.1');
  const port = (app.getHttpServer().address() as { port: number }).port;
  return { app, url: `http://127.0.0.1:${port}/api/v1` };
}
const post = (url: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${url}/auth/${path}`, { method: 'POST', headers: { origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('auth persists only in its own SQLite file, enforces origin, cookie and revocation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-api-'));
  const previous = ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_LEDGER_PATH']
    .map(key => process.env[key]);
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_LEDGER_PATH = join(dir, 'scans.sqlite');
  let server: Awaited<ReturnType<typeof serve>> | undefined;
  try {
    server = await serve();
    const { url } = server;
    assert.equal((await fetch(`${url}/auth/me`)).status, 401);
    assert.equal((await post(url, 'register', credentials, { origin: 'http://evil.example' })).status, 403);
    assert.equal((await post(url, 'register', credentials, { origin: '' })).status, 403);
    assert.equal((await fetch(`${url}/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(credentials) })).status, 403);
    assert.equal((await post(url, 'login', credentials, { origin: '' })).status, 403);
    assert.equal((await post(url, 'logout', {}, { origin: '' })).status, 403);
    assert.equal((await fetch(`${url}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
    assert.equal((await post(url, 'register', { ...credentials, password: 'short' })).status, 400);
    const registered = await post(url, 'register', credentials);
    assert.equal(registered.status, 201);
    const payload = await registered.json() as { id: string; email: string };
    assert.match(payload.id, /^[a-f0-9]{32}$/);
    assert.equal(payload.email, 'test@example.com');
    assert.equal(Object.keys(payload).length, 2);
    const cookie = registered.headers.get('set-cookie') ?? '';
    assert.match(cookie, /^demo_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Lax; Path=\/; Max-Age=604800/);
    assert.doesNotMatch(cookie, /Secure/);
    const session = cookie.split(';')[0];
    assert.equal((await fetch(`${url}/auth/me`, { headers: { cookie: session } })).status, 200);
    assert.equal((await fetch(`${url}/auth/me`, { headers: { cookie: `${session}; ${session}` } })).status, 401);
    assert.equal((await post(url, 'register', { ...credentials, email: 'test@example.com' })).status, 409);
    assert.equal((await post(url, 'login', { ...credentials, password: 'long-secret-0000' })).status, 401);
    assert.equal((await post(url, 'login', { ...credentials, email: 'other@example.com' })).status, 401);
    assert.equal((await fetch(`${url}/scans`, { headers: { cookie: session } })).status, 401);
    assert.equal((await fetch(`${url}/scans`, { method: 'POST', headers: { cookie: session, origin, 'content-type': 'application/json' }, body: '{}' })).status, 401);
    await server.app.close();
    server = await serve();
    assert.equal((await fetch(`${server.url}/auth/me`, { headers: { cookie: session } })).status, 200);
    assert.equal((await post(server.url, 'logout', {}, { cookie: session, origin: 'http://evil.example' })).status, 403);
    assert.equal((await fetch(`${server.url}/auth/me`, { headers: { cookie: session } })).status, 200);
    const logout = await post(server.url, 'logout', {}, { cookie: session });
    assert.equal(logout.status, 204);
    assert.match(logout.headers.get('set-cookie') ?? '', /Max-Age=0/);
    assert.equal((await fetch(`${server.url}/auth/me`, { headers: { cookie: session } })).status, 401);
    assert.equal((await post(server.url, 'login', { ...credentials, email: 'TEST@example.com' })).status, 200);
  } finally {
    await server?.app.close();
    ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_LEDGER_PATH'].forEach((key, i) => {
      if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i];
    });
    rmSync(dir, { recursive: true, force: true });
  }
});


test('HTTP login enforces the per-email rate limit before password verification', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-rate-'));
  const keys = ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP'] as const;
  const previous = keys.map(key => process.env[key]);
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  let server: Awaited<ReturnType<typeof serve>> | undefined;
  try {
    server = await serve();
    for (let i = 0; i < 5; i++) {
      assert.equal((await post(server.url, 'login', credentials)).status, 401);
    }
    const blocked = await post(server.url, 'login', credentials);
    assert.equal(blocked.status, 429);
    assert.deepEqual(await blocked.json(), { errorCode: 'RATE_LIMITED' });
  } finally {
    await server?.app.close();
    keys.forEach((key, i) => {
      if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i];
    });
    rmSync(dir, { recursive: true, force: true });
  }
});

test('public HTTPS origin sets Secure cookie even behind an HTTP reverse proxy', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-https-'));
  const oldPath = process.env.AUTH_DB_PATH;
  const oldOrigin = process.env.AUTH_ORIGIN;
  const oldLocal = process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = 'https://demo.example';
  delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
  const server = await serve();
  try {
    assert.equal((await post(server.url, 'register', credentials)).status, 403);
    const response = await post(server.url, 'register', credentials, { origin: 'https://demo.example' });
    assert.equal(response.status, 201);
    assert.match(response.headers.get('set-cookie') ?? '', /; Secure$/);
  } finally {
    await server.app.close();
    if (oldPath === undefined) delete process.env.AUTH_DB_PATH; else process.env.AUTH_DB_PATH = oldPath;
    if (oldOrigin === undefined) delete process.env.AUTH_ORIGIN; else process.env.AUTH_ORIGIN = oldOrigin;
    if (oldLocal === undefined) delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP; else process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = oldLocal;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('missing AUTH_DB_PATH fails closed rather than using memory', async () => {
  const old = process.env.AUTH_DB_PATH;
  const oldOrigin = process.env.AUTH_ORIGIN;
  const oldLocal = process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
  delete process.env.AUTH_DB_PATH;
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  const server = await serve();
  try {
    assert.equal((await post(server.url, 'register', credentials)).status, 503);
    assert.equal((await post(server.url, 'login', credentials)).status, 503);
    assert.equal((await post(server.url, 'logout', {})).status, 503);
  } finally {
    await server.app.close();
    if (old === undefined) delete process.env.AUTH_DB_PATH; else process.env.AUTH_DB_PATH = old;
    if (oldOrigin === undefined) delete process.env.AUTH_ORIGIN; else process.env.AUTH_ORIGIN = oldOrigin;
    if (oldLocal === undefined) delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP; else process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = oldLocal;
  }
});
