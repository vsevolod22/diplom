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
test('HTTP JWT and enrolled browser SSE replay, isolate foreign scans and reject invalid cursor', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-sse-http-'));
  const keys = ['SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE', 'SCAN_LEDGER_PATH',
    'AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS'];
  const previous = keys.map(key => process.env[key]);
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
  process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_DB_PATH = join(dir, 'accounts.sqlite');
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const registered = await fetch(`${base}/auth/register`, { method: 'POST',
      headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'sse@example.com', password: 'long-secret-1234' }) });
    assert.equal(registered.status, 201);
    const subject = (await registered.json() as { id: string }).id;
    const cookie = (registered.headers.get('set-cookie') ?? '').split(';')[0];
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = subject;
    const ledger = app.get(LedgerStore).ledger!;
    const enqueue = (owner: string, key: string) => ledger.enqueue({ subject: owner, idempotencyKey: key,
      registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`,
      platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    const scanId = enqueue(subject, 'alice-key');
    const first = ledger.events(scanId, subject, null)![0].id;
    const job = ledger.claim()!;
    assert.equal(ledger.finishWithResult(scanId, job.attempts, [], '0.69.3'), true);
    const last = ledger.events(scanId, subject, first)!.at(-1)!.id;
    const foreignId = enqueue('bob', 'bob-key');
    const payload = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
      iss: 'issuer.example', aud: 'scan-api', sub: subject, iat: Math.floor(Date.now() / 1000) - 1,
      exp: Math.floor(Date.now() / 1000) + 60, scope: 'scan:create',
    })).toString('base64url')}`;
    const token = `${payload}.${createHmac('sha256', process.env.SCAN_JWT_SECRET).update(payload).digest('base64url')}`;
    for (const [path, headers] of [
      ['scans', { authorization: `Bearer ${token}` }],
      ['browser/scans', { cookie }],
    ] as const) {
      const url = `${base}/${path}`;
      const replay = await fetch(`${url}/${scanId}/events`, { headers: { ...headers, 'last-event-id': String(first) } });
      assert.equal(replay.status, 200);
      assert.match(replay.headers.get('content-type') ?? '', /^text\/event-stream/);
      const data = await replay.text();
      assert.equal((data.match(/event: scan/g) ?? []).length, 2);
      assert.match(data, /"state":"completed","percent":null/);
      const exhausted = await fetch(`${url}/${scanId}/events`, { headers: { ...headers, 'last-event-id': String(last) } });
      assert.equal(exhausted.status, 200);
      assert.doesNotMatch(await exhausted.text(), /event: scan/);
      assert.equal((await fetch(`${url}/${foreignId}/events`, { headers })).status, 404);
      assert.equal((await fetch(`${url}/${scanId}/events`, { headers: { ...headers, 'last-event-id': '01' } })).status, 400);
    }
  } finally {
    await app.close();
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
