import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { ScanLedger } from '../ledger/ledger.js';

function token(subject: string, scope = 'scan:create scan:list') {
  const now = Math.floor(Date.now() / 1000);
  const data = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'issuer.example', aud: 'scan-api', sub: subject, iat: now - 1, exp: now + 60, scope })).toString('base64url')}`;
  return `${data}.${createHmac('sha256', 'dedicated-test-secret-not-for-production-12345').update(data).digest('base64url')}`;
}

test('authenticated HTTP list and snapshot isolate subjects and retain pinned target', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dip-list-http-'));
  const file = join(dir, 'scan.sqlite');
  const keys = ['SCAN_LEDGER_PATH', 'SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE'] as const;
  const previous = keys.map(key => process.env[key]);
  process.env.SCAN_LEDGER_PATH = file;
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
  const ledger = new ScanLedger(file);
  const digest: `sha256:${string}` = `sha256:${'a'.repeat(64)}`;
  const a = ledger.enqueue({ subject: 'alice', idempotencyKey: 'a', registry: 'registry-1.docker.io', repository: 'library/alpine', digest, platform: 'linux/amd64' }).scanId;
  ledger.enqueue({ subject: 'alice', idempotencyKey: 'b', registry: 'registry-1.docker.io', repository: 'library/alpine', digest, platform: 'linux/amd64' });
  ledger.enqueue({ subject: 'bob', idempotencyKey: 'a', registry: 'registry-1.docker.io', repository: 'library/alpine', digest, platform: 'linux/amd64' });
  ledger.close();
  try {
    const app = await NestFactory.create(AppModule, { logger: false });
    try {
      await app.listen(0, '127.0.0.1');
      const address = app.getHttpServer().address() as { port: number };
      const url = `http://127.0.0.1:${address.port}/api/v1/scans`;
      const auth = (subject: string) => ({ authorization: `Bearer ${token(subject)}` });
      assert.equal((await fetch(url)).status, 401);
      assert.equal((await fetch(`${url}/${a}`, { headers: auth('bob') })).status, 404);
      assert.equal((await fetch(url, { headers: { authorization: `Bearer ${token('alice', 'scan:create')}` } })).status, 403);
      assert.equal((await fetch(`${url}?cursor=-1`, { headers: auth('alice') })).status, 400);
      for (const cursor of ['1:3', '2:999999999999999']) {
        const invalid = await fetch(`${url}?cursor=${cursor}`, { headers: auth('alice') });
        assert.equal(invalid.status, 400);
        assert.deepEqual(await invalid.json(), { errorCode: 'INVALID_PAGINATION' });
      }
      const status = await fetch(`${url}/${a}`, { headers: auth('alice') });
      assert.equal(status.status, 200);
      assert.deepEqual(await status.json(), { scanId: a, state: 'queued', digest, platform: 'linux/amd64', result: null });
      const first = await fetch(`${url}?limit=1`, { headers: auth('alice') });
      assert.equal(first.status, 200);
      const page = await first.json() as { scans: Array<{ scanId: string; targetLabel: string }>; nextCursor: string };
      assert.equal(page.scans.length, 1);
      assert.match(page.nextCursor, /^[1-9]\d*:[1-9]\d*$/);
      assert.equal(page.scans[0].targetLabel, `registry-1.docker.io/library/alpine@${digest}`);
      const next = await fetch(`${url}?limit=1&cursor=${page.nextCursor}`, { headers: auth('alice') });
      const second = await next.json() as { scans: Array<{ scanId: string }>; nextCursor: null };
      assert.equal(second.scans.length, 1);
      assert.equal(second.nextCursor, null);
      const bob = await fetch(url, { headers: auth('bob') });
      assert.equal((await bob.json() as { scans: unknown[] }).scans.length, 1);
      assert.equal(JSON.stringify(page).includes('idempotency'), false);
    } finally {
      await app.close();
    }
  } finally {
    keys.forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
