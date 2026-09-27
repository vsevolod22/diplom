import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { AppModule } from '../app.module.js';
import { NestFactory } from '@nestjs/core';

import { createHmac } from 'node:crypto';


test('real HTTP POST never returns 202 without resolver and worker', async () => {
  const keys = ['SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER', 'SCAN_JWT_AUDIENCE'];
  const previous = keys.map(key => process.env[key]);
  process.env.SCAN_JWT_SECRET = 'dedicated-test-secret-not-for-production-12345';
  process.env.SCAN_JWT_ISSUER = 'issuer.example';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
  const body = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'issuer.example', aud: 'scan-api', sub: 'alice', iat: Math.floor(Date.now()/1000)-1, exp: Math.floor(Date.now()/1000)+60, scope: 'scan:create' })).toString('base64url')}`;
  const token = `${body}.${createHmac('sha256', process.env.SCAN_JWT_SECRET).update(body).digest('base64url')}`;
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address() as { port: number };
    const url = `http://127.0.0.1:${address.port}/api/v1/scans`;
    assert.equal((await fetch(url, { method: 'POST' })).status, 401);
        assert.equal((await fetch(url, { method: 'POST', headers: { authorization: 'Bearer invalid' } })).status, 401);
    const response = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { errorCode: 'SCANNER_UNAVAILABLE' });
  } finally {
    await app.close();
    keys.forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
  }
});
