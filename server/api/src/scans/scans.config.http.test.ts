import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { format } from 'node:util';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { ScansService } from './scans.service.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';

// Actual Nest auth/controller/service, actual consumer/private adapter/module and SQLite.
// Only readiness, OCI byte transport and legacy scanner ports are controlled.
test('real browser POST → worker → v11 → GET/SSE → strict parser, independent coverage and redaction', async () => {
  const { parseCurrentStatus, parseScanEventHint } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const directory = mkdtempSync(join(tmpdir(), 'config-http-'));
  const origin = 'http://127.0.0.1:8080';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_VULN_ENABLED: 'true' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  const consoleMethods = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const originalConsole = consoleMethods.map(method => console[method]);
  const messages: string[] = [];
  consoleMethods.forEach(method => { console[method] = (...args: unknown[]) => { messages.push(format(...args)); }; });
  try {
    const service = app.get(ScansService);
    Object.defineProperty(service, 'readiness', { value: async () => true });
    Object.defineProperty(service, 'vulnDbReady', { value: async () => true });
    let bytes = configBytes();
    Object.defineProperty(app.get(OciResolver), 'resolvePublicAlpine', { value: async () => ({ registry: 'registry-1.docker.io', repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64' }) });
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'disposable-config-test-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('config-owner@example.com'), other = await register('config-other@example.com');
    const path = `${base}/browser/scans`;
    const ledger = app.get(LedgerStore).ledger!;
    const post = (checks: string[], key: string, extra = {}) => fetch(path, { method: 'POST', headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' },
      body: JSON.stringify({ imageReference: 'registry-1.docker.io/library/alpine:latest', checks, scope: 'image', idempotencyKey: key, ...extra }) });
    assert.equal((await fetch(path)).status, 401);
    assert.equal((await post(['config'], 'reject-proof', { verified: true })).status, 400);
    assert.equal((await post(['config'], 'reject-repo', { imageReference: 'registry-1.docker.io/library/nginx:latest' })).status, 400);
    for (const [index, user, checks, outcome] of [
      [0, '0', ['config'], 'checked'],
      [2, 'CANARY_USER', ['config'], 'unsupported'], [3, null, ['config'], 'checked'],
      [4, '0', ['secret'], 'skipped'], [5, false, ['secret', 'sbom', 'vuln', 'config'], 'failed'],
      [6, '0', ['secret', 'sbom', 'vuln', 'config'], 'checked'],
    ] as const) {
      bytes = configBytes(user);
      const response = await post([...checks], `config-case-${index}`);
      assert.equal(response.status, 202);
      const receipt = await response.json() as { scanId: string };
      const id = receipt.scanId;
      const pending = parseCurrentStatus(await (await fetch(`${path}/${id}`, { headers: { cookie: owner.cookie } })).json());
      assert.equal(pending.config, undefined);
      assert.equal((await post([...checks], `config-case-${index}`)).status, 202);
      assert.equal((await post(checks.some(check => check === 'config') ? ['secret'] : ['config'], `config-case-${index}`)).status, 409);
      let loads = 0;
      const loader = fixtureLoader(bytes);
      await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', configLoader: async (...args) => { loads++; return loader(...args); } },
        async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }), Date.now(),
        async () => ({ ok: false, errorCode: 'SCAN_TIMEOUT' }), async () => { throw new Error('CANARY_SCANNER_ERROR'); });
      assert.equal(loads, checks.some(check => check === 'config') ? 1 : 0);
      const actual = await fetch(`${path}/${id}`, { headers: { cookie: owner.cookie } });
      assert.equal(actual.status, 200); assert.equal(actual.headers.get('cache-control'), 'no-store');
      const text = await actual.text(); assert.equal(text.includes('CANARY'), false);
      const parsed = parseCurrentStatus(JSON.parse(text));
      assert.deepEqual(parsed.checks, checks); assert.equal(parsed.config.config.outcome, outcome);
            assert.equal(parsed.config.checksVersion, 'image-config-user-v1');
            assert.equal(parsed.config.resourcePolicyVersion, 'image-config-policy-v1');
            assert.deepEqual(parsed.config.completedRuleIds, outcome === 'checked' ? ['IMGCFG_USER_ROOT'] : []);
            if (user === null) assert.equal(parsed.config.findings[0]?.classification, 'DEFAULT_ROOT');
            if (outcome === 'failed') assert.equal(parsed.config.config.reason, 'INVALID_CONFIG');
      if (checks.some(check => check === 'secret')) assert.equal(parsed.perCheck.secret.outcome, 'checked');
      if (checks.some(check => check === 'sbom')) assert.equal(parsed.perCheck.sbom.outcome, 'failed');
      assert.equal(parsed.state, checks.length > 1 ? 'partial' : ['checked', 'skipped'].includes(outcome) ? 'completed' : 'failed');
      assert.equal((await fetch(`${path}/${id}`, { headers: { cookie: other.cookie } })).status, 404);
      assert.equal((await fetch(`${path}/${id}`)).status, 401);
      const eventResponse = await fetch(`${path}/${id}/events`, { headers: { cookie: owner.cookie } });
      assert.equal(eventResponse.status, 200);
      const events = await eventResponse.text(); assert.equal(events.includes('CANARY'), false);
      for (const line of events.split('\n').filter(line => line.startsWith('data: '))) assert.equal(parseScanEventHint(JSON.parse(line.slice(6)), id), true);
      if (checks.some(check => check === 'secret')) assert.equal((await fetch(`${path}/${id}/results`, { headers: { cookie: owner.cookie } })).status, 200);
    }
    const reader = new Database(env.SCAN_LEDGER_PATH);
    try {
      assert.equal(reader.pragma('user_version', { simple: true }), 11);
      assert.equal(JSON.stringify(reader.prepare('SELECT * FROM scan_check_results').all()).includes('CANARY'), false);
      assert.equal(JSON.stringify(reader.prepare('SELECT * FROM scan_audit').all()).includes('CANARY'), false);
      assert.equal(reader.pragma('integrity_check', { simple: true }), 'ok');
      assert.deepEqual(reader.pragma('foreign_key_check'), []);
    } finally { reader.close(); }
    assert.equal(messages.join('\n').includes('CANARY'), false);
  } finally {
    consoleMethods.forEach((method, index) => { console[method] = originalConsole[index]; });
    await app.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
