import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { ScansService } from '../scans/scans.service.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { createPinnedConfigLoader } from '../oci/pinned-image-config.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import { compatibleCases, formats, linkedInput, minimalConfig } from './optional-null-fixtures.js';

// Real HTTP/auth/consumer/private authority/SQLite; transport bytes are synthetic, not live proof.
test('Docker/OCI optional-null matrix survives actual owner HTTP → worker → persisted status/SSE/parser', async () => {
  const { parseCurrentStatus } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const directory = mkdtempSync(join(tmpdir(), 'optional-null-http-'));
  const origin = 'http://127.0.0.1:8080';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    Object.defineProperty(app.get(ScansService), 'readiness', { value: async () => true });
    let input = linkedInput(minimalConfig());
    Object.defineProperty(app.get(OciResolver), 'resolvePublicAlpine', { value: async () => ({
      registry: input.identity.registry, repository: input.identity.repository,
      digest: input.identity.manifestDigest, platform: 'linux/amd64' }) });
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'disposable-null-test-1234' }) });
      assert.equal(response.status, 201);
      return response.headers.get('set-cookie')!.split(';')[0];
    };
    let owner = await register('null-owner@example.com');
    const other = await register('null-other@example.com');
    const path = `${base}/browser/scans`, ledger = app.get(LedgerStore).ledger!;
    let index = 0;
    for (const format of Object.keys(formats) as (keyof typeof formats)[]) {
      const cases: readonly [string, Record<string, unknown>, string[]][] = [
        ...compatibleCases.map(([name, fields]): [string, Record<string, unknown>, string[]] => [name, fields, ['config']]),
        ['null config with successful sibling', { config: { User: null, Labels: null } }, ['secret', 'config']],
        ['genuine malformed with successful sibling', { config: { User: false } }, ['secret', 'config']],
        ['off', { config: { Labels: null } }, ['secret']],
      ];
      for (const [name, fields, checks] of cases) {
        // Respect real per-owner admission limits; no limiter or database bypass.
        if (index > 0 && index % 5 === 0) owner = await register(`null-owner-${index}@example.com`);
        input = linkedInput({ ...minimalConfig(), ...fields }, format);
        const response = await fetch(path, { method: 'POST', headers: { cookie: owner, origin, 'content-type': 'application/json' },
          body: JSON.stringify({ imageReference: 'registry-1.docker.io/library/alpine:latest', scope: 'image', checks, idempotencyKey: `optional-null-${index++}` }) });
        assert.equal(response.status, 202, `${format}/${name}`);
        const { scanId } = await response.json() as { scanId: string };
        let loads = 0;
        const loader = createPinnedConfigLoader(async (_gateway, url) => ({ status: 200,
          headers: { 'content-type': url.pathname.includes('/manifests/') ? formats[format][0] : 'application/octet-stream' },
          body: Buffer.from(url.pathname.includes('/manifests/') ? input.manifestBytes : input.configBytes) }));
        await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', configLoader: async (...args) => { loads++; return loader(...args); } },
          async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }));
        const selected = checks.includes('config'), invalid = name.startsWith('genuine malformed');
        const expected = !selected ? 'skipped' : invalid ? 'failed' : 'checked';
        assert.equal(loads, selected ? 1 : 0);
        const actual = await fetch(`${path}/${scanId}`, { headers: { cookie: owner } });
        assert.equal(actual.status, 200);
        const text = await actual.text(); assert.equal(text.includes('CANARY'), false);
        const parsed = parseCurrentStatus(JSON.parse(text));
        assert.equal(parsed.config.config.outcome, expected, `${format}/${name}`);
        assert.equal(parsed.state, invalid ? 'partial' : 'completed');
        assert.equal(parsed.config.checksVersion, 'image-config-user-v1');
        assert.equal(parsed.config.resourcePolicyVersion, 'image-config-policy-v1');
        assert.deepEqual(parsed.config.completedRuleIds, expected === 'checked' ? ['IMGCFG_USER_ROOT'] : []);
        assert.equal(parsed.config.findings[0]?.classification, expected === 'checked' ? 'DEFAULT_ROOT' : undefined);
        assert.equal(parsed.config.history.reason, 'RULE_NOT_IMPLEMENTED');
        assert.equal(parsed.config.dockerfile.reason, 'SOURCE_NOT_PROVIDED');
        if (checks.includes('secret')) assert.equal(parsed.perCheck.secret.outcome, 'checked');
        assert.equal((await fetch(`${path}/${scanId}`, { headers: { cookie: other } })).status, 404);
        assert.equal((await fetch(`${path}/${scanId}`)).status, 401);
        const events = await (await fetch(`${path}/${scanId}/events`, { headers: { cookie: owner } })).text();
        assert.equal(events.includes('CANARY'), false);
        const reader = new Database(env.SCAN_LEDGER_PATH);
        try {
          const row = reader.prepare('SELECT report FROM scan_check_results WHERE scan_id = ?').get(scanId) as { report: string };
          assert.deepEqual(JSON.parse(row.report), parsed.config);
          assert.equal(JSON.stringify(reader.prepare('SELECT * FROM scan_audit').all()).includes('CANARY'), false);
          assert.equal(reader.pragma('integrity_check', { simple: true }), 'ok');
        } finally { reader.close(); }
      }
    }
  } finally {
    await app.close();
    Object.keys(env).forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
