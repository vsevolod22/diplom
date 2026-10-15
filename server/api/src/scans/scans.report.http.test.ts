import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import type { VulnFinding } from '../worker/vuln-findings.js';
import type { ReportPage } from './report-page.js';

type Page = { page: ReportPage; nextCursor: string | null; findings?: VulnFinding[];
  components?: Array<{ ecosystem: string; name: string; version: string }>; findingCount?: number };

// Real loopback/auth/SQLite contract test with synthetic stored outcomes only.
// No scan admission, resolver, scanner, release, provider or deployed store is used.
test('report-v1 HTTP: both authenticated routes preserve global filters, cursor scope and legacy pages', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'report-view-http-'));
  const origin = 'http://127.0.0.1:8080', secret = randomBytes(32).toString('hex');
  const env = { AUTH_DB_PATH: join(dir, 'auth.sqlite'), SCAN_LEDGER_PATH: join(dir, 'ledger.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_JWT_SECRET: secret, SCAN_JWT_ISSUER: 'report-test', SCAN_JWT_AUDIENCE: 'scan-api' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST',
        headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'synthetic-report-password-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('report-owner@example.com'), other = await register('report-other@example.com');
    const token = (subject: string) => {
      const now = Math.floor(Date.now() / 1000);
      const unsigned = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
        iss: env.SCAN_JWT_ISSUER, aud: env.SCAN_JWT_AUDIENCE, sub: subject, iat: now - 1, exp: now + 60, scope: 'scan:create',
      })).toString('base64url')}`;
      return `${unsigned}.${createHmac('sha256', secret).update(unsigned).digest('base64url')}`;
    };
    const ledger = app.get(LedgerStore).ledger!;
    const target = { subject: owner.id, idempotencyKey: 'report-view', registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: `sha256:${'a'.repeat(64)}` as `sha256:${string}`, platform: 'linux/amd64', checks: '["secret","sbom","vuln"]', scope: 'image' };
    const scanId = ledger.enqueue(target).scanId, job = ledger.claim()!;
    assert.equal(job.scanId, scanId);
    const provenanceRef = `target-${'b'.repeat(64)}`;
    const findings: VulnFinding[] = Array.from({ length: 12 }, (_, i) => {
      const cveId = `CVE-2026-${String(i).padStart(4, '0')}`;
      return { findingId: `vuln-${createHash('sha256').update(JSON.stringify(['apk', provenanceRef, cveId, 'busybox', '1.2-r0'])).digest('hex')}`,
        cveId, ecosystem: 'apk', provenanceRef, packageName: 'busybox', installedVersion: '1.2-r0', fixedVersion: null,
        severity: i < 6 ? 'LOW' : 'HIGH', severitySources: ['unknown'] };
    });
    assert.equal(ledger.finishCombined(scanId, job.attempts, [
      { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: Array.from({ length: 12 }, (_, i) => ({
        findingId: `secret-${i}-0`, ruleId: 'opaque-rule', line: i < 6 ? i : null, evidenceRef: `result-${i}-secret-0`,
      })) },
      { check: 'sbom', outcome: 'checked', scannerVersion: '0.69.3', sbom: {
        image: `${target.registry}/${target.repository}@${target.digest}`, platform: 'linux/amd64', os: { name: 'alpine', version: '3.20' },
        components: Array.from({ length: 12 }, (_, i) => ({ ecosystem: i < 6 ? 'apk' : 'npm', name: `pkg-${String(i).padStart(2, '0')}`, version: '1' })),
      } },
      { check: 'vuln', outcome: 'checked', scannerVersion: '0.69.3',
        image: `${target.registry}/${target.repository}@${target.digest}`, findings },
    ]), true);
    for (const ingress of ['scans', 'browser/scans']) {
      const headers: Record<string, string> = ingress === 'scans' ? { authorization: `Bearer ${token(owner.id)}` } : { cookie: owner.cookie };
      const foreign: Record<string, string> = ingress === 'scans' ? { authorization: `Bearer ${token(other.id)}` } : { cookie: other.cookie };
      const path = `${base}/${ingress}/${scanId}`;
      const get = async (suffix: string, status = 200, auth: Record<string, string> = headers): Promise<Page> => {
        const response = await fetch(`${path}/${suffix}`, { headers: auth });
        assert.equal(response.status, status, suffix);
        if (ingress === 'browser/scans' && status === 200) assert.equal(response.headers.get('cache-control'), 'no-store');
        return await response.json() as Page;
      };
      for (const route of ['vuln', 'sbom', 'results']) {
        await get(`${route}?view=report-v1&cursor=malformed`, 404, foreign);
        await get(`${route}?view=report-v1`, 401, {});
        const legacy = await get(`${route}?limit=1`);
        assert.equal(Object.hasOwn(legacy, 'page'), false);
        assert.equal(legacy.nextCursor, 1);
      }
      const first = await get('vuln?view=report-v1&limit=5&severity=HIGH');
      assert.equal(first.page.totalCount, 12); assert.equal(first.page.matchedCount, 6);
      assert.equal(first.findings!.length, 5); assert.equal(first.findingCount, 12);
      assert.ok(first.findings!.every(row => row.severity === 'HIGH'));
      assert.ok(first.nextCursor);
      const cursor = encodeURIComponent(first.nextCursor);
      const last = await get(`vuln?view=report-v1&limit=5&severity=HIGH&cursor=${cursor}`);
      assert.equal(last.findings!.length, 1); assert.equal(last.nextCursor, null);
      assert.equal(new Set([...first.findings!, ...last.findings!].map(row => row.findingId)).size, 6);
      await get(`vuln?view=report-v1&limit=10&severity=HIGH&cursor=${cursor}`, 400);
      await get(`vuln?view=report-v1&limit=5&severity=LOW&cursor=${cursor}`, 400);
      await get(`sbom?view=report-v1&limit=5&cursor=${cursor}`, 400);
      for (const invalid of ['view=report-v1&limit=1', 'view=report-v1&severity=HIGH&severity=LOW',
        'view=report-v1&view=report-v1', 'view=report-v1&unknown=x']) await get(`vuln?${invalid}`, 400);
      const none = await get('vuln?view=report-v1&severity=CRITICAL');
      assert.equal(none.page.matchedCount, 0); assert.equal(none.page.totalCount, 12);
      const sbom = await get('sbom?view=report-v1&limit=5&ecosystem=npm&name=PKG-&sort=name:desc');
      assert.equal(sbom.page.matchedCount, 6); assert.equal(sbom.components![0].name, 'pkg-11');
      const secrets = await get('results?view=report-v1&limit=5&ruleId=opaque-rule&linePresence=unknown');
      assert.equal(secrets.page.matchedCount, 6); assert.equal(secrets.page.totalCount, 12);
      for (const limit of [5, 10, 25, 50]) {
        const ids: string[] = []; let next: string | null = null;
        do {
          const value = await get(`vuln?view=report-v1&limit=${limit}${next ? `&cursor=${encodeURIComponent(next)}` : ''}`);
          assert.equal(value.page.limit, limit); assert.equal(value.page.totalCount, 12);
          ids.push(...value.findings!.map(row => row.findingId)); next = value.nextCursor;
        } while (next);
        assert.equal(ids.length, 12); assert.equal(new Set(ids).size, 12);
      }
    }
  } finally {
    await app.close();
    Object.keys(env).forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
