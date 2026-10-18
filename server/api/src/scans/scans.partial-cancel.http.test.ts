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
import type { CombinedOutcome } from '../ledger/ledger.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../worker/cve-db-policy.mjs';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';
import { runImageConfig } from '../worker/image-config-runner.js';

type Check = 'secret' | 'sbom' | 'vuln';
const checks: Check[] = ['secret', 'sbom', 'vuln'];
const routes = { secret: 'results', sbom: 'sbom', vuln: 'vuln' };

// Real HTTP, auth, checkpoint transaction and disposable SQLite; only scanner outputs are synthetic.
// Import UI parsers dynamically so server-only builds do not require browser source in their image.
test('cancelled checkpoints: ordinary/archive HTTP, strict browser parsers, all pages, owner, SSE and reopen', { timeout: 45_000 }, async () => {
  const browserModule = new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url);
  const { parseCurrentStatus, parseCurrentResults, parseCurrentSbom, parseCurrentVuln, parseScanEventHint } = await import(browserModule.href);
  const parsers = { secret: parseCurrentResults, sbom: parseCurrentSbom, vuln: parseCurrentVuln };
  const dir = mkdtempSync(join(tmpdir(), 'partial-cancel-http-'));
  const origin = 'http://127.0.0.1:8080';
  const env = { AUTH_DB_PATH: join(dir, 'auth.sqlite'), SCAN_LEDGER_PATH: join(dir, 'ledger.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_JWT_SECRET: randomBytes(32).toString('hex'),
    SCAN_JWT_ISSUER: 'checkpoint-test', SCAN_JWT_AUDIENCE: 'scan-api' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  let app = await NestFactory.create(AppModule, { logger: false });
  try {
    const listen = async () => {
      await app.listen(0, '127.0.0.1');
      return `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    };
    let base = await listen();
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'synthetic-cancel-password-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('checkpoint-owner@example.com'), other = await register('checkpoint-other@example.com');
    const token = (subject: string) => {
      const now = Math.floor(Date.now() / 1000);
      const payload = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
        iss: env.SCAN_JWT_ISSUER, aud: env.SCAN_JWT_AUDIENCE, sub: subject, iat: now - 1, exp: now + 120, scope: 'scan:create scan:cancel',
      })).toString('base64url')}`;
      return `${payload}.${createHmac('sha256', env.SCAN_JWT_SECRET).update(payload).digest('base64url')}`;
    };
    const ledger = app.get(LedgerStore).ledger!;
    const cases: Array<{ id: string; saved: Check[]; firstPages: Map<string, unknown>; events: string }> = [];
    for (const archive of [false, true]) {
      for (const saved of [[], ['secret'], ['sbom'], ['vuln'], checks] as Check[][]) {
        const target = archive ? NGINX_ARCHIVE_TARGET : { registry: 'registry-1.docker.io', repository: 'library/alpine',
          digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64' };
        const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: owner.id,
          idempotencyKey: `${archive}-${saved.join('-')}`, checks: JSON.stringify(checks), scope: 'image', cvePolicy: CURRENT_DB_POLICY }).scanId;
        const job = ledger.claim()!;
        assert.equal(job.scanId, id);
        const image = `${target.registry}/${target.repository}@${target.digest}`;
        const at = Date.now();
        const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2,
          source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`, manifestDigest: `sha256:${'d'.repeat(64)}`,
          artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
          updatedAt: new Date(at - 60_000).toISOString(), downloadedAt: new Date(at - 30_000).toISOString(), nextUpdate: new Date(at + 60_000).toISOString() };
        const dbPolicy = evaluateDbPolicy(db, CURRENT_DB_POLICY, at)!;
        const secret = { outcome: 'checked' as const, findings: Array.from({ length: 12 }, (_, i) => ({
          findingId: `secret-${i}-0`, ruleId: 'checkpoint-rule', line: i, evidenceRef: `result-${i}-secret-0` })) };
        const sbom = { outcome: 'checked' as const, sbom: { image, platform: 'linux/amd64' as const,
          os: { name: 'alpine' as const, version: '3.21.3' }, components: Array.from({ length: 12 }, (_, i) => ({
            ecosystem: 'apk' as const, name: `pkg-${String(i).padStart(2, '0')}`, version: '1.2' })) } };
        const findings = Array.from({ length: 12 }, (_, i) => {
          const cveId = `CVE-2026-${1000 + i}`, provenanceRef = `target-${'b'.repeat(64)}`;
          const identity = ['apk', provenanceRef, cveId, 'busybox', '1.2'];
          return { findingId: `vuln-${createHash('sha256').update(JSON.stringify(archive ? [image, 'linux/amd64', 'vuln', ...identity] : identity)).digest('hex')}`,
            cveId, provenanceRef, ecosystem: 'apk' as const, packageName: 'busybox', installedVersion: '1.2', fixedVersion: null,
            severity: 'HIGH' as const, severitySources: ['unknown'] };
        });
        const envelope: Omit<ArchiveScanReport, 'secret' | 'sbom' | 'vuln'> = {
          receipt: { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
            archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1',
            resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
          scannerVersion: '0.69.3', checkedAt: at, metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
            expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 } };
        for (const check of saved) {
          if (archive) {
            const result = check === 'secret' ? { secret } : check === 'sbom' ? { sbom } : { vuln: {
              outcome: 'checked' as const, findings, db, dbPolicy, os: { outcome: 'checked' as const },
              node: { outcome: 'unsupported' as const, reason: 'NODE_INVENTORY_ABSENT' as const } } };
            assert.equal(ledger.checkpointArchive(job, check, { ...envelope, ...result }), true);
          } else {
            const result: CombinedOutcome = check === 'secret' ? { check, ...secret, scannerVersion: '0.69.3' }
              : check === 'sbom' ? { check, ...sbom, scannerVersion: '0.69.3' }
              : { check, outcome: 'checked', findings, image, scannerVersion: '0.69.3', dbEvidence: { db, checkedAt: at, dbPolicy } };
            assert.equal(ledger.checkpointCombined(job, result), true);
          }
        }
        const path = `${base}/browser/scans/${id}`;
        const getStatus = async () => parseCurrentStatus(await (await fetch(path, { headers: { cookie: owner.cookie } })).json());
        assert.ok(Object.values((await getStatus()).perCheck).every(value => value === null), 'checkpoint is not a public running report');
        const cancel = (cookie: string) => fetch(`${path}/cancel`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' }, body: '{}' });
        assert.equal((await cancel(other.cookie)).status, 404);
        assert.equal((await getStatus()).state, 'running');
        assert.equal((await cancel(owner.cookie)).status, 200);
        assert.equal((await cancel(owner.cookie)).status, 200);
        assert.equal(ledger.checkpointCombined(job, { check: 'secret', ...secret, scannerVersion: '0.69.3' }), false);
        assert.equal(ledger.finishCombined(id, job.attempts, checks.map(check => ({ check, outcome: 'failed', errorCode: 'SCAN_FAILED' })), undefined, job.leaseToken), false);
        const stored = ledger.archiveResult(id, owner.id);
        if (archive && saved.length) assert.deepEqual(checks.filter(check => Object.hasOwn(stored!, check)), saved, 'missing archive result keys stay absent');
        else assert.equal(stored, undefined);
        const events = await (await fetch(`${path}/events`, { headers: { cookie: owner.cookie }, signal: AbortSignal.timeout(5000) })).text();
        const hints = [...events.matchAll(/^data: (.+)$/gm)].map(match => JSON.parse(match[1]));
        assert.deepEqual(hints.map(hint => hint.state), ['queued', 'running', 'cancelled']);
        assert.ok(hints.every(hint => parseScanEventHint(hint, id)));
        cases.push({ id, saved, firstPages: new Map(), events });
      }
    }
    const configCases: Array<{ id: string; report: Awaited<ReturnType<typeof runImageConfig>> | undefined }> = [];
    for (const saved of [false, true]) {
      const bytes = configBytes();
      const id = ledger.enqueue({ subject: owner.id, idempotencyKey: `config-${saved}`, registry: 'registry-1.docker.io',
        repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64', checks: '["secret","config"]' }).scanId;
      const job = ledger.claim()!;
      const report = saved ? await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes)) : undefined;
      if (report) assert.equal(ledger.checkpointConfig(job, report), true);
      const response = await fetch(`${base}/browser/scans/${id}/cancel`, { method: 'POST',
        headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' }, body: '{}' });
      assert.equal(response.status, 200);
      configCases.push({ id, report });
    }
    for (const reopened of [false, true]) {
      if (reopened) {
        await app.close();
        app = await NestFactory.create(AppModule, { logger: false });
        base = await listen();
      }
      for (const { id, report } of configCases) {
        for (const ingress of ['browser/scans', 'scans']) {
          const headers: Record<string, string> = ingress === 'scans' ? { authorization: `Bearer ${token(owner.id)}` } : { cookie: owner.cookie };
          const response = await fetch(`${base}/${ingress}/${id}`, { headers });
          assert.equal(response.status, 200);
          const status = parseCurrentStatus(await response.json());
          assert.equal(status.state, 'cancelled');
          assert.equal(status.perCheck.secret, null);
          assert.deepEqual(status.config, report);
          if (report) assert.equal(status.perCheck.config.outcome, report.config.outcome);
          else assert.equal(status.perCheck.config, null, 'interrupted config is not synthesized as skipped');
        }
      }
      for (const item of cases) {
        for (const ingress of ['browser/scans', 'scans']) {
          const headers: Record<string, string> = ingress === 'scans' ? { authorization: `Bearer ${token(owner.id)}` } : { cookie: owner.cookie };
          const foreign: Record<string, string> = ingress === 'scans' ? { authorization: `Bearer ${token(other.id)}` } : { cookie: other.cookie };
          const path = `${base}/${ingress}/${item.id}`;
          const get = async (suffix: string, expected = 200, auth = headers) => {
            const response = await fetch(path + suffix, { headers: auth, signal: AbortSignal.timeout(5000) });
            assert.equal(response.status, expected, `${ingress} ${item.id} ${suffix}`);
            if (ingress === 'browser/scans' && expected === 200) assert.equal(response.headers.get('cache-control'), 'no-store');
            return response.json();
          };
          const wire = await get(''), status = parseCurrentStatus(wire);
          assert.equal(status.state, 'cancelled');
          assert.equal(wire.result, null);
          assert.deepEqual(checks.filter(check => status.perCheck[check]?.outcome === 'checked'), item.saved);
          for (const check of checks.filter(check => !item.saved.includes(check))) assert.equal(status.perCheck[check], null);
          await get('', 404, foreign); await get('', 401, {});
          for (const check of checks) {
            const route = `/${routes[check]}`;
            for (const view of [false, true]) {
              await get(`${route}${view ? '?view=report-v1' : ''}`, 404, foreign);
              await get(`${route}${view ? '?view=report-v1' : ''}`, 401, {});
              if (!item.saved.includes(check)) {
                if (check === 'secret' && !view) {
                  const empty = await get(route);
                  assert.deepEqual(empty, { findings: [], nextCursor: null, coverage: null });
                  assert.deepEqual(parseCurrentResults(empty), { findings: [], nextCursor: null, coverage: [] });
                } else await get(`${route}${view ? '?view=report-v1' : ''}`, 404);
                continue;
              }
              const ids: string[] = [];
              let cursor: string | undefined;
              do {
                const suffix = `${route}?limit=5${view ? '&view=report-v1' : ''}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
                const page = await get(suffix);
                const decoded = parsers[check](page, view ? { view: 'report-v1', limit: 5 } : undefined, cursor);
                assert.equal(decoded.nextCursor, page.nextCursor === null ? null : String(page.nextCursor));
                if (!cursor) {
                  const key = `${ingress}:${check}:${view}`;
                  if (reopened) assert.deepEqual(page, item.firstPages.get(key), 'terminal report version/cursor/DB timestamp must survive reopen unchanged');
                  else item.firstPages.set(key, page);
                  assert.deepEqual(await get(suffix), page, 'reload is byte-equivalent JSON');
                }
                const rows = check === 'sbom' ? page.components : page.findings;
                ids.push(...rows.map((row: { findingId?: string; name?: string }) => row.findingId ?? row.name));
                if (view) { assert.equal(page.page.totalCount, 12); assert.equal(page.page.matchedCount, 12); }
                cursor = decoded.nextCursor ?? undefined;
              } while (cursor);
              assert.equal(ids.length, 12); assert.equal(new Set(ids).size, 12);
            }
          }
          const response = await fetch(`${path}/events`, { headers, signal: AbortSignal.timeout(5000) });
          assert.equal(response.status, 200); assert.equal(await response.text(), item.events);
          const terminalId = [...item.events.matchAll(/^id: (.+)$/gm)].at(-1)![1];
          const replay = await fetch(`${path}/events`, { headers: { ...headers, 'last-event-id': terminalId }, signal: AbortSignal.timeout(5000) });
          assert.equal(replay.status, 200); assert.doesNotMatch(await replay.text(), /event: scan/);
          await get('/events', 404, foreign); await get('/events', 401, {});
        }
      }
    }
  } finally {
    await app.close();
    Object.keys(env).forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  }
});
