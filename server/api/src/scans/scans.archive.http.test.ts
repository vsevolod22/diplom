import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';


const origin = 'http://127.0.0.1:8080';
const target = NGINX_SUPPORTED_CANDIDATE;
// Synthetic persisted outcomes, real Nest/browser auth/service/JSON/strict UI parser.
// This is the failed-SBOM wire regression, not real scanner or public admission proof.
test('real browser HTTP failed/partial archive SBOM roundtrips through the actual strict browser parser', async () => {
  // Load the sibling UI source at test runtime; server-only Docker typecheck must
  // not require copying/bundling the browser workspace into production images.
  const browserModule = new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url);
  const { parseCurrentSbom, parseCurrentStatus } = await import(browserModule.href);
  const directory = mkdtempSync(`${tmpdir()}/archive-http-`);
  const env = { SCAN_LEDGER_PATH: `${directory}/ledger.sqlite`, AUTH_DB_PATH: `${directory}/auth.sqlite`,
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_JWT_SECRET: 'disposable-test-secret-for-archive-http-only-1234', SCAN_JWT_ISSUER: 'archive-test',
    SCAN_JWT_AUDIENCE: 'archive-test', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]);
  Object.assign(process.env, env);
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (email: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'disposable-only-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('archive-owner@example.com'), other = await register('archive-other@example.com');
    const ledger = app.get(LedgerStore).ledger!;
    for (const reason of ['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE'] as const) {
      for (const partial of [true, false]) {
        const checks = partial ? ['secret', 'sbom'] : ['sbom'];
        const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: owner.id,
          idempotencyKey: `${reason}-${partial}`, checks: JSON.stringify(checks), scope: 'image' }).scanId;
        const job = ledger.claim()!;
        const report: ArchiveScanReport = { receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`],
          diffIds: [`sha256:${'b'.repeat(64)}`], archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(target),
          resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
          scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
            expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
          ...(partial ? { secret: { outcome: 'checked' as const, findings: [] } } : {}), sbom: { outcome: 'failed', reason } };
        assert.equal(ledger.finishArchive(id, job.attempts, report), true);
        const path = `${base}/browser/scans/${id}`;
        const status = parseCurrentStatus(await (await fetch(path, { headers: { cookie: owner.cookie } })).json());
        assert.equal(status.state, partial ? 'partial' : 'failed');
        if (partial) assert.equal(status.perCheck?.secret?.outcome, 'checked');
        const response = await fetch(`${path}/sbom`, { headers: { cookie: owner.cookie } });
        assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
        const wire = await response.json();
        const page = parseCurrentSbom(wire);
        assert.deepEqual(page, { outcome: 'failed', coverage: 'image', reason,
          errorCode: reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED', components: [], nextCursor: null });
        assert.throws(() => parseCurrentSbom({ ...wire, reason: 'SECRET_CANARY' }));
        assert.throws(() => parseCurrentSbom({ ...wire, raw: 'SECRET_CANARY' }));
        assert.equal((await fetch(`${path}/sbom`)).status, 401);
        assert.equal((await fetch(`${path}/sbom`, { headers: { cookie: other.cookie } })).status, 404);
      }
    }
  } finally {
    await app.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
