import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from '../oci/public-image.module.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_RESOURCE_POLICY } from '../oci/public-image-policy.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { ScanLedger, type ScanProgress, type CombinedOutcome } from '../ledger/ledger.js';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';
import { runImageConfig } from '../worker/image-config-runner.js';
import { ScansService } from './scans.service.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';

// Actual loopback HTTP/auth/SQLite. Normalized scanner and config inputs are synthetic;
// no production store, registry, provider, scanner, Docker or maintenance operations.
test('owner status progress: private durable metadata, strict browser decoding, retry/cancel/reopen and atomic identity', { timeout: 45_000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'http-progress-')), origin = 'http://127.0.0.1:8081';
  const file = join(directory, 'ledger.sqlite');
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: file, AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_JWT_SECRET: randomBytes(32).toString('hex'), SCAN_JWT_ISSUER: 'progress-test', SCAN_JWT_AUDIENCE: 'scan-api' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  let app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
  configurePublicImageIngress(app);
  const raw = new Database(file);
  const browser = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  try {
    const listen = async () => {
      await app.listen(0, '127.0.0.1');
      return `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    };
    let base = await listen();
    const register = async (name: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email: `${name}@example.com`, password: 'disposable-progress-1234' }), signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('progress-owner'), foreign = await register('progress-foreign');
    const token = (subject: string) => {
      const now = Math.floor(Date.now() / 1000);
      const body = `${Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({
        iss: env.SCAN_JWT_ISSUER, aud: env.SCAN_JWT_AUDIENCE, sub: subject, iat: now - 1, exp: now + 120,
        scope: 'scan:create scan:list scan:cancel' })).toString('base64url')}`;
      return `${body}.${createHmac('sha256', env.SCAN_JWT_SECRET).update(body).digest('base64url')}`;
    };
    const headers = (ingress: string, person = owner): Record<string, string> => ingress === 'scans'
      ? { authorization: `Bearer ${token(person.id)}` } : { cookie: person.cookie };
    const get = async (id: string, ingress = 'browser/scans') => {
      const response = await fetch(`${base}/${ingress}/${id}`, { headers: headers(ingress), signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200);
      if (ingress === 'browser/scans') assert.equal(response.headers.get('cache-control'), 'no-store');
      const wire = await response.json();
      const decoded = browser.parseCurrentStatus(wire);
      assert.equal(decoded.percent, null);
      return { wire, decoded };
    };
    let ledger = app.get(LedgerStore).ledger!;
    const bytes = configBytes(), checks = ['secret', 'sbom', 'vuln', 'config'];
    const target = { subject: owner.id, idempotencyKey: 'http-progress', registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: bytes.digest, platform: 'linux/amd64', checks: JSON.stringify(checks) };
    const id = ledger.enqueue(target).scanId;
    const empty: ScanProgress = { basis: 'durable-outcomes-v1', requestedChecks: ['secret', 'sbom', 'vuln', 'config'],
      outcomes: { secret: null, sbom: null, vuln: null, config: null }, resolvedChecks: 0, checkedChecks: 0 };
    for (const ingress of ['scans', 'browser/scans']) {
      const { wire } = await get(id, ingress);
      assert.deepEqual(wire.progress, empty); assert.equal(wire.state, 'queued');
    }
    const job = ledger.claim()!;
    const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [
      { findingId: 'secret-0-0', ruleId: 'PRIVATE_PROGRESS_RULE', line: 1, evidenceRef: 'result-0-secret-0' }] };
    assert.equal(ledger.checkpointCombined(job, secret), true);
    assert.equal(ledger.checkpointCombined(job, { check: 'sbom', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' }), true);
    const config = await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes));
    assert.equal(ledger.checkpointConfig(job, config), true);
    const expected = { ...empty, outcomes: { secret: 'checked', sbom: 'failed', vuln: null, config: 'checked' }, resolvedChecks: 3, checkedChecks: 2 };
    const before = raw.serialize();
    for (const ingress of ['scans', 'browser/scans']) {
      const { wire, decoded } = await get(id, ingress);
      assert.deepEqual(wire.progress, expected); assert.deepEqual(decoded.progress, expected);
      assert.equal(wire.state, 'running'); assert.equal(wire.result, null); assert.equal(wire.config, undefined);
      assert.deepEqual(wire.perCheck, empty.outcomes);
      for (const privateField of ['PRIVATE_PROGRESS_RULE', 'SCAN_TIMEOUT', 'leaseToken', 'checkedAt', 'findings', 'scannerVersion', 'dbPolicy'])
        assert.equal(JSON.stringify(wire).includes(privateField), false, privateField);
      const results = await fetch(`${base}/${ingress}/${id}/results`, { headers: headers(ingress) });
      assert.deepEqual(await results.json(), { findings: [], nextCursor: null, coverage: null });
      for (const suffix of ['sbom', 'vuln']) assert.equal((await fetch(`${base}/${ingress}/${id}/${suffix}`, { headers: headers(ingress) })).status, 404);
      const list = await fetch(`${base}/${ingress}?limit=10`, { headers: headers(ingress) });
      assert.equal(list.status, 200);
      assert.equal(JSON.stringify(await list.json()).includes('progress'), false, 'native list is unchanged');
    }
    assert.deepEqual(raw.serialize(), before, 'authorized GETs do not mutate schema/outbox/events/checkpoint/results');
    // Existing unauthenticated-guard audit writes are outside the progress projection.
    for (const ingress of ['scans', 'browser/scans']) assert.equal((await fetch(`${base}/${ingress}/${id}`)).status, 401);
    const internals = ledger as unknown as { checkpointRows: (id: string) => unknown[] };
    const rows = t.mock.method(internals, 'checkpointRows');
    for (const ingress of ['scans', 'browser/scans']) {
      const response = await fetch(`${base}/${ingress}/${id}`, { headers: headers(ingress, foreign) });
      assert.equal(response.status, 404);
      assert.equal(JSON.stringify(await response.json()).includes('progress'), false);
    }
    assert.equal(rows.mock.callCount(), 0, 'foreign denial before checkpoint read'); rows.mock.restore();

    // Pin a running snapshot, then commit cancel from another WAL connection in the middle of GET.
    const writer = new ScanLedger(file);
    try {
      let raced = false;
      const original = ledger.snapshot.bind(ledger);
      const spy = t.mock.method(ledger, 'snapshot', (scanId: string, subject: string) => {
        const snapshot = original(scanId, subject);
        if (!raced && scanId === id && subject === owner.id) { raced = true; assert.equal(writer.cancel(id, owner.id), 'cancelled'); }
        return snapshot;
      });
      try {
        const { wire } = await get(id);
        assert.equal(raced, true); assert.equal(wire.state, 'running');
        assert.deepEqual(wire.progress, expected); assert.deepEqual(wire.perCheck, empty.outcomes);
        assert.equal(wire.result, null); assert.equal(wire.config, undefined);
        assert.equal(wire.digest, target.digest); assert.equal(wire.imageReference, `${target.registry}/${target.repository}@${target.digest}`);
      } finally { spy.mock.restore(); }
    } finally { writer.close(); }
    const terminal = (await get(id)).wire;
    assert.equal(terminal.state, 'cancelled'); assert.deepEqual(terminal.progress, expected);
    assert.equal(terminal.perCheck.secret.outcome, 'checked'); assert.equal(terminal.perCheck.sbom.outcome, 'failed');
    assert.equal(terminal.perCheck.vuln, null); assert.equal(terminal.perCheck.config.outcome, 'checked');
    assert.equal(ledger.checkpointCombined(job, { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_FAILED' }), false);

    // Public archive running checkpoint stays metadata-only through the public subclass.
    const publicId = ledger.enqueue({ ...target, idempotencyKey: 'public-progress', repository: 'example/app', checks: '["secret","sbom"]' }).scanId;
    const publicJob = ledger.claim()!;
    const report: ArchiveScanReport = { receipt: { registry: publicJob.registry, repository: publicJob.repository, digest: target.digest,
      configDigest: bytes.configDigest, platform: 'linux/amd64', layerDigests: [`sha256:${'b'.repeat(64)}`], diffIds: [`sha256:${'c'.repeat(64)}`],
      archiveSha256: `sha256:${'d'.repeat(64)}`, profileVersion: PUBLIC_IMAGE_PROFILE, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION,
      resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY }, scannerVersion: '0.69.3', checkedAt: Date.now(),
      metrics: { wireBytes: 100, requests: 2, compressedBytes: 10, expandedBytes: 1024, entries: 1, archiveBytes: 2048, reservationPeak: 2048, scratchPeak: 2048 },
      secret: { outcome: 'checked', findings: [] } };
    assert.equal(ledger.checkpointArchive(publicJob, 'secret', report), true);
    const publicRunning = (await get(publicId)).wire;
    assert.equal(publicRunning.profile, PUBLIC_IMAGE_PROFILE);
    assert.deepEqual(publicRunning.progress, { basis: 'durable-outcomes-v1', requestedChecks: ['secret', 'sbom'],
      outcomes: { secret: 'checked', sbom: null }, resolvedChecks: 1, checkedChecks: 1 });
    assert.deepEqual(publicRunning.perCheck, { secret: null, sbom: null });
    assert.equal(ledger.retry(publicId, publicJob.attempts, Date.now() - 1, publicJob.leaseToken), true);
    assert.equal((await get(publicId)).wire.progress.resolvedChecks, 0);
    const replacement = ledger.claim()!;
    const { secret: omitted, ...envelope } = report;
    void omitted;
    const sbomFailure: ArchiveScanReport = { ...envelope, sbom: { outcome: 'failed', reason: 'SCAN_TIMEOUT' } };
    assert.equal(ledger.checkpointArchive(replacement, 'sbom', sbomFailure), true);
    const retried = (await get(publicId)).wire;
    assert.deepEqual(retried.progress.outcomes, { secret: null, sbom: 'failed' });
    assert.equal(retried.progress.resolvedChecks, 1); assert.equal(retried.progress.checkedChecks, 0);
    assert.equal(ledger.finishArchive(publicId, replacement.attempts, { ...sbomFailure, secret: report.secret }, undefined, replacement.leaseToken), true);
    const published = (await get(publicId)).wire;
    assert.equal(published.state, 'partial');
    assert.deepEqual(published.progress.outcomes, { secret: 'checked', sbom: 'failed' });
    assert.equal(published.progress.resolvedChecks, 2); assert.equal(published.progress.checkedChecks, 1);

    await app.close();
    app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
    configurePublicImageIngress(app); base = await listen(); ledger = app.get(LedgerStore).ledger!;
    for (const ingress of ['scans', 'browser/scans']) {
      assert.deepEqual((await get(id, ingress)).wire, terminal);
      assert.deepEqual((await get(publicId, ingress)).wire, published);
    }

    const corruptId = ledger.enqueue({ ...target, idempotencyKey: 'corrupt-progress' }).scanId, corruptJob = ledger.claim()!;
    ledger.checkpointCombined(corruptJob, secret);
    raw.prepare("UPDATE scan_checkpoints SET evidence_hash='corrupted' WHERE scan_id=?").run(corruptId);
    for (const ingress of ['scans', 'browser/scans']) {
      const denied = await fetch(`${base}/${ingress}/${corruptId}`, { headers: headers(ingress, foreign) });
      assert.equal(denied.status, 404);
      const invalid = await fetch(`${base}/${ingress}/${corruptId}`, { headers: headers(ingress) });
      assert.equal(invalid.status, 500);
      const body = JSON.stringify(await invalid.json());
      assert.equal(body.includes('PRIVATE_PROGRESS_RULE'), false); assert.equal(body.includes('progress'), false);
    }
  } finally {
    raw.close(); await app.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});

test('base service (without public wrapper) also snapshots state/progress/published outcomes atomically', t => {
  const directory = mkdtempSync(join(tmpdir(), 'base-status-progress-')), file = join(directory, 'ledger.sqlite');
  const ledger = new ScanLedger(file), writer = new ScanLedger(file);
  t.after(() => { writer.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  const service = new ScansService({ ledger } as LedgerStore, {} as OciResolver);
  const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'base-progress', registry: 'registry-1.docker.io', repository: 'library/alpine',
    digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
  const job = ledger.claim()!;
  ledger.checkpointCombined(job, { check: 'secret', outcome: 'checked', findings: [], scannerVersion: '0.69.3' });
  let raced = false;
  const original = ledger.snapshot.bind(ledger);
  const spy = t.mock.method(ledger, 'snapshot', (scanId: string, subject: string) => {
    const snapshot = original(scanId, subject);
    if (!raced) { raced = true; assert.equal(writer.cancel(id, 'alice'), 'cancelled'); }
    return snapshot;
  });
  try {
    const response = service.status({ subject: 'alice', scope: ['scan:create'] }, id);
    assert.equal(response.state, 'running');
    assert.equal(response.progress?.checkedChecks, 1);
    assert.equal(response.perCheck?.secret, null); assert.equal(response.result, null);
    assert.equal(response.digest, `sha256:${'a'.repeat(64)}`);
  } finally { spy.mock.restore(); }
  const response = service.status({ subject: 'alice', scope: ['scan:create'] }, id);
  assert.equal(response.state, 'cancelled'); assert.equal(response.perCheck?.secret?.outcome, 'checked');
});
