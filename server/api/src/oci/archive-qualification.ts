import 'reflect-metadata';
import assert from 'node:assert/strict';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { LedgerStore } from '../ledger/ledger-store.js';
import { ScansService } from '../scans/scans.service.js';

import { NGINX_ARCHIVE_TARGET, NGINX_SUPPORTED_CANDIDATE } from './bounded-image-archive.js';
import { consumeOne } from '../worker/outbox-consumer.js';

// Disposable loopback HTTP server; never uses the live ledger/auth volume or JWT.
const temporary = await mkdtemp('/tmp/trivy/archive-http-');
process.env.SCAN_LEDGER_PATH = `${temporary}/ledger.sqlite`;
process.env.AUTH_DB_PATH = `${temporary}/auth.sqlite`;
process.env.AUTH_ORIGIN = 'http://127.0.0.1:8080';
process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
process.env.SCAN_JWT_SECRET = randomBytes(32).toString('hex');
const app = await NestFactory.create(AppModule, { logger: false });
const ledger = app.get(LedgerStore).ledger!;
const key = await readFile(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url));
assert.equal(createHash('sha256').update(createPublicKey(key).export({ type: 'spki', format: 'der' })).digest('hex'),
  'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078');
const manifest = process.env.SCAN_VULN_MANIFEST_DIGEST!;
const options = { timeoutMs: 120_000, dbDir: '/tmp/trivy', vuln: {
  cacheDir: '/tmp/trivy', releaseDir: '/opt/release', trust: { trustedPublicKeyPem: key.toString('utf8'),
    expectedSigner: 'local-db-operator-v1', expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifest}`,
    expectedSchemaVersion: 2, expectedManifestDigest: manifest, expectedArtifactSha256: process.env.SCAN_VULN_ARTIFACT_SHA256! } } };
try {
  const service = app.get(ScansService);
  await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
  const register = async (email: string) => {
    const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: {
      origin: process.env.AUTH_ORIGIN!, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: randomBytes(24).toString('hex') }) });
    assert.equal(response.status, 201);
    return { id: (await response.json() as { id: string }).id, cookie: response.headers.get('set-cookie')!.split(';')[0] };
  };
  const owner = await register('archive-owner@example.com'), other = await register('archive-other@example.com');
  const get = (path: string, cookie?: string) => fetch(`${base}/browser/scans/${path}`, { headers: cookie ? { cookie } : {} });
  const scenarios = [
    { name: 'supported-vuln', checks: ['vuln'] as const, options, expected: 'checked', candidate: NGINX_SUPPORTED_CANDIDATE },
    { name: 'supported-combined', checks: ['secret', 'sbom', 'vuln'] as const, options, expected: 'checked', candidate: NGINX_SUPPORTED_CANDIDATE },
    { name: 'vuln-eol', checks: ['vuln'] as const, options, expected: 'unsupported' },
    { name: 'combined-eol', checks: ['secret', 'sbom', 'vuln'] as const, options, expected: 'unsupported' },
    { name: 'combined-missing-db-config', checks: ['secret', 'sbom', 'vuln'] as const,
      options: { timeoutMs: 120_000, dbDir: '/tmp/trivy' }, expected: 'failed' },
    { name: 'combined-wrong-db-pin', checks: ['secret', 'sbom', 'vuln'] as const,
      options: { ...options, vuln: { ...options.vuln, trust: { ...options.vuln.trust, expectedArtifactSha256: '0'.repeat(64) } } }, expected: 'failed' },
  ];
  for (const scenario of scenarios) {
    const checks = scenario.checks;
    const candidate = 'candidate' in scenario ? scenario.candidate! : NGINX_ARCHIVE_TARGET;
        const target = { ...candidate, digest: candidate.digest as `sha256:${string}`, subject: owner.id,
      idempotencyKey: `qualification-${scenario.name}`, checks: JSON.stringify(checks), scope: 'image', fingerprint: createHash('sha256').update(`exact-nginx-v1-${scenario.name}`).digest('hex') };
    const id = ledger.enqueue(target).scanId;
    assert.equal(await consumeOne(ledger, scenario.options), true);
    const report = ledger.archiveResult(id, target.subject);
    assert.ok(report, 'actual consumer must persist bounded receipt report');
    assert.equal(report.vuln?.outcome, scenario.expected, `Candidate outcome mismatch (${report.vuln?.outcome === 'failed' ? report.vuln.reason : report.vuln?.outcome})`);
    if (report.vuln?.outcome === 'unsupported') assert.equal(report.vuln.reason, 'OS_EOL');
    if (checks.length > 1) {
      assert.equal(report.secret?.outcome, 'checked'); assert.equal(report.sbom?.outcome, 'checked');
      if (report.sbom?.outcome === 'checked') assert.ok(report.sbom.sbom.components.length > 0);
      assert.equal(ledger.state(id, target.subject), scenario.expected === 'checked' ? 'completed' : 'partial');
    } else assert.equal(ledger.state(id, target.subject), scenario.expected === 'checked' ? 'completed' : 'failed');
        if (report.vuln?.outcome === 'checked') {
          assert.ok(report.vuln.findings.length > 0, 'positive proof requires actual normalized CVEs');
          assert.equal(report.vuln.os.outcome, 'checked'); assert.equal(report.vuln.node.outcome, 'unsupported');
        }
    assert.equal(ledger.archiveResult(id, 'other-subject'), undefined);
    const identity = { subject: target.subject, scope: ['scan:read'] } as Parameters<ScansService['status']>[0];
    const status = service.status(identity, id);
    assert.equal(status.perCheck?.vuln?.outcome, scenario.expected);
    assert.equal(service.vuln(identity, id, undefined, undefined).outcome, scenario.expected);
    if (checks.length > 1) {
      const sbomPage = service.sbom(identity, id, '0', '10');
      assert.equal(sbomPage.components.length, 10);
      assert.ok(sbomPage.nextCursor !== null);
      assert.equal(service.results(identity, id, undefined, undefined).findings.length, report.secret?.outcome === 'checked' ? report.secret.findings.length : 0);
      assert.throws(() => service.sbom({ ...identity, subject: 'other-subject' }, id, undefined, undefined));
    }
    assert.throws(() => service.status({ ...identity, subject: 'other-subject' }, id));
    for (const suffix of ['', '/vuln', ...(checks.length > 1 ? ['/sbom', '/results'] : [])]) {
      assert.equal((await get(`${id}${suffix}`)).status, 401);
      assert.equal((await get(`${id}${suffix}`, other.cookie)).status, 404);
      const response = await get(`${id}${suffix}`, owner.cookie);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const body = await response.json() as Record<string, any>;
      if (!suffix) { assert.equal(body.state, scenario.expected === 'checked' ? 'completed' : checks.length > 1 ? 'partial' : 'failed'); assert.equal(body.imageProfile.qualified, false); }
      if (suffix === '/vuln') { assert.equal(body.outcome, scenario.expected); if (scenario.expected === 'checked') assert.ok(body.findingCount > 0); }
      if (suffix === '/sbom') assert.equal(body.componentCount, scenario.expected === 'checked' ? 72 : 67);
    }
    if (checks.length > 1) {
      const first = await (await get(`${id}/sbom?limit=10`, owner.cookie)).json() as { components: unknown[]; nextCursor: number };
      assert.equal(first.components.length, 10); assert.equal(first.nextCursor, 10);
      assert.equal((await get(`${id}/sbom?cursor=999`, owner.cookie)).status, 400);
    }
    const denied: Response = await fetch(`${base}/browser/scans`, { method: 'POST', headers: {
      cookie: owner.cookie, origin: process.env.AUTH_ORIGIN!, 'content-type': 'application/json' },
    body: JSON.stringify({ imageReference: `${target.registry}/${target.repository}@${target.digest}`,
      scope: 'image', checks, idempotencyKey: target.idempotencyKey }) });
    assert.equal(denied.status, 400, 'closed public admission cannot replay internally seeded jobs');
    assert.equal(ledger.enqueue(target).scanId, id);
    assert.equal(await consumeOne(ledger, scenario.options), false);
    const residue = await readdir('/tmp/trivy/jobs'); assert.equal(residue.length, 0, 'attempt tree cleaned including fanal/cache');
    console.log(JSON.stringify({ scenario: scenario.name, checks, terminal: ledger.state(id, target.subject),
      secret: report.secret?.outcome, sbom: report.sbom?.outcome, vuln: report.vuln?.outcome,
      reason: report.vuln?.outcome === 'unsupported' ? report.vuln.reason : undefined,
      findings: report.vuln?.outcome === 'checked' ? report.vuln.findings.length : undefined,
            components: report.sbom?.outcome === 'checked' ? report.sbom.sbom.components.length : undefined,
      metrics: report.metrics, archiveSha256: report.receipt.archiveSha256,
      dbManifest: report.vuln && report.vuln.outcome !== 'failed' ? report.vuln.db?.manifestDigest : undefined,
      cleanup: true, ownership: true, replay: true, cookieHttp: true, qualified: false }));
  }
} finally { await app.close(); await rm(temporary, { recursive: true, force: true }); }
