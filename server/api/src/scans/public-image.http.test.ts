import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NestFactory } from '@nestjs/core';
import { PublicImageModule, configurePublicImageIngress } from '../oci/public-image.module.js';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { inspectPublicImage } from '../oci/public-image-inspection.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_LIMITS } from '../oci/public-image-policy.js';
import type { ManifestFetch } from '../oci/registry-resolver.js';
import type { ImageReference } from './image-reference.js';
import { ScansService } from './scans.service.js';
import { PublicImageScansService } from './public-image-scans.service.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { BrowserScansController } from './browser-scans.controller.js';
import { ImageSearchSessions } from './image-search.js';
import { REPORT_ECOSYSTEMS } from './report-query.js';

const sha = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}` as const;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const configType = 'application/vnd.oci.image.config.v1+json';
const layerType = 'application/vnd.oci.image.layer.v1.tar+gzip';
function fixture(architecture = 'amd64', layerSize = 10) {
  const config = encode({ os: 'linux', architecture, config: { User: '1000' }, rootfs: { type: 'layers', diff_ids: [`sha256:${'c'.repeat(64)}`] } });
  const manifest = encode({ schemaVersion: 2, mediaType: manifestType, config: { mediaType: configType, size: config.length, digest: sha(config) },
    layers: [{ mediaType: layerType, size: layerSize, digest: `sha256:${'b'.repeat(64)}` }] });
  const calls: string[] = [];
  const transport: ManifestFetch = async (host, path) => {
    assert.equal(host, 'registry-1.docker.io'); calls.push(path);
    const body = path.includes('/manifests/') ? manifest : config;
    return { status: 200, headers: { 'content-type': path.includes('/manifests/') ? manifestType : configType, 'docker-content-digest': sha(body) }, body };
  };
  return { transport, calls, digest: sha(manifest), configDigest: sha(config) };
}

// Real loopback HTTP, cookie auth, controllers, SQLite and OCI byte validation.
// Readiness and repository-scoped OCI transport are controlled fixtures; no live registry/Trivy claim.
async function publicHttpProof(persist: boolean) {
  const directory = mkdtempSync(join(tmpdir(), 'public-api-'));
  const origin = 'http://127.0.0.1:8081';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false', SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_VULN_ENABLED: 'true', SCAN_VULN_RELEASE_DIR: '' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  const app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
  const browser = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  let ready = true, source = fixture(), inspections = 0;
  try {
    const service = app.get(ScansService);
    assert.ok(service instanceof PublicImageScansService);
    Object.defineProperty(service, 'readiness', { value: async () => ready });
    Object.defineProperty(service, 'inspect', { value: async (ref: ImageReference) => { inspections++; return inspectPublicImage(ref, source.transport); } });
    // The same service hook is used by production discovery, without claiming search is inspection.
    Object.defineProperty(app.get(BrowserScansController), 'imageSearch', { value: new ImageSearchSessions(async () => ({ results: [{ repo_name: 'example/app' }], count: 1, next: null }), undefined, item => service.imageSuggestion(item)) });
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (name: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email: `${name}@example.com`, password: 'disposable-public-1234' }) });
      assert.equal(response.status, 201);
      return { cookie: response.headers.get('set-cookie')!.split(';')[0], id: (await response.json() as { id: string }).id };
    };
    const owner = await register('owner'), other = await register('other');
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = owner.id;
    const path = `${base}/browser/scans`;
    const body = { imageReference: 'registry-1.docker.io/example/app:stable', checks: ['secret', 'sbom'], scope: 'image', idempotencyKey: 'public-http-001' };
    const post = (value: unknown = body, cookie = owner.cookie, requestOrigin = origin, suffix = '') => fetch(path + suffix, { method: 'POST', headers: { cookie, origin: requestOrigin, 'content-type': 'application/json' }, body: JSON.stringify(value) });
    assert.equal((await fetch(path)).status, 401);
    assert.equal((await post(body, other.cookie)).status, 403);
    assert.equal((await post(body, owner.cookie, 'http://foreign.example')).status, 403);
    assert.equal((await fetch(`${base}/scans`, { headers: { cookie: owner.cookie } })).status, 401);
    const discovery = await fetch(`${path}/images?q=example&generation=gen`, { headers: { cookie: owner.cookie } });
    const suggestion = (await discovery.json() as { items: { eligibility: string; scannable: boolean; reason: string }[] }).items[0];
    assert.equal(suggestion.eligibility, 'public-hub-profile'); assert.equal(suggestion.scannable, false); assert.equal(inspections, 0);
    const preflight = await post({ imageReference: body.imageReference, checks: body.checks }, owner.cookie, origin, '/images/eligibility');
    assert.equal(preflight.status, 200); assert.equal(preflight.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await preflight.json(), { imageReference: body.imageReference, eligible: true, eligibility: 'public-hub-profile', allowedCheckSets: Array.from({ length: 15 }, (_, mask) => ['secret', 'sbom', 'vuln', 'config'].filter((_, bit) => (mask + 1) & (1 << bit))), reason: 'READY' });
    const created = await post(); assert.equal(created.status, 202);
    const receipt = await created.json() as { scanId: string };
    const ledger = app.get(LedgerStore).ledger!;
    const get = (suffix = '', cookie = owner.cookie) => fetch(`${path}/${receipt.scanId}${suffix}`, { headers: { cookie } });
    const queued = browser.parseCurrentStatus(await (await get()).json());
    assert.equal(queued.imageReference, `registry-1.docker.io/example/app@${source.digest}`); assert.equal(queued.profile, PUBLIC_IMAGE_PROFILE);
    assert.equal(queued.platform, 'linux/amd64');
    const before = inspections; ready = false;
    assert.equal((await post()).status, 202); assert.equal(inspections, before);
    assert.equal((await post({ ...body, checks: ['config'] })).status, 409);
    ready = true;
    const job = ledger.claim()!; assert.equal(job.repository, 'example/app'); assert.equal(job.executionProfile, undefined);
    if (persist) {
    // Synthetic normalized persisted outcome, not scanner output or live acquisition.
    const components = REPORT_ECOSYSTEMS.map(ecosystem => ({ ecosystem, name: ecosystem === 'maven' ? 'org.example:lib' : ecosystem === 'gomod' ? 'example.com/lib' : ecosystem === 'composer' ? 'example/lib' : 'package', version: '1' }));
    assert.equal(ledger.finishArchive(job.scanId, job.attempts, {
      receipt: { registry: job.registry, repository: job.repository, digest: source.digest, configDigest: source.configDigest, platform: 'linux/amd64',
        layerDigests: [`sha256:${'b'.repeat(64)}`], diffIds: [`sha256:${'c'.repeat(64)}`], archiveSha256: `sha256:${'d'.repeat(64)}`,
        profileVersion: PUBLIC_IMAGE_PROFILE, resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION },
      scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 2, compressedBytes: 10, expandedBytes: 1024, entries: 1, archiveBytes: 2048, reservationPeak: 2048, scratchPeak: 2048 },
      secret: { outcome: 'checked', findings: [] }, sbom: { outcome: 'checked', sbom: { image: queued.imageReference!, platform: 'linux/amd64', os: { name: 'debian', version: '12' }, components } },
    }, undefined, job.leaseToken), true);
    const completed = browser.parseCurrentStatus(await (await get()).json()); assert.equal(completed.state, 'completed');
    assert.equal(browser.parseCurrentResults(await (await get('/results')).json()).coverage[0].findingCount, 0);
    assert.equal(browser.parseCurrentSbom(await (await get('/sbom')).json()).components.length, REPORT_ECOSYSTEMS.length);
    const query = { view: 'report-v1', ecosystem: 'maven', name: 'org.example:', sort: 'ecosystem:desc', limit: 5 };
    const page = browser.parseCurrentSbom(await (await get('/sbom?view=report-v1&ecosystem=maven&name=org.example%3A&sort=ecosystem:desc&limit=5')).json(), query);
    assert.equal(page.components.length, 1); assert.equal(page.components[0].ecosystem, 'maven');
    }
    assert.equal((await get('', other.cookie)).status, 403); // unlisted user is stopped before owner read
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = `${owner.id},${other.id}`;
    assert.equal((await get('', other.cookie)).status, 404); assert.equal((await get('/sbom', other.cookie)).status, 404);
    for (const imageReference of ['docker.io/library/node:22', 'registry-1.docker.io/node:22', 'registry-1.docker.io/library/node', 'registry-1.docker.io/team/nested/app:tag', 'ghcr.io/team/app:tag']) {
      assert.equal((await post({ ...body, imageReference, idempotencyKey: 'invalid-http' })).status, 400);
    }
    assert.equal((await post({ ...body, public: true } as typeof body)).status, 400);
    assert.equal((await post({ ...body, platform: 'linux/arm64' } as typeof body)).status, 400);
    source = fixture('arm64');
    assert.equal((await post({ ...body, idempotencyKey: 'wrong-platform' })).status, 503);
    source = fixture('amd64', PUBLIC_IMAGE_LIMITS.compressedLayer + 1);
    assert.equal((await post({ ...body, idempotencyKey: 'too-large-layer' })).status, 503);
    source = fixture(); ready = false;
    const count = inspections;
    assert.equal((await post({ ...body, idempotencyKey: 'worker-offline' })).status, 503); assert.equal(inspections, count);
    ready = true;
    // Ordinary official DockerHub path uses the same inspector, not legacy Alpine resolution.
    assert.equal((await post({ ...body, imageReference: 'registry-1.docker.io/library/node:22', checks: ['config'], idempotencyKey: 'official-config' })).status, 202);
    assert.equal((await post({ ...body, checks: ['vuln'], idempotencyKey: 'db-not-verified' })).status, 503);
    assert.ok(source.calls.every(call => call.startsWith('/v2/library/node/')));
    assert.equal(ledger.pending().length, persist ? 1 : 2);
  } finally {
    await app.close(); Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
}

test('public module HTTP admission: canonical official/namespaced inspection, auth, resource/DB/readiness guards and replay', () => publicHttpProof(false));
test('public module HTTP persisted reports: normalized Debian/all-ecosystem archive → strict status/results/SBOM/report-v1', () => publicHttpProof(true));
