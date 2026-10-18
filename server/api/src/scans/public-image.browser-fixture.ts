import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from '../oci/public-image.module.js';
import { inspectPublicImage } from '../oci/public-image-inspection.js';
import { createPinnedConfigLoader } from '../oci/pinned-image-config.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION } from '../oci/public-image-policy.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import type { ArchiveScanReport, scanPublicImageArchive } from '../worker/archive-scan-worker.js';
import { ScansService } from './scans.service.js';
import { PublicImageScansService } from './public-image-scans.service.js';
import type { ImageReference } from './image-reference.js';

const sha = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}` as const;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const configType = 'application/vnd.oci.image.config.v1+json';
const repository = 'browser-proof/application';
export const browserFixtureReference = `registry-1.docker.io/${repository}:controlled`;
const canary = 'PUBLIC_BROWSER_CANARY_NEVER_PUBLISH';

/** Disposable proof adapter only; never imported by an application module or worker entrypoint. */
export async function startPublicImageBrowserFixture(accounts: { password: string; ownerEmail: string; otherEmail: string }) {
  assert.equal(process.env.NODE_ENV, 'test');
  const directory = process.env.PUBLIC_IMAGE_PROOF_DIR;
  assert.ok(directory && isAbsolute(directory));
  for (const [key, file] of [['AUTH_DB_PATH', 'auth.sqlite'], ['SCAN_LEDGER_PATH', 'ledger.sqlite']]) {
    assert.equal(process.env[key], join(directory, file));
    assert.equal(existsSync(join(directory, file)), false, 'Proof requires new disposable databases');
  }
  const config = encode({ os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: [sha(encode('controlled diff ID'))] },
    config: { User: '1000', Env: [`FIXTURE_ONLY=${canary}`], Labels: { fixture: canary } }, history: [{ created_by: canary }] });
  // No layer/archive bytes are acquired: the public archive runner below is an
  // explicit normalized-outcome fixture, not a gzip/tar or Trivy qualification.
  const layerDigest = sha(encode('controlled layer descriptor only'));
  const manifest = encode({ schemaVersion: 2, mediaType: manifestType,
    config: { mediaType: configType, digest: sha(config), size: config.length },
    layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: layerDigest, size: 64 }] });
  const digest = sha(manifest), configDigest = sha(config);
  const image = `registry-1.docker.io/${repository}@${digest}`;
  const target = { registry: 'registry-1.docker.io', repository, digest, configDigest, platform: 'linux/amd64' };
  let inspections = 0, configLoads = 0, workerInvocations = 0;
  const checkpoints: string[] = [];
  const response = (path: string) => {
    if (path === `/v2/${repository}/manifests/controlled` || path === `/v2/${repository}/manifests/${digest}` ||
        path === `/v2/${repository}/manifests/${encodeURIComponent(digest)}`) {
      return { status: 200, headers: { 'content-type': manifestType, 'docker-content-digest': digest }, body: manifest };
    }
    assert.ok(path === `/v2/${repository}/blobs/${configDigest}` || path === `/v2/${repository}/blobs/${encodeURIComponent(configDigest)}`);
    return { status: 200, headers: { 'content-type': configType, 'docker-content-digest': configDigest }, body: config };
  };
  const app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
  configurePublicImageIngress(app);
  const sockets = new Set<import('node:net').Socket>();
  app.getHttpServer().on('connection', (socket: import('node:net').Socket) => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  });
  const close = async () => { for (const socket of sockets) socket.destroy(); await app.close(); };
  try {
    const service = app.get(ScansService);
    assert.ok(service instanceof PublicImageScansService);
    Object.defineProperty(service, 'readiness', { value: async () => true });
    Object.defineProperty(service, 'inspect', { value: async (ref: ImageReference) => {
      assert.equal(ref.canonical, browserFixtureReference);
      inspections++;
      return inspectPublicImage(ref, async (host, path) => { assert.equal(host, target.registry); return response(path); });
    } });
    await app.listen(0, '127.0.0.1');
    const apiOrigin = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
    const register = async (email: string) => {
      const reply = await fetch(`${apiOrigin}/api/v1/auth/register`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000),
        headers: { origin: process.env.AUTH_ORIGIN!, 'content-type': 'application/json' }, body: JSON.stringify({ email, password: accounts.password }) });
      assert.equal(reply.status, 201);
      return reply.json() as Promise<{ id: string }>;
    };
    const owner = await register(accounts.ownerEmail), other = await register(accounts.otherEmail);
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = `${owner.id},${other.id}`;
    const ledger = app.get(LedgerStore).ledger!;
    const legacyDigest = sha(encode('controlled legacy Alpine edge identity'));
    const legacyId = ledger.enqueue({ registry: target.registry, repository: 'library/alpine', digest: legacyDigest, platform: target.platform,
      subject: owner.id, idempotencyKey: 'browser-legacy-edge', checks: '["sbom"]', scope: 'image' }).scanId;
    const legacyJob = ledger.claim()!;
    assert.equal(legacyJob.scanId, legacyId);
    assert.equal(ledger.finishWithSbom(legacyId, legacyJob.attempts, { image: `${target.registry}/library/alpine@${legacyDigest}`, platform: 'linux/amd64',
      os: { name: 'alpine', version: 'edge' }, components: [{ ecosystem: 'apk', name: 'busybox', version: '1.37.0-r0' }] }, '0.69.3', legacyJob.leaseToken), true);
    const components = [
      { ecosystem: 'deb' as const, name: 'libc6', version: '2.36-9+deb12u1' },
      { ecosystem: 'deb' as const, name: 'openssl', version: '3.0.16-1' },
      { ecosystem: 'npm' as const, name: '@proof/widget', version: '1.2.3' },
      { ecosystem: 'npm' as const, name: 'proof-tool', version: '2.0.0' },
    ];
    const configLoader = createPinnedConfigLoader(async (_gateway, url) => {
      configLoads++;
      assert.equal(url.hostname, target.registry);
      return response(url.pathname);
    }, true);
    const publicRunner: typeof scanPublicImageArchive = async (checks, options) => {
      workerInvocations++;
      assert.deepEqual(checks, ['secret', 'sbom']);
      assert.deepEqual(options.target, { registry: target.registry, repository, digest, platform: target.platform });
      const report: ArchiveScanReport = { receipt: { ...target, layerDigests: [layerDigest], diffIds: [sha(encode('controlled diff ID'))],
        archiveSha256: sha(encode('controlled archive receipt only')), profileVersion: PUBLIC_IMAGE_PROFILE,
        resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION },
        scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 64,
          expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
        secret: { outcome: 'checked', findings: [{ findingId: 'secret-1-1', ruleId: `rule-${'6'.repeat(16)}`, line: 0, evidenceRef: 'result-1-secret-1' }] },
        sbom: { outcome: 'checked', sbom: { image, platform: 'linux/amd64', os: { name: 'debian', version: '12' }, components } } };
      const header = { receipt: report.receipt, scannerVersion: report.scannerVersion, checkedAt: report.checkedAt, metrics: report.metrics };
      assert.equal(options.onCheckpoint?.('secret', { ...header, secret: report.secret }), true);
      checkpoints.push('secret');
      assert.equal(options.onCheckpoint?.('sbom', { ...header, sbom: report.sbom }), true);
      checkpoints.push('sbom');
      return report;
    };
    const neverScan = async (): Promise<never> => { throw new Error('Unexpected native or legacy scanner invocation'); };
    return {
      ready: { apiOrigin, reference: browserFixtureReference, image, digest, platform: target.platform, profile: PUBLIC_IMAGE_PROFILE,
        legacyId, componentNames: components.map(component => component.name) },
      async consume(scanId: string) {
        assert.equal(workerInvocations, 0);
        assert.deepEqual(ledger.pending().map(job => job.scanId), [scanId]);
        assert.equal(ledger.pinnedTarget(scanId, owner.id)?.digest, digest);
        assert.equal(ledger.pinnedTarget(scanId, other.id), undefined);
        const signal = AbortSignal.timeout(15_000);
        assert.equal(await consumeOne(ledger, { timeoutMs: 1000, dbDir: join(directory, 'unused-db'), publicImagePolicy: true, configLoader, signal },
          neverScan, Date.now(), neverScan, neverScan, neverScan, publicRunner), true);
        const status = service.status({ subject: owner.id, scope: ['scan:create'] }, scanId);
        assert.equal(status.state, 'completed'); assert.equal(status.config?.config.outcome, 'checked');
        assert.equal(JSON.stringify(status).includes(canary), false);
        assert.equal(ledger.pending().length, 0);
        return { workerInvocations, configLoads, inspections, checkpoints: [...checkpoints], state: status.state };
      },
      close,
    };
  } catch (error) { await close(); throw error; }
}
