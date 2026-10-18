import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BadRequestException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { PUBLIC_IMAGE_LIMITS } from '../oci/public-image-policy.js';
import { PublicImageScansService, type PublicImageInspection, type PublicImageInspector } from './public-image-scans.service.js';
import { ScansService } from './scans.service.js';
import { PRODUCTION_DB_TRUST_ANCHOR, localDbTrustAnchorFromEnv } from '../worker/vuln-db-trust.js';

const identity = { subject: 'alice', scope: ['scan:create'] };
const request = { imageReference: 'registry-1.docker.io/example/app:stable', scope: 'image', checks: ['secret'], idempotencyKey: 'public-unit-test' };
const target: PublicImageInspection = { registry: 'registry-1.docker.io', repository: 'example/app', digest: `sha256:${'a'.repeat(64)}`,
  configDigest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64', layers: [{ digest: `sha256:${'c'.repeat(64)}`, size: 100, mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' }] };
function setup(inspect: PublicImageInspector = async () => target) {
  const directory = mkdtempSync(join(tmpdir(), 'public-service-'));
  const ledger = new ScanLedger(join(directory, 'db.sqlite'));
  const store = { ledger } as LedgerStore;
  const resolver = { resolvePublicAlpine() { assert.fail('Public service must use inspection, not Alpine resolution'); } } as unknown as OciResolver;
  class Ready extends PublicImageScansService {
    ready = true;
    protected override async readiness() { return this.ready; }
    getAnchor() { return this.dbTrustAnchor(); }
  }
  const service = new Ready(store, resolver, inspect);
  return { ledger, store, resolver, service, close() { ledger.close(); rmSync(directory, { recursive: true, force: true }); } };
}

test('public adapters cannot enqueue foreign identities, absent config digests or out-of-budget inventories', async () => {
  const layer = target.layers[0];
  for (const invalid of [
    { ...target, registry: 'ghcr.io' }, { ...target, repository: 'other/app' }, { ...target, digest: 'not-a-digest' },
    { ...target, configDigest: '' }, { ...target, platform: 'linux/arm64' }, { ...target, layers: [] },
    { ...target, layers: Array.from({ length: PUBLIC_IMAGE_LIMITS.maxLayers + 1 }, () => layer) },
    { ...target, layers: [{ ...layer, size: PUBLIC_IMAGE_LIMITS.compressedLayer + 1 }] },
    { ...target, layers: Array.from({ length: 5 }, () => ({ ...layer, size: PUBLIC_IMAGE_LIMITS.compressedLayer })) },
    { ...target, layers: [{ ...layer, mediaType: 'application/vnd.oci.image.layer.v1.tar+zstd' }] },
  ]) {
    const f = setup(async () => invalid as PublicImageInspection);
    try { await assert.rejects(f.service.create(identity, request), ServiceUnavailableException); assert.equal(f.ledger.pending().length, 0); }
    finally { f.close(); }
  }
});

test('public readiness is checked again after inspection, and eligibility is not a create reservation', async () => {
  const f = setup(async () => { f.service.ready = false; return target; });
  try {
    await assert.rejects(f.service.create(identity, request), ServiceUnavailableException);
    assert.equal(f.ledger.pending().length, 0);
    f.service.ready = true;
    const eligibility = await f.service.eligibility(identity, { imageReference: request.imageReference, checks: ['secret'] });
    assert.equal(eligibility.eligible, false); assert.equal(f.ledger.pending().length, 0);
  } finally { f.close(); }
});

test('public profile inherits scope/ledger/replay fences; no generic user flag or default-service admission', async () => {
  let inspections = 0;
  const f = setup(async () => { inspections++; return target; });
  try {
    await assert.rejects(f.service.create({ subject: 'alice', scope: [] }, request), ForbiddenException);
    for (const body of [{ ...request, public: true }, { ...request, scope: 'host' }, { ...request, platform: 'linux/arm64' },
      { ...request, imageReference: 'registry-1.docker.io/example/app' }, { ...request, imageReference: 'registry-1.docker.io/example/nested/app:tag' }]) {
      await assert.rejects(f.service.create(identity, body), BadRequestException);
    }
    assert.equal(inspections, 0);
    const receipt = await f.service.create(identity, request);
    f.service.ready = false;
    assert.deepEqual(await f.service.create(identity, request), receipt); assert.equal(inspections, 1);
    assert.equal(f.service.status(identity, receipt.scanId).imageReference, `registry-1.docker.io/example/app@${target.digest}`);
    const legacy = new ScansService(f.store, f.resolver);
    await assert.rejects(legacy.create(identity, request), BadRequestException); // policy before even committed replay
    assert.equal(f.ledger.pending().length, 1);
    assert.equal(f.ledger.claim()?.executionProfile, undefined);
    assert.deepEqual(f.service.getAnchor(), PRODUCTION_DB_TRUST_ANCHOR);
    assert.equal(localDbTrustAnchorFromEnv({ LOCAL_CVE_TRUST_SHA256: 'f'.repeat(64) }).publicKeyPath, '/opt/local-db-trust/public.pem');
    assert.throws(() => localDbTrustAnchorFromEnv({ LOCAL_CVE_TRUST_SHA256: 'not-a-fingerprint' }));
  } finally { f.close(); }
});

test('authenticated DB guard is retained for public CVE; historical boolean true cannot authorize', async () => {
  const previous = process.env.SCAN_VULN_ENABLED;
  process.env.SCAN_VULN_ENABLED = 'true';
  let inspections = 0;
  const f = setup(async () => { inspections++; return target; });
  Object.defineProperty(f.service, 'vulnDbReady', { value: async () => true });
  try {
    const checks = ['vuln'];
    assert.equal((await f.service.eligibility(identity, { imageReference: request.imageReference, checks })).eligible, false);
    await assert.rejects(f.service.create(identity, { ...request, checks }), ServiceUnavailableException);
    assert.equal(inspections, 0); assert.equal(f.ledger.pending().length, 0);
  } finally { f.close(); if (previous === undefined) delete process.env.SCAN_VULN_ENABLED; else process.env.SCAN_VULN_ENABLED = previous; }
});
