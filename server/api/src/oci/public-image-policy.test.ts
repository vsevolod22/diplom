import assert from 'node:assert/strict';
import test from 'node:test';
import { ArchiveAttemptBudget } from './archive-budget.js';
import { archiveLimits, ARCHIVE_LIMITS, ArchiveRejected } from './layer-tar-validator.js';
import { NGINX_ARCHIVE_TARGET, type ArchiveReceipt } from './bounded-image-archive.js';
import { validArchiveBinding, validateArchiveJson, validateArchiveSbom } from './archive-identity.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION,
  PUBLIC_IMAGE_LIMITS as L, validPublicTarget, isPublicReceipt } from './public-image-policy.js';
import { fixture, sha } from './public-image.test-fixtures.js';

const source = fixture();
const receipt: ArchiveReceipt = { ...source.target, layerDigests: [sha(source.compressed)], diffIds: [sha(source.bytes)],
  archiveSha256: sha(Buffer.from('fixture archive')), profileVersion: PUBLIC_IMAGE_PROFILE,
  resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION };
const archivePath = '/tmp/trivy/jobs/00000000-0000-4000-8000-000000000000/image.tar';

test('public target/receipt validation is structural, strict and never a raw public flag', () => {
  assert.equal(validPublicTarget(source.target), true);
  assert.equal(validPublicTarget({ ...source.target, configDigest: undefined }), true);
  assert.equal(isPublicReceipt(receipt), true);
  for (const bad of [null, true, 'public', {}, { public: true }, { ...receipt, public: true },
    { ...receipt, registry: 'docker.io' }, { ...receipt, registry: 'evil.example' }, { ...receipt, repository: '../image' },
    { ...receipt, repository: 'team/Image' }, { ...receipt, repository: 'a'.repeat(256) },
    { ...receipt, platform: 'linux/arm64' }, { ...receipt, digest: 'sha256:bad' }, { ...receipt, configDigest: undefined },
    { ...receipt, archiveSha256: 'sha256:bad' }, { ...receipt, profileVersion: 'nginx-alpine-amd64-v1' },
    { ...receipt, checksVersion: 'trivy-0.69.3-archive-v1' }, { ...receipt, resourcePolicyVersion: 'nginx-archive-resources-v1' },
    { ...receipt, diffIds: [] }, { ...receipt, diffIds: [123] }, { ...receipt, layerDigests: undefined },
    { ...receipt, diffIds: new Array(1) }, { ...receipt, layerDigests: new Array(1) },
    { ...receipt, diffIds: [receipt.diffIds[0], receipt.diffIds[0]] },
    { ...receipt, diffIds: Array(L.maxLayers + 1).fill(receipt.diffIds[0]), layerDigests: Array(L.maxLayers + 1).fill(receipt.layerDigests[0]) },
  ]) {
    assert.equal(isPublicReceipt(bad), false);
    assert.equal(validArchiveBinding({ receipt: bad as ArchiveReceipt, archivePath }), false);
  }
  const maximum = { ...receipt, diffIds: Array(L.maxLayers).fill(receipt.diffIds[0]),
    layerDigests: Array(L.maxLayers).fill(receipt.layerDigests[0]) };
  assert.equal(isPublicReceipt(maximum), true);
  for (const path of ['/tmp/elsewhere/image.tar', `${archivePath}/../image.tar`, 'image.tar']) {
    assert.equal(validArchiveBinding({ receipt, archivePath: path }), false);
  }
  assert.equal(validArchiveBinding(null as never), false);
});

test('public archive JSON and CycloneDX bind config, platform and ordered/multiplicity-aware diffIDs', () => {
  const binding = { receipt, archivePath };
  const value = { SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: archivePath,
    Metadata: { ImageID: receipt.configDigest, DiffIDs: receipt.diffIds,
      ImageConfig: { os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: receipt.diffIds } } } };
  assert.equal(validateArchiveJson(value, binding), value);
  for (const bad of [
    { ...value, ArtifactName: 'registry-1.docker.io/example-team/namespaced-image:stable' },
    { ...value, Metadata: { ...value.Metadata, ImageID: sha(Buffer.from('wrong')) } },
    { ...value, Metadata: { ...value.Metadata, RepoDigests: [] } },
    { ...value, Metadata: { ...value.Metadata, DiffIDs: [] } },
    { ...value, Metadata: { ...value.Metadata, DiffIDs: new Array(receipt.diffIds.length) } },
    { ...value, Metadata: { ...value.Metadata, ImageConfig: { ...value.Metadata.ImageConfig, architecture: 'arm64' } } },
  ]) assert.throws(() => validateArchiveJson(bad, binding), ArchiveRejected);
  const sbom = { bomFormat: 'CycloneDX', specVersion: '1.6', metadata: { component: { type: 'container', name: archivePath,
    properties: [{ name: 'aquasecurity:trivy:ImageID', value: receipt.configDigest },
      { name: 'aquasecurity:trivy:DiffID', value: receipt.diffIds[0] }] } } };
  assert.equal(validateArchiveSbom(sbom, binding), sbom);
  sbom.metadata.component.properties.push(sbom.metadata.component.properties[1]);
  assert.throws(() => validateArchiveSbom(sbom, binding), ArchiveRejected);
  sbom.metadata.component.properties.pop(); sbom.metadata.component.properties[0].value = receipt.digest;
  assert.throws(() => validateArchiveSbom(sbom, binding), ArchiveRejected);
  const other = sha(Buffer.from('other layer'));
  const ordered = { ...receipt, diffIds: [receipt.diffIds[0], other], layerDigests: [receipt.layerDigests[0], other] };
  const reversed = { ...value, Metadata: { ...value.Metadata, DiffIDs: [...ordered.diffIds].reverse(),
    ImageConfig: { ...value.Metadata.ImageConfig, rootfs: { type: 'layers', diff_ids: ordered.diffIds } } } };
  assert.throws(() => validateArchiveJson(reversed, { receipt: ordered, archivePath }), ArchiveRejected);
});

test('legacy exact-nginx receipt acceptance is unchanged; mixed identities/policies still reject', () => {
  const legacy = { ...receipt, ...NGINX_ARCHIVE_TARGET, profileVersion: 'nginx-alpine-amd64-v1',
    checksVersion: 'trivy-0.69.3-archive-v1', resourcePolicyVersion: 'nginx-archive-resources-v1' };
  assert.equal(validArchiveBinding({ receipt: legacy, archivePath }), true);
  for (const bad of [{ ...legacy, repository: receipt.repository }, { ...legacy, digest: receipt.digest },
    { ...legacy, profileVersion: PUBLIC_IMAGE_PROFILE }, { ...legacy, resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY },
    { ...legacy, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION }]) assert.equal(validArchiveBinding({ receipt: bad, archivePath }), false);
});

test('only frozen internal resource profiles select limits; legacy defaults remain identical', () => {
  assert.ok(Object.isFrozen(L)); assert.ok(Object.isFrozen(ARCHIVE_LIMITS));
  assert.equal(archiveLimits(), ARCHIVE_LIMITS); assert.equal(archiveLimits(PUBLIC_IMAGE_PROFILE), L);
  assert.throws(() => archiveLimits({ ...L, expandedLayer: Infinity } as never), ArchiveRejected);
  assert.throws(() => new ArchiveAttemptBudget(undefined, true as never), ArchiveRejected);
  assert.equal(ARCHIVE_LIMITS.compressedLayer, 32 * 1024 ** 2);
  assert.equal(ARCHIVE_LIMITS.scratchBytes, 448 * 1024 ** 2);
  const legacy = new ArchiveAttemptBudget(); legacy.wire(ARCHIVE_LIMITS.wireBytes);
  assert.throws(() => legacy.wire(1), ArchiveRejected);
  for (const [method, limit] of [['wire', L.wireBytes], ['layer', L.compressedTotal], ['reserve', L.scratchBytes]] as const) {
    const budget = new ArchiveAttemptBudget(undefined, PUBLIC_IMAGE_PROFILE);
    budget[method](limit); assert.throws(() => budget[method](1), ArchiveRejected);
    assert.throws(() => budget.request(), ArchiveRejected);
  }
  const scratch = new ArchiveAttemptBudget(undefined, PUBLIC_IMAGE_PROFILE);
  scratch.reserve(L.scratchBytes); scratch.release(L.scratchBytes); scratch.reserve(L.scratchBytes);
  assert.equal(scratch.reservationPeak, L.scratchBytes);
  const requests = new ArchiveAttemptBudget(undefined, PUBLIC_IMAGE_PROFILE);
  for (let i = 0; i < L.requests; i++) requests.request();
  assert.throws(() => requests.request(), ArchiveRejected);
  let now = 10;
  const deadline = new ArchiveAttemptBudget(() => now, PUBLIC_IMAGE_PROFILE);
  now += L.deadlineMs - 1; assert.equal(deadline.remaining(), 1);
  now++; assert.throws(() => deadline.request(), ArchiveRejected);
});
