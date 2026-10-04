import test from 'node:test';
import assert from 'node:assert/strict';
import { NGINX_ARCHIVE_TARGET, NGINX_SUPPORTED_CANDIDATE, type ArchiveReceipt } from './bounded-image-archive.js';
import { validateArchiveJson, validateArchiveSbom } from './archive-identity.js';
export const receipt: ArchiveReceipt = { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`],
  diffIds: [`sha256:${'b'.repeat(64)}`], archiveSha256: `sha256:${'c'.repeat(64)}`,
  profileVersion: 'nginx-alpine-amd64-v1', resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
const archivePath = '/tmp/trivy/jobs/00000000-0000-0000-0000-000000000000/image.tar';
const binding = { receipt, archivePath };
const report = () => ({ SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: archivePath,
  Metadata: { ImageID: receipt.configDigest, DiffIDs: receipt.diffIds, ImageConfig: { os: 'linux', architecture: 'amd64',
    rootfs: { type: 'layers', diff_ids: receipt.diffIds } } } });
test('actual archive schema uses config/diffIds receipt, never synthetic remote RepoDigests', () => {
  const value = report(); assert.equal(validateArchiveJson(value, binding), value);
  assert.equal(Object.hasOwn(value.Metadata, 'RepoDigests'), false);
  for (const bad of [ { ...value, ArtifactName: 'remote-image' }, { ...value, Metadata: { ...value.Metadata, RepoDigests: [] } },
    { ...value, Metadata: { ...value.Metadata, ImageID: `sha256:${'d'.repeat(64)}` } },
    { ...value, Metadata: { ...value.Metadata, DiffIDs: [] } } ]) assert.throws(() => validateArchiveJson(bad, binding));
  assert.throws(() => validateArchiveJson(value, { ...binding, receipt: { ...receipt, configDigest: `sha256:${'d'.repeat(64)}` as typeof receipt.configDigest } }));
});
test('second exact candidate cannot mix config/digest/profile identity or become arbitrary repository admission', () => {
  const next: ArchiveReceipt = { ...receipt, ...NGINX_SUPPORTED_CANDIDATE, profileVersion: 'nginx-alpine-amd64-v2-candidate' };
  const base = report(); const value = { ...base, Metadata: { ...base.Metadata, ImageID: next.configDigest } };
  assert.equal(validateArchiveJson(value, { receipt: next, archivePath }), value);
  for (const bad of [{ ...next, configDigest: receipt.configDigest }, { ...next, digest: receipt.digest },
    { ...next, profileVersion: receipt.profileVersion }, { ...next, repository: 'library/node' }]) {
    assert.throws(() => validateArchiveJson(value, { receipt: bad as ArchiveReceipt, archivePath }));
  }
});
test('actual CycloneDX archive properties require one exact config ID and ordered diffIds', () => {
  const value = { bomFormat: 'CycloneDX', specVersion: '1.6', metadata: { component: { type: 'container', name: archivePath,
    properties: [{ name: 'aquasecurity:trivy:ImageID', value: receipt.configDigest },
      { name: 'aquasecurity:trivy:DiffID', value: receipt.diffIds[0] }] } } };
  assert.equal(validateArchiveSbom(value, binding), value);
  value.metadata.component.properties.push(value.metadata.component.properties[0]);
  assert.throws(() => validateArchiveSbom(value, binding));
  value.metadata.component.properties.pop(); value.metadata.component.properties[1].value = 'wrong';
  assert.throws(() => validateArchiveSbom(value, binding));
});
