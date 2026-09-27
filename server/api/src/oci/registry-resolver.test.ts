import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { proxyManifestFetch, resolveManifest, ResolutionRejected, type ManifestFetch } from './registry-resolver.js';
import { parseImageReference } from '../scans/image-reference.js';

const sha = (data: Buffer) => `sha256:${createHash('sha256').update(data).digest('hex')}`;
const media = {
  index: 'application/vnd.oci.image.index.v1+json',
  image: 'application/vnd.oci.image.manifest.v1+json',
  config: 'application/vnd.oci.image.config.v1+json',
};
const config = Buffer.from(JSON.stringify({ os: 'linux', architecture: 'amd64' }));
const image = Buffer.from(JSON.stringify({ schemaVersion: 2, config: { digest: sha(config), size: config.length, mediaType: media.config } }));
const index = Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [{ digest: sha(image), mediaType: media.image,
  platform: { os: 'linux', architecture: 'amd64' } }] }));
const ref = parseImageReference('registry.example.com/team/image:mutable', new Set(['registry.example.com']));
function fixture(changes: { redirect?: 'manifest' | 'blob'; wrongDigest?: boolean; index?: Buffer;
  config?: Buffer; image?: Buffer; blobStatus?: number } = {}): ManifestFetch {
  return async (host, path) => {
    assert.equal(host, ref.registry);
    const first = path.endsWith('/mutable');
    const blob = path.includes('/blobs/');
    const body = blob ? changes.config || config : first ? changes.index || index : changes.image || image;
    return { status: changes.blobStatus && blob ? changes.blobStatus : changes.redirect === (blob ? 'blob' : 'manifest') ? 302 : 200,
      body, headers: { 'docker-content-digest': changes.wrongDigest ? `sha256:${'0'.repeat(64)}` : sha(body),
        'content-type': blob ? media.config : first ? media.index : media.image } };
  };
}
test('index pins child digest and verifies config platform; direct digest also verifies config', async () => {
  const pinned = { registry: ref.registry, repository: ref.repository, digest: sha(image), platform: 'linux/amd64' };
  assert.deepEqual(await resolveManifest(ref, 'linux/amd64', fixture()), pinned);
  const direct = parseImageReference(`registry.example.com/team/image@${sha(image)}`, new Set(['registry.example.com']));
  assert.deepEqual(await resolveManifest(direct, 'linux/amd64', fixture()), pinned);
  await assert.rejects(resolveManifest(ref, 'linux/arm64', fixture()), ResolutionRejected);
  await assert.rejects(resolveManifest(ref, 'linux/amd64', fixture({ wrongDigest: true })), ResolutionRejected);
});
test('transport rejects metadata/private/unauthorized hosts and encoded traversal before CONNECT', async () => {
  const allowed = new Set(['registry.example.com']);
  for (const [host, path] of [
    ['169.254.169.254', '/v2/team/image/manifests/latest'],
    ['127.0.0.1', '/v2/team/image/manifests/latest'],
    ['evil.example.com', '/v2/team/image/manifests/latest'],
    ['registry.example.com', '/v2/team/image/manifests/../../token'],
    ['registry.example.com', '/v2/team/image/manifests/latest?secret=1'],
  ]) await assert.rejects(proxyManifestFetch('127.0.0.1', 1, host, path, allowed), ResolutionRejected);
  await assert.rejects(proxyManifestFetch('127.0.0.1', 1, 'registry.example.com',
    '/v2/team/image/manifests/latest', new Set()), ResolutionRejected);
});
test('never accept mismatched child, config digest/size/platform or redirects', async () => {
  for (const variant of [
    { redirect: 'manifest' as const }, { redirect: 'blob' as const }, { blobStatus: 401 },
    { config: Buffer.from(JSON.stringify({ os: 'linux', architecture: 'arm64' })) },
    { config: Buffer.from(JSON.stringify({ os: 'linux', architecture: 'amd64', variant: 'v8' })) },
    { image: Buffer.from(JSON.stringify({ schemaVersion: 2, config: { digest: sha(config), size: 999, mediaType: media.config } })) },
    { index: Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [{ digest: `sha256:${'f'.repeat(64)}`,
      mediaType: media.image, platform: { os: 'linux', architecture: 'amd64' } }] })) },
  ]) await assert.rejects(resolveManifest(ref, 'linux/amd64', fixture(variant)), ResolutionRejected);
});
