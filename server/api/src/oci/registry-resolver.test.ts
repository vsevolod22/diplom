import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { resolveManifest, ResolutionRejected, type ManifestFetch } from './registry-resolver.js';
import { parseImageReference } from '../scans/image-reference.js';
const sha = (data: Buffer) => `sha256:${createHash('sha256').update(data).digest('hex')}`;
const image = Buffer.from('{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}');
const index = Buffer.from(JSON.stringify({ manifests: [{ digest: sha(image), platform: { os: 'linux', architecture: 'amd64' } }] }));
const ref = parseImageReference('registry.example.com/team/image:mutable', new Set(['registry.example.com']));
function fixture(changes: { redirect?: boolean; wrongDigest?: boolean; index?: Buffer } = {}): ManifestFetch {
  return async (_host, path) => {
    const first = path.endsWith('/mutable');
    const body = first ? changes.index || index : image;
    return { status: changes.redirect && !first ? 302 : 200, body,
      headers: { 'docker-content-digest': changes.wrongDigest ? `sha256:${'0'.repeat(64)}` : sha(body),
        'content-type': first ? 'application/vnd.oci.image.index.v1+json' : 'application/vnd.oci.image.manifest.v1+json' } };
  };
}
test('index pins child manifest digest and exact platform, not mutable tag', async () => {
  assert.deepEqual(await resolveManifest(ref, 'linux/amd64', fixture()), {
    registry: ref.registry, repository: ref.repository, digest: sha(image), platform: 'linux/amd64',
  });
  await assert.rejects(resolveManifest(ref, 'linux/arm64', fixture()), ResolutionRejected);
  await assert.rejects(resolveManifest(ref, 'linux/amd64', fixture({ wrongDigest: true })), ResolutionRejected);
  await assert.rejects(resolveManifest(ref, 'linux/amd64', fixture({ redirect: true })), ResolutionRejected);
  const direct = parseImageReference(`registry.example.com/team/image@${sha(image)}`, new Set(['registry.example.com']));
  await assert.rejects(resolveManifest(direct, 'linux/amd64', async () => ({ status: 200, body: image,
    headers: { 'docker-content-digest': sha(image), 'content-type': 'application/vnd.oci.image.manifest.v1+json' } })), ResolutionRejected);
});
