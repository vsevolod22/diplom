import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { prepareBoundedImageArchive } from './bounded-image-archive.js';
import { inspectPublicImage } from './public-image-inspection.js';
import { validatePublicConfigDescriptor } from './public-image-config-data.js';
import { PUBLIC_IMAGE_LIMITS as L, PUBLIC_IMAGE_PROFILE, isPublicReceipt } from './public-image-policy.js';
import { ResolutionRejected, type ManifestFetch } from './registry-resolver.js';
import { fixture, media, sha } from './public-image.test-fixtures.js';

function inlineFixture(options: { data?: unknown; descriptor?: Record<string, unknown>; configBytes?: number;
  config?: Record<string, unknown> } = {}) {
  const settings = { configBytes: options.configBytes ?? 453, config: options.config };
  const base = fixture(settings);
  const descriptor = { digest: sha(base.config), size: base.config.length, mediaType: media.config,
    data: Object.hasOwn(options, 'data') ? options.data : base.config.toString('base64'), ...options.descriptor };
  return fixture({ ...settings, image: { config: descriptor } });
}

test('config helper returns only frozen bounded evidence and does not mutate or relabel input', () => {
  const source = inlineFixture();
  const descriptor = JSON.parse(source.image.toString()).config;
  const before = sha(Buffer.from(JSON.stringify(descriptor)));
  const evidence = validatePublicConfigDescriptor(descriptor);
  assert.deepEqual(evidence, { digest: source.target.configDigest, size: source.config.length, mediaType: media.config,
    embedded: { digest: source.target.configDigest, size: source.config.length } });
  assert.ok(Object.isFrozen(evidence) && Object.isFrozen(evidence.embedded));
  assert.equal(sha(Buffer.from(JSON.stringify(descriptor))), before);
  assert.equal(Object.hasOwn(evidence, 'data'), false);
  assert.equal(Object.hasOwn(evidence, 'config'), false);
});

test('ordinary Docker config descriptors without embedded data remain supported', async () => {
  const base = fixture();
  const source = fixture({ image: { config: { digest: sha(base.config), size: base.config.length,
    mediaType: 'application/vnd.docker.container.image.v1+json' } } });
  assert.equal((await inspectPublicImage(source.reference, source.fetch)).configDigest, source.target.configDigest);
});

test('canonical embedded OCI config is accepted but still fetched and bound to the immutable child', async () => {
  for (const configBytes of [453, 454, 455, L.maxConfigBytes]) {
    const source = inlineFixture({ configBytes });
    const result = await inspectPublicImage(source.reference, source.fetch);
    assert.equal(result.digest, source.target.digest);
    assert.equal(result.configDigest, source.target.configDigest);
    assert.equal(source.calls.length, 3);
    assert.equal(source.calls.filter(path => path.includes(`/v2/${source.target.repository}/blobs/`)).length, 1);
    assert.deepEqual(Object.keys(result).sort(), ['configDigest', 'digest', 'layers', 'platform', 'registry', 'repository']);
  }
});

test('embedded config never bypasses a missing, different, incorrectly labelled or platform-invalid gateway blob', async () => {
  for (const mode of ['unavailable', 'different', 'mediaType'] as const) {
    const source = inlineFixture();
    let blobs = 0;
    const fetch: ManifestFetch = async (host, path) => {
      const response = await source.fetch(host, path);
      if (!path.includes(`/v2/${source.target.repository}/blobs/`)) return response;
      blobs++;
      if (mode === 'unavailable') return { status: 404, headers: {}, body: Buffer.alloc(0) };
      if (mode === 'mediaType') return { ...response, headers: { ...response.headers, 'content-type': 'text/plain' } };
      const body = Buffer.from(response.body); body[body.length - 1] = 10;
      return { ...response, body, headers: { ...response.headers, 'docker-content-digest': sha(body) } };
    };
    await assert.rejects(inspectPublicImage(source.reference, fetch), ResolutionRejected);
    assert.equal(blobs, 1, 'valid inline config must not fail before the mandatory blob fetch');
  }
  for (const config of [{ os: 'windows' }, { architecture: 'arm64' }, { rootfs: { type: 'layers', diff_ids: [] } }]) {
    const source = inlineFixture({ config });
    await assert.rejects(inspectPublicImage(source.reference, source.fetch), ResolutionRejected);
    assert.equal(source.calls.length, 3);
  }
});

test('inline config rejects malformed, noncanonical, oversized and descriptor-inconsistent base64 before blob fetch', async () => {
  const base = fixture({ configBytes: 454 });
  const canonical = base.config.toString('base64');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const position = canonical.length - 3;
  const alias = canonical.slice(0, position) + alphabet[alphabet.indexOf(canonical[position]) + 1] + canonical.slice(position + 1);
  const badData: unknown[] = [null, 1, {}, '', canonical + '\n', canonical.slice(0, -1),
    canonical + '=', canonical.replace(/=/g, ''), '-' + canonical.slice(1),
    canonical.slice(0, 10) + '=' + canonical.slice(11), alias, 'A'.repeat(canonical.length),
    'A'.repeat(4 * Math.ceil(L.maxConfigBytes / 3) + 4)];
  for (const data of badData) {
    const source = inlineFixture({ configBytes: 454, data });
    await assert.rejects(inspectPublicImage(source.reference, source.fetch), ResolutionRejected);
    assert.equal(source.calls.length, 2);
  }
  for (const descriptor of [{ size: 452 }, { size: L.maxConfigBytes + 1 },
    { digest: `sha256:${'a'.repeat(64)}` }, { mediaType: 'application/vnd.docker.container.image.v1+json' },
    { urls: ['https://evil.example/config'] }]) {
    const source = inlineFixture({ descriptor });
    await assert.rejects(inspectPublicImage(source.reference, source.fetch), ResolutionRejected);
    assert.equal(source.calls.length, 2);
  }
  const oversized = inlineFixture({ configBytes: L.maxConfigBytes + 1 });
  await assert.rejects(inspectPublicImage(oversized.reference, oversized.fetch), ResolutionRejected);
  assert.equal(oversized.calls.length, 2);
});

test('embedded data remains forbidden on index child and layer descriptors', async () => {
  const source = inlineFixture();
  const child = fixture({ child: { data: source.image.toString('base64') } });
  await assert.rejects(inspectPublicImage(child.reference, child.fetch), ResolutionRejected);
  assert.equal(child.calls.length, 1);
  const layer = fixture({ layers: [{ digest: sha(source.compressed), size: source.compressed.length,
    mediaType: media.layer, data: source.compressed.toString('base64') }] });
  await assert.rejects(inspectPublicImage(layer.reference, layer.fetch), ResolutionRejected);
  assert.equal(layer.calls.length, 2);
});

test('public acquisition revalidates inline config without adding raw data to receipt or inspection evidence', async () => {
  const root = await mkdtemp(`${tmpdir()}/dip-public-inline-config-`);
  try {
    const source = inlineFixture();
    const result = await prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, source.request, root);
    try {
      assert.equal(isPublicReceipt(result.receipt), true);
      assert.equal(result.receipt.digest, source.target.digest);
      assert.equal(result.receipt.configDigest, source.target.configDigest);
      assert.equal(result.metrics.requests, 3);
      assert.deepEqual(Object.keys(result.receipt).sort(), ['archiveSha256', 'checksVersion', 'configDigest', 'diffIds',
        'digest', 'layerDigests', 'platform', 'profileVersion', 'registry', 'repository', 'resourcePolicyVersion']);
    } finally { await result.cleanup(); }
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});
