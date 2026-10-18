import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectPublicImage, publicImageInspectionFetch } from './public-image-inspection.js';
import { PUBLIC_IMAGE_LIMITS as L } from './public-image-policy.js';
import { fixture, media, sha } from './public-image.test-fixtures.js';
import { ResolutionRejected, type ManifestFetch } from './registry-resolver.js';

const layer = (size: number) => ({ digest: `sha256:${'a'.repeat(64)}`, size, mediaType: media.layer });
test('generic namespaced Hub images resolve to frozen child/config/layer identities, not fake nginx', async () => {
  for (const repository of ['example-team/namespaced-image', 'library/node', 'org/sub/image_1.2', 'org/blobs', 'blobs/image']) {
    const source = fixture({ repository });
    const result = await inspectPublicImage(source.reference, source.fetch);
    assert.deepEqual({ ...result, layers: undefined }, { ...source.target, layers: undefined });
    assert.equal(result.layers[0].digest, sha(source.compressed));
    assert.ok(Object.isFrozen(result) && Object.isFrozen(result.layers) && Object.isFrozen(result.layers[0]));
    assert.equal(source.calls.length, 3);
    const direct = { ...source.reference, selector: result.digest,
      canonical: `${result.registry}/${repository}@${result.digest}` };
    assert.equal((await inspectPublicImage(direct, source.fetch)).digest, result.digest);
  }
});

test('inspection snapshots canonical input before awaiting metadata', async () => {
  const source = fixture();
  const reference = { ...source.reference };
  const pending = inspectPublicImage(reference, async (host, path) => {
    reference.repository = 'changed/repository'; reference.selector = 'moved';
    return source.fetch(host, path);
  });
  assert.equal((await pending).repository, source.target.repository);
});

test('reference/canonical/registry validation happens before any request', async () => {
  const source = fixture();
  for (const reference of [null, { ...source.reference, registry: 'evil.example' },
    { ...source.reference, repository: 'org/../image' }, { ...source.reference, selector: 'other-tag' },
    { ...source.reference, canonical: 'https://registry-1.docker.io/team/image' },
    { ...source.reference, repository: 'a'.repeat(256) }, { ...source.reference, selector: 'sha256:bad' }]) {
    await assert.rejects(inspectPublicImage(reference as typeof source.reference, source.fetch), ResolutionRejected);
  }
  assert.equal(source.calls.length, 0);
});

test('public layer count/compressed layer/aggregate limits accept N, reject N+1 before config fetch', async () => {
  for (const layers of [[layer(L.compressedLayer)], Array.from({ length: L.maxLayers }, () => layer(1)),
    Array.from({ length: 4 }, () => layer(L.compressedLayer))]) {
    const source = fixture({ layers });
    await inspectPublicImage(source.reference, source.fetch);
  }
  for (const layers of [[], [layer(L.compressedLayer + 1)], Array.from({ length: L.maxLayers + 1 }, () => layer(1)),
    [...Array.from({ length: 4 }, () => layer(L.compressedLayer)), layer(1)], [layer(0)], [layer(-1)], [layer(1.5)],
    [{ ...layer(1), mediaType: 'application/vnd.oci.image.layer.v1.tar+zstd' }],
    [{ ...layer(1), mediaType: 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip' }],
    [{ ...layer(1), urls: ['https://evil.example/blob'] }], [{ ...layer(1), data: 'inline' }],
    [{ ...layer(1), digest: 'sha256:BAD' }], [null]]) {
    const source = fixture({ layers });
    await assert.rejects(inspectPublicImage(source.reference, source.fetch), ResolutionRejected);
    assert.ok(source.calls.length <= 2);
  }
});

test('config/platform/rootfs and index/manifest descriptors fail closed', async () => {
  for (const options of [
    { config: { os: 'windows' } }, { config: { architecture: 'arm64' } }, { config: { variant: '' } },
    { config: { rootfs: null } }, { config: { rootfs: { type: 'layers', diff_ids: [] } } },
    { config: { rootfs: { type: 'layers', diff_ids: ['sha256:bad'] } } },
    { duplicate: true }, { child: { size: 1 } }, { child: { urls: ['https://evil.example'] } },
    { child: { platform: { os: 'linux', architecture: 'amd64', variant: 'v1' } } },
    { image: { mediaType: media.index } }, { image: { schemaVersion: 1 } },
    { image: { artifactType: 'application/example' } }, { image: { subject: {} } },
    { image: { config: { ...layer(1), mediaType: media.layer } } }, { image: { layers: null } },
  ]) {
    const source = fixture(options);
    await assert.rejects(inspectPublicImage(source.reference, source.fetch), ResolutionRejected);
  }
});

test('immutable manifest hash, child hash, config hash/header and UTF-8 cannot drift', async () => {
  for (const stage of ['child', 'config', 'header', 'utf8']) {
    const source = fixture();
    const tampered: ManifestFetch = async (host, path) => {
      const response = await source.fetch(host, path);
      if (stage === 'header') return { ...response, headers: { ...response.headers, 'docker-content-digest': 'sha256:bad' } };
      if (stage === 'utf8') return { ...response, body: Buffer.from([0xff]) };
      if (stage === 'config' && path.includes('/blobs/') || stage === 'child' && !path.endsWith('/stable')) {
        const body = Buffer.from(response.body); body[0] = 32;
        return { ...response, body, headers: { ...response.headers, 'docker-content-digest': sha(body) } };
      }
      return response;
    };
    await assert.rejects(inspectPublicImage(source.reference, tampered), ResolutionRejected);
  }
  const source = fixture();
  const digest = `sha256:${'f'.repeat(64)}`;
  await assert.rejects(inspectPublicImage({ ...source.reference, selector: digest,
    canonical: `${source.reference.registry}/${source.reference.repository}@${digest}` }, source.fetch), ResolutionRejected);
});

test('metadata object/config N/N+1 byte limits are independent from larger layer ceilings', async () => {
  for (const option of ['configBytes', 'imageBytes', 'indexBytes'] as const) {
    const limit = option === 'configBytes' ? L.maxConfigBytes : L.maxObjectBytes;
    const at = fixture({ [option]: limit });
    await inspectPublicImage(at.reference, at.fetch);
    const over = fixture({ [option]: limit + 1 });
    await assert.rejects(inspectPublicImage(over.reference, over.fetch), ResolutionRejected);
  }
});

test('inspection transport counts scoped auth, redirects and strips cross-origin credentials', async () => {
  const repository = 'team/custom-image';
  const seen: Array<{ host: string; auth?: string; maximum?: number }> = [];
  const fetch = publicImageInspectionFetch(repository, async (_gateway, url, headers, maximum) => {
    seen.push({ host: url.hostname, auth: headers.authorization, maximum });
    if (url.hostname === 'auth.docker.io') {
      assert.equal(url.searchParams.get('scope'), `repository:${repository}:pull`);
      return { status: 200, headers: {}, body: Buffer.from('{"token":"fixture-token"}') };
    }
    if (url.hostname === 'production.cloudfront.docker.com') return { status: 200, headers: {}, body: Buffer.alloc(0) };
    if (!headers.authorization) return { status: 401, headers: { 'www-authenticate':
      `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:${repository}:pull"` }, body: Buffer.alloc(0) };
    return { status: 302, headers: { location: 'https://production.cloudfront.docker.com/blob' }, body: Buffer.alloc(0) };
  });
  const path = `/v2/${repository}/blobs/sha256:${'a'.repeat(64)}`;
  await fetch('registry-1.docker.io', path);
  assert.deepEqual(seen.map(item => [item.host, item.auth]), [
    ['registry-1.docker.io', undefined], ['auth.docker.io', undefined],
    ['registry-1.docker.io', 'Bearer fixture-token'], ['production.cloudfront.docker.com', undefined],
  ]);
  assert.equal(seen[1].maximum, 32_768);
  for (let i = 0; i < 4; i++) await fetch('registry-1.docker.io', path);
  assert.equal(seen.length, L.inspectionRequests);
  await assert.rejects(fetch('registry-1.docker.io', path), ResolutionRejected);
  assert.equal(seen.length, L.inspectionRequests);
});

test('repository components named blobs never turn manifest redirects into blob redirects', async () => {
  let calls = 0;
  const fetch = publicImageInspectionFetch('org/blobs/image', async () => {
    calls++;
    return { status: 302, headers: { location: 'https://production.cloudfront.docker.com/manifest' }, body: Buffer.alloc(0) };
  });
  await assert.rejects(fetch('registry-1.docker.io', '/v2/org/blobs/image/manifests/stable'), ResolutionRejected);
  assert.equal(calls, 1);
});

test('inspection transport refuses foreign auth/redirects, N+1 wire, timeouts, and stays failed', async () => {
  for (const response of [
    { status: 401, headers: { 'www-authenticate': 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:other/image:pull"' } },
    { status: 302, headers: { location: 'https://evil.example/blob' } },
    { status: 302, headers: { location: 'https://production.cloudfront.docker.com:444/blob' } },
  ]) {
    let calls = 0;
    const fetch = publicImageInspectionFetch('team/image', async () => { calls++; return { ...response, body: Buffer.alloc(0) }; });
    await assert.rejects(fetch('registry-1.docker.io', '/v2/team/image/blobs/sha256:abc'), ResolutionRejected);
    assert.equal(calls, 1);
  }
  let calls = 0;
  const over = publicImageInspectionFetch('team/image', async (_gateway, _url, _headers, max) => {
    calls++; return { status: 200, headers: {}, body: Buffer.alloc(max! + 1) };
  });
  await assert.rejects(over('registry-1.docker.io', '/v2/team/image/manifests/stable'), ResolutionRejected);
  await assert.rejects(over('registry-1.docker.io', '/v2/team/image/manifests/stable'), ResolutionRejected);
  assert.equal(calls, 1);
  const aggregate = publicImageInspectionFetch('team/image', async () => ({ status: 200, headers: {}, body: Buffer.alloc(L.maxObjectBytes) }));
  for (let i = 0; i < L.inspectionWireBytes / L.maxObjectBytes; i++) await aggregate('registry-1.docker.io', '/v2/team/image/manifests/stable');
  await assert.rejects(aggregate('registry-1.docker.io', '/v2/team/image/manifests/stable'), ResolutionRejected);
  let now = 0;
  const timed = publicImageInspectionFetch('team/image', async () => {
    now = L.inspectionDeadlineMs; return { status: 200, headers: {}, body: Buffer.alloc(0) };
  }, () => now);
  await assert.rejects(timed('registry-1.docker.io', '/v2/team/image/manifests/stable'), ResolutionRejected);
  await assert.rejects(inspectPublicImage(fixture().reference, async () => { throw new Error('secret-canary'); }),
    (error: unknown) => error instanceof ResolutionRejected && !error.message.includes('secret-canary'));
});
