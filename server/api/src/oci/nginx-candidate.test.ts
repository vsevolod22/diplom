import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { inspectNginxCandidate, nginxCandidateFetch, NGINX_CANDIDATE_LIMITS, NGINX_PROFILE } from './nginx-candidate.js';
import { ResolutionRejected, type ManifestFetch } from './registry-resolver.js';
import { parseImageReference } from '../scans/image-reference.js';

const sha = (body: Buffer) => `sha256:${createHash('sha256').update(body).digest('hex')}`;
const media = { index: 'application/vnd.oci.image.index.v1+json', image: 'application/vnd.oci.image.manifest.v1+json',
  config: 'application/vnd.oci.image.config.v1+json', layer: 'application/vnd.oci.image.layer.v1.tar+gzip' };
const ref = parseImageReference('registry-1.docker.io/library/nginx:1.26.3-alpine', new Set(['registry-1.docker.io']));
function fixture(options: { layers?: unknown; os?: string; architecture?: string; duplicate?: boolean; badSize?: boolean;
  tamperConfig?: boolean; invalidUtf8?: boolean; configBytes?: number; imageBytes?: number; indexBytes?: number } = {}) {
  const sized = (data: unknown, bytes?: number) => {
    const text = JSON.stringify(data);
    return Buffer.from(text.padEnd(bytes ?? text.length, ' '));
  };
  const config = sized({ os: options.os ?? 'linux', architecture: options.architecture ?? 'amd64' }, options.configBytes);
  const image = sized({ schemaVersion: 2,
    config: { digest: sha(config), size: config.length, mediaType: media.config },
    layers: Object.hasOwn(options, 'layers') ? options.layers : [{ digest: `sha256:${'a'.repeat(64)}`, size: 1024, mediaType: media.layer }] }, options.imageBytes);
  const child = { digest: sha(image), size: image.length + (options.badSize ? 1 : 0), mediaType: media.image,
    platform: { os: 'linux', architecture: 'amd64' } };
  const index = sized({ schemaVersion: 2, manifests: options.duplicate ? [child, child] : [child] }, options.indexBytes);
  let calls = 0;
  const fetch: ManifestFetch = async (_host, path) => {
    calls++;
    const blob = path.includes('/blobs/');
    const body = blob ? options.tamperConfig ? Buffer.from('{}') : config : path.endsWith('/1.26.3-alpine') ? index : image;
    return { status: 200, headers: { 'content-type': blob ? media.config : path.endsWith('/1.26.3-alpine') ? media.index : media.image,
      'docker-content-digest': sha(body) }, body: options.invalidUtf8 ? Buffer.from([0xff]) : body };
  };
  return { fetch, config, image, calls: () => calls };
}

test('candidate inspection binds child/config/platform but never grants admission or claims Alpine', async () => {
  const source = fixture();
  const result = await inspectNginxCandidate(ref, source.fetch);
  assert.equal(result.digest, sha(source.image));
  assert.equal(result.configDigest, sha(source.config));
  assert.equal(result.platform, 'linux/amd64');
  assert.equal(result.repository, 'library/nginx');
  assert.equal(result.compressedBytes, 1024);
  assert.equal(result.layers.length, 1);
  assert.equal(source.calls(), 3);
  assert.equal(NGINX_PROFILE.enabled, false);
  assert.deepEqual(NGINX_PROFILE.qualifiedTargets, []);
  assert.equal(result.qualification, 'unqualified');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.layers[0]));
});

test('fixed repository rejects foreign targets before any fetch', async () => {
  for (const repository of ['library/alpine', 'library/node', 'team/nginx']) {
    const source = fixture();
    const other = parseImageReference(`registry-1.docker.io/${repository}:latest`, new Set(['registry-1.docker.io']));
    await assert.rejects(inspectNginxCandidate(other, source.fetch), ResolutionRejected);
    assert.equal(source.calls(), 0);
  }
});

test('layer count and compressed bytes enforce N/N+1, reject unknown compression and missing inventory', async () => {
  const layer = (size: number) => ({ digest: `sha256:${'a'.repeat(64)}`, size, mediaType: media.layer });
  const limits = NGINX_CANDIDATE_LIMITS;
  for (const layers of [
    [layer(limits.maxLayerCompressedBytes)],
    Array.from({ length: limits.maxLayers }, () => layer(1)),
    Array.from({ length: limits.maxCompressedBytes / limits.maxLayerCompressedBytes }, () => layer(limits.maxLayerCompressedBytes)),
  ]) await inspectNginxCandidate(ref, fixture({ layers }).fetch);
  for (const layers of [undefined, [], [layer(limits.maxLayerCompressedBytes + 1)],
    Array.from({ length: limits.maxLayers + 1 }, () => layer(1)),
    [layer(limits.maxLayerCompressedBytes), layer(limits.maxLayerCompressedBytes), layer(limits.maxLayerCompressedBytes), layer(1)],
    [{ ...layer(1), mediaType: 'application/vnd.oci.image.layer.v1.tar+zstd' }],
    [layer(-1)], [layer(1.5)], [{ ...layer(1), urls: ['https://evil.example/layer'] }],
    [{ ...layer(1), digest: 'sha256:bad' }],
  ]) {
    const source = fixture({ layers: layers === undefined ? null : layers });
    await assert.rejects(inspectNginxCandidate(ref, source.fetch), ResolutionRejected);
    assert.ok(source.calls() <= 2, 'reject descriptors before fetching config or layers');
  }
});

test('reject ambiguous child, descriptor size, config platform/hash and malformed encoding', async () => {
  for (const options of [{ duplicate: true }, { badSize: true }, { os: 'windows' }, { architecture: 'arm64' },
    { tamperConfig: true }, { invalidUtf8: true }]) {
    await assert.rejects(inspectNginxCandidate(ref, fixture(options).fetch), ResolutionRejected);
  }
});

test('transport budgets include scoped auth retry, redirects, aggregate bytes, deadlines and sticky failure', async () => {
  const path = '/v2/library/nginx/manifests/1.26.3-alpine';
  let clock = 0;
  let calls = 0;
  const maxes: number[] = [];
  const auth = nginxCandidateFetch(async (_gateway, url, headers, max, deadline) => {
    calls++;
    maxes.push(max!);
    assert.equal(deadline, 30_000);
    if (url.hostname === 'auth.docker.io') {
      assert.equal(headers.authorization, undefined);
      assert.equal(url.searchParams.get('scope'), 'repository:library/nginx:pull');
      return { status: 200, headers: {}, body: Buffer.from('{"token":"fixture-token"}') };
    }
    if (!headers.authorization) return { status: 401, headers: { 'www-authenticate':
      'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"' }, body: Buffer.alloc(0) };
    return { status: 200, headers: {}, body: Buffer.alloc(0) };
  }, () => clock);
  await auth('registry-1.docker.io', path);
  assert.equal(calls, 3);
  assert.deepEqual(maxes, [4_000_000, 32_768, 4_000_000]);
  clock = 30_000;
  await assert.rejects(auth('registry-1.docker.io', path), ResolutionRejected);
  assert.equal(calls, 3);

  calls = 0;
  const counted = nginxCandidateFetch(async () => { calls++; return { status: 200, headers: {}, body: Buffer.alloc(0) }; });
  for (let i = 0; i < 12; i++) await counted('registry-1.docker.io', path);
  await assert.rejects(counted('registry-1.docker.io', path), ResolutionRejected);
  assert.equal(calls, 12);
  const aggregate = nginxCandidateFetch(async () => ({ status: 200, headers: {}, body: Buffer.alloc(4_000_000) }));
  for (let i = 0; i < 4; i++) await aggregate('registry-1.docker.io', path);
  await assert.rejects(aggregate('registry-1.docker.io', path), ResolutionRejected);
  let failures = 0;
  const oversized = nginxCandidateFetch(async (_gateway, _url, _headers, max) => {
    failures++; return { status: 200, headers: {}, body: Buffer.alloc(max! + 1) };
  });
  await assert.rejects(oversized('registry-1.docker.io', path), ResolutionRejected);
  await assert.rejects(oversized('registry-1.docker.io', path), ResolutionRejected);
  assert.equal(failures, 1);
});

test('candidate CDN redirects strip token and foreign scopes never fetch token', async () => {
  const seen: Array<{ host: string; auth: string | undefined }> = [];
  const fetch = nginxCandidateFetch(async (_gateway, url, headers) => {
    seen.push({ host: url.hostname, auth: headers.authorization });
    if (url.hostname === 'auth.docker.io') {
      assert.equal(url.searchParams.get('scope'), 'repository:library/nginx:pull');
      return { status: 200, headers: {}, body: Buffer.from('{"token":"fixture-token"}') };
    }
    if (url.hostname === 'production.cloudfront.docker.com') return { status: 200, headers: {}, body: Buffer.alloc(0) };
    if (!headers.authorization) return { status: 401, headers: { 'www-authenticate':
      'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"' }, body: Buffer.alloc(0) };
    return { status: 302, headers: { location: 'https://production.cloudfront.docker.com/blob' }, body: Buffer.alloc(0) };
  });
  const path = `/v2/library/nginx/blobs/sha256:${'a'.repeat(64)}`;
  await fetch('registry-1.docker.io', path);
  assert.deepEqual(seen, [
    { host: 'registry-1.docker.io', auth: undefined },
    { host: 'auth.docker.io', auth: undefined },
    { host: 'registry-1.docker.io', auth: 'Bearer fixture-token' },
    { host: 'production.cloudfront.docker.com', auth: undefined },
  ]);
  for (let i = 0; i < 4; i++) await fetch('registry-1.docker.io', path);
  assert.equal(seen.length, 12, 'auth, registry retries and CDN redirects share the request budget');
  await assert.rejects(fetch('registry-1.docker.io', path), ResolutionRejected);
  assert.equal(seen.length, 12);
  let calls = 0;
  const foreign = nginxCandidateFetch(async () => {
    calls++; return { status: 401, headers: { 'www-authenticate':
      'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/node:pull"' }, body: Buffer.alloc(0) };
  });
  await assert.rejects(foreign('registry-1.docker.io', '/v2/library/nginx/manifests/latest'), ResolutionRejected);
  assert.equal(calls, 1);
});

test('valid JSON object/config N boundaries pass; N+1 rejects; immutable direct child works', async () => {
  for (const option of ['imageBytes', 'indexBytes', 'configBytes'] as const) {
    const maximum = option === 'configBytes' ? NGINX_CANDIDATE_LIMITS.maxConfigBytes : NGINX_CANDIDATE_LIMITS.maxObjectBytes;
    await inspectNginxCandidate(ref, fixture({ [option]: maximum }).fetch);
    await assert.rejects(inspectNginxCandidate(ref, fixture({ [option]: maximum + 1 }).fetch), ResolutionRejected);
  }
  const source = fixture();
  const direct = parseImageReference(`registry-1.docker.io/library/nginx@${sha(source.image)}`, new Set(['registry-1.docker.io']));
  assert.equal((await inspectNginxCandidate(direct, source.fetch)).digest, sha(source.image));
  assert.equal(source.calls(), 2);
});

test('object byte boundary enforced before parsing and transport errors remain safe', async () => {
  for (const size of [NGINX_CANDIDATE_LIMITS.maxObjectBytes, NGINX_CANDIDATE_LIMITS.maxObjectBytes + 1]) {
    const fetch: ManifestFetch = async () => ({ status: 200, headers: {}, body: Buffer.alloc(size) });
    await assert.rejects(inspectNginxCandidate(ref, fetch), ResolutionRejected);
  }
  await assert.rejects(inspectNginxCandidate(ref, async () => { throw new Error('secret-canary'); }),
    (error: unknown) => error instanceof ResolutionRejected && !error.message.includes('secret-canary'));
});
