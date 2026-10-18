import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { prepareBoundedImageArchive, prepareNginxArchive } from './bounded-image-archive.js';
import { preparePublicImageArchive } from './public-image-archive.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_LIMITS as L, isPublicReceipt } from './public-image-policy.js';
import { ArchiveRejected } from './layer-tar-validator.js';
import { fixture, sha, tar } from './public-image.test-fixtures.js';
import type { gatewayGet } from './gateway-transport.js';

async function scratch(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(`${tmpdir()}/dip-public-acquire-`);
  try { await run(root); } finally { await rm(root, { recursive: true, force: true }); }
}
function members(bytes: Buffer) {
  const result = new Map<string, Buffer>();
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) break;
    const name = header.subarray(0, header.indexOf(0)).toString();
    const size = Number.parseInt(header.subarray(124, 136).toString().replace(/\0/g, '').trim(), 8);
    result.set(name, bytes.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return result;
}

test('public acquisition streams real generic identity into Docker-save tar; no tag or nginx substitution', async () => {
  await scratch(async root => {
    const source = fixture();
    const input = { ...source.target };
    const result = await prepareBoundedImageArchive(undefined, input, PUBLIC_IMAGE_PROFILE, source.request, root);
    try {
      assert.equal(isPublicReceipt(result.receipt), true);
      assert.equal(result.receipt.repository, 'example-team/namespaced-image');
      assert.equal(result.receipt.digest, source.target.digest);
      assert.equal(result.receipt.configDigest, source.target.configDigest);
      assert.deepEqual(result.receipt.layerDigests, [sha(source.compressed)]);
      assert.deepEqual(result.receipt.diffIds, [sha(source.bytes)]);
      assert.ok(Object.isFrozen(result.receipt) && Object.isFrozen(result.receipt.diffIds));
      assert.ok(source.calls.every(call => !call.includes('/manifests/stable')));
      const bytes = await readFile(result.archivePath);
      assert.equal(sha(bytes), result.receipt.archiveSha256);
      assert.equal((await stat(result.archivePath)).mode & 0o777, 0o400);
      const archive = members(bytes);
      const configName = `${source.target.configDigest.slice(7)}.json`;
      assert.deepEqual(archive.get(configName), source.config);
      assert.deepEqual(archive.get('0/layer.tar'), source.bytes);
      assert.deepEqual(JSON.parse(archive.get('manifest.json')!.toString()), [{ Config: configName, RepoTags: [], Layers: ['0/layer.tar'] }]);
      assert.deepEqual(await readdir(result.directory), ['image.tar']);
      assert.equal(result.metrics.expandedBytes, source.bytes.length);
      assert.equal(result.metrics.compressedBytes, source.compressed.length);
      assert.equal(result.metrics.archiveBytes, bytes.length);
      assert.equal(result.metrics.requests, 3);
      assert.equal(result.metrics.wireBytes, source.image.length + source.config.length + source.compressed.length);
      assert.ok(result.metrics.reservationPeak <= L.scratchBytes);
    } finally { await result.cleanup(); await result.cleanup(); }
    assert.deepEqual(await readdir(root), []);
  });
});

test('acquisition auth retries/CDN redirects stay scoped, counted and streamed without forwarding credentials', async () => {
  await scratch(async root => {
    const source = fixture();
    const seen: Array<{ host: string; auth?: string }> = [];
    const request: typeof gatewayGet = async (_gateway, url, headers, maximum, _deadline, sink) => {
      seen.push({ host: url.hostname, auth: headers.authorization });
      let response;
      if (url.hostname === 'auth.docker.io') {
        assert.equal(url.searchParams.get('scope'), `repository:${source.target.repository}:pull`);
        response = { status: 200, headers: {}, body: Buffer.from('{"token":"fixture-token"}') };
      } else if (url.hostname === 'production.cloudfront.docker.com') {
        response = { status: 200, headers: { 'content-type': 'application/octet-stream' },
          body: url.pathname === '/config' ? source.config : source.compressed };
      } else if (!headers.authorization) {
        response = { status: 401, headers: { 'www-authenticate':
          `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:${source.target.repository}:pull"` }, body: Buffer.from('auth') };
      } else if (url.pathname.includes('/blobs/')) {
        const kind = decodeURIComponent(url.pathname).endsWith(source.target.configDigest) ? 'config' : 'layer';
        response = { status: 302, headers: { location: `https://production.cloudfront.docker.com/${kind}` }, body: Buffer.alloc(0) };
      } else response = await source.fetch(url.hostname, url.pathname);
      assert.ok(response.body.length <= maximum!);
      if (!sink) return response;
      await sink(response.body, response.status);
      return { ...response, body: Buffer.alloc(0) };
    };
    const result = await prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, request, root);
    try {
      assert.equal(result.metrics.requests, 7);
      assert.equal(seen.filter(item => item.host === 'production.cloudfront.docker.com').length, 2);
      assert.ok(seen.filter(item => item.host !== 'registry-1.docker.io').every(item => item.auth === undefined));
      assert.equal(isPublicReceipt(result.receipt), true);
    } finally { await result.cleanup(); }
  });
});

test('optional config pin is resolved, but supplied mismatch and immutable digest/tag drift reject and clean', async () => {
  await scratch(async root => {
    const source = fixture();
    const result = await prepareBoundedImageArchive(undefined, { ...source.target, configDigest: undefined },
      PUBLIC_IMAGE_PROFILE, source.request, root);
    assert.equal(result.receipt.configDigest, source.target.configDigest);
    await result.cleanup();
    for (const target of [{ ...source.target, configDigest: sha(Buffer.from('wrong config')) },
      { ...source.target, digest: sha(Buffer.from('wrong manifest')) }]) {
      await assert.rejects(prepareBoundedImageArchive(undefined, target, PUBLIC_IMAGE_PROFILE, source.request, root), ArchiveRejected);
      assert.deepEqual(await readdir(root), []);
    }
    // Simulate registry/tag content changing after inspection: immutable queued hash
    // must reject even when the transport reports the new content's honest hash.
    const replacement = fixture({ config: { architecture: 'arm64' } });
    await assert.rejects(prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, replacement.request, root), ArchiveRejected);
    assert.deepEqual(await readdir(root), []);
  });
});

test('every stage rejects malformed config/platform, compressed hash/size, gzip, tar and diffID and removes its attempt', async () => {
  await scratch(async root => {
    const good = fixture();
    const corruptCrc = Buffer.from(good.compressed); corruptCrc[corruptCrc.length - 8] ^= 1;
    for (const source of [
      fixture({ config: { architecture: 'arm64' } }), fixture({ config: { rootfs: { type: 'layers', diff_ids: [sha(Buffer.from('wrong diffID'))] } } }),
      fixture({ compressed: corruptCrc }), fixture({ compressed: Buffer.concat([good.compressed, good.compressed]) }),
      fixture({ compressed: Buffer.concat([good.compressed, Buffer.from('junk')]) }),
      fixture({ compressed: good.compressed.subarray(0, -1) }), fixture({ bytes: tar('../escape') }),
      fixture({ bytes: tar('/absolute') }), fixture({ bytes: tar('device', Buffer.alloc(0), '3') }),
      fixture({ bytes: tar('link', Buffer.alloc(0), '1', '../escape') }),
    ]) {
      await assert.rejects(prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, source.request, root), ArchiveRejected);
      assert.deepEqual(await readdir(root), []);
    }
    for (const mode of ['hash', 'short', 'oversize', 'config'] as const) {
      const request: typeof gatewayGet = async (gateway, url, headers, max, deadline, sink, signal) => {
        if (url.pathname.includes('/blobs/') && (mode === 'config' || decodeURIComponent(url.pathname).endsWith(sha(good.compressed)))) {
          let bytes = mode === 'config' ? Buffer.from('{}') : Buffer.from(good.compressed);
          if (mode === 'hash') bytes[20] ^= 1;
          if (mode === 'short') bytes = bytes.subarray(0, -1);
          if (mode === 'oversize') bytes = Buffer.concat([bytes, Buffer.from([0])]);
          await sink!(bytes, 200);
          return { status: 200, headers: { 'content-type': 'application/octet-stream' }, body: Buffer.alloc(0) };
        }
        return good.request(gateway, url, headers, max, deadline, sink, signal);
      };
      await assert.rejects(prepareBoundedImageArchive(undefined, good.target, PUBLIC_IMAGE_PROFILE, request, root), ArchiveRejected);
      assert.deepEqual(await readdir(root), []);
    }
  });
});

test('cancellation, transport errors and bounded non-200 bodies fail closed and clean only their own attempt', async () => {
  await scratch(async root => {
    const source = fixture();
    const controller = new AbortController();
    let calls = 0;
    const cancelled: typeof gatewayGet = async (gateway, url, headers, max, deadline, sink, signal) => {
      calls++;
      if (calls === 3) controller.abort();
      return source.request(gateway, url, headers, max, deadline, sink, signal);
    };
    await assert.rejects(prepareBoundedImageArchive(controller.signal, source.target, PUBLIC_IMAGE_PROFILE, cancelled, root), ArchiveRejected);
    assert.deepEqual(await readdir(root), []);
    for (const request of [
      async () => { throw new Error('secret-canary'); },
      async (_gateway, _url, _headers, _max, _deadline, sink) => {
        await sink!(Buffer.alloc(L.maxObjectBytes + 1), 401);
        return { status: 401, headers: {}, body: Buffer.alloc(0) };
      },
    ] satisfies Array<typeof gatewayGet>) {
      await assert.rejects(prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, request, root),
        (error: unknown) => error instanceof ArchiveRejected && !error.message.includes('secret-canary'));
      assert.deepEqual(await readdir(root), []);
    }
    // Unrelated content in the scratch root is not recovered/deleted by preparation.
    await writeFile(`${root}/sentinel`, 'preserve');
    const result = await prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, source.request, root);
    await result.cleanup(); assert.equal(await readFile(`${root}/sentinel`, 'utf8'), 'preserve');
  });
});

test('retained expanded layers are rehashed on archive copy; same-size tampering cannot inherit a valid diffID', async () => {
  await scratch(async root => {
    const base = fixture();
    const source = fixture({ layers: [0, 1].map(() => ({ digest: sha(base.compressed), size: base.compressed.length,
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' })) });
    let layers = 0;
    const request: typeof gatewayGet = async (gateway, url, headers, max, deadline, sink, signal) => {
      if (decodeURIComponent(url.pathname).endsWith(sha(base.compressed)) && ++layers === 2) {
        const [directory] = await readdir(root);
        const bytes = Buffer.from(source.bytes); bytes[512] ^= 1;
        await writeFile(`${root}/${directory}/0.tar`, bytes);
      }
      return source.request(gateway, url, headers, max, deadline, sink, signal);
    };
    await assert.rejects(prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, request, root), ArchiveRejected);
    assert.deepEqual(await readdir(root), []);
  });
});

test('input mutation cannot change repository, identity or receipt after async preparation begins', async () => {
  await scratch(async root => {
    const source = fixture({ repository: 'org/blobs' });
    const target = { ...source.target };
    const pending = prepareBoundedImageArchive(undefined, target, PUBLIC_IMAGE_PROFILE, source.request, root);
    target.repository = 'attacker/changed'; target.digest = sha(Buffer.from('changed'));
    const result = await pending;
    assert.equal(result.receipt.repository, source.target.repository);
    assert.equal(result.receipt.digest, source.target.digest);
    await result.cleanup();
  });
});

test('production wrappers reject invalid targets before gateway or scratch I/O and legacy never admits arbitrary images', async () => {
  const source = fixture();
  await assert.rejects(prepareNginxArchive(undefined, source.target as never), ArchiveRejected);
  for (const target of [{ ...source.target, platform: 'linux/arm64' }, { ...source.target, registry: 'evil.example' },
    { ...source.target, digest: 'stable' }, { ...source.target, configDigest: 'sha256:bad' }]) {
    await assert.rejects(preparePublicImageArchive(undefined, target), ArchiveRejected);
  }
});
