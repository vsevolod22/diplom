import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { parseImageReference } from '../scans/image-reference.js';
import type { ManifestFetch, ManifestResponse } from './registry-resolver.js';
import type { gatewayGet } from './gateway-transport.js';

export const sha = (bytes: Buffer): `sha256:${string}` => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export const media = { index: 'application/vnd.oci.image.index.v1+json', image: 'application/vnd.oci.image.manifest.v1+json',
  config: 'application/vnd.oci.image.config.v1+json', layer: 'application/vnd.oci.image.layer.v1.tar+gzip' };
export function tarHeader(path = 'usr/share/example/data', size = 7, type = '0', link = '') {
  const header = Buffer.alloc(512);
  header.write(path); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(size.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
  header.fill(32, 148, 156); header.write(type, 156); header.write(link, 157); header.write('ustar\0', 257); header.write('00', 263);
  header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return header;
}
export function tar(path = 'usr/share/example/data', body: Buffer = Buffer.from('example'), type = '0', link = '') {
  return Buffer.concat([tarHeader(path, body.length, type, link), body,
    Buffer.alloc((512 - body.length % 512) % 512), Buffer.alloc(1024)]);
}
export function fixture(options: { repository?: string; layers?: unknown; config?: Record<string, unknown>;
  image?: Record<string, unknown>; child?: Record<string, unknown>; duplicate?: boolean; bytes?: Buffer;
  compressed?: Buffer; configBytes?: number; imageBytes?: number; indexBytes?: number } = {}) {
  const repository = options.repository ?? 'example-team/namespaced-image';
  const reference = parseImageReference(`registry-1.docker.io/${repository}:stable`, new Set(['registry-1.docker.io']));
  const bytes = options.bytes ?? tar();
  const compressed = options.compressed ?? gzipSync(bytes);
  const layers = options.layers ?? [{ digest: sha(compressed), size: compressed.length, mediaType: media.layer }];
  const sized = (value: unknown, length?: number) => Buffer.from(JSON.stringify(value).padEnd(length ?? 0, ' '));
  const diffIds = Array.isArray(layers) ? layers.map(() => sha(bytes)) : [];
  const config = sized({ os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: diffIds }, ...options.config }, options.configBytes);
  const image = sized({ schemaVersion: 2, mediaType: media.image,
    config: { digest: sha(config), size: config.length, mediaType: media.config }, layers, ...options.image }, options.imageBytes);
  const child = { digest: sha(image), size: image.length, mediaType: media.image,
    platform: { os: 'linux', architecture: 'amd64' }, ...options.child };
  const index = sized({ schemaVersion: 2, mediaType: media.index, manifests: options.duplicate ? [child, child] : [child] }, options.indexBytes);
  const calls: string[] = [];
  const fetch: ManifestFetch = async (host, path) => {
    calls.push(`${host}${path}`);
    const decoded = decodeURIComponent(path);
    const blob = decoded.startsWith(`/v2/${repository}/blobs/`);
    const body = blob ? decoded.endsWith(sha(config)) ? config : compressed : decoded.endsWith('/stable') ? index : image;
    return { status: 200, headers: { 'content-type': blob ? 'application/octet-stream' : body === index ? media.index : media.image,
      'docker-content-digest': sha(body) }, body };
  };
  const request: typeof gatewayGet = async (_gateway, url, _headers, maximum, _deadline, sink, signal) => {
    signal?.throwIfAborted();
    const response = await fetch(url.hostname, url.pathname);
    if (response.body.length > maximum!) throw new Error('Fixture transport size limit');
    if (!sink) return response;
    // Deliberately fragmented to exercise streaming framing and writes.
    for (let offset = 0; offset < response.body.length; offset += 73) {
      signal?.throwIfAborted();
      await sink(response.body.subarray(offset, offset + 73), response.status);
    }
    return { ...response, body: Buffer.alloc(0) } satisfies ManifestResponse;
  };
  const target = { registry: reference.registry, repository, digest: sha(image), configDigest: sha(config), platform: 'linux/amd64' };
  return { reference, target, bytes, compressed, config, image, index, fetch, request, calls };
}
