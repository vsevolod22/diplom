import { createHash, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';

export const sha = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export const media = Object.freeze({ image: 'application/vnd.oci.image.manifest.v1+json',
  config: 'application/vnd.oci.image.config.v1+json', layer: 'application/vnd.oci.image.layer.v1.tar+gzip' });

export function tarMember(name, body) {
  if (!/^[a-zA-Z0-9._/-]{1,100}$/.test(name) || name.startsWith('/') || name.split('/').some(p => !p || p === '..' || p === '.'))
    throw new Error('Unsafe qualification member');
  const header = Buffer.alloc(512);
  header.write(name); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(body.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
  header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
  header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([header, body, Buffer.alloc((512 - body.length % 512) % 512)]);
}

// Never print/serialize this object. These are random pattern canaries, never issued tokens.
export function makeFixture() {
  const values = [0, 1].map(() => 'ghp_' + randomBytes(27).toString('base64url').replace(/[-_]/g, 'Q'));
  const marker = 'qualification_' + randomBytes(12).toString('hex');
  const path = `app/${marker}.env`;
  const layer = Buffer.concat([tarMember(path, Buffer.from(`TOKEN_A=${values[0]}\nTOKEN_B=${values[1]}\n`)), Buffer.alloc(1024)]);
  const compressed = gzipSync(layer, { level: 6 });
  const config = Buffer.from(JSON.stringify({ os: 'linux', architecture: 'amd64',
    config: { User: '65532:65532', Env: [`QUALIFICATION_MARKER=${marker}`] },
    rootfs: { type: 'layers', diff_ids: [sha(layer)] } }));
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: media.image,
    config: { mediaType: media.config, digest: sha(config), size: config.length },
    layers: [{ mediaType: media.layer, digest: sha(compressed), size: compressed.length }] }));
  const target = { registry: 'registry-1.docker.io', repository: 'qualification/synthetic-secrets',
    digest: sha(manifest), configDigest: sha(config), platform: 'linux/amd64' };
  const objects = new Map([[`/v2/${target.repository}/manifests/${target.digest}`, [manifest, media.image]],
    [`/v2/${target.repository}/blobs/${sha(config)}`, [config, media.config]],
    [`/v2/${target.repository}/blobs/${sha(compressed)}`, [compressed, media.layer]]]);
  const fetch = async (host, input) => {
    if (host !== target.registry || !objects.has(decodeURIComponent(input))) throw new Error('Unexpected synthetic transport');
    const [body, type] = objects.get(decodeURIComponent(input));
    return { status: 200, headers: { 'content-type': type, 'docker-content-digest': sha(body) }, body };
  };
  let requests = 0;
  const request = async (_gateway, url, _headers, maximum, _deadline, sink, signal) => {
    signal?.throwIfAborted();
    if (++requests > 12 || url.protocol !== 'https:') throw new Error('Synthetic transport bound');
    const result = await fetch(url.hostname, url.pathname);
    if (result.body.length > maximum) throw new Error('Synthetic object bound');
    if (!sink) return result;
    for (let offset = 0; offset < result.body.length; offset += 73) {
      signal?.throwIfAborted(); await sink(result.body.subarray(offset, offset + 73), 200);
    }
    return { ...result, body: Buffer.alloc(0) };
  };
  return { values, marker, path, layer, compressed, config, manifest, target, fetch, request };
}

export function hasPrivate(value, forbidden) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  return forbidden.some(item => bytes.includes(Buffer.from(item))) || /ghp_[a-zA-Z0-9]{36}/.test(bytes.toString());
}
