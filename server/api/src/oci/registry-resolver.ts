import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import type { ImageReference } from '../scans/image-reference.js';

export class ResolutionRejected extends Error {}
export type ManifestResponse = { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer };
export type ManifestFetch = (host: string, path: string) => Promise<ManifestResponse>;
const accept = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';
const digest = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}` as `sha256:${string}`;

export async function resolveManifest(ref: ImageReference, platform: string, fetchManifest: ManifestFetch): Promise<{
  registry: string; repository: string; digest: `sha256:${string}`; platform: string;
}> {
  if (!/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/.test(platform)) throw new ResolutionRejected('Unsupported platform');
  async function load(path: string, expected?: string): Promise<{ body: Buffer; actual: `sha256:${string}`; mediaType: string }> {
    const response = await fetchManifest(ref.registry, path);
    // A 3xx or 401 is not permission to follow a new host or send credentials.
    if (response.status !== 200 || response.body.length > 4_000_000) throw new ResolutionRejected('OCI object unavailable');
    const actual = digest(response.body);
    const header = response.headers['docker-content-digest'];
    if (typeof header !== 'string' || header !== actual || (expected && expected !== actual))
      throw new ResolutionRejected('Digest mismatch');
    const mediaType = String(response.headers['content-type'] || '').split(';')[0];
    return { body: response.body, actual, mediaType };
  }
  const manifest = (selector: string) => load(`/v2/${ref.repository}/manifests/${encodeURIComponent(selector)}`,
    selector.startsWith('sha256:') ? selector : undefined);
  const first = await manifest(ref.selector);
  const indexTypes = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];
  const manifestTypes = ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'];
  let selected = first;
  if (indexTypes.includes(first.mediaType)) {
    let index: { schemaVersion?: number; manifests?: Array<{ digest?: string; mediaType?: string; platform?: { os?: string; architecture?: string; variant?: string } }> };
    try { index = JSON.parse(first.body.toString('utf8')); } catch { throw new ResolutionRejected('Invalid index'); }
    if (index.schemaVersion !== 2 || !Array.isArray(index.manifests) || index.manifests.length > 1024)
      throw new ResolutionRejected('Invalid index');
    const matches = index.manifests.filter(item => [item.platform?.os, item.platform?.architecture, item.platform?.variant].filter(Boolean).join('/') === platform);
    if (matches.length !== 1 || !/^sha256:[a-f0-9]{64}$/.test(matches[0].digest || '') ||
        !manifestTypes.includes(matches[0].mediaType || '')) throw new ResolutionRejected('Platform ambiguous or unavailable');
    selected = await manifest(matches[0].digest!);
    if (selected.mediaType !== matches[0].mediaType) throw new ResolutionRejected('Manifest media type mismatch');
  }
  if (!manifestTypes.includes(selected.mediaType)) throw new ResolutionRejected('Unsupported manifest');
  let image: { schemaVersion?: number; config?: { digest?: string; size?: number; mediaType?: string } };
  try { image = JSON.parse(selected.body.toString('utf8')); } catch { throw new ResolutionRejected('Invalid manifest'); }
  const config = image.config;
  if (image.schemaVersion !== 2 || !config || !/^sha256:[a-f0-9]{64}$/.test(config.digest || '') ||
      !Number.isSafeInteger(config.size) || config.size! < 0 || config.size! > 4_000_000 ||
      !['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'].includes(config.mediaType || ''))
    throw new ResolutionRejected('Invalid config descriptor');
  const blob = await load(`/v2/${ref.repository}/blobs/${encodeURIComponent(config.digest!)}`, config.digest);
  if (blob.body.length !== config.size || blob.mediaType !== config.mediaType)
    throw new ResolutionRejected('Config descriptor mismatch');
  let details: { os?: string; architecture?: string; variant?: string };
  try { details = JSON.parse(blob.body.toString('utf8')); } catch { throw new ResolutionRejected('Invalid config'); }
  if ([details.os, details.architecture, details.variant].filter(Boolean).join('/') !== platform)
    throw new ResolutionRejected('Platform mismatch');
  return { registry: ref.registry, repository: ref.repository, digest: selected.actual, platform };
}

// TLS verification is performed by Node against the original DNS hostname. The only
// TCP connection to registry is made by the allowlisted gateway; never use fetch() here.
export async function proxyManifestFetch(proxyHost: string, proxyPort: number, host: string, path: string,
  allowedHosts: ReadonlySet<string>): Promise<ManifestResponse> {
  // No implicit trust in caller-provided realms, redirects or blob hosts. An exact
  // hostname allowlist is required in addition to the gateway's per-CONNECT IP policy.
  if (!allowedHosts.has(host) || !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(host) ||
      !/^[a-z][a-z0-9.-]*\.[a-z]{2,}$/.test(host) ||
      !/^\/v2\/[a-z0-9/._%-]+$/.test(path) || path.includes('..') ||
      !Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535)
    throw new ResolutionRejected('Invalid destination');
  return new Promise((resolve, reject) => {
    const connect = httpRequest({ host: proxyHost, port: proxyPort, method: 'CONNECT', path: `${host}:443`, timeout: 5000 });
    connect.on('connect', (response, socket, head) => {
      if (response.statusCode !== 200 || head.length !== 0) { socket.destroy(); reject(new ResolutionRejected('Gateway refused')); return; }
      const secure = tlsConnect({ socket, servername: host, rejectUnauthorized: true });
      secure.setTimeout(10_000, () => secure.destroy());
      secure.once('error', () => reject(new ResolutionRejected('TLS failed')));
      secure.once('secureConnect', () => {
        const request = httpsRequest({ host, method: 'GET', path, headers: { accept }, createConnection: () => secure, agent: false, timeout: 10000 }, result => {
          const chunks: Buffer[] = [];
          let size = 0;
          result.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 4_000_000) result.destroy(); else chunks.push(chunk); });
          result.on('end', () => resolve({ status: result.statusCode || 0, headers: result.headers, body: Buffer.concat(chunks) }));
          result.on('error', () => reject(new ResolutionRejected('Manifest read failed')));
        });
        request.on('error', () => reject(new ResolutionRejected('Manifest request failed')));
        request.end();
      });
    });
    connect.on('timeout', () => connect.destroy());
    connect.on('error', () => reject(new ResolutionRejected('Gateway unavailable')));
    connect.end();
  });
}
