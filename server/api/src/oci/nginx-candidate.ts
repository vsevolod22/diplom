import type { ImageReference } from '../scans/image-reference.js';
import { dockerHubManifestFetch, DOCKER_HUB_HOSTS, gatewayGet } from './gateway-transport.js';
import { resolveManifest, ResolutionRejected, type ManifestFetch, type ManifestResponse } from './registry-resolver.js';

// Inspection is not qualification. No environment flag can enable this unfinished
// profile: layer streaming/unpack enforcement and remote/browser proof are pending.
export const NGINX_PROFILE = Object.freeze({ version: 'nginx-alpine-amd64-v1', enabled: false,
  qualifiedTargets: Object.freeze([]), scannerVersion: '0.69.3' });
export const NGINX_CANDIDATE_LIMITS = Object.freeze({
  version: 'nginx-candidate-resources-v1', maxObjectBytes: 4_000_000, maxConfigBytes: 1_000_000,
  maxWireBytes: 16_000_000, maxWireRequests: 12, deadlineMs: 30_000,
  maxLayers: 32, maxLayerCompressedBytes: 32 * 1024 * 1024, maxCompressedBytes: 96 * 1024 * 1024,
});
const manifestTypes = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const indexTypes = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);
const layerTypes = new Set(['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip']);
const validDigest = (value: unknown): value is `sha256:${string}` => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const validSize = (value: unknown, max: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= max;
function json(body: Buffer): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    if (object(value)) return value;
  } catch { /* Never include untrusted bytes or parser messages in errors. */ }
  throw new ResolutionRejected('Invalid candidate OCI object');
}

type CandidateRequest = (gateway: { host: string; port: number }, url: URL, headers: Record<string, string>,
  maxBytes?: number, deadlineMs?: number) => Promise<ManifestResponse>;
// Counts auth retries and CDN redirects too, not just the three resolver objects.
export function nginxCandidateFetch(request: CandidateRequest = gatewayGet, now = () => performance.now()): ManifestFetch {
  const limits = NGINX_CANDIDATE_LIMITS;
  const started = now();
  let bytes = 0;
  let requests = 0;
  let failed = false;
  return dockerHubManifestFetch({ host: 'egress', port: 8080 }, 'library/nginx', async (gateway, url, headers, requestedMax) => {
    const remainingMs = limits.deadlineMs - (now() - started);
    if (failed || ++requests > limits.maxWireRequests || remainingMs <= 0 || bytes >= limits.maxWireBytes) {
      failed = true;
      throw new ResolutionRejected('Candidate transport budget exhausted');
    }
    const maxBytes = Math.min(requestedMax ?? limits.maxObjectBytes, limits.maxWireBytes - bytes);
    try {
      const result = await request(gateway, url, headers, maxBytes, remainingMs);
      bytes += result.body.length;
      if (result.body.length > maxBytes || now() - started >= limits.deadlineMs) throw new Error();
      return result;
    } catch {
      failed = true;
      throw new ResolutionRejected('Candidate transport failed');
    }
  });
}

export async function inspectNginxCandidate(ref: ImageReference, fetch: ManifestFetch = nginxCandidateFetch()) {
  if (ref.registry !== DOCKER_HUB_HOSTS.registry || ref.repository !== 'library/nginx')
    throw new ResolutionRejected('Unsupported candidate repository');
  const limits = NGINX_CANDIDATE_LIMITS;
  let selectedSize: number | undefined;
  let configDigest: `sha256:${string}` | undefined;
  let layers: Readonly<{ digest: `sha256:${string}`; size: number; mediaType: string }>[] = [];
  let compressedBytes = 0;
  let objects = 0;
  const bounded: ManifestFetch = async (host, path) => {
    if (++objects > 3) throw new ResolutionRejected('Candidate object count exceeded');
    const response = await fetch(host, path);
    if (response.status !== 200 || response.body.length > limits.maxObjectBytes)
      throw new ResolutionRejected('Candidate object unavailable');
    const type = String(response.headers['content-type'] ?? '').split(';')[0];
    const data = json(response.body);
    if (path.includes('/blobs/')) {
      if (response.body.length > limits.maxConfigBytes) throw new ResolutionRejected('Candidate config too large');
    } else if (indexTypes.has(type)) {
      if (data.schemaVersion !== 2 || !Array.isArray(data.manifests) || data.manifests.length > 1024)
        throw new ResolutionRejected('Invalid candidate index');
      const matches = data.manifests.filter(item => object(item) && object(item.platform) &&
        item.platform.os === 'linux' && item.platform.architecture === 'amd64' && item.platform.variant === undefined);
      if (matches.length !== 1 || !validSize(matches[0].size, limits.maxObjectBytes))
        throw new ResolutionRejected('Candidate platform ambiguous or unbounded');
      selectedSize = matches[0].size;
    } else if (manifestTypes.has(type)) {
      if (selectedSize !== undefined && selectedSize !== response.body.length)
        throw new ResolutionRejected('Candidate child size mismatch');
      if (!object(data.config) || !validDigest(data.config.digest) || !validSize(data.config.size, limits.maxConfigBytes) ||
          !Array.isArray(data.layers) || !data.layers.length || data.layers.length > limits.maxLayers)
        throw new ResolutionRejected('Invalid candidate descriptors');
      configDigest = data.config.digest;
      layers = data.layers.map((layer: unknown) => {
        if (!object(layer) || !validDigest(layer.digest) || !validSize(layer.size, limits.maxLayerCompressedBytes) ||
            typeof layer.mediaType !== 'string' || !layerTypes.has(layer.mediaType) || layer.urls !== undefined)
          throw new ResolutionRejected('Unsupported candidate layer');
        compressedBytes += layer.size;
        if (compressedBytes > limits.maxCompressedBytes) throw new ResolutionRejected('Candidate compressed size exceeded');
        return Object.freeze({ digest: layer.digest, size: layer.size, mediaType: layer.mediaType });
      });
    }
    return response;
  };
  try {
    const identity = await resolveManifest(ref, 'linux/amd64', bounded);
    if (!configDigest || !layers.length) throw new ResolutionRejected('Candidate inventory unavailable');
    // Descriptors prove compressed sizes only. No layer bytes have been downloaded,
    // unpacked or scanned; Linux config is not proof of Alpine/APK or CVE support.
    return Object.freeze({ ...identity, configDigest, layers: Object.freeze(layers), compressedBytes,
      qualification: 'unqualified' as const, resourcePolicyVersion: limits.version });
  } catch {
    throw new ResolutionRejected('Candidate inspection rejected');
  }
}
