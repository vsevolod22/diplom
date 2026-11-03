import { createHash } from 'node:crypto';
import type { ImageReference } from '../scans/image-reference.js';
import { parseImageReference } from '../scans/image-reference.js';
import { dockerHubManifestFetch, gatewayGet } from './gateway-transport.js';
import { resolveManifest, ResolutionRejected, type ManifestFetch, type ManifestResponse } from './registry-resolver.js';
import { PUBLIC_IMAGE_LIMITS as L, publicDigest, publicObject, validPublicRepository, publicLayerEncoding } from './public-image-policy.js';
import { validatePublicConfigDescriptor, type PublicConfigDescriptorEvidence } from './public-image-config-data.js';

const manifestTypes = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const indexTypes = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);

import { imageFailureDetail, registryFailureDetail, type ImageFailureDetail } from './image-failure.js';
const reject = (detail: ImageFailureDetail = { reason: 'IMAGE_INVALID', stage: 'inspection' }): never => {
  throw new ResolutionRejected('Public image inspection rejected', detail);
};
const resource = (value: 'layers' | 'layer_bytes' | 'download_bytes' | 'requests'): never =>
  reject({ reason: 'RESOURCE_LIMIT', stage: 'inspection', resource: value });
const validSize = (size: unknown, maximum: number): size is number =>
  typeof size === 'number' && Number.isSafeInteger(size) && size > 0 && size <= maximum;
function json(body: Buffer): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    if (publicObject(value)) return value;
  } catch { /* Untrusted parser diagnostics must not escape. */ }
  return reject();
}
function descriptor(value: unknown, types: Set<string>, maximum: number): value is {
  digest: `sha256:${string}`; size: number; mediaType: string;
} {
  return publicObject(value) && publicDigest(value.digest) && validSize(value.size, maximum) &&
    typeof value.mediaType === 'string' && types.has(value.mediaType) && value.urls === undefined && value.data === undefined;
}

type InspectionRequest = (gateway: { host: string; port: number }, url: URL, headers: Record<string, string>,
  maximum?: number, deadlineMs?: number) => Promise<ManifestResponse>;
// The seam is for deterministic transport tests; production still uses the same
// repository-scoped gateway/auth/redirect enforcement as legacy acquisition.
export function publicImageInspectionFetch(repository: string, request: InspectionRequest = gatewayGet,
  now = () => performance.now()): ManifestFetch {
  if (!validPublicRepository(repository)) return reject();
  const started = now();
  let requests = 0, bytes = 0, failed = false;
  return dockerHubManifestFetch({ host: 'egress', port: 8080 }, repository, async (gateway, url, headers, requestedMax) => {
    const remaining = L.inspectionDeadlineMs - (now() - started);
    if (failed) return reject();
    if (remaining <= 0) { failed = true; return reject({ reason: 'DEADLINE_EXCEEDED', stage: 'inspection' }); }
    if (++requests > L.inspectionRequests) { failed = true; return resource('requests'); }
    if (bytes >= L.inspectionWireBytes) { failed = true; return resource('download_bytes'); }
    const objectLimit = url.pathname.startsWith(`/v2/${repository}/blobs/`) || headers.accept === 'application/octet-stream'
      ? L.maxConfigBytes : L.maxObjectBytes;
    const maximum = Math.min(requestedMax ?? objectLimit, L.inspectionWireBytes - bytes);
    try {
      const result = await request(gateway, url, headers, maximum, remaining);
      bytes += result.body.length;
      if ([301, 302, 303, 307, 308].includes(result.status) && url.hostname === 'registry-1.docker.io' &&
          !url.pathname.startsWith(`/v2/${repository}/blobs/`)) return reject();
      if (result.body.length > maximum) return resource('download_bytes');
            if (now() - started >= L.inspectionDeadlineMs) return reject({ reason: 'DEADLINE_EXCEEDED', stage: 'inspection' });
      return result;
    } catch (error) {
          failed = true;
          const detail = imageFailureDetail(error);
          return reject(detail ? { ...detail, stage: 'inspection' } : { reason: 'REGISTRY_UNAVAILABLE', stage: 'inspection' });
        }
  });
}

export async function inspectPublicImage(reference: ImageReference, transport?: ManifestFetch) {
  try {
    if (!publicObject(reference) || reference.registry !== 'registry-1.docker.io' || !validPublicRepository(reference.repository) ||
        typeof reference.canonical !== 'string') return reject();
    const parsed = parseImageReference(reference.canonical, new Set(['registry-1.docker.io']));
    if (parsed.registry !== reference.registry || parsed.repository !== reference.repository ||
        parsed.selector !== reference.selector || parsed.canonical !== reference.canonical) return reject();
    const fetch = transport ?? publicImageInspectionFetch(parsed.repository);
    let objects = 0, selectedSize: number | undefined, configDigest: `sha256:${string}` | undefined;
    let configEvidence: PublicConfigDescriptorEvidence | undefined;
    let layers: Readonly<{ digest: `sha256:${string}`; size: number; mediaType: string }>[] = [];
    const bounded: ManifestFetch = async (host, path) => {
      if (++objects > 3) return reject();
      const response = await fetch(host, path);
      const blob = path.startsWith(`/v2/${parsed.repository}/blobs/`);
      if (response.status !== 200) return reject(registryFailureDetail(response.status, 'inspection'));
            if (response.body.length > (blob ? L.maxConfigBytes : L.maxObjectBytes)) return resource('download_bytes');
      const type = String(response.headers['content-type'] ?? '').split(';')[0];
      if (blob && configEvidence?.embedded && (response.body.length !== configEvidence.embedded.size ||
          `sha256:${createHash('sha256').update(response.body).digest('hex')}` !== configEvidence.embedded.digest)) return reject();
      const data = json(response.body);
      if (blob) {
        if (data.os !== 'linux' || data.architecture !== 'amd64' || data.variant !== undefined)
          return reject({ reason: 'PLATFORM_UNSUPPORTED', stage: 'inspection' });
        if (!publicObject(data.rootfs) || data.rootfs.type !== 'layers' ||
            !Array.isArray(data.rootfs.diff_ids) || data.rootfs.diff_ids.length !== layers.length ||
            data.rootfs.diff_ids.some(value => !publicDigest(value))) return reject();
      } else {
        if (data.schemaVersion !== 2 || data.artifactType !== undefined || data.subject !== undefined)
          return reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'inspection' });
        if (data.mediaType !== undefined && data.mediaType !== type) return reject();
        if (indexTypes.has(type)) {
          if (!Array.isArray(data.manifests) || !data.manifests.length || data.manifests.length > 1024 ||
              data.manifests.some(item => !descriptor(item, manifestTypes, L.maxObjectBytes))) return reject();
          const matches = data.manifests.filter(item => publicObject(item.platform) && item.platform.os === 'linux' &&
            item.platform.architecture === 'amd64' && item.platform.variant === undefined);
          if (!matches.length) return reject({ reason: 'PLATFORM_UNSUPPORTED', stage: 'inspection' });
                    if (matches.length !== 1) return reject();
          selectedSize = matches[0].size;
        } else if (manifestTypes.has(type)) {
          if (selectedSize !== undefined && response.body.length !== selectedSize ||
              !Array.isArray(data.layers) || !data.layers.length) return reject();
                        if (data.layers.length > L.maxLayers) return resource('layers');
          configEvidence = validatePublicConfigDescriptor(data.config);
          configDigest = configEvidence.digest;
          let total = 0;
          layers = data.layers.map(layer => {
            if (!publicObject(layer) || !publicDigest(layer.digest) || !validSize(layer.size, Number.MAX_SAFE_INTEGER) ||
                            layer.urls !== undefined || layer.data !== undefined) return reject();
                        if (typeof layer.mediaType !== 'string' || !publicLayerEncoding(layer.mediaType))
                                      return reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'inspection' });
                        if (layer.size > L.compressedLayer) return resource('layer_bytes');
                        if ((total += layer.size) > L.compressedTotal) return resource('download_bytes');
            return Object.freeze({ digest: layer.digest, size: layer.size, mediaType: layer.mediaType });
          });
        } else return reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'inspection' });
      }
      return response;
    };
    const identity = await resolveManifest(parsed, 'linux/amd64', bounded);
    if (!configDigest || !layers.length) return reject();
    return Object.freeze({ ...identity, configDigest, layers: Object.freeze(layers) });
  } catch (error) { return reject(imageFailureDetail(error)); }
}
