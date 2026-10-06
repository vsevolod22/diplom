import { createHash } from 'node:crypto';
import type { AuthorizedImageInput } from '../image-config/contract.js';
import { isObject, parseBoundedJson } from '../image-config/bounded-json.js';
import { fail, POLICY } from '../image-config/policy.js';
import { NGINX_ARCHIVE_CANDIDATES } from './bounded-image-archive.js';
import { dockerHubManifestFetch, gatewayGet } from './gateway-transport.js';
import type { Job } from '../ledger/ledger.js';

export const CONFIG_LOAD_MS = 30_000;
export const CONFIG_LOAD_REQUESTS = 8;
export type ConfigLoader = (job: Readonly<Job>, signal: AbortSignal) => Promise<AuthorizedImageInput>;

export function admittedConfigTarget(job: Pick<Job, 'registry' | 'repository' | 'digest' | 'platform' | 'scope'>): boolean {
  return job.scope === 'image' && job.registry === 'registry-1.docker.io' && job.platform === 'linux/amd64' &&
    /^sha256:[a-f0-9]{64}$/.test(job.digest) && (job.repository === 'library/alpine' ||
      NGINX_ARCHIVE_CANDIDATES.some(candidate => candidate.registry === job.registry && candidate.repository === job.repository &&
        candidate.digest === job.digest && candidate.platform === job.platform));
}

/** Bootstrap transport injection; production always uses the existing HTTPS gateway path. */
export function createPinnedConfigLoader(request: typeof gatewayGet = gatewayGet): ConfigLoader {
  return async (job, signal) => {
    if (!admittedConfigTarget(job)) return fail('OCI_IDENTITY_REJECTED');
    const deadline = Date.now() + CONFIG_LOAD_MS;
    let requests = 0;
    let cap = POLICY.manifestBytes;
    const fetchObject = dockerHubManifestFetch({ host: 'egress', port: 8080 }, job.repository,
      async (gateway, url, headers, requestedCap) => {
        if (signal.aborted || ++requests > CONFIG_LOAD_REQUESTS || Date.now() >= deadline) return fail('OCI_IDENTITY_REJECTED');
        const maxBytes = Math.min(cap, requestedCap ?? cap);
        const result = await request(gateway, url, headers, maxBytes, deadline - Date.now(), undefined, signal);
        if (signal.aborted || Date.now() >= deadline) return fail('OCI_IDENTITY_REJECTED');
        if (result.body.length > maxBytes) return fail('CONFIG_LIMIT_EXCEEDED');
        return result;
      });
    const manifest = await fetchObject(job.registry, `/v2/${job.repository}/manifests/${job.digest}`);
    const manifestBytes = Buffer.from(manifest.body);
    if (`sha256:${createHash('sha256').update(manifestBytes).digest('hex')}` !== job.digest) return fail('OCI_IDENTITY_REJECTED');
    const decoded = parseBoundedJson(manifestBytes);
    if (!isObject(decoded) || decoded.schemaVersion !== 2 ||
        typeof decoded.mediaType !== 'string' ||
        !['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(decoded.mediaType) ||
        !isObject(decoded.config) || !Array.isArray(decoded.layers)) return fail('OCI_IDENTITY_REJECTED');
    const descriptor = decoded.config;
    if (typeof descriptor.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(descriptor.digest) ||
        typeof descriptor.size !== 'number' || !Number.isSafeInteger(descriptor.size) || descriptor.size < 0 ||
        typeof descriptor.mediaType !== 'string' ||
        !['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'].includes(descriptor.mediaType)) return fail('OCI_IDENTITY_REJECTED');
    if (descriptor.size > POLICY.configBytes) return fail('CONFIG_LIMIT_EXCEEDED');
    cap = POLICY.configBytes;
    const config = await fetchObject(job.registry, `/v2/${job.repository}/blobs/${descriptor.digest}`);
    const configBytes = Buffer.from(config.body);
    const mediaType = config.headers['content-type'];
    if (typeof mediaType !== 'string' || ![descriptor.mediaType, 'application/octet-stream'].includes(mediaType.split(';')[0]) ||
        configBytes.length !== descriptor.size) return fail('OCI_IDENTITY_REJECTED');
    const manifestType = manifest.headers['content-type'];
    if (typeof manifestType !== 'string' || manifestType.split(';')[0] !== decoded.mediaType) return fail('OCI_IDENTITY_REJECTED');
    const [os, architecture, variant] = job.platform.split('/');
    return { identity: { registry: job.registry, repository: job.repository, manifestDigest: job.digest,
      platform: { os, architecture, ...(variant ? { variant } : {}) } }, manifestBytes, configBytes };
  };
}
export const loadPinnedConfig = createPinnedConfigLoader();
