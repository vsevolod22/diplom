import { createHash } from 'node:crypto';
import { createPinnedConfigLoader } from '../oci/pinned-image-config.js';

/** Synthetic hash-linked OCI bytes; not live registry or Trivy proof. */
export function configBytes(user: unknown = '0', overrides: Record<string, unknown> = {}) {
  const config = Buffer.from(JSON.stringify({ os: 'linux', architecture: 'amd64', config: { User: user,
    Env: ['CANARY_ENV=SECRET'], Labels: { CANARY_LABEL: 'SECRET' } }, history: [{ created_by: 'CANARY_HISTORY_SECRET' }], ...overrides }));
  const digest = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}` as const;
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: digest(config), size: config.length }, layers: [] }));
  return { config, manifest, digest: digest(manifest), configDigest: digest(config) };
}
export function fixtureLoader(bytes: ReturnType<typeof configBytes>) {
  return createPinnedConfigLoader(async (_gateway, url) => ({ status: 200,
    headers: { 'content-type': url.pathname.includes('/manifests/') ? 'application/vnd.oci.image.manifest.v1+json' : 'application/octet-stream' },
    body: url.pathname.includes('/manifests/') ? bytes.manifest : bytes.config }));
}
