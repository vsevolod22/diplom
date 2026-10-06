// TEST ONLY: this registry proves fixture handle origin, not real scan authorization.
import { createHash } from 'node:crypto';
import { createImageConfigModule } from './index.js';
import type { AuthorizedImageInput } from './contract.js';

export const digest = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
export const baseConfig = () => ({ os: 'linux', architecture: 'amd64', config: { User: '0' } });

export function setup(config: unknown = baseConfig()) {
  const configBytes = config instanceof Uint8Array ? Buffer.from(config) : encode(config);
  const manifest = { schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: digest(configBytes), size: configBytes.length }, layers: [] };
  const manifestBytes = encode(manifest);
  const target = Object.freeze({});
  const input = { identity: { registry: 'registry.example', repository: 'demo/image', manifestDigest: digest(manifestBytes),
    platform: { os: 'linux', architecture: 'amd64' } as { os: string; architecture: string; variant?: string } }, manifestBytes, configBytes };
  let calls = 0;
  const module = createImageConfigModule({ resolveAuthorizedTarget(handle) { calls++; return handle === target ? input : undefined; } });
  const repinManifest = (bytes: Uint8Array = encode(manifest)) => { input.manifestBytes = Buffer.from(bytes); input.identity.manifestDigest = digest(bytes); };
  return { module, input, target, manifest, repinManifest, calls: () => calls,
    analyze: (extra: Record<string, unknown> = {}) => module.analyze({ enabled: true, target, ...extra }) };
}

export function pad(bytes: Buffer, size: number): Buffer {
  if (size < bytes.length) throw new Error('Invalid fixture size');
  return Buffer.concat([bytes, Buffer.alloc(size - bytes.length, 32)]);
}

export function fixturePort(input: AuthorizedImageInput) {
  const target = Object.freeze({});
  return { target, port: { resolveAuthorizedTarget(handle: unknown) { return handle === target ? input : undefined; } } };
}
