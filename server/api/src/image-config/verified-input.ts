import { createHash } from 'node:crypto';
import type { AuthorizedImageInput, Platform } from './contract.js';
import { has, isObject, parseBoundedJson, type JsonObject } from './bounded-json.js';
import { fail, POLICY } from './policy.js';

const MANIFEST_TYPES = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const CONFIG_TYPES = new Set(['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json']);
const OS = new Set(['linux', 'windows', 'freebsd']);
const ARCHITECTURES = new Set(['amd64', '386', 'arm', 'arm64', 'ppc64', 'ppc64le', 's390x', 'riscv64', 'mips', 'mipsle', 'mips64', 'mips64le', 'loong64']);
const VARIANTS = new Set(['v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9']);
const sha256 = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const isDigest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);

export interface VerifiedInput {
  readonly manifestDigest: string;
  readonly configDigest: string;
  readonly platform: Readonly<Platform>;
  readonly user?: string;
}

function canonicalPlatform(value: Platform): Readonly<Platform> {
  const { os, architecture, variant } = value;
  if (!OS.has(os) || !ARCHITECTURES.has(architecture) ||
    (variant !== undefined && (!VARIANTS.has(variant) || !['arm', 'arm64', 'amd64'].includes(architecture)))) {
    return fail('OCI_IDENTITY_REJECTED');
  }
  return Object.freeze({ os, architecture, ...(variant === undefined ? {} : { variant }) });
}

function validateMetadata(config: JsonObject): string | undefined {
  let user: string | undefined;
  if (has(config, 'config')) {
    const runtime = config.config;
    if (!isObject(runtime)) return fail('INVALID_CONFIG');
    if (has(runtime, 'User')) {
      if (typeof runtime.User !== 'string') return fail('INVALID_CONFIG');
      if (Buffer.byteLength(runtime.User, 'utf8') > POLICY.userBytes) return fail('CONFIG_LIMIT_EXCEEDED');
      user = runtime.User;
    }
    if (has(runtime, 'Env')) {
      if (!Array.isArray(runtime.Env)) return fail('INVALID_CONFIG');
      if (runtime.Env.length > POLICY.env) return fail('CONFIG_LIMIT_EXCEEDED');
      if (!runtime.Env.every(entry => typeof entry === 'string')) return fail('INVALID_CONFIG');
    }
    if (has(runtime, 'Labels')) {
      if (!isObject(runtime.Labels)) return fail('INVALID_CONFIG');
      if (Object.keys(runtime.Labels).length > POLICY.labels) return fail('CONFIG_LIMIT_EXCEEDED');
      if (!Object.values(runtime.Labels).every(entry => typeof entry === 'string')) return fail('INVALID_CONFIG');
    }
  }
  if (has(config, 'history')) {
    if (!Array.isArray(config.history)) return fail('INVALID_CONFIG');
    if (config.history.length > POLICY.history) return fail('CONFIG_LIMIT_EXCEEDED');
    for (const record of config.history) {
      if (!isObject(record)) return fail('INVALID_CONFIG');
      for (const field of ['created', 'created_by', 'author', 'comment']) {
        if (has(record, field) && typeof record[field] !== 'string') return fail('INVALID_CONFIG');
      }
      if (has(record, 'empty_layer') && typeof record.empty_layer !== 'boolean') return fail('INVALID_CONFIG');
    }
  }
  return user;
}

/** Internal to a module instance: receipts have no public brand or structural proof.
 * No bytes or parsed documents escape; only this verifier can read its receipts.
 */
export function createVerifier() {
  const receipts = new WeakMap<object, Readonly<VerifiedInput>>();
  return Object.freeze({
    verify(input: AuthorizedImageInput): object {
      const manifestSource = input.manifestBytes;
      const configSource = input.configBytes;
      if (!(manifestSource instanceof Uint8Array) || !(configSource instanceof Uint8Array) ||
        manifestSource.buffer instanceof SharedArrayBuffer || configSource.buffer instanceof SharedArrayBuffer) {
        return fail('OCI_IDENTITY_REJECTED');
      }
      if (manifestSource.byteLength > POLICY.manifestBytes || configSource.byteLength > POLICY.configBytes ||
        manifestSource.byteLength + configSource.byteLength > POLICY.totalBytes) return fail('CONFIG_LIMIT_EXCEEDED');
      // Own copies before hashing/parsing. No await or callback between proof and rule input.
      const manifestBytes = Buffer.from(manifestSource);
      const configBytes = Buffer.from(configSource);
      const identity = input.identity;
      const manifestDigest = identity.manifestDigest;
      if (typeof identity.registry !== 'string' || !identity.registry || identity.registry.length > 253 ||
        typeof identity.repository !== 'string' || !identity.repository || identity.repository.length > 1024 ||
        !isDigest(manifestDigest)) return fail('OCI_IDENTITY_REJECTED');
      const platform = canonicalPlatform(identity.platform);
      if (sha256(manifestBytes) !== manifestDigest) return fail('OCI_IDENTITY_REJECTED');
      const manifest = parseBoundedJson(manifestBytes);
      if (!isObject(manifest) || manifest.schemaVersion !== 2 || typeof manifest.mediaType !== 'string' ||
        !MANIFEST_TYPES.has(manifest.mediaType) || !Array.isArray(manifest.layers) || !isObject(manifest.config)) {
        return fail('OCI_IDENTITY_REJECTED');
      }
      // Descriptor is extracted exclusively from the hashed child manifest.
      const descriptor = manifest.config;
      if (!isDigest(descriptor.digest) || !Number.isSafeInteger(descriptor.size) ||
        typeof descriptor.size !== 'number' || descriptor.size < 0 || descriptor.size !== configBytes.byteLength ||
        typeof descriptor.mediaType !== 'string' || !CONFIG_TYPES.has(descriptor.mediaType) ||
        sha256(configBytes) !== descriptor.digest) return fail('OCI_IDENTITY_REJECTED');
      const config = parseBoundedJson(configBytes);
      if (!isObject(config)) return fail('INVALID_CONFIG');
      if (config.os !== platform.os || config.architecture !== platform.architecture ||
        (has(config, 'variant') ? config.variant : undefined) !== platform.variant) return fail('OCI_IDENTITY_REJECTED');
      const user = validateMetadata(config);
      const verified = Object.freeze({ manifestDigest, configDigest: descriptor.digest, platform,
        ...(user === undefined ? {} : { user }) });
      const receipt = Object.freeze(Object.create(null) as object);
      receipts.set(receipt, verified);
      return receipt;
    },
    read(receipt: unknown): Readonly<VerifiedInput> {
      if (typeof receipt !== 'object' || receipt === null) return fail('OCI_IDENTITY_REJECTED');
      const verified = receipts.get(receipt);
      return verified ?? fail('OCI_IDENTITY_REJECTED');
    },
  });
}
