// TEST ONLY: synthetic SHA-linked bytes, never external pinned-image evidence.
import { createHash } from 'node:crypto';
import type { AuthorizedImageInput } from './contract.js';

export const formats = {
  oci: ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.config.v1+json'],
  docker: ['application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.docker.container.image.v1+json'],
} as const;
export const hash = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export const minimalConfig = () => ({ os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: [] } });

export function linkedInput(config: unknown, format: keyof typeof formats = 'oci'): AuthorizedImageInput {
  const configBytes = config instanceof Uint8Array ? Buffer.from(config) : Buffer.from(JSON.stringify(config));
  const [mediaType, configType] = formats[format];
  const manifestBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType, layers: [],
    config: { mediaType: configType, digest: hash(configBytes), size: configBytes.length } }));
  return { manifestBytes, configBytes, identity: { registry: 'registry-1.docker.io', repository: 'library/alpine',
    manifestDigest: hash(manifestBytes), platform: { os: 'linux', architecture: 'amd64' } } };
}

export const compatibleCases: readonly [string, Record<string, unknown>][] = [
  ['absent', {}], ['config null', { config: null }], ['config empty', { config: {} }],
  ['User null', { config: { User: null } }], ['User empty', { config: { User: '' } }],
  ['Env null', { config: { Env: null } }], ['Env empty', { config: { Env: [] } }],
  ['Env nonempty', { config: { Env: ['CANARY_ENV=value'] } }],
  ['Labels null', { config: { Labels: null } }], ['Labels empty', { config: { Labels: {} } }],
  ['Labels nonempty', { config: { Labels: { CANARY_LABEL: 'value' } } }],
  ['history null', { history: null }], ['history empty', { history: [] }],
  ['history optional nulls', { history: [{ created: null, created_by: null, author: null, comment: null, empty_layer: null }] }],
  ['history nonempty', { history: [{ created_by: 'CANARY_HISTORY', empty_layer: false }] }],
  ['variant null', { variant: null }],
  ['Docker nil-map shape', { config: { User: '', Env: ['CANARY_ENV=value'], Labels: null, Entrypoint: null, Cmd: ['sh'], Volumes: null }, history: [{}, {}] }],
];
