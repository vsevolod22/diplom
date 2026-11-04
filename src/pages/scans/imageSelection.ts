import { publicImageReference } from '@/shared/api/scans/publicImageProfile';

const HUB_PREFIX = 'registry-1.docker.io/';

/** Syntax convenience only: the public validator and server admission remain authoritative. */
export function normalizeDockerHubReference(input: string): string | null {
  const value = input.trim();
  if (!value || /\s|:\/\/|[?#%\\]/.test(value)) return null;
  if (publicImageReference.safeParse(value).success) return value;
  const explicitHub = value.startsWith(HUB_PREFIX) || value.startsWith('docker.io/');
  const reference = value.startsWith(HUB_PREFIX) ? value.slice(HUB_PREFIX.length)
    : value.startsWith('docker.io/') ? value.slice('docker.io/'.length) : value;
  const firstPart = reference.split('/')[0];
  if (!explicitHub && reference.includes('/') && (/[.:@]/.test(firstPart) || firstPart === 'localhost')) return null;
  const canonical = HUB_PREFIX + (reference.includes('/') ? reference : `library/${reference}`);
  return publicImageReference.safeParse(canonical).success ? canonical : null;
}

export function repositoryFromReference(reference: string): string | null {
  if (!publicImageReference.safeParse(reference).success) return null;
  return reference.slice(HUB_PREFIX.length).split(/[:@]/)[0];
}

export function tagFromReference(reference: string): string | null {
  if (!publicImageReference.safeParse(reference).success || reference.includes('@')) return null;
  return reference.slice(reference.lastIndexOf(':') + 1);
}

export function validDiscoveryQuery(query: string, repository: string | null): boolean {
  if (repository !== null) {
    return repositoryFromReference(`${HUB_PREFIX}${repository}:latest`) === repository &&
      query.length <= 64 && /^[A-Za-z0-9_.-]*$/.test(query);
  }
  return query.length >= 2 && query.length <= 64 && /^[a-zA-Z0-9_./: -]+$/.test(query) &&
    !query.includes('..') && !query.includes('//') && !query.includes('://');
}

// Curated examples, not popularity rankings or assertions of availability/vulnerabilities.
export const OLDER_IMAGE_PRESETS = [
  { label: 'Node 18.17.1 · сборка 2023 · только для тестов', reference: 'registry-1.docker.io/library/node@sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55' },
  { label: 'Alpine 3.16 · точная сборка', reference: 'registry-1.docker.io/library/alpine@sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6' },
  { label: 'nginx 1.24-alpine', reference: 'registry-1.docker.io/library/nginx:1.24-alpine' },
  { label: 'Node 18-alpine', reference: 'registry-1.docker.io/library/node:18-alpine' },
  { label: 'Python 3.10-alpine', reference: 'registry-1.docker.io/library/python:3.10-alpine' },
  { label: 'Redis 6.2-alpine', reference: 'registry-1.docker.io/library/redis:6.2-alpine' },
  { label: 'PostgreSQL 13-alpine', reference: 'registry-1.docker.io/library/postgres:13-alpine' },
] as const;
