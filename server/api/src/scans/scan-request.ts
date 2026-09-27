import { parseImageReference, requestFingerprint, type ImageReference } from './image-reference.js';

export type ScanRequest = { reference: ImageReference; checks: readonly string[]; scope: 'image'; idempotencyKey: string; fingerprint: string };
export function parseScanRequest(body: unknown, allowedRegistries: ReadonlySet<string>): ScanRequest {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('Invalid scan request');
  const data = body as Record<string, unknown>;
  if (Object.keys(data).some(key => !['imageReference', 'checks', 'scope', 'idempotencyKey'].includes(key)) ||
      !Array.isArray(data.checks) || data.checks.length < 1 || data.checks.length > 3 ||
      data.checks.some(value => typeof value !== 'string' || !['vuln', 'secret', 'license'].includes(value)) ||
      new Set(data.checks).size !== data.checks.length || data.scope !== 'image' ||
      typeof data.idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(data.idempotencyKey)) {
    throw new TypeError('Invalid scan request');
  }
  const reference = parseImageReference(data.imageReference, allowedRegistries);
  const checks = data.checks as string[];
  return { reference, checks, scope: 'image', idempotencyKey: data.idempotencyKey,
    fingerprint: requestFingerprint(reference, checks, 'image') };
}
