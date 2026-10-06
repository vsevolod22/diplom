import { parseImageReference, requestFingerprint, type ImageReference } from './image-reference.js';

export type ScanCheck = 'secret' | 'sbom' | 'vuln' | 'config';
export type ScanRequest = { reference: ImageReference; checks: readonly ScanCheck[]; scope: 'image'; idempotencyKey: string; fingerprint: string };
export function parseScanRequest(body: unknown, allowedRegistries: ReadonlySet<string>): ScanRequest {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('Invalid scan request');
  const data = body as Record<string, unknown>;
  const checks = data.checks;
  if (Object.keys(data).some(key => !['imageReference', 'checks', 'scope', 'idempotencyKey'].includes(key)) ||
      !Array.isArray(checks) || checks.length < 1 || checks.length > 4 ||
      checks.some((check, index) => !['secret', 'sbom', 'vuln', 'config'].includes(check) ||
        index > 0 && ['secret', 'sbom', 'vuln', 'config'].indexOf(checks[index - 1]) >=
          ['secret', 'sbom', 'vuln', 'config'].indexOf(check)) || data.scope !== 'image' ||
      typeof data.idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(data.idempotencyKey)) {
    throw new TypeError('Invalid scan request');
  }
  const reference = parseImageReference(data.imageReference, allowedRegistries);
  return { reference, checks: checks as ScanCheck[], scope: 'image', idempotencyKey: data.idempotencyKey,
    fingerprint: requestFingerprint(reference, checks as ScanCheck[], 'image') };
}
