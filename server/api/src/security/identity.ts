import { createHmac, timingSafeEqual } from 'node:crypto';

export type Identity = { subject: string; scope: readonly string[] };
export class InvalidIdentity extends Error {}

// HS256 is only suitable when this service and the trusted issuer share a dedicated secret.
// Never reuse the legacy SCAN_API_TOKEN as a subject or as a signing key.
export function verifyIdentity(authorization: string | undefined, config: {
  secret: string; issuer: string; audience: string; now?: number;
}): Identity {
  if (!config.secret || Buffer.byteLength(config.secret) < 32 || !config.issuer || !config.audience ||
      !authorization?.startsWith('Bearer ')) throw new InvalidIdentity();
  const jwt = authorization.slice(7);
  const parts = jwt.split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p) || p.length > 4096)) throw new InvalidIdentity();
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    if (header.alg !== 'HS256' || header.typ !== 'JWT' || header.kid !== undefined || header.crit !== undefined) throw new InvalidIdentity();
    const signature = createHmac('sha256', config.secret).update(`${parts[0]}.${parts[1]}`).digest();
    const presented = Buffer.from(parts[2], 'base64url');
    if (signature.length !== presented.length || !timingSafeEqual(signature, presented)) throw new InvalidIdentity();
    const now = config.now ?? Math.floor(Date.now() / 1000);
    if (payload.iss !== config.issuer ||
        !(payload.aud === config.audience || (Array.isArray(payload.aud) && payload.aud.includes(config.audience))) ||
        typeof payload.sub !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(payload.sub) ||
        typeof payload.exp !== 'number' || !Number.isSafeInteger(payload.exp) || payload.exp <= now ||
        payload.exp > now + 3600 || typeof payload.iat !== 'number' || payload.iat > now + 60 ||
        (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || payload.nbf > now))) throw new InvalidIdentity();
    const scope = typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
    if (!scope.includes('scan:create')) throw new InvalidIdentity();
    return { subject: payload.sub, scope };
  } catch { throw new InvalidIdentity(); }
}
