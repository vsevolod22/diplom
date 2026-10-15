import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseRuntimeJson } from './runtime-json.js';
import { originForRequest } from '../auth/auth.controller.js';
import { hasRuntimeHeader, RUNTIME_PREFIX, runtimeRequestPath } from './runtime-http.js';

const BODIES = new WeakMap<object, unknown>();
let active = 0;
const owners = new Map<string, number>();
const rates = new Map<string, { start: number; count: number }>();
function admitRate(key: string, limit: number): boolean {
  const now = Date.now();
  for (const [k, v] of rates) if (now - v.start >= 60000) rates.delete(k);
  const prior = rates.get(key);
  if (!prior && rates.size >= 1024) return false;
  if (prior && prior.count >= limit) return false;
  rates.set(key, { start: prior?.start ?? now, count: (prior?.count ?? 0) + 1 });
  return true;
}
export function runtimeBody(req: object): unknown {
  if (!BODIES.has(req)) throw new Error('RUNTIME_RAW_INTAKE_REQUIRED');
  return BODIES.get(req);
}
export { RUNTIME_PREFIX } from './runtime-http.js';
const control =
  /^\/api\/v1\/browser\/runtime\/(?:consents|consents\/[a-f0-9]{32}\/revoke|captures|captures\/[a-f0-9]{32}\/(?:cancel|image-links))$/;
// Parent installs this BEFORE app.useBodyParser('json'); mutation DTOs never use @Body.
export type RuntimeIntakeIdentity = (req: IncomingMessage) => string;
export function createRuntimeIntake(identity: RuntimeIntakeIdentity) {
  return (req: IncomingMessage, res: ServerResponse, next: () => void): void =>
    intake(req, res, next, identity);
}
// Unconfigured compatibility hook is fail-closed; parent must inject real Nest RuntimeIdentity before parsing.
export function runtimeIntake(req: IncomingMessage, res: ServerResponse, next: () => void): void {
  intake(req, res, next);
}
function intake(
  req: IncomingMessage,
  res: ServerResponse,
  next: () => void,
  identity?: RuntimeIntakeIdentity,
): void {
  const { pathname, protectedNamespace } = runtimeRequestPath(req.url ?? '');
  if (!protectedNamespace) {
    next();
    return;
  }
  res.setHeader('Cache-Control', 'no-store');
  const deny = (status: number, code: string) => {
    if (!res.headersSent) {
      res.setHeader('Connection', 'close');
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify({ errorCode: code }));
    }
  };
  // Express matches case variants and optional trailing slashes. Classify them as protected,
  // but admit only the original canonical route; never let them fall through to ordinary JSON.
  if (!(req.url ?? '').startsWith('/') ||
      !pathname.startsWith(`${RUNTIME_PREFIX}/`) || pathname !== pathname.toLowerCase())
    return deny(400, 'INVALID_RUNTIME_INPUT');
  if (req.method !== 'POST') {
    next();
    return;
  }
  const importRoute = pathname === `${RUNTIME_PREFIX}/imports`;
  const cap = importRoute ? 65536 : 1024;
  // Explicit conservative process-global pre-auth budget, independent of proxy peers/X-Forwarded-For.
  if (!admitRate('preauth-global', 60)) return deny(429, 'RUNTIME_CAPACITY');
  try {
    if (
      (!importRoute && !control.test(pathname)) ||
      req.url !== pathname ||
      hasRuntimeHeader(req, 'authorization') ||
      req.headers['sec-fetch-site'] === 'cross-site' ||
      hasRuntimeHeader(req, 'content-encoding') ||
      hasRuntimeHeader(req, 'transfer-encoding') ||
      hasRuntimeHeader(req, 'expect')
    )
      return deny(400, 'INVALID_RUNTIME_INPUT');
    const unique = new Set<string>();
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const key = req.rawHeaders[i].toLowerCase();
      if (
        unique.has(key) &&
        ['content-length', 'content-type', 'origin', 'cookie', 'authorization'].includes(key)
      )
        return deny(400, 'INVALID_RUNTIME_INPUT');
      unique.add(key);
    }
    originForRequest(req);
    const length = req.headers['content-length'];
    if (
      typeof length !== 'string' ||
      !/^(0|[1-9][0-9]*)$/.test(length) ||
      Number(length) > cap ||
      !/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? ''))
    )
      return deny(413, 'INVALID_RUNTIME_INPUT');
    if (!identity) return deny(503, 'RUNTIME_RAW_INTAKE_REQUIRED');
    let subject: string;
    try {
      subject = identity(req);
    } catch (error: unknown) {
      const status =
        error && typeof error === 'object' && 'getStatus' in error && typeof error.getStatus === 'function'
          ? (error.getStatus() as number)
          : 401;
      return deny(status === 403 ? 403 : 401, 'UNAUTHORIZED');
    }
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(subject)) return deny(401, 'UNAUTHORIZED');
    if (active >= 2 || owners.has(subject) || !admitRate(`owner:${subject}`, 12))
      return deny(429, 'RUNTIME_CAPACITY');
    active++;
    owners.set(subject, 1);
    let size = 0;
    const chunks: Buffer[] = [];
    let finished = false;
    const finish = () => {
      active--;
      owners.delete(subject);
      clearTimeout(timer);
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onError);
    };
    const onError = () => {
      if (finished) return;
      finished = true;
      finish();
      deny(400, 'INVALID_RUNTIME_INPUT');
    };
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > cap || size > Number(length)) {
        onError();
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (finished) return;
      finished = true;
      finish();
      if (size !== Number(length)) return deny(400, 'INVALID_RUNTIME_INPUT');
      try {
        BODIES.set(req, parseRuntimeJson(Buffer.concat(chunks, size)));
        next();
      } catch {
        deny(400, 'INVALID_RUNTIME_INPUT');
      }
    };
    const timer = setTimeout(onError, 5000);
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onError);
  } catch {
    deny(403, 'INVALID_BROWSER_REQUEST');
  }
}
