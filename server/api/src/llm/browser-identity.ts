import { ForbiddenException, HttpException, HttpStatus, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthStore } from '../auth/auth.store.js';
import { originForRequest, tokenFrom } from '../auth/auth.controller.js';
import type { Identity } from '../security/identity.js';

export type BrowserRequest = { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string } };

// Shared cookie bridge: private JWT scopes and existing browser gates remain independent.
export function browserIdentity(store: AuthStore, req: BrowserRequest, mutation = false): Identity {
  const localDemoRequested = process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS === 'true';
  const localDemo = localDemoRequested && process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP === 'true' &&
    process.env.AUTH_ORIGIN === 'http://127.0.0.1:8080';
  const allowed = process.env.SCAN_BROWSER_ALLOWED_USER_IDS;
  if ((localDemoRequested && !localDemo) || (!localDemo && !allowed))
    throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DISABLED' });
  if (req.headers.authorization || req.headers['sec-fetch-site'] === 'cross-site')
    throw new ForbiddenException({ errorCode: 'INVALID_BROWSER_REQUEST' });
  const user = store.userForToken(tokenFrom(req) ?? '');
  if (!user) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
  if (!localDemo && !allowed?.split(',').map(id => id.trim()).includes(user.id))
    throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
  if (mutation) {
    originForRequest(req);
    const length = req.headers['content-length'];
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? '')) ||
        typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > 1024)
      throw new HttpException({ errorCode: 'INVALID_CONTENT_TYPE' }, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
  }
  return { subject: user.id, scope: ['scan:create', 'scan:list', 'scan:cancel'] };
}

@Injectable()
export class BrowserIdentity {
  constructor(@Inject(AuthStore) private readonly store: AuthStore) {}
  resolve(req: BrowserRequest, mutation = false): Identity {
    const identity = browserIdentity(this.store, req, mutation);
    return { subject: identity.subject, scope: [...identity.scope, 'scan:read'] };
  }
}
