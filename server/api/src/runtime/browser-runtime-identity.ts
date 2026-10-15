import { Inject, Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { AuthStore } from '../auth/auth.store.js';
import { tokenFrom, originForRequest } from '../auth/auth.controller.js';
import { hasRuntimeHeader } from './runtime-http.js';
export type RuntimeRequest = {
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
  rawHeaders?: readonly string[];
};
@Injectable()
export class RuntimeIdentity {
  constructor(@Inject(AuthStore) private readonly auth: AuthStore) {}
  resolve(req: RuntimeRequest, mutation = false): string {
    if (hasRuntimeHeader(req, 'authorization') || req.headers['sec-fetch-site'] === 'cross-site')
      throw new ForbiddenException({ errorCode: 'INVALID_BROWSER_REQUEST' });
    if (mutation) originForRequest(req);
    const user = this.auth.userForToken(tokenFrom(req) ?? '');
    if (!user) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    // Account authentication is not runtime rights. Store checks enrolled target/consent separately.
    return user.id;
  }
}
