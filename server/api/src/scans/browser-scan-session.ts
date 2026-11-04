import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import type { AuthStore } from '../auth/auth.store.js';
import { tokenFrom } from '../auth/auth.controller.js';
import { browserIdentity, type BrowserRequest, type BrowserScanLocalOrigin } from '../llm/browser-identity.js';
import type { Identity } from '../security/identity.js';

/** Execute a synchronous commit/publication while the original browser session is live. */
export type ScanSessionGuard = <T>(action: () => T) => T;

export function browserScanSession(store: AuthStore, request: BrowserRequest, mutation: boolean,
  localOrigin: BrowserScanLocalOrigin): { identity: Identity; guard: ScanSessionGuard } {
  const identity = browserIdentity(store, request, mutation, localOrigin);
  const session = store.sessionForToken(tokenFrom(request) ?? '');
  if (!session || session.subject !== identity.subject)
    throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
  return {
    identity,
    guard: action => {
      // Recheck enrollment/origin too, but never replace the captured session with a
      // newer login for the same owner. guardSession fences revocation across action.
      const current = browserIdentity(store, request, mutation, localOrigin);
      if (current.subject !== identity.subject) throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
      return store.guardSession(session, action, 100);
    },
  };
}
