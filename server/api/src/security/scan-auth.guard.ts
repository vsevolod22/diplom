import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { verifyIdentity, type Identity } from './identity.js';
import { LedgerStore } from '../ledger/ledger-store.js';

export type AuthenticatedRequest = { headers: { authorization?: string; 'last-event-id'?: string }; identity?: Identity };

@Injectable()
export class ScanAuthGuard implements CanActivate {
  constructor(@Inject(LedgerStore) private readonly ledgerStore: LedgerStore) {}
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    try {
      request.identity = verifyIdentity(request.headers.authorization, {
        secret: process.env.SCAN_JWT_SECRET || '', issuer: process.env.SCAN_JWT_ISSUER || '',
        audience: process.env.SCAN_JWT_AUDIENCE || '',
      });
      return true;
    } catch {
      // No bearer or request content is passed to the audit writer.
      try { this.ledgerStore.ledger?.audit('anonymous', 'unknown', 'unknown', 'rejected', 'UNAUTHORIZED'); }
      catch { /* An authentication failure remains a failure if audit storage is down. */ }
      throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    }
  }
}
