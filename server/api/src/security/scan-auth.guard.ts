import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { verifyIdentity, type Identity } from './identity.js';

export type AuthenticatedRequest = { headers: { authorization?: string }; identity?: Identity };

@Injectable()
export class ScanAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    try {
      request.identity = verifyIdentity(request.headers.authorization, {
        secret: process.env.SCAN_JWT_SECRET || '', issuer: process.env.SCAN_JWT_ISSUER || '',
        audience: process.env.SCAN_JWT_AUDIENCE || '',
      });
      return true;
    } catch {
      throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    }
  }
}
