import { Body, Controller, Get, Header, HttpCode, HttpException, HttpStatus, Inject, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthStore, validPassword, type AuthAction, type SessionSnapshot, type User } from './auth.store.js';
import { PasswordResetService, type PasswordResetStatus } from './password-reset.service.js';

const COOKIE = 'demo_session';
type Request = { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string; encrypted?: boolean } };
type Response = { setHeader(name: string, value: string): void };
const invalid = (status: HttpStatus, code: string): never => { throw new HttpException({ errorCode: code }, status); };

export function originForRequest(req: Request): { secure: boolean } {
  const allowed = process.env.AUTH_ORIGIN;
  let url: URL;
  try {
    if (!allowed) throw new Error('missing origin');
    url = new URL(allowed);
    if (url.origin !== allowed || url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      !['https:', 'http:'].includes(url.protocol)) throw new Error('invalid origin');
    if (url.protocol === 'http:' &&
      !(process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP === 'true' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
      throw new Error('insecure origin');
    }
  } catch { return invalid(HttpStatus.SERVICE_UNAVAILABLE, 'AUTH_UNAVAILABLE'); }
  if (req.headers.origin !== allowed) return invalid(HttpStatus.FORBIDDEN, 'INVALID_ORIGIN');
  return { secure: url.protocol === 'https:' };
}

function credentials(body: unknown): { email: string; password: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  const input = body as Record<string, unknown>;
  if (Object.keys(input).sort().join(',') !== 'email,password' ||
    typeof input.email !== 'string' || typeof input.password !== 'string') return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  const email = input.email.trim().toLowerCase();
  if (email.length > 254 || Buffer.byteLength(email) > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    Buffer.byteLength(input.password) < 12 || Buffer.byteLength(input.password) > 128) {
    return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  }
  return { email, password: input.password };
}

export function tokenFrom(req: Request): string | null {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return null;
  const values = header.split(';').map(part => part.trim()).filter(part => part.startsWith(`${COOKIE}=`));
  if (values.length !== 1) return null;
  const token = values[0].slice(COOKIE.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function setCookie(res: Response, token: string, secure: boolean): void {
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure ? '; Secure' : ''}`);
}

function clearCookie(res: Response, secure: boolean): void {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure ? '; Secure' : ''}`);
}

function exactInput(body: unknown, keys: string[]): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join(',') !== keys.sort().join(','))
    return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  return body as Record<string, unknown>;
}

function normalizedEmail(value: unknown): string {
  if (typeof value !== 'string') return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  const email = value.trim().toLowerCase();
  if (Buffer.byteLength(email) > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
  return email;
}

@Controller('api/v1/auth')
export class AuthController {
  constructor(
    @Inject(AuthStore) private readonly store: AuthStore,
    @Inject(PasswordResetService) private readonly reset: PasswordResetService,
  ) {}

  @Post('register')
  @Header('Cache-Control', 'no-store')
  async register(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() body: unknown): Promise<User> {
    const { secure } = this.checkMutation(req);
    const { email, password } = credentials(body);
    if (!this.store.rateLimit('register', email, req.socket.remoteAddress ?? 'unknown'))
      return invalid(HttpStatus.TOO_MANY_REQUESTS, 'RATE_LIMITED');
    const user = await this.store.register(email, password);
    if (!user) return invalid(HttpStatus.CONFLICT, 'REGISTRATION_UNAVAILABLE');
    setCookie(res, this.store.createAuthenticatedSession(user, tokenFrom(req)), secure);
    return user;
  }

  @Post('login')
  @Header('Cache-Control', 'no-store')
  @HttpCode(200)
  async login(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() body: unknown): Promise<User> {
    const { secure } = this.checkMutation(req);
    const { email, password } = credentials(body);
    if (!this.store.rateLimit('login', email, req.socket.remoteAddress ?? 'unknown'))
      return invalid(HttpStatus.TOO_MANY_REQUESTS, 'RATE_LIMITED');
    const user = await this.store.login(email, password);
    if (!user) throw new UnauthorizedException({ errorCode: 'INVALID_CREDENTIALS' });
    setCookie(res, this.store.createAuthenticatedSession(user, tokenFrom(req)), secure);
    return user;
  }

  @Post('logout')
  @Header('Cache-Control', 'no-store')
  @HttpCode(204)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): void {
    const { secure } = this.checkMutation(req);
    const token = tokenFrom(req);
    if (token) this.store.revoke(token);
    else this.store.userForToken(''); // Check storage availability even for anonymous mutations.
    res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure ? '; Secure' : ''}`);
  }

  @Get('me')
  @Header('Cache-Control', 'no-store')
  me(@Req() req: Request): User {
    const token = tokenFrom(req);
    const user = this.store.userForToken(token ?? '');
    if (!user) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    return user;
  }

  @Post('change-password')
  @Header('Cache-Control', 'no-store')
  @HttpCode(204)
  async changePassword(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() body: unknown): Promise<void> {
    return this.safe(async () => {
      const { secure } = this.checkMutation(req, 2048);
      const snapshot = this.currentSession(req);
      this.limit('change-password', snapshot.subject, req);
      const input = exactInput(body, ['currentPassword', 'newPassword']);
      if (!validPassword(input.currentPassword) || !validPassword(input.newPassword)) return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
      if (!await this.store.changePassword(snapshot, input.currentPassword, input.newPassword))
        return invalid(HttpStatus.UNAUTHORIZED, 'INVALID_CREDENTIALS');
      clearCookie(res, secure);
    });
  }

  @Post('revoke-all')
  @Header('Cache-Control', 'no-store')
  @HttpCode(204)
  async revokeAll(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() body: unknown): Promise<void> {
    return this.safe(async () => {
      const { secure } = this.checkMutation(req, 2048);
      const snapshot = this.currentSession(req);
      this.limit('revoke-all', snapshot.subject, req);
      const input = exactInput(body, ['currentPassword']);
      if (!validPassword(input.currentPassword)) return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
      if (!await this.store.revokeAll(snapshot, input.currentPassword)) return invalid(HttpStatus.UNAUTHORIZED, 'INVALID_CREDENTIALS');
      clearCookie(res, secure);
    });
  }

  @Get('password-reset/status')
  @Header('Cache-Control', 'no-store')
  passwordResetStatus(): PasswordResetStatus { return this.reset.status(); }

  @Post('password-reset/request')
  @Header('Cache-Control', 'no-store')
  @HttpCode(202)
  async requestPasswordReset(@Req() req: Request, @Body() body: unknown): Promise<{ status: 'accepted' }> {
    return this.safe(() => {
      this.checkMutation(req, 2048);
      this.reset.requireAvailable();
      const input = exactInput(body, ['email']);
      const email = normalizedEmail(input.email);
      this.limit('reset-request', email, req);
      this.reset.request(email);
      // Acceptance of a bounded recovery attempt, NOT confirmation of an account or delivery.
      return { status: 'accepted' as const };
    });
  }

  @Post('password-reset/confirm')
  @Header('Cache-Control', 'no-store')
  @HttpCode(204)
  async confirmPasswordReset(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() body: unknown): Promise<void> {
    return this.safe(async () => {
      const { secure } = this.checkMutation(req, 2048);
      this.reset.requireAvailable();
      const input = exactInput(body, ['token', 'newPassword']);
      if (typeof input.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.token) || !validPassword(input.newPassword))
        return invalid(HttpStatus.BAD_REQUEST, 'INVALID_INPUT');
      this.limit('reset-confirm', input.token, req);
      if (!await this.store.confirmPasswordReset(input.token, input.newPassword)) return invalid(HttpStatus.BAD_REQUEST, 'INVALID_RESET_TOKEN');
      clearCookie(res, secure);
    });
  }

  private currentSession(req: Request): SessionSnapshot {
    const snapshot = this.store.sessionForToken(tokenFrom(req) ?? '');
    if (!snapshot) return invalid(HttpStatus.UNAUTHORIZED, 'UNAUTHORIZED');
    return snapshot;
  }

  private limit(action: AuthAction, identity: string, req: Request): void {
    // Forwarded headers remain untrusted until infra supplies a qualified proxy contract.
    if (!this.store.rateLimit(action, identity, req.socket.remoteAddress ?? 'unknown')) return invalid(HttpStatus.TOO_MANY_REQUESTS, 'RATE_LIMITED');
  }

  private async safe<T>(action: () => T | Promise<T>): Promise<T> {
    try { return await action(); }
    catch (error) {
      if (error instanceof HttpException) throw error;
      return invalid(HttpStatus.SERVICE_UNAVAILABLE, 'AUTH_UNAVAILABLE');
    }
  }

  private checkMutation(req: Request, maxBytes = 512): { secure: boolean } {
    const origin = originForRequest(req);
    const length = req.headers['content-length'];
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? '')) ||
      typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > maxBytes) {
      return invalid(HttpStatus.UNSUPPORTED_MEDIA_TYPE, 'INVALID_CONTENT_TYPE');
    }
    return origin;
  }
}
