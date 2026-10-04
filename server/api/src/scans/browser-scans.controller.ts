import { Body, Controller, ForbiddenException, Get, Header, HttpCode, HttpException, HttpStatus, Inject, Param, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { AuthStore } from '../auth/auth.store.js';
import { originForRequest, tokenFrom } from '../auth/auth.controller.js';
import { ScansService } from './scans.service.js';
import type { Identity } from '../security/identity.js';
import { ImageSearchSessions } from './image-search.js';

type BrowserRequest = { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string } };

// The browser never receives a bearer token. This controller is the sole session-to-scan
// bridge; the internal JWT-only scan controller keeps its independent authentication.
@Controller('api/v1/browser/scans')
export class BrowserScansController {
  private readonly imageSearch: ImageSearchSessions;
  constructor(@Inject(AuthStore) private readonly store: AuthStore, @Inject(ScansService) private readonly scans: ScansService) {
    this.imageSearch = new ImageSearchSessions(undefined, undefined, item => this.scans.imageSuggestion(item));
  }

  private identity(req: BrowserRequest, mutation = false): Identity {
    // The demo override is deliberately impossible to use with a public/HTTPS origin.
    const localDemoRequested = process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS === 'true';
    const localDemo = localDemoRequested && process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP === 'true' &&
      process.env.AUTH_ORIGIN === 'http://127.0.0.1:8080';
    const allowed = process.env.SCAN_BROWSER_ALLOWED_USER_IDS;
    if ((localDemoRequested && !localDemo) || (!localDemo && !allowed)) {
      throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DISABLED' });
    }
    if (req.headers.authorization || req.headers['sec-fetch-site'] === 'cross-site') {
      throw new ForbiddenException({ errorCode: 'INVALID_BROWSER_REQUEST' });
    }
    const user = this.store.userForToken(tokenFrom(req) ?? '');
    if (!user) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    if (!localDemo && !allowed?.split(',').map(id => id.trim()).includes(user.id)) {
      throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
    }
    if (mutation) {
      originForRequest(req);
      const length = req.headers['content-length'];
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? '')) ||
          typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > 1024) {
        throw new HttpException({ errorCode: 'INVALID_CONTENT_TYPE' }, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
      }
    }
    return { subject: user.id, scope: ['scan:create', 'scan:list', 'scan:cancel'] };
  }

  @Get('images')
  @Header('Cache-Control', 'no-store')
  searchImages(@Req() req: BrowserRequest, @Query('q') query?: string, @Query('generation') generation?: string, @Query('cursor') cursor?: string) {
    const { subject } = this.identity(req);
    return this.imageSearch.search(subject, query, generation, cursor);
  }

  @Post()
  @Header('Cache-Control', 'no-store')
  @HttpCode(202)
  create(@Req() req: BrowserRequest, @Body() body: unknown) {
    return this.scans.create(this.identity(req, true), body);
  }

  @Get()
  @Header('Cache-Control', 'no-store')
  list(@Req() req: BrowserRequest, @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.list(this.identity(req), cursor, limit);
  }

  @Post(':scanId/cancel')
  @Header('Cache-Control', 'no-store')
  @HttpCode(200)
  cancel(@Req() req: BrowserRequest, @Param('scanId') id: string, @Body() body: unknown) {
    return this.scans.cancel(this.identity(req, true), id, body);
  }

  @Get(':scanId')
  @Header('Cache-Control', 'no-store')
  status(@Req() req: BrowserRequest, @Param('scanId') id: string) {
    return this.scans.status(this.identity(req), id);
  }

  @Get(':scanId/results')
  @Header('Cache-Control', 'no-store')
  results(@Req() req: BrowserRequest, @Param('scanId') id: string, @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.results(this.identity(req), id, cursor, limit);
  }

  @Get(':scanId/sbom')
  @Header('Cache-Control', 'no-store')
  sbom(@Req() req: BrowserRequest, @Param('scanId') id: string, @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.sbom(this.identity(req), id, cursor, limit);
  }

  @Get(':scanId/vuln')
  @Header('Cache-Control', 'no-store')
  vuln(@Req() req: BrowserRequest, @Param('scanId') id: string, @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.vuln(this.identity(req), id, cursor, limit);
  }

  @Get(':scanId/events')
  events(@Req() req: BrowserRequest, @Param('scanId') id: string, @Res() response: ServerResponse): void {
    this.scans.events(this.identity(req), id, req.headers['last-event-id'], response);
  }
}
