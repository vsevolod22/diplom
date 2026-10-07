import { Body, Controller, Get, Header, HttpCode, HttpException, Inject, Param, Post, Query, Req, Res } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { AuthStore } from '../auth/auth.store.js';
import { browserIdentity, type BrowserRequest } from '../llm/browser-identity.js';
import { ScansService } from './scans.service.js';
import type { Identity } from '../security/identity.js';
import { ImageSearchSessions } from './image-search.js';


// The browser never receives a bearer token. The shared cookie bridge keeps the
// internal JWT-only scan controller's authentication independent.
@Controller('api/v1/browser/scans')
export class BrowserScansController {
  private readonly imageSearch: ImageSearchSessions;
  constructor(@Inject(AuthStore) private readonly store: AuthStore, @Inject(ScansService) private readonly scans: ScansService) {
    this.imageSearch = new ImageSearchSessions(undefined, undefined, item => this.scans.imageSuggestion(item));
  }

  private identity(req: BrowserRequest, mutation = false): Identity {
    return browserIdentity(this.store, req, mutation);
  }

  @Get('images')
  @Header('Cache-Control', 'no-store')
  searchImages(@Req() req: BrowserRequest, @Query('q') query?: string, @Query('generation') generation?: string, @Query('cursor') cursor?: string) {
    const { subject } = this.identity(req);
    return this.imageSearch.search(subject, query, generation, cursor);
  }

  private async withRetryHeaders(response: ServerResponse, operation: () => Promise<unknown>) {
    response.setHeader('Cache-Control', 'no-store');
    try { return await operation(); }
    catch (error) {
      if (error instanceof HttpException && error.getStatus() === 429) {
        const body = error.getResponse();
        const seconds = typeof body === 'object' && body !== null && 'retryAfterSeconds' in body ? body.retryAfterSeconds : undefined;
        if (typeof seconds === 'number' && Number.isInteger(seconds) && seconds >= 1 && seconds <= 60)
          response.setHeader('Retry-After', String(seconds));
      }
      throw error;
    }
  }

  @Post('images/eligibility')
  @Header('Cache-Control', 'no-store')
  @HttpCode(200)
  eligibility(@Req() req: BrowserRequest, @Body() body: unknown, @Res({ passthrough: true }) response: ServerResponse) {
    return this.withRetryHeaders(response, () => this.scans.eligibility(this.identity(req, true), body));
  }

  @Post()
  @Header('Cache-Control', 'no-store')
  @HttpCode(202)
  create(@Req() req: BrowserRequest, @Body() body: unknown, @Res({ passthrough: true }) response: ServerResponse) {
    return this.withRetryHeaders(response, () => this.scans.create(this.identity(req, true), body));
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
