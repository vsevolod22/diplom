import { Body, Controller, Get, Header, HttpCode, Inject, Param, Post, Query, Req, UseGuards } from '@nestjs/common';
import { ScanAuthGuard, type AuthenticatedRequest } from '../security/scan-auth.guard.js';
import { ScansService } from './scans.service.js';

@Controller('api/v1/scans')
@UseGuards(ScanAuthGuard)
export class ScansController {
  constructor(@Inject(ScansService) private readonly scans: ScansService) {}

  @Post()
  @HttpCode(202)
  create(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.scans.create(request.identity!, body);
  }

  @Get(':scanId')
  status(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string) {
    return this.scans.status(request.identity!, scanId);
  }

  @Get(':scanId/results')
  results(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string,
    @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.results(request.identity!, scanId, cursor, limit);
  }

  @Get(':scanId/events')
  @Header('Content-Type', 'text/event-stream')
  @Header('Cache-Control', 'no-store')
  events(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string): string {
    const last = request.headers['last-event-id'];
    return `retry: 2000\n${this.scans.events(request.identity!, scanId, typeof last === 'string' ? last : undefined)}`;
  }
}
