import { Body, Controller, Get, HttpCode, Inject, Param, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
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

  @Get()
  list(@Req() request: AuthenticatedRequest, @Query('cursor') cursor?: string, @Query('limit') limit?: string) {
    return this.scans.list(request.identity!, cursor, limit);
  }

  @Post(':scanId/cancel')
  @HttpCode(200)
  cancel(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string, @Body() body: unknown) {
    return this.scans.cancel(request.identity!, scanId, body);
  }

  @Get(':scanId')
  status(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string) {
    return this.scans.status(request.identity!, scanId);
  }

  @Get(':scanId/results')
  results(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string, @Query() query: unknown) {
    return this.scans.report(request.identity!, scanId, 'secret', query);
  }

  @Get(':scanId/sbom')
  sbom(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string, @Query() query: unknown) {
    return this.scans.report(request.identity!, scanId, 'sbom', query);
  }

  @Get(':scanId/vuln')
  vuln(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string, @Query() query: unknown) {
    return this.scans.report(request.identity!, scanId, 'vuln', query);
  }

  @Get(':scanId/events')
  events(@Req() request: AuthenticatedRequest, @Param('scanId') scanId: string, @Res() response: ServerResponse): void {
    this.scans.events(request.identity!, scanId, request.headers['last-event-id'], response);
  }
}
