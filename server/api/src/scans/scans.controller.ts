import { Body, Controller, Inject, Post, Req, UseGuards } from '@nestjs/common';
import { ScanAuthGuard, type AuthenticatedRequest } from '../security/scan-auth.guard.js';
import { ScansService } from './scans.service.js';

@Controller('api/v1/scans')
@UseGuards(ScanAuthGuard)
export class ScansController {
  constructor(@Inject(ScansService) private readonly scans: ScansService) {}

  @Post()
  create(@Req() request: AuthenticatedRequest, @Body() body: unknown): never {
    return this.scans.create(request.identity!, body);
  }
}
