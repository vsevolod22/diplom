import { Body, Controller, Get, Header, HttpCode, HttpException, Inject, Param, Post, Req, Res, ServiceUnavailableException } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { BrowserIdentity, type BrowserRequest } from './browser-identity.js';
import { LlmService } from './llm.service.js';

@Controller('api/v1/browser/scans/:scanId/llm')
export class LlmController {
  constructor(@Inject(BrowserIdentity) private readonly identity: BrowserIdentity, @Inject(LlmService) private readonly llm: LlmService) {}
  @Get('context')
  @Header('Cache-Control', 'no-store')
  context(@Req() req: BrowserRequest, @Param('scanId') scanId: string) {
    return this.safe(() => this.llm.context(this.identity.resolve(req), scanId));
  }
  @Get('usage')
  @Header('Cache-Control', 'no-store')
  usage(@Req() req: BrowserRequest, @Param('scanId') scanId: string) {
    return this.safe(() => this.llm.usage(this.identity.resolve(req), scanId));
  }
  @Post('summary')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async summary(@Req() req: IncomingMessage, @Res({ passthrough: true }) res: ServerResponse,
    @Param('scanId') scanId: string, @Body() body: unknown) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    req.on('aborted', abort); res.on('close', abort);
    try { return await this.safe(() => this.llm.summary(() => this.identity.resolve(req, true), scanId, body, controller.signal)); }
    finally { req.off('aborted', abort); res.off('close', abort); }
  }
  private async safe<T>(operation: () => T): Promise<Awaited<T>> {
    try { return await operation(); }
    catch (error) {
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException({ errorCode: 'LLM_UNAVAILABLE' });
    }
  }
}
