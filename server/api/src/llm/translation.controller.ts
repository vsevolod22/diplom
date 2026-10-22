import { Body, Controller, Get, HttpException, Inject, Param, Post, Query, Req, Res, ServiceUnavailableException } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { BrowserRequest } from './browser-identity.js';
import { LlmService } from './llm.service.js';
import type { TranslationResult } from './translation.service.js';

// Registered exclusively by PublicImageModule, not the legacy LlmModule.
@Controller('api/v1/browser/scans/:scanId/llm/translation')
export class TranslationController {
  constructor(@Inject(LlmService) private readonly llm: LlmService) {}
  @Get('context')
  async context(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string, @Query() query: unknown) {
    const result = await this.safe(() => this.llm.translation().context(req, scanId, query));
    await this.safe(() => this.write(res, result));
  }
  @Post()
  async translate(@Req() req: IncomingMessage, @Res() res: ServerResponse, @Param('scanId') scanId: string, @Body() body: unknown) {
    const controller = new AbortController(), abort = () => controller.abort();
    req.on('aborted', abort); res.on('close', abort);
    let result: TranslationResult | undefined;
    try {
      result = await this.safe(() => this.llm.translation().generate(req, scanId, body, controller.signal));
      await this.safe(() => this.write(res, result!));
    } finally { result?.release?.(); req.off('aborted', abort); res.off('close', abort); }
  }
  private write(res: ServerResponse, result: TranslationResult) {
    const body = JSON.stringify(result.value);
    result.write(() => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(body);
    });
  }
  private async safe<T>(operation: () => T): Promise<Awaited<T>> {
    try { return await operation(); }
    catch (error) {
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException({ errorCode: 'LLM_UNAVAILABLE' });
    }
  }
}
