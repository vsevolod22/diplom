import { Body, Controller, Get, Header, HttpCode, HttpException, Inject, Param, Post, Req, Res, ServiceUnavailableException } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { BrowserIdentity, type BrowserRequest } from './browser-identity.js';
import { LlmService } from './llm.service.js';
import type { HistoryResult } from './history.service.js';
import type { SummaryPublication } from './summary-result-cache.js';
import { chatRepresentation, writeDelivery } from './history-delivery.js';

@Controller('api/v1/browser/scans/:scanId/llm')
export class LlmController {
  constructor(@Inject(BrowserIdentity) private readonly identity: BrowserIdentity, @Inject(LlmService) private readonly llm: LlmService) {}
  @Get('context')
  @Header('Cache-Control', 'no-store')
  context(@Req() req: BrowserRequest, @Param('scanId') scanId: string) {
    return this.safe(() => this.llm.context(this.identity.resolve(req), scanId));
  }
  @Get('readiness')
  @Header('Cache-Control', 'no-store')
  readiness(@Req() req: BrowserRequest, @Param('scanId') scanId: string) {
    return this.safe(() => this.llm.readiness(this.identity.resolve(req), scanId));
  }
  @Get('usage')
  @Header('Cache-Control', 'no-store')
  usage(@Req() req: BrowserRequest, @Param('scanId') scanId: string) {
    return this.safe(() => this.llm.usage(this.identity.resolve(req), scanId));
  }
  @Get('summary')
  async existingSummary(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string) {
    const result = await this.safe(() => this.llm.readSummary(req, scanId));
    await this.safe(() => this.writeSummaryResponse(res, result));
  }
  private writeSummaryResponse(res: ServerResponse, result: SummaryPublication) {
    const body = JSON.stringify(result.value);
    result.write(() => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store',
        'x-llm-summary-retention': 'process-lifetime' });
      res.end(body);
    });
  }
  @Post('summary')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async summary(@Req() req: IncomingMessage, @Res({ passthrough: true }) res: ServerResponse,
    @Param('scanId') scanId: string, @Body() body: unknown) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    req.on('aborted', abort); res.on('close', abort);
    try {
      if (this.llm.summaryCacheEnabled()) {
        const result = await this.safe(() => this.llm.summaryForBrowser(req, scanId, body, controller.signal));
        await this.safe(() => this.writeSummaryResponse(res, result));
        return;
      }
      return await this.safe(() => this.llm.summary(() => this.identity.resolve(req, true), scanId, body, controller.signal));
    }
    finally { req.off('aborted', abort); res.off('close', abort); }
  }
  @Get('history')
  async history(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string) {
    return this.historyResponse(res, () => this.llm.history().read(req, scanId));
  }
  @Get('chat/context')
  async chatContext(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string) {
    return this.historyResponse(res, () => this.llm.history().context(req, scanId));
  }
  @Get('chat/usage')
  async chatUsage(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string) {
    return this.historyResponse(res, () => this.llm.history().usage(req, scanId));
  }
  @Post('history/decision')
  async decision(@Req() req: BrowserRequest, @Res() res: ServerResponse, @Param('scanId') scanId: string, @Body() body: unknown) {
    return this.historyResponse(res, () => this.llm.history().decision(req, scanId, body));
  }
  @Post('chat')
  async chat(@Req() req: IncomingMessage, @Res() res: ServerResponse, @Param('scanId') scanId: string, @Body() body: unknown) {
    const representation = chatRepresentation(req.headers.accept);
    const controller = new AbortController(), abort = () => controller.abort();
    req.on('aborted', abort); res.on('close', abort);
    let result: HistoryResult | undefined;
    try {
      result = await this.safe(() => this.llm.history().generate(req, scanId, body, controller.signal, representation));
      if (representation === 'ndjson') {
        if (!result.delivery) throw new ServiceUnavailableException({ errorCode: 'LLM_UNAVAILABLE' });
        await this.safe(() => writeDelivery({ delivery: result!.delivery!, write: result!.write, release: () => result?.release?.() }, res, controller.signal));
      } else this.writeHistoryResponse(res, result);
    } finally { result?.release?.(); req.off('aborted', abort); res.off('close', abort); }
  }
  private async historyResponse(res: ServerResponse, operation: () => HistoryResult | Promise<HistoryResult>) {
    const result = await this.safe(operation);
    this.writeHistoryResponse(res, result);
  }
  private writeHistoryResponse(res: ServerResponse, result: HistoryResult) {
    const body = JSON.stringify(result.value);
    // Guard surrounds the actual final write, not a permission used after an await.
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
