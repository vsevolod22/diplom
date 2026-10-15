import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Req,
  Res,
  Inject,
  Header,
  HttpCode,
  HttpException,
} from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { RuntimeIdentity, type RuntimeRequest } from './browser-runtime-identity.js';
import { RuntimeApiService } from './runtime-api.service.js';
import { runtimeBody } from './runtime-intake.js';
import { RuntimeFault } from './runtime-store.js';
import { canonical, exact, ID, str } from '../../../runtime/src/contract.js';
@Controller('api/v1/browser/runtime')
export class BrowserRuntimeController {
  constructor(
    @Inject(RuntimeIdentity) private readonly identity: RuntimeIdentity,
    @Inject(RuntimeApiService) private readonly api: RuntimeApiService,
  ) {}
  private body(req: RuntimeRequest): unknown {
    try {
      return runtimeBody(req);
    } catch {
      throw new HttpException({ errorCode: 'RUNTIME_RAW_INTAKE_REQUIRED' }, 503);
    }
  }
  private async safe<T>(fn: () => T | Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof HttpException) throw e;
      throw new HttpException(
        { errorCode: e instanceof RuntimeFault ? e.code : 'INVALID_RUNTIME_INPUT' },
        e instanceof RuntimeFault ? e.status : 400,
      );
    }
  }
  @Get('capabilities') @Header('Cache-Control', 'no-store') capabilities(@Req() req: RuntimeRequest) {
    this.identity.resolve(req);
    return this.api.capabilities();
  }
  @Get('targets') @Header('Cache-Control', 'no-store') targets(@Req() req: RuntimeRequest) {
    const s = this.identity.resolve(req);
    return this.safe(() => ({ targets: this.api.database().targets(s) }));
  }
  @Post('consents') consent(@Req() req: RuntimeRequest) {
    const s = this.identity.resolve(req, true);
    return this.safe(() => this.api.consents(s, this.body(req)));
  }
  @Post('consents/:id/revoke') @HttpCode(200) revoke(@Req() req: RuntimeRequest, @Param('id') id: string) {
    const s = this.identity.resolve(req, true);
    return this.safe(async () => {
      exact(this.body(req), []);
      return this.api.revoke(s, id);
    });
  }
  @Post('imports') @HttpCode(202) imports(@Req() req: RuntimeRequest) {
    const s = this.identity.resolve(req, true);
    return this.safe(() => this.api.import(s, this.body(req)));
  }
  @Post('captures') @HttpCode(202) create(@Req() req: RuntimeRequest) {
    const s = this.identity.resolve(req, true);
    return this.safe(() => this.api.capture(s, this.body(req)));
  }
  @Get('captures') @Header('Cache-Control', 'no-store') history(
    @Req() req: RuntimeRequest,
    @Query('cursor') cursor?: string,
  ) {
    const s = this.identity.resolve(req);
    return this.safe(() => this.api.database().history(s, cursor));
  }
  @Get('captures/:id') @Header('Cache-Control', 'no-store') detail(
    @Req() req: RuntimeRequest,
    @Param('id') id: string,
  ) {
    const s = this.identity.resolve(req);
    return this.safe(() => this.api.database().read(s, str(id, ID)));
  }
  @Get('captures/:id/results') @Header('Cache-Control', 'no-store') results(
    @Req() req: RuntimeRequest,
    @Param('id') id: string,
  ) {
    const s = this.identity.resolve(req);
    return this.safe(() => this.api.database().read(s, str(id, ID)));
  }
  @Post('captures/:id/cancel') @HttpCode(200) cancel(@Req() req: RuntimeRequest, @Param('id') id: string) {
    const s = this.identity.resolve(req, true);
    return this.safe(async () => {
      exact(this.body(req), []);
      return this.api.cancel(s, id);
    });
  }
  @Post('captures/:id/image-links') @HttpCode(200) link(@Req() req: RuntimeRequest, @Param('id') id: string) {
    const s = this.identity.resolve(req, true);
    return this.safe(() => this.api.imageLink(s, id, this.body(req)));
  }
  @Get('captures/:id/events') events(
    @Req() req: RuntimeRequest,
    @Param('id') id: string,
    @Res() res: ServerResponse,
  ) {
    const s = this.identity.resolve(req);
    return this.safe(() => {
      const header = req.headers['last-event-id'];
      if (header !== undefined && (typeof header !== 'string' || !/^(0|[1-9][0-9]{0,14})$/.test(header)))
        throw new Error('INVALID_RUNTIME_INPUT');
      const events = this.api.database().events(s, str(id, ID), header ? Number(header) : 0);
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-store');
      // Finite durable replay batch, not a long-lived process-local event cache.
      res.end(
        events
          .map(
            (e) =>
              `id: ${e.id}\nevent: runtime-state\ndata: ${canonical({ captureId: id, state: e.state })}\n\n`,
          )
          .join(''),
      );
    });
  }
}
