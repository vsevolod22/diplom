import { ArgumentsHost, Catch, HttpException, Inject } from '@nestjs/common';
import { APP_FILTER, BaseExceptionFilter, HttpAdapterHost } from '@nestjs/core';
import type { ServerResponse } from 'node:http';
import { quotaDenial } from './quota-policy.js';

const safeCodes = new Set(['LLM_UNAVAILABLE', 'LLM_INVALID_REQUEST', 'LLM_CONSENT_REQUIRED', 'LLM_STALE_REPORT',
  'LLM_STALE_POLICY', 'LLM_CONTEXT_LIMIT', 'LLM_NO_EVIDENCE', 'LLM_CAPACITY', 'LLM_REQUEST_ABORTED', 'LLM_RESPONSE_LIMIT',
  'LLM_PROVIDER_UNAVAILABLE', 'LLM_INVALID_RESPONSE', 'LLM_REPORT_UNAVAILABLE', 'LLM_CONFIGURATION_UNAVAILABLE',
    'LLM_QUOTA_UNAVAILABLE', 'LLM_QUOTA_EXCEEDED', 'LLM_HISTORY_UNAVAILABLE', 'LLM_HISTORY_CONFLICT', 'LLM_HISTORY_CAPACITY',
  'SCAN_ACCESS_DENIED', 'SCAN_ACCESS_DISABLED', 'SCAN_NOT_FOUND', 'INVALID_BROWSER_REQUEST', 'UNAUTHORIZED',
  'INVALID_ORIGIN', 'INVALID_CONTENT_TYPE', 'AUTH_UNAVAILABLE']);

// Express JSON/size errors occur before controller filters and can contain raw body
// excerpts. The global registration is necessary; handling is restricted to LLM URLs.
@Catch()
export class LlmExceptionFilter extends BaseExceptionFilter {
  constructor(@Inject(HttpAdapterHost) private readonly adapters: HttpAdapterHost) { super(adapters.httpAdapter); }
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const request = http.getRequest<{ originalUrl?: string; url?: string }>();
    // Match Express's case-insensitive, optional-trailing-slash literal routes.
    // Do not decode static segments: Express does not route their encoded aliases.
    if (!/^\/api\/v1\/browser\/scans\/[^/?]+\/llm\/(?:context|summary|usage|history(?:\/decision)?|chat(?:\/(?:context|usage))?)\/?(?:\?|$)/i.test(request.originalUrl ?? request.url ?? ''))
      return super.catch(exception, host);
    const response = http.getResponse<ServerResponse>();
    const adapter = this.adapters.httpAdapter;
    if (adapter.isHeadersSent(response)) { adapter.end(response); return; }
    let status = exception instanceof HttpException ? exception.getStatus() : 500;
    if (exception instanceof Error && 'type' in exception && 'status' in exception &&
        ['entity.parse.failed', 'entity.too.large'].includes(String(exception.type)) &&
        typeof exception.status === 'number' && [400, 413].includes(exception.status)) status = exception.status;
    if (status < 400 || status > 599) status = 500;
    let errorCode = status === 400 || status === 413 ? 'LLM_INVALID_REQUEST' : 'LLM_UNAVAILABLE';
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      if (body && typeof body === 'object' && 'errorCode' in body && typeof body.errorCode === 'string' && safeCodes.has(body.errorCode))
        errorCode = body.errorCode;
    }
    response.setHeader('Cache-Control', 'no-store');
    const admission = status === 429 && errorCode === 'LLM_QUOTA_EXCEEDED' ? quotaDenial(exception) : undefined;
        adapter.reply(response, { errorCode, ...(admission ? { admission } : {}) }, status);
  }
}
export const llmExceptionProvider = { provide: APP_FILTER, useClass: LlmExceptionFilter };
