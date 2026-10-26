import { BadGatewayException, HttpException, ServiceUnavailableException } from '@nestjs/common';
import type { LlmPolicy } from './policy.js';
import { prepareSummary, checkedPrepared, type PreparedRequest } from './prepared-request.js';
import { usageObservation, type QuotaPolicy, type UsageObservation } from './quota-policy.js';
import { openRouterTransport, OpenRouterHttpFailure, MAX_PROVIDER_RETRY_SECONDS, type ProviderHttpFailure, type BodySendGuard, type GuardedTransport } from './openrouter-transport.js';
import { abortDiagnostic, carryDiagnostic, diagnose, diagnostic, rejectedFinishReason, stoppedDiagnostic, type FailurePhase, type FailureReason } from './provider-diagnostic.js';
import type { ReportContext } from './report-context.js';
import { PUBLIC_OPENROUTER_KEY_FILE, readPublicProviderKey } from './public-key-file.js';
import { object } from './response.js';

export const OPENROUTER_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
export type UsageReceipt = { policy: QuotaPolicy; observe(observation: UsageObservation): void };
export interface LlmProvider {
  summarize(report: ReportContext, policy: LlmPolicy, signal: AbortSignal): Promise<unknown>;
  prepare?(report: ReportContext, policy: LlmPolicy): PreparedRequest;
  summarizePrepared?(request: PreparedRequest, policy: LlmPolicy, signal: AbortSignal, receipt: UsageReceipt): Promise<unknown>;
  generateGuarded?(request: PreparedRequest, policy: LlmPolicy, signal: AbortSignal, receipt: UsageReceipt, guard: BodySendGuard): Promise<unknown>;
}
const failed = (phase: FailurePhase, reason: FailureReason) => diagnose(new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }), phase, reason);
const stoppedFailure = (signal: AbortSignal) => {
  const error = new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
  stoppedDiagnostic(signal, error); return error;
};
export const configError = () => new ServiceUnavailableException({ errorCode: 'LLM_CONFIGURATION_UNAVAILABLE' });
export type ProviderFailureResponse = Readonly<{
  errorCode: 'LLM_PROVIDER_RATE_LIMITED' | 'LLM_PROVIDER_AUTH_FAILED' | 'LLM_PROVIDER_UNAVAILABLE';
  providerFailure: ProviderHttpFailure;
}>;
const failureCode = (kind: ProviderHttpFailure['kind']): ProviderFailureResponse['errorCode'] =>
  kind === 'rate_limited' ? 'LLM_PROVIDER_RATE_LIMITED' : kind === 'auth_failed' ? 'LLM_PROVIDER_AUTH_FAILED' : 'LLM_PROVIDER_UNAVAILABLE';
// Reconstruct only bounded scalars at every wire boundary; never spread provider diagnostics.
export function safeProviderFailure(value: unknown): ProviderFailureResponse | undefined {
  if (!object(value) || !object(value.providerFailure)) return undefined;
  const failure = value.providerFailure, status = failure.status;
  if (!Number.isInteger(status) || (status as number) < 300 || (status as number) > 599 ||
      Object.keys(failure).some(key => !['kind', 'status', 'retryAfterSeconds'].includes(key))) return undefined;
  const kind = status === 429 || status === 503 ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable';
  if (failure.kind !== kind || value.errorCode !== failureCode(kind)) return undefined;
  const retry = failure.retryAfterSeconds;
  if (retry !== undefined && (kind !== 'rate_limited' || !Number.isSafeInteger(retry) || (retry as number) < 0 || (retry as number) > MAX_PROVIDER_RETRY_SECONDS)) return undefined;
  return Object.freeze({ errorCode: failureCode(kind), providerFailure: Object.freeze({ kind, status: status as number,
    ...(retry !== undefined ? { retryAfterSeconds: retry as number } : {}) }) });
}
class ProviderHttpException extends HttpException {
  constructor(failure: ProviderHttpFailure) {
    super({ errorCode: failureCode(failure.kind), providerFailure: failure },
      failure.kind === 'rate_limited' ? failure.status : failure.kind === 'auth_failed' ? 503 : 502);
  }
}
export function providerFailureFromException(error: unknown): ProviderFailureResponse | undefined {
  return error instanceof ProviderHttpException ? safeProviderFailure(error.getResponse()) : undefined;
}
function envelopeFailure(value: unknown, retryAfter?: string | null): OpenRouterHttpFailure | undefined {
  if (!object(value) || !Number.isInteger(value.code) || (value.code as number) < 400 || (value.code as number) > 599) return undefined;
  return new OpenRouterHttpFailure(value.code as number, retryAfter, 'envelope');
}

export class OpenRouterProvider implements LlmProvider {
  constructor(private readonly key: string, private readonly transport: typeof fetch = openRouterTransport) {}
  prepare(report: ReportContext, policy: LlmPolicy) { return prepareSummary(report, policy); }
  async summarize(report: ReportContext, policy: LlmPolicy, signal: AbortSignal): Promise<unknown> {
    return this.send(this.prepare(report, policy), policy, signal);
  }
  async summarizePrepared(request: PreparedRequest, policy: LlmPolicy, signal: AbortSignal, receipt: UsageReceipt): Promise<unknown> {
    return this.send(request, policy, signal, receipt);
  }
  async generateGuarded(request: PreparedRequest, policy: LlmPolicy, signal: AbortSignal, receipt: UsageReceipt, guard: BodySendGuard): Promise<unknown> {
    if (!policy.freeOnly || typeof (this.transport as Partial<GuardedTransport>).sendGuarded !== 'function') throw configError();
    return this.send(request, policy, signal, receipt, guard);
  }
  private async send(request: PreparedRequest, policy: LlmPolicy, signal: AbortSignal, receipt?: UsageReceipt, guard?: BodySendGuard): Promise<unknown> {
    if (signal.aborted) throw stoppedFailure(signal);
    const body = checkedPrepared(request, policy);
    const controller = new AbortController();
    const abort = () => {
      if (diagnostic(signal.reason)) controller.abort(signal.reason);
      else abortDiagnostic(controller, 'caller_abort');
    };
    signal.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(() => abortDiagnostic(controller, 'deadline'), policy.timeoutMs);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let phase: FailurePhase = 'headers';
    try {
      const stopped = new Promise<never>((_, reject) => {
        controller.signal.addEventListener('abort', () => reject(stoppedFailure(controller.signal)), { once: true });
      });
      const operation = async () => {
        const init: RequestInit = { method: 'POST', redirect: 'error',
          headers: { authorization: `Bearer ${this.key}`, 'content-type': 'application/json', accept: 'application/json' },
          body, signal: controller.signal };
        const response = await (guard ? (this.transport as GuardedTransport).sendGuarded(OPENROUTER_ENDPOINT, init, guard) : this.transport(OPENROUTER_ENDPOINT, init));
        if (controller.signal.aborted) { void response.body?.cancel().catch(() => {}); throw stoppedFailure(controller.signal); }
        if (!response.ok || response.status >= 300) {
          const failure = new OpenRouterHttpFailure(response.status, response.headers.get('retry-after'));
          void response.body?.cancel().catch(() => {}); throw failure;
        }
        if (response.redirected || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) {
          void response.body?.cancel().catch(() => {}); throw failed('headers', 'invalid_type');
        }
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d+$/.test(length) || Number(length) > policy.responseBytes)) {
          void response.body?.cancel().catch(() => {}); throw failed('headers', 'limit');
        }
        if (!response.body) throw failed('body', 'invalid_shape');
        phase = 'body'; reader = response.body.getReader();
        const chunks: Uint8Array[] = []; let count = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (controller.signal.aborted) throw stoppedFailure(controller.signal);
          if (done) break;
          count += value.byteLength;
          if (count > policy.responseBytes) throw failed('body', 'limit');
          chunks.push(value);
        }
        phase = 'json';
        let envelope: unknown;
        try { envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
        catch { throw failed('json', 'invalid_json'); }
        const matchingModel = object(envelope) && envelope.model === policy.model;
        const errorChoice = object(envelope) && Array.isArray(envelope.choices) && envelope.choices.length === 1 && object(envelope.choices[0]) ? envelope.choices[0] : undefined;
        const remoteFailure = envelopeFailure(object(envelope) && envelope.error !== undefined ? envelope.error : errorChoice?.error, response.headers.get('retry-after'));
        // Accounting precedes content/publication checks, even on an error envelope.
        if (receipt && object(envelope) && matchingModel && (!remoteFailure || envelope.usage !== undefined)) {
          phase = 'usage';
          const observation = usageObservation(envelope.usage, request.reserve, receipt.policy);
          try { receipt.observe(observation); }
          catch { throw remoteFailure ?? failed('accounting', 'observation_failed'); }
          if (!observation.normal) throw remoteFailure ?? failed('usage', 'invalid_receipt');
        }
        if (object(envelope) && envelope.error !== undefined || errorChoice?.error !== undefined)
          throw remoteFailure ?? failed('envelope', 'invalid_shape');
        if (!object(envelope)) throw failed('envelope', 'invalid_shape');
        if (!matchingModel) throw failed('model', 'mismatch');
        if (!Array.isArray(envelope.choices) || envelope.choices.length !== 1 || !object(envelope.choices[0])) throw failed('envelope', 'invalid_shape');
        const choice = envelope.choices[0];
        if (choice.finish_reason !== 'stop') throw failed('finish', rejectedFinishReason(choice.finish_reason));
        if (!object(choice.message) || Object.keys(choice.message).some(key => !['role', 'content', 'refusal', 'reasoning', 'annotations'].includes(key)) ||
            choice.message.refusal != null || choice.message.reasoning != null ||
            choice.message.annotations !== undefined && (!Array.isArray(choice.message.annotations) || choice.message.annotations.length !== 0) ||
            choice.message.role !== 'assistant' || typeof choice.message.content !== 'string') throw failed('content', 'invalid_shape');
        if (Buffer.byteLength(choice.message.content) > policy.responseBytes) throw failed('content', 'limit');
        if (!object(envelope.usage) || !Number.isSafeInteger(envelope.usage.completion_tokens) || (envelope.usage.completion_tokens as number) < 0 ||
            (envelope.usage.completion_tokens as number) > policy.outputTokens || policy.freeOnly && envelope.usage.cost !== 0) throw failed('usage', 'invalid_receipt');
        try { return JSON.parse(choice.message.content); } catch { throw failed('content', 'invalid_json'); }
      };
      return await Promise.race([operation(), stopped]);
    } catch (error) {
      if (error instanceof OpenRouterHttpFailure) throw carryDiagnostic(error, new ProviderHttpException(error.failure));
      const failure = carryDiagnostic(error, new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }));
      throw diagnose(failure, phase, 'io_error');
    } finally {
      clearTimeout(timeout); signal.removeEventListener('abort', abort); controller.abort();
      if (reader) void reader.cancel().catch(() => {});
    }
  }
}

export function productionProvider(env: NodeJS.ProcessEnv = process.env, transport: typeof fetch = openRouterTransport): LlmProvider {
  const file = env.OPENROUTER_API_KEY_FILE;
  if (file !== undefined && (file !== PUBLIC_OPENROUTER_KEY_FILE || env.OPENROUTER_API_KEY !== undefined)) throw configError();
  const key = file === undefined ? env.OPENROUTER_API_KEY : readPublicProviderKey(file);
  if (!key || key.length > 512 || !/^[A-Za-z0-9_-]{16,512}$/.test(key)) throw configError();
  return new OpenRouterProvider(key, transport);
}
