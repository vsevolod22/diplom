import { BadGatewayException } from '@nestjs/common';
import { object } from './response.js';
import { carryDiagnostic, diagnose, diagnostic, abortDiagnostic, stoppedDiagnostic, rejectedFinishReason,
  type FailurePhase, type FailureReason } from './provider-diagnostic.js';
import { OPENAI_ENDPOINT, checkedOpenAiPolicy, openAiConfigurationError, type OpenAiPolicy } from './openai-policy.js';
import { checkedOpenAiPrepared, validateOpenAiPreparedReply, type OpenAiPrepared, type OpenAiOperation } from './openai-prepared-request.js';
import { observeOpenAiUsage, type OpenAiReserve, type OpenAiUsage } from './openai-usage.js';
import { diagnoseOpenAiHttp, readOpenAiHttpError } from './openai-http-diagnostic.js';

// Trusted transport seam, NOT a production network implementation. It must use
// the fixed endpoint, forbid redirects, honor abort and invoke guard immediately
// before writing any request bytes. There is deliberately no fetch/default transport.
export type OpenAiGuardedTransport = Readonly<{
  sendGuarded(endpoint: typeof OPENAI_ENDPOINT, init: RequestInit, guard: (send: () => undefined) => void): Promise<Response>;
}>;
export type OpenAiAccountingBinding = Readonly<{
  operation: OpenAiOperation; policyVersion: string; requestHash: string; reserve: OpenAiReserve;
}>;
export type OpenAiAccounting = Readonly<{
  // Must verify a durable reservation bound to the caller's owner/scan/attempt.
  assertReserved(binding: OpenAiAccountingBinding): boolean;
  // Must durably account before returning true. Even a rejected answer can cost.
  observe(binding: OpenAiAccountingBinding, usage: OpenAiUsage): boolean;
}>;
// Must recheck owner/session/consent/report and atomically mark dispatched before
// invoking send synchronously, exactly once. No refund/release is performed here:
// unknown usage, aborts and failed dispatches retain the caller's liability.
export type OpenAiSendGuard = (binding: OpenAiAccountingBinding, send: () => undefined) => void;
const attempted = new WeakSet<OpenAiPrepared>();
const failed = (phase: FailurePhase, reason: FailureReason) =>
  diagnose(new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }), phase, reason);

function stoppedError(signal: AbortSignal): BadGatewayException {
  const error = new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
  stoppedDiagnostic(signal, error); return error;
}

export class OpenAiProvider {
  readonly #policy: OpenAiPolicy;
  readonly #key: string;
  readonly #transport: OpenAiGuardedTransport;
  constructor(policy: OpenAiPolicy, key: string, transport: OpenAiGuardedTransport) {
    checkedOpenAiPolicy(policy);
    if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{16,512}$/.test(key) || !transport || typeof transport.sendGuarded !== 'function')
      throw openAiConfigurationError();
    this.#policy = policy; this.#key = key; this.#transport = transport;
  }

  async generate(request: OpenAiPrepared, signal: AbortSignal, accounting: OpenAiAccounting, guard: OpenAiSendGuard) {
    checkedOpenAiPrepared(request, this.#policy);
    if (!accounting || typeof accounting.assertReserved !== 'function' || typeof accounting.observe !== 'function' || typeof guard !== 'function')
      throw openAiConfigurationError();
    if (signal.aborted) throw stoppedError(signal);
    if (attempted.has(request)) throw failed('request', 'rejected');
    attempted.add(request);
    const binding = Object.freeze({ operation: request.operation, policyVersion: request.policyVersion,
      requestHash: request.hash, reserve: request.reserve });
    try {
      if (accounting.assertReserved(binding) !== true) throw failed('accounting', 'rejected');
    } catch { throw failed('accounting', 'rejected'); }
    const received = await this.receive(request, signal, accounting, guard, binding);
    // Run the existing grounding/Russian validators after usage accounting. Never
    // translate, repair, retry, publish or persist a reply inside this adapter.
    return { ...validateOpenAiPreparedReply(request, this.#policy, received.value), usage: received.usage };
  }

  private async receive(request: OpenAiPrepared, signal: AbortSignal, accounting: OpenAiAccounting,
    guard: OpenAiSendGuard, binding: OpenAiAccountingBinding): Promise<{ value: unknown; usage: OpenAiUsage }> {
    const policy = this.#policy, controller = new AbortController();
    const abort = () => {
      if (diagnostic(signal.reason)) controller.abort(signal.reason);
      else abortDiagnostic(controller, 'caller_abort');
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const timer = setTimeout(() => abortDiagnostic(controller, 'deadline'), policy.timeoutMs);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let phase: FailurePhase = 'dispatch_guard';
    let guarded = false, sent = false, guardCompleted = false, guardInvalid = false;
    let guardRejection: BadGatewayException | undefined;
    let httpFailure: { error: BadGatewayException; status: number } | undefined;
    const rejectGuard = (): never => {
      guardInvalid = true;
      guardRejection ??= failed('dispatch_guard', 'rejected');
      if (!controller.signal.aborted) controller.abort(guardRejection);
      throw guardRejection;
    };
    const requireSynchronousReturn = (value: unknown): void => {
      if (value === undefined) return;
      // Assimilate rejected promises/thenables without trusting their .catch or
      // exposing rejection text. An invalid scalar is rejected by the same gate.
      void new Promise<unknown>(resolve => resolve(value)).catch(() => {});
      rejectGuard();
    };
    try {
      const interrupted = new Promise<never>((_, reject) => {
        if (controller.signal.aborted) reject(stoppedError(controller.signal));
        else controller.signal.addEventListener('abort', () => reject(stoppedError(controller.signal)), { once: true });
      });
      const operation = async () => {
        if (controller.signal.aborted) throw stoppedError(controller.signal);
        const response = await this.#transport.sendGuarded(OPENAI_ENDPOINT, {
          method: 'POST', redirect: 'error', signal: controller.signal,
          headers: { authorization: `Bearer ${this.#key}`, 'content-type': 'application/json', accept: 'application/json' },
          body: request.body,
        }, send => {
          if (guarded || controller.signal.aborted || typeof send !== 'function') return rejectGuard();
          guarded = true;
          let open = true;
          try {
            const result = guard(binding, () => {
              if (!open || sent || controller.signal.aborted) return rejectGuard();
              sent = true; phase = 'headers';
              const sendResult: unknown = send();
              requireSynchronousReturn(sendResult);
              return undefined;
            });
            requireSynchronousReturn(result);
            if (!sent || guardInvalid) return rejectGuard();
            guardCompleted = true;
          } catch { return rejectGuard(); }
          finally { open = false; }
        });
        if (controller.signal.aborted || !guardCompleted || guardInvalid) {
          void response.body?.cancel().catch(() => {});
          throw controller.signal.aborted ? stoppedError(controller.signal) : failed('dispatch_guard', 'rejected');
        }
        phase = 'headers';
        const discard = () => { void response.body?.cancel().catch(() => {}); };
        if (!response.ok || response.status !== 200 || response.redirected) {
          const error = failed('headers', 'http_error');
          httpFailure = { error, status: response.status };
          throw await readOpenAiHttpError(error, response, controller.signal, policy.responseBytes);
        }
        if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) {
          discard(); throw failed('headers', 'invalid_type');
        }
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d{1,10}$/.test(length) || Number(length) > policy.responseBytes)) {
          discard(); throw failed('headers', 'limit');
        }
        if (!response.body) throw failed('body', 'invalid_shape');
        phase = 'body'; reader = response.body.getReader();
        const chunks: Uint8Array[] = []; let bytes = 0;
        for (;;) {
          const next = await reader.read();
          if (controller.signal.aborted) throw stoppedError(controller.signal);
          if (next.done) break;
          bytes += next.value.byteLength;
          if (bytes > policy.responseBytes) throw failed('body', 'limit');
          if (next.value.byteLength) chunks.push(next.value);
        }
        phase = 'json';
        let envelope: unknown;
        try { envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
        catch { throw failed('json', 'invalid_json'); }
        if (!object(envelope)) throw failed('envelope', 'invalid_shape');
        if (envelope.model !== policy.model) throw failed('model', 'mismatch');
        if (envelope.service_tier !== undefined && envelope.service_tier !== 'default') throw failed('envelope', 'invalid_shape');
        phase = 'usage';
        const usage = observeOpenAiUsage(envelope.usage, request.reserve, policy);
        try { if (accounting.observe(binding, usage) !== true) throw failed('accounting', 'observation_failed'); }
        catch { throw failed('accounting', 'observation_failed'); }
        if (!usage.normal) throw failed('usage', 'invalid_receipt');
        if (envelope.error !== undefined || !Array.isArray(envelope.choices) || envelope.choices.length !== 1 || !object(envelope.choices[0]))
          throw failed('envelope', 'invalid_shape');
        const choice = envelope.choices[0];
        if (choice.finish_reason !== 'stop') throw failed('finish', rejectedFinishReason(choice.finish_reason));
        const message = choice.message;
        if (!object(message) || Object.keys(message).some(key => !['role', 'content', 'refusal', 'tool_calls', 'annotations'].includes(key)) ||
            message.role !== 'assistant' || typeof message.content !== 'string' || message.refusal != null ||
            message.tool_calls !== undefined && (!Array.isArray(message.tool_calls) || message.tool_calls.length !== 0) ||
            message.annotations !== undefined && (!Array.isArray(message.annotations) || message.annotations.length !== 0))
          throw failed('content', 'invalid_shape');
        if (Buffer.byteLength(message.content) > policy.responseBytes) throw failed('content', 'limit');
        let value: unknown;
        try { value = JSON.parse(message.content); } catch { throw failed('content', 'invalid_json'); }
        return { value, usage };
      };
      return await Promise.race([operation(), interrupted]);
    } catch (error) {
      // Once error headers arrived, retain their status even if diagnostic-body reading times out.
      const source = httpFailure ? diagnoseOpenAiHttp(httpFailure.error, httpFailure.status) : error;
      throw diagnose(carryDiagnostic(source, new BadGatewayException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' })), phase, 'io_error');
    } finally {
      clearTimeout(timer); signal.removeEventListener('abort', abort); controller.abort();
      if (reader) void reader.cancel().catch(() => {});
    }
  }
}
