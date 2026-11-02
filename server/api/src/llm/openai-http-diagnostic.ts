// HTTP error metadata only, never a receipt or permission to retry/release liability.
export const OPENAI_ERROR_BODY_BYTES = 8192;
export const OPENAI_ERROR_BODY_MS = 1000;
const codes = ['invalid_json_schema', 'invalid_request_error', 'unsupported_parameter', 'unsupported_value',
  'invalid_value', 'context_length_exceeded', 'model_not_found', 'rate_limit_exceeded', 'insufficient_quota',
  'invalid_api_key', 'server_error'] as const;
const params = ['response_format', 'response_format.type', 'response_format.json_schema',
  'response_format.json_schema.schema', 'response_format.json_schema.strict', 'model', 'messages',
  'max_completion_tokens', 'reasoning_effort', 'service_tier', 'store', 'stream', 'n'] as const;
type HttpDiagnostic = Readonly<{ status: number; code?: typeof codes[number]; param?: typeof params[number] }>;
const details = new WeakMap<object, HttpDiagnostic>();
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const member = <T extends string>(values: readonly T[], value: unknown): T | undefined =>
  typeof value === 'string' ? values.find(item => item === value) : undefined;

export function diagnoseOpenAiHttp<T extends object>(target: T, status: unknown, body?: Uint8Array): T {
  if (details.has(target) || typeof status !== 'number' || !Number.isInteger(status) || status < 200 || status > 599 || status === 200)
    return target;
  let code: HttpDiagnostic['code'], param: HttpDiagnostic['param'];
  if (body && body.byteLength <= OPENAI_ERROR_BODY_BYTES) {
    try {
      const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
      if (object(parsed) && object(parsed.error)) {
        // Exact finite members only. Do not inspect message/type, coerce or echo unknown strings/paths.
        code = member(codes, parsed.error.code); param = member(params, parsed.error.param);
      }
    } catch { /* Malformed/oversized/non-JSON bodies yield status only. */ }
  }
  details.set(target, Object.freeze({ status, ...(code ? { code } : {}), ...(param ? { param } : {}) }));
  return target;
}
export function carryOpenAiHttp<T extends object>(from: unknown, to: T): T {
  const detail = object(from) ? details.get(from) : undefined;
  if (detail && !details.has(to)) details.set(to, detail);
  return to;
}
export function openAiHttpHeaders(value: unknown): Record<string, string> {
  const detail = object(value) ? details.get(value) : undefined;
  return detail ? { 'X-LLM-Provider-Status': String(detail.status),
    ...(detail.code ? { 'X-LLM-Provider-Error-Code': detail.code } : {}),
    ...(detail.param ? { 'X-LLM-Provider-Error-Param': detail.param } : {}) } : {};
}

// A bounded accumulator shared by native transport and injected Response seams.
// No partial-body parsing: truncation/overflow discards all fields, preserving status only.
export function openAiErrorBody(limit: number) {
  const capacity = Math.min(OPENAI_ERROR_BODY_BYTES, limit);
  const buffer = new Uint8Array(capacity);
  let bytes = 0, chunks = 0, invalid = false;
  return {
    append(chunk: Uint8Array): boolean {
      if (invalid || ++chunks > 256 || bytes + chunk.byteLength > capacity) {
        invalid = true; buffer.fill(0); return false;
      }
      buffer.set(chunk, bytes); bytes += chunk.byteLength; return true;
    },
    finish<T extends object>(target: T, status: number, complete: boolean): T {
      try { return diagnoseOpenAiHttp(target, status, complete && !invalid ? buffer.subarray(0, bytes) : undefined); }
      finally { buffer.fill(0); invalid = true; }
    },
  };
}

export async function readOpenAiHttpError<T extends object>(target: T, response: Response, signal: AbortSignal, limit: number): Promise<T> {
  const body = openAiErrorBody(limit);
  const length = response.headers.get('content-length');
  const encoding = response.headers.get('content-encoding');
  if (response.redirected || response.status < 400 || !response.body ||
      !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') ||
      encoding !== null && encoding !== 'identity' ||
      length !== null && (!/^\d{1,10}$/.test(length) || Number(length) > Math.min(limit, OPENAI_ERROR_BODY_BYTES))) {
    void response.body?.cancel().catch(() => {});
    return body.finish(target, response.status, false);
  }
  const reader = response.body.getReader();
  let stop!: () => void;
  const stopped = new Promise<false>(resolve => { stop = () => resolve(false); });
  const timer = setTimeout(stop, OPENAI_ERROR_BODY_MS);
  signal.addEventListener('abort', stop, { once: true });
  let bytes = 0;
  const read = async () => {
    try {
      for (;;) {
        if (signal.aborted) return false;
        const next = await reader.read();
        if (next.done) return length === null || bytes === Number(length);
        bytes += next.value.byteLength;
        if (!body.append(next.value)) return false;
      }
    } catch { return false; }
  };
  try { return body.finish(target, response.status, await Promise.race([read(), stopped])); }
  finally {
    clearTimeout(timer); signal.removeEventListener('abort', stop);
    // Do not wait for an untrusted cancellation promise.
    void reader.cancel().catch(() => {});
  }
}
