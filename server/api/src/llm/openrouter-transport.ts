import { request as httpRequest } from 'node:http';
import { Agent, request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { CEILINGS } from './policy.js';
import { carryDiagnostic, diagnose, stoppedDiagnostic, type FailurePhase, type FailureReason } from './provider-diagnostic.js';

const ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
const HOST = 'openrouter.ai';
const PATH = '/api/v1/chat/completions';
const unavailable = (phase: FailurePhase = 'request', reason: FailureReason = 'invalid_request') => diagnose(new Error('OpenRouter transport unavailable'), phase, reason);
export type ProviderHttpFailure = Readonly<{
  kind: 'rate_limited' | 'auth_failed' | 'unavailable';
  status: number;
  retryAfterSeconds?: number;
}>;
export const MAX_PROVIDER_RETRY_SECONDS = 86400;
// Retry hints are advisory metadata, never permission to resend or release liability.
export function providerRetryAfter(value: string | null | undefined, now = Date.now()): number | undefined {
  if (!value || value.length > 128) return undefined;
  let seconds: number;
  if (/^\d{1,10}$/.test(value)) seconds = Number(value);
  else if (/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) {
    const date = Date.parse(value);
    if (!Number.isFinite(date)) return undefined;
    seconds = Math.max(0, Math.ceil((date - now) / 1000));
  } else return undefined;
  return Math.min(MAX_PROVIDER_RETRY_SECONDS, seconds);
}
export class OpenRouterHttpFailure extends Error {
  readonly failure: ProviderHttpFailure;
  constructor(status: number, retryAfter?: string | null, phase: 'headers' | 'envelope' = 'headers') {
    super('OpenRouter transport unavailable');
    if (!Number.isInteger(status) || status < 300 || status > 599) throw unavailable();
    const kind = status === 429 || status === 503 ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable';
    const retryAfterSeconds = kind === 'rate_limited' ? providerRetryAfter(retryAfter) : undefined;
    this.failure = Object.freeze({ kind, status, ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) });
    diagnose(this, phase, 'http_error');
  }
}
export type BodySendGuard = (send: () => void) => void;
export type GuardedTransport = typeof fetch & { sendGuarded(input: string, init: RequestInit, guard: BodySendGuard): Promise<Response> };

// The injectable gateway is a test seam, not a runtime/environment endpoint override.
// Production never uses fetch, ambient proxies, remote DNS or a direct-connect fallback.
export function makeOpenRouterTransport(gateway: Readonly<{ host: string; port: number }>): GuardedTransport {
  const transport = async (input: unknown, init?: RequestInit, guard?: BodySendGuard): Promise<Response> => {
    const headers = new Headers(init?.headers);
    if (input !== ENDPOINT || init?.method !== 'POST' || init.redirect !== 'error' ||
        typeof init.body !== 'string' || Buffer.byteLength(init.body) > CEILINGS.requestBytes ||
        headers.get('content-type') !== 'application/json' || headers.get('accept') !== 'application/json' ||
        !/^Bearer [A-Za-z0-9_-]{16,512}$/.test(headers.get('authorization') ?? '') ||
        [...headers.keys()].some(k => !['authorization', 'content-type', 'accept'].includes(k))) throw unavailable();
    const body = init.body;
    const signal = init.signal;
    return new Promise<Response>((resolve, reject) => {
      let settled = false;
      let phase: FailurePhase = 'connect';
      const resources: Array<{ destroy(): void }> = [];
      // eslint-disable-next-line prefer-const -- A pre-aborted signal calls cleanup before the deadline is initialized.
      let deadline: ReturnType<typeof setTimeout> | undefined;
      const cleanup = () => {
        clearTimeout(deadline); signal?.removeEventListener('abort', abort);
        // A guard can reject inside TLSWrap's secureConnect/read callback. Destroying
        // its underlying CONNECT socket there can re-enter SSL_read (Node 23).
        // Settle immediately, but release sockets after that native callback unwinds.
        setImmediate(() => { for (const resource of resources) resource.destroy(); });
      };
      const fail = (error?: unknown, reason: FailureReason = 'io_error', at: FailurePhase = phase) => {
        if (!settled) {
          settled = true; cleanup();
          const failure = error instanceof OpenRouterHttpFailure ? error : carryDiagnostic(error, new Error('OpenRouter transport unavailable'));
          reject(diagnose(failure, at, reason));
        }
      };

      const abort = () => { const error = new Error('OpenRouter transport unavailable'); stoppedDiagnostic(signal!, error); fail(error); };
      if (signal?.aborted) { abort(); return; }
      signal?.addEventListener('abort', abort, { once: true });
      deadline = setTimeout(() => fail(undefined, 'timeout', 'deadline'), CEILINGS.timeoutMs);
      const tunnel = httpRequest({ hostname: gateway.host, port: gateway.port, method: 'CONNECT',
        path: `${HOST}:443`, headers: { host: `${HOST}:443` }, timeout: 5000 });
      resources.push(tunnel);
      tunnel.on('response', result => { result.destroy(); fail(undefined, 'rejected', 'connect'); });
      tunnel.on('error', fail); tunnel.on('timeout', () => fail(undefined, 'timeout', 'connect'));
      tunnel.on('connect', (response, socket, head) => {
        resources.push(socket);
        socket.on('error', fail);
        if (settled) { socket.destroy(); return; }
        if (response.statusCode !== 200 || head.length) { fail(undefined, 'rejected', 'connect'); return; }
        phase = 'tls';
        const secure = tlsConnect({ socket, servername: HOST, rejectUnauthorized: true });
        resources.push(secure);
        secure.on('error', fail); secure.setTimeout(10_000, () => fail(undefined, 'timeout'));
        secure.once('secureConnect', () => {
          if (settled) return;
          phase = 'dispatch_guard';
          const send = () => {
            if (signal?.aborted || settled) throw unavailable();
            const agent = new Agent({ keepAlive: false });
            resources.push(agent);
            // Reuse only this authenticated tunnel; never let the agent dial the host.
            agent.createConnection = () => secure;
            phase = 'headers';
            const request = httpsRequest({ hostname: HOST, path: PATH, method: 'POST', agent,
              headers: { ...Object.fromEntries(headers), 'content-length': String(Buffer.byteLength(body)) }, timeout: 10_000 }, result => {
              resources.push(result);
              const length = result.headers['content-length'];
              if (settled) { result.destroy(); return; }
              if (result.statusCode && result.statusCode >= 300 && result.statusCode <= 599) {
                // Do not buffer, parse, log or retain an error body, even if it claims JSON.
                fail(new OpenRouterHttpFailure(result.statusCode, typeof result.headers['retry-after'] === 'string' ? result.headers['retry-after'] : undefined));
                return;
              }
              if (!result.statusCode || result.statusCode < 200 || result.statusCode >= 300) { fail(undefined, 'invalid_shape'); return; }
              if (!/^application\/json(?:;|$)/i.test(result.headers['content-type'] ?? '')) { fail(undefined, 'invalid_type'); return; }
              if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > CEILINGS.responseBytes)) { fail(undefined, 'limit'); return; }
              phase = 'body';
              const chunks: Buffer[] = []; let bytes = 0;
              result.on('error', fail); result.on('aborted', fail);
              result.on('data', (chunk: Buffer) => {
                if (settled) return;
                bytes += chunk.length;
                if (bytes > CEILINGS.responseBytes) { fail(undefined, 'limit'); return; }
                chunks.push(chunk);
              });
              result.on('end', () => {
                if (settled) return;
                try {
                  const retryAfterSeconds = providerRetryAfter(typeof result.headers['retry-after'] === 'string' ? result.headers['retry-after'] : undefined);
                  const reply = new Response(new Uint8Array(Buffer.concat(chunks)), {
                    status: result.statusCode, headers: { 'content-type': result.headers['content-type']!,
                      ...(retryAfterSeconds !== undefined ? { 'retry-after': String(retryAfterSeconds) } : {}) } });
                  settled = true; cleanup(); resolve(reply);
                } catch { fail(); }
              });
            });
            resources.push(request);
            request.on('error', fail); request.on('timeout', () => fail(undefined, 'timeout'));
            request.end(body);
          };
          try { if (guard) guard(send); else send(); } catch (error) { fail(error, 'rejected', 'dispatch_guard'); }
        });
      });
      tunnel.end();
    });
  };
  const fetchTransport = transport as typeof fetch;
  return Object.assign(fetchTransport, { sendGuarded: (input: string, init: RequestInit, guard: BodySendGuard) => transport(input, init, guard) });
}

export const openRouterTransport = makeOpenRouterTransport(Object.freeze({ host: 'llm-egress', port: 8080 }));
