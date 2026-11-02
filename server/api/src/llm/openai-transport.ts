import { request as httpRequest } from 'node:http';
import { Agent, request as httpsRequest } from 'node:https';
import { checkServerIdentity, connect as tlsConnect } from 'node:tls';
import { checkedOpenAiPolicy, OPENAI_ENDPOINT, openAiConfigurationError, type OpenAiPolicy } from './openai-policy.js';
import type { OpenAiGuardedTransport } from './openai-provider.js';
import { diagnose, stoppedDiagnostic, type FailurePhase, type FailureReason } from './provider-diagnostic.js';
import { OPENAI_ERROR_BODY_BYTES, OPENAI_ERROR_BODY_MS, openAiErrorBody } from './openai-http-diagnostic.js';

const HOST = 'api.openai.com';
const PATH = '/v1/chat/completions';
const GATEWAY = Object.freeze({ host: 'openai-egress', port: 8080 });
const MAX_CONCURRENT = 8;
// A process-wide cap also covers multiple provider/transport instances. No queue/retry.
let active = 0;
const unavailable = (phase: FailurePhase, reason: FailureReason) =>
  diagnose(new Error('OpenAI transport unavailable'), phase, reason);

// Trusted server composition only. No fetch callable, arbitrary gateway, env endpoint,
// ambient proxy, shared OpenRouter agent or direct-network fallback is exposed.
export function makeOpenAiTransport(policy: OpenAiPolicy, maxConcurrent: number): OpenAiGuardedTransport {
  checkedOpenAiPolicy(policy);
  if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > MAX_CONCURRENT) throw openAiConfigurationError();
  let localActive = 0;
  return Object.freeze({
    async sendGuarded(endpoint, init, guard): Promise<Response> {
      let headers: Headers;
      try { headers = new Headers(init.headers); } catch { throw unavailable('request', 'invalid_request'); }
      if (endpoint !== OPENAI_ENDPOINT || init.method !== 'POST' || init.redirect !== 'error' ||
          typeof init.body !== 'string' || !init.body.length || Buffer.byteLength(init.body) > policy.requestBytes ||
          !(init.signal instanceof AbortSignal) || typeof guard !== 'function' ||
          Object.keys(init).some(key => !['method', 'redirect', 'body', 'headers', 'signal'].includes(key)) ||
          headers.get('content-type') !== 'application/json' || headers.get('accept') !== 'application/json' ||
          !/^Bearer [A-Za-z0-9_-]{16,512}$/.test(headers.get('authorization') ?? '') ||
          [...headers.keys()].some(key => !['authorization', 'content-type', 'accept'].includes(key)))
        throw unavailable('request', 'invalid_request');
      const body = init.body, signal = init.signal;
      if (active >= MAX_CONCURRENT || localActive >= maxConcurrent) throw unavailable('connect', 'limit');
      active++; localActive++;
      return new Promise<Response>((resolve, reject) => {
        let settled = false, phase: FailurePhase = 'connect';
        let httpFailure: { error: Error; status: number; body: ReturnType<typeof openAiErrorBody> } | undefined;
        // eslint-disable-next-line prefer-const -- Pre-abort cleanup runs before the deadline is installed.
        let deadline: ReturnType<typeof setTimeout> | undefined;
        let phaseDeadline: ReturnType<typeof setTimeout> | undefined;
        const expires = performance.now() + policy.timeoutMs;
        const resources: Array<{ destroy(): void }> = [];
        const cleanup = () => {
          clearTimeout(deadline); clearTimeout(phaseDeadline); signal.removeEventListener('abort', abort);
          // Do not destroy the underlying tunnel inside TLSWrap's native read callback.
          // Hold admission slots until destruction, not merely Promise settlement.
          setImmediate(() => {
            try { for (const resource of resources) resource.destroy(); }
            finally { active--; localActive--; }
          });
        };
        const fail = (reason: FailureReason = 'io_error', at: FailurePhase = phase) => {
          if (settled) return;
          const error = httpFailure && at !== 'dispatch_guard'
            ? httpFailure.body.finish(httpFailure.error, httpFailure.status, false) : unavailable(at, reason);
          settled = true; cleanup(); reject(error);
        };
        const abort = () => {
          if (settled) return;
          const error = new Error('OpenAI transport unavailable');
          stoppedDiagnostic(signal, error); settled = true; cleanup();
          reject(httpFailure ? httpFailure.body.finish(httpFailure.error, httpFailure.status, false) : error);
        };
        const live = () => {
          if (signal.aborted) abort();
          if (performance.now() >= expires) fail('timeout', 'deadline');
          return !settled;
        };
        const timeout = (milliseconds: number, at: FailurePhase) => {
          clearTimeout(phaseDeadline);
          phaseDeadline = setTimeout(() => fail('timeout', at), Math.min(milliseconds, policy.timeoutMs));
        };
        signal.addEventListener('abort', abort, { once: true });
        if (!live()) return;
        deadline = setTimeout(() => fail('timeout', 'deadline'), policy.timeoutMs);
        timeout(5000, 'connect');
        try {
          const tunnel = httpRequest({ hostname: GATEWAY.host, port: GATEWAY.port, method: 'CONNECT',
            path: `${HOST}:443`, headers: { host: `${HOST}:443` }, agent: false, maxHeaderSize: 8192 });
          resources.push(tunnel);
          tunnel.on('error', () => fail());
          tunnel.on('response', response => { response.destroy(); fail('rejected', 'connect'); });
          tunnel.on('connect', (response, socket, head) => {
            resources.push(socket); socket.on('error', () => fail());
            if (!live()) { socket.destroy(); return; }
            if (response.statusCode !== 200 || head.length) { fail('rejected', 'connect'); return; }
            phase = 'tls'; timeout(10_000, 'tls'); socket.setTimeout(0);
            try {
              const secure = tlsConnect({ socket, servername: HOST, rejectUnauthorized: true,
                checkServerIdentity, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] });
              resources.push(secure);
              secure.on('error', () => fail());
              secure.once('secureConnect', () => {
                if (!live()) return;
                try {
                  // Explicit identity verification also applies to a preconnected CONNECT socket.
                  if (!secure.authorized || checkServerIdentity(HOST, secure.getPeerCertificate()) ||
                      secure.alpnProtocol && secure.alpnProtocol !== 'http/1.1') { fail('rejected', 'tls'); return; }
                  clearTimeout(phaseDeadline);
                  secure.setTimeout(policy.timeoutMs, () => fail('timeout'));
                  phase = 'dispatch_guard';
                  let open = true, sent = false;
                  const rejectGuard = (): never => { fail('rejected', 'dispatch_guard'); throw unavailable('dispatch_guard', 'rejected'); };
                  try {
                    const returned: unknown = guard(() => {
                      if (!open || sent || !live()) return rejectGuard();
                      sent = true;
                      const agent = new Agent({ keepAlive: false, maxSockets: 1, maxTotalSockets: 1 });
                      resources.push(agent);
                      // Never permit this agent to obtain a second socket or resolve/dial HOST.
                      let handedOut = false;
                      agent.createConnection = () => {
                        if (handedOut || !live()) throw unavailable('tls', 'rejected');
                        handedOut = true; return secure;
                      };
                      phase = 'headers';
                      const request = httpsRequest({ hostname: HOST, port: 443, path: PATH, method: 'POST', agent,
                        maxHeaderSize: 8192, headers: { ...Object.fromEntries(headers),
                          'content-length': String(Buffer.byteLength(body)), 'accept-encoding': 'identity', connection: 'close' } }, result => {
                        resources.push(result);
                        result.on('error', () => fail()); result.on('aborted', () => fail());
                        if (!live()) { result.destroy(); return; }
                        if (result.statusCode !== 200) {
                          const status = result.statusCode ?? 0;
                          const errorBody = openAiErrorBody(policy.responseBytes);
                          const error = unavailable('headers', 'http_error');
                          httpFailure = { error, status, body: errorBody };
                          const length = result.headers['content-length'];
                          if (status < 400 || !/^application\/json(?:;|$)/i.test(result.headers['content-type'] ?? '') ||
                              result.headers['content-encoding'] !== undefined && result.headers['content-encoding'] !== 'identity' ||
                              length !== undefined && (!/^\d{1,10}$/.test(length) || Number(length) > Math.min(policy.responseBytes, OPENAI_ERROR_BODY_BYTES))) {
                            fail('http_error', 'headers'); return;
                          }
                          // Best-effort finite metadata only; never return/log the upstream body.
                          timeout(OPENAI_ERROR_BODY_MS, 'headers');
                          let bytes = 0;
                          result.on('data', (chunk: Buffer) => {
                            if (!live()) return;
                            bytes += chunk.length;
                            if (!errorBody.append(chunk)) fail('http_error', 'headers');
                          });
                          result.on('end', () => {
                            if (!live()) return;
                            errorBody.finish(error, status, result.complete && (length === undefined || bytes === Number(length)));
                            fail('http_error', 'headers');
                          });
                          result.on('close', () => { if (!result.complete) fail('http_error', 'headers'); });
                          return;
                        }
                        if (!/^application\/json(?:;|$)/i.test(result.headers['content-type'] ?? '') ||
                            result.headers['content-encoding'] !== undefined && result.headers['content-encoding'] !== 'identity') {
                          fail('invalid_type', 'headers'); return;
                        }
                        const length = result.headers['content-length'];
                        if (length !== undefined && (!/^\d{1,10}$/.test(length) || Number(length) > policy.responseBytes)) {
                          fail('limit', 'headers'); return;
                        }
                        phase = 'body'; let bytes = 0;
                        const chunks: Buffer[] = [];
                        result.on('data', (chunk: Buffer) => {
                          if (!live()) return;
                          bytes += chunk.length;
                          if (bytes > policy.responseBytes) { fail('limit'); return; }
                          chunks.push(chunk);
                        });
                        result.on('end', () => {
                          if (!live()) return;
                          if (!result.complete || length !== undefined && bytes !== Number(length)) { fail('invalid_shape'); return; }
                          try {
                            const reply = new Response(new Uint8Array(Buffer.concat(chunks)), {
                              status: 200, headers: { 'content-type': 'application/json' } });
                            settled = true; cleanup(); resolve(reply);
                          } catch { fail(); }
                        });
                        result.on('close', () => { if (!result.complete) fail(); });
                      });
                      resources.push(request);
                      request.on('error', () => fail());
                      request.on('upgrade', (_response, upgraded) => { upgraded.destroy(); fail('rejected'); });
                      // First authenticated HTTP bytes are written only inside this synchronous guard.
                      request.end(body);
                      return undefined;
                    });
                    if (returned !== undefined) {
                      void Promise.resolve(returned).catch(() => {});
                      rejectGuard();
                    }
                    if (!sent) rejectGuard();
                  } catch { fail('rejected', 'dispatch_guard'); }
                  finally { open = false; }
                } catch { fail(); }
              });
            } catch { fail(); }
          });
          tunnel.end();
        } catch { fail(); }
      });
    },
  });
}
