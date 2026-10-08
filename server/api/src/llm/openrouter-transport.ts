import { request as httpRequest } from 'node:http';
import { Agent, request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { CEILINGS } from './policy.js';

const ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
const HOST = 'openrouter.ai';
const PATH = '/api/v1/chat/completions';
const unavailable = () => new Error('OpenRouter transport unavailable');

// The injectable gateway is a test seam, not a runtime/environment endpoint override.
// Production never uses fetch, ambient proxies, remote DNS or a direct-connect fallback.
export function makeOpenRouterTransport(gateway: Readonly<{ host: string; port: number }>): typeof fetch {
  return (async (input: unknown, init?: RequestInit): Promise<Response> => {
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
      const resources: Array<{ destroy(): void }> = [];
      let deadline: ReturnType<typeof setTimeout> | undefined;
      const cleanup = () => {
        clearTimeout(deadline); signal?.removeEventListener('abort', abort);
        for (const resource of resources) resource.destroy();
      };
      const fail = () => { if (!settled) { settled = true; cleanup(); reject(unavailable()); } };
      const abort = () => fail();
      if (signal?.aborted) { fail(); return; }
      signal?.addEventListener('abort', abort, { once: true });
      deadline = setTimeout(fail, CEILINGS.timeoutMs);
      const tunnel = httpRequest({ hostname: gateway.host, port: gateway.port, method: 'CONNECT',
        path: `${HOST}:443`, headers: { host: `${HOST}:443` }, timeout: 5000 });
      resources.push(tunnel);
      tunnel.on('response', result => { result.destroy(); fail(); });
      tunnel.on('error', fail); tunnel.on('timeout', fail);
      tunnel.on('connect', (response, socket, head) => {
        resources.push(socket);
        socket.on('error', fail);
        if (settled) { socket.destroy(); return; }
        if (response.statusCode !== 200 || head.length) { fail(); return; }
        const secure = tlsConnect({ socket, servername: HOST, rejectUnauthorized: true });
        resources.push(secure);
        secure.on('error', fail); secure.setTimeout(10_000, fail);
        secure.once('secureConnect', () => {
          if (settled) return;
          const agent = new Agent({ keepAlive: false });
          resources.push(agent);
          // Reuse only this authenticated tunnel; never let the agent dial the host.
          agent.createConnection = () => secure;
          const request = httpsRequest({ hostname: HOST, path: PATH, method: 'POST', agent,
            headers: { ...Object.fromEntries(headers), 'content-length': String(Buffer.byteLength(body)) }, timeout: 10_000 }, result => {
            resources.push(result);
            const length = result.headers['content-length'];
            if (settled) { result.destroy(); return; }
            if (!result.statusCode || result.statusCode < 200 || result.statusCode >= 300 ||
                !/^application\/json(?:;|$)/i.test(result.headers['content-type'] ?? '') ||
                length !== undefined && (!/^\d+$/.test(length) || Number(length) > CEILINGS.responseBytes)) { fail(); return; }
            const chunks: Buffer[] = []; let bytes = 0;
            result.on('error', fail); result.on('aborted', fail);
            result.on('data', (chunk: Buffer) => {
              if (settled) return;
              bytes += chunk.length;
              if (bytes > CEILINGS.responseBytes) { fail(); return; }
              chunks.push(chunk);
            });
            result.on('end', () => {
              if (settled) return;
              try {
                const reply = new Response(new Uint8Array(Buffer.concat(chunks)), {
                  status: result.statusCode, headers: { 'content-type': result.headers['content-type']! } });
                settled = true; cleanup(); resolve(reply);
              } catch { fail(); }
            });
          });
          resources.push(request);
          request.on('error', fail); request.on('timeout', fail);
          request.end(body);
        });
      });
      tunnel.end();
    });
  }) as typeof fetch;
}

export const openRouterTransport = makeOpenRouterTransport(Object.freeze({ host: 'llm-egress', port: 8080 }));
