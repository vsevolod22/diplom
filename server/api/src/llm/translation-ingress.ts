import type { INestApplication } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { TRANSLATION } from './translation-contract.js';

const parsed = new WeakSet<object>();
export const translationBodyParsed = (request: object) => parsed.has(request);
const uuid = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
const mutation = new RegExp(`^/api/v1/browser/scans/${uuid}/llm/translation$`);
const context = new RegExp(`^/api/v1/browser/scans/${uuid}/llm/translation/context\\?[^#]+$`);
const candidate = /^\/api\/v1\/browser\/scans\/[^/?]+\/llm\/translation(?:[/?]|$)/i;

// Public composition only; run before Nest's body parser, never a generic LLM proxy.
export function registerTranslationIngress(app: INestApplication): void {
  app.use((req: IncomingMessage & { body?: unknown; originalUrl?: string }, res: ServerResponse, next: () => void) => {
    const path = req.originalUrl ?? req.url ?? '';
    if (!candidate.test(path)) { next(); return; }
    const refuse = (status: number) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
      res.once('finish', () => req.socket.destroy());
      res.end(JSON.stringify({ errorCode: 'LLM_INVALID_REQUEST' })); req.resume();
    };
    if (req.headers['transfer-encoding'] || req.headers['content-encoding'] || req.headers.expect) { refuse(400); return; }
    if (req.method === 'GET' && context.test(path)) {
      if (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0') { refuse(400); return; }
      next(); return;
    }
    if (req.method !== 'POST' || !mutation.test(path)) { refuse(400); return; }
    const length = req.headers['content-length'];
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? '')) ||
        typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length)) { refuse(415); return; }
    if (Number(length) > TRANSLATION.bodyBytes) { refuse(413); return; }
    let done = false, received = 0;
    const chunks: Buffer[] = [];
    const fail = (status = 400) => {
      if (done) return; done = true; clearTimeout(deadline); chunks.length = 0; refuse(status);
    };
    const deadline = setTimeout(() => fail(408), 2000);
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      received += chunk.length;
      if (received > Number(length) || received > TRANSLATION.bodyBytes) { fail(413); return; }
      chunks.push(chunk);
    });
    req.once('error', () => fail());
    req.once('aborted', () => { done = true; clearTimeout(deadline); chunks.length = 0; });
    req.once('end', () => {
      if (done) return;
      try {
        if (received !== Number(length)) { fail(); return; }
        req.body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      } catch { fail(); return; }
      done = true; clearTimeout(deadline); chunks.length = 0; parsed.add(req); next();
    });
  });
}
