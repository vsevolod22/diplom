import type { INestApplication } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { HISTORY } from './history-contract.js';

const parsed = new WeakSet<IncomingMessage>();
export const historyBodyParsed = (request: IncomingMessage) => parsed.has(request);
const uuid = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
const exactMutation = new RegExp(`^/api/v1/browser/scans/${uuid}/llm/(chat|history/decision)$`);
const candidate = /^\/api\/v1\/browser\/scans\/[^/?]+\/llm\/(chat(?:\/[^?]*)?|history(?:\/[^?]*)?)\/?(?:\?|$)/i;

// Register BEFORE app.init/listen (and therefore before Nest's ordinary JSON parser).
// Unrelated routes, JWT defaults, auth512 and summary1024 behavior are untouched.
export function registerHistoryIngress(app: INestApplication): void {
  app.use((req: IncomingMessage & { body?: unknown; originalUrl?: string }, res: ServerResponse, next: () => void) => {
    const path = req.originalUrl ?? req.url ?? '';
    if (req.method !== 'POST' || !candidate.test(path)) { next(); return; }
    let done = false; const chunks: Buffer[] = []; let received = 0;
    const refuse = (status = 400) => {
      if (done) return; done = true; clearTimeout(deadline); chunks.length = 0;
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
      res.once('finish', () => req.socket.destroy());
      res.end(JSON.stringify({ errorCode: 'LLM_INVALID_REQUEST' })); req.resume();
    };
    const deadline = setTimeout(() => refuse(408), 2000);
    const length = req.headers['content-length'];
    if (!exactMutation.test(path) || req.headers['transfer-encoding'] || req.headers['content-encoding'] ||
      !/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(String(req.headers['content-type'] ?? '')) ||
      typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > HISTORY.bodyBytes) { refuse(413); return; }
    req.on('data', (chunk: Buffer) => {
      if (done) return; received += chunk.length;
      if (received > HISTORY.bodyBytes || received > Number(length)) { refuse(413); return; }
      chunks.push(chunk);
    });
    req.once('error', () => refuse()); req.once('aborted', () => { done = true; clearTimeout(deadline); chunks.length = 0; });
    req.once('end', () => {
      if (done) return;
      try {
        if (received !== Number(length)) { refuse(); return; }
        req.body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      } catch { refuse(); return; }
      done = true; clearTimeout(deadline); chunks.length = 0; parsed.add(req); next();
    });
  });
}
