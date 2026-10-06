import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { chmodSync, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
import { Broker, type Reply } from './broker.js';
import { HEX_ID, type Limits, type Target } from './contracts.js';
import { canonical } from './projection.js';
const ROUTE = /^\/v1\/contexts\/([a-z][a-z0-9-]{0,31})\/containers\/([a-f0-9]{64})\/inspect$/;
export function admission(req: IncomingMessage, bound: Limits): Target | undefined {
  const raw = req.url ?? '';
  if (
    req.httpVersion !== '1.1' ||
    req.method !== 'GET' ||
    Buffer.byteLength(raw) > bound.targetBytes ||
    req.rawHeaders.length / 2 > bound.headers
  )
    return;
  const match = ROUTE.exec(raw);
  if (!match) return;
  let bytes = Buffer.byteLength(`${req.method} ${raw} HTTP/${req.httpVersion}\r\n`) + 2;
  const headers = new Map<string, string>();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const key = req.rawHeaders[i].toLowerCase();
    const value = req.rawHeaders[i + 1];
    bytes += Buffer.byteLength(`${req.rawHeaders[i]}: ${value}\r\n`);
    if (
      headers.has(key) ||
      !['host', 'authorization', 'x-broker-grant', 'connection', 'content-length'].includes(key)
    )
      return;
    headers.set(key, value);
  }
  if (
    bytes > bound.ingressBytes ||
    headers.get('host') !== 'broker' ||
    (headers.has('content-length') && headers.get('content-length') !== '0') ||
    (headers.has('connection') && !['close', 'keep-alive'].includes(headers.get('connection')!.toLowerCase()))
  )
    return;
  const authorization = headers.get('authorization');
  const credential = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
  const grant = headers.get('x-broker-grant') ?? '';
  if (!HEX_ID.test(credential) || !/^[a-z][a-z0-9-]{0,31}$/.test(grant)) return;
  return { context: match[1], id: match[2], credential, grant };
}
function send(res: ServerResponse, reply: Reply, body = canonical(reply)): void {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(reply.status === 'checked' ? 200 : reply.status === 'not_authorized' ? 403 : 502, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}
export function createIngress(broker: Broker): Server {
  const timers = new WeakMap<object, ReturnType<typeof setTimeout>>();
  const used = new WeakSet<object>();
  const rawStates = new WeakMap<object, { prefix: Buffer; complete: boolean; invalid: boolean }>();
  const server = createServer(
    { maxHeaderSize: broker.bound.ingressBytes, insecureHTTPParser: false, requireHostHeader: true },
    (req, res) => {
      clearTimeout(timers.get(req.socket));
      req.socket.setTimeout(0);
      const rawState = rawStates.get(req.socket);
      if (!rawState?.complete || rawState.invalid || used.has(req.socket)) {
        broker.deny();
        req.socket.destroy();
        return;
      }
      used.add(req.socket);
      const target = admission(req, broker.bound);
      if (!target) {
        send(res, broker.deny());
        return;
      }
      const cancel = new AbortController();
      const closed = () => {
        if (!res.writableFinished) cancel.abort();
      };
      res.once('close', closed);
      req.once('aborted', () => cancel.abort());
      req.on('data', () => {
        cancel.abort();
        req.destroy();
      });
      req.resume();
      void broker
        .handle(target, cancel.signal, (reply, body) => send(res, reply, body))
        .catch(() => {
          send(res, { status: 'failed' });
        })
        .finally(() => res.removeListener('close', closed));
    },
  );
  server.maxHeadersCount = 0; // Never silently truncate away forbidden/duplicate headers.
  server.headersTimeout = broker.bound.headerMs;
  server.requestTimeout = broker.bound.totalMs;
  server.keepAliveTimeout = 1;
  server.maxRequestsPerSocket = 1;
  server.maxConnections = 16;
  server.on('connection', (socket) => {
    const state = { prefix: Buffer.alloc(0), complete: false, invalid: false };
    rawStates.set(socket, state);
    // Runs before Node's HTTP parser. Count actual wire bytes, not trimmed header values.
    // Retain at most B+1 bytes and reject surplus bytes/body/pipelining without dispatch.
    socket.prependListener('data', (chunk: Buffer) => {
      if (state.complete) {
        state.invalid = true;
        socket.destroy();
        return;
      }
      const part = chunk.subarray(0, broker.bound.ingressBytes + 1 - state.prefix.length);
      state.prefix = Buffer.concat([state.prefix, part]);
      const end = state.prefix.indexOf('\r\n\r\n');
      if (end >= 0) {
        state.complete = true;
        state.invalid =
          end + 4 > broker.bound.ingressBytes ||
          chunk.length > part.length ||
          state.prefix.length !== end + 4;
        // No bare-LF/obs-fold framing that Node might accept/normalize differently.
        if (!state.invalid) {
          const lines = state.prefix.subarray(0, end).toString('latin1').split('\r\n');
          const requestLine = /^GET ([^ ]+) HTTP\/1\.1$/.exec(lines[0]);
          state.invalid =
            !requestLine ||
            !ROUTE.test(requestLine[1]) ||
            lines.some((line) => /[\r\n]/.test(line)) ||
            lines.slice(1).some((line) => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\x00-\x1f\x7f]*$/.test(line));
        }
        state.prefix = Buffer.alloc(0);
      } else if (state.prefix.length > broker.bound.ingressBytes || chunk.length > part.length)
        state.invalid = true;
      if (state.invalid) {
        broker.deny();
        socket.destroy();
      }
    });
    const timer = setTimeout(() => socket.destroy(), broker.bound.headerMs);
    timers.set(socket, timer);
    socket.once('close', () => clearTimeout(timer));
  });
  server.on('clientError', (_error, socket) => {
    broker.deny();
    socket.destroy();
  });
  server.on('upgrade', (_req, socket) => {
    broker.deny();
    socket.destroy();
  });
  server.on('connect', (_req, socket) => {
    broker.deny();
    socket.destroy();
  });
  server.on('checkContinue', (_req, res) => send(res, broker.deny()));
  server.on('checkExpectation', (_req, res) => send(res, broker.deny()));
  return server;
}
// No TCP listener in supported runtime. Production main never calls this.
export async function listenPrivate(server: Server, socket: string): Promise<void> {
  const root = lstatSync(dirname(socket));
  if (!root.isDirectory() || root.uid !== process.getuid?.() || (root.mode & 0o777) !== 0o700)
    throw new Error('private_ingress_required');
  // Caller owns a fresh path: no unlinking/replacing another service's socket.
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  chmodSync(socket, 0o600);
}
