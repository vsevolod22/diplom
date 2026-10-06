import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdtempSync, chmodSync, realpathSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { once } from 'node:events';
import { AuditBuffer } from '../src/audit.js';
import { verifyPrivateBoundary } from '../src/boundary.js';
import { Broker, type Barriers } from '../src/broker.js';
import { UnixEngine } from '../src/engine.js';
import { createIngress, listenPrivate } from '../src/ingress.js';
import { PolicyStore } from '../src/policy.js';
import type { Clock, Limits } from '../src/contracts.js';
import { fixtureState, inspect, route, TOKEN } from './support.js';
export function barrier() {
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    entered,
    release,
    wait: () => {
      enter();
      return held;
    },
  };
}
export async function harness(
  options: {
    handler?: (req: IncomingMessage, res: ServerResponse) => void;
    limits?: Partial<Limits>;
    barriers?: Barriers;
    enabled?: boolean;
    audit?: AuditBuffer;
    fakeClock?: Clock;
  } = {},
) {
  // macOS sandbox TMPDIR may exceed sockaddr_un; keep owned fixtures in the writeset.
  const root = realpathSync(mkdtempSync(join(fileURLToPath(new URL('../', import.meta.url)), '.f-')));
  chmodSync(root, 0o700);
  const endpoint = join(root, 'e');
  const ingressPath = join(root, 'b');
  const calls: { method: string; path: string; headers: IncomingMessage['headers'] }[] = [];
  const upstream = createServer((req, res) => {
    calls.push({ method: req.method!, path: req.url!, headers: req.headers });
    if (options.handler) return options.handler(req, res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(inspect()));
  });
  await new Promise<void>((resolve) => upstream.listen(endpoint, resolve));
  chmodSync(endpoint, 0o600);
  const policy = new PolicyStore();
  policy.replace(fixtureState(endpoint));
  let wall = 100_000;
  let mono = 0;
  const fakeClock = options.fakeClock ?? { wall: () => wall, mono: () => mono };
  const engine = new UnixEngine();
  const audit = options.audit ?? new AuditBuffer();
  const broker = new Broker({
    policy,
    engine,
    audit,
    enabled: options.enabled ?? true,
    boundary: verifyPrivateBoundary(root, endpoint),
    clock: fakeClock,
    limits: options.limits,
    barriers: options.barriers,
  });
  const ingress = createIngress(broker);
  await listenPrivate(ingress, ingressPath);
  const ask = (path = route(), headers: Record<string, string> = {}) =>
    new Promise<any>((resolve, reject) => {
      const req = httpRequest(
        {
          socketPath: ingressPath,
          path,
          method: 'GET',
          agent: false,
          headers: {
            Host: 'broker',
            Authorization: `Bearer ${TOKEN}`,
            'X-Broker-Grant': 'grant-a',
            ...headers,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (b) => chunks.push(b));
          res.on('end', () => {
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString()));
            } catch (e) {
              reject(e);
            }
          });
          res.on('error', reject);
        },
      );
      req.on('error', reject);
      req.setTimeout(7000, () => req.destroy());
      req.end();
    });
  const raw = (text: string) =>
    new Promise<string>((resolve, reject) => {
      const socket = connect(ingressPath);
      const chunks: Buffer[] = [];
      socket.on('connect', () => socket.write(text));
      socket.on('data', (b) => chunks.push(b));
      socket.on('error', (error: NodeJS.ErrnoException) =>
        ['ECONNRESET', 'EPIPE'].includes(error.code ?? '') ? resolve('') : reject(error),
      );
      socket.on('close', () => resolve(Buffer.concat(chunks).toString()));
      socket.setTimeout(7000, () => socket.destroy());
    });
  return {
    root,
    endpoint,
    ingressPath,
    calls,
    policy,
    engine,
    audit,
    broker,
    ask,
    raw,
    advance: (ms: number) => {
      wall += ms;
      mono += ms;
    },
    advanceWall: (ms: number) => {
      wall += ms;
    },
    refill: () => {
      mono += 60_000;
    },
    cleanup: async () => {
      ingress.closeAllConnections();
      upstream.closeAllConnections();
      const closed = [once(ingress, 'close'), once(upstream, 'close')];
      ingress.close();
      upstream.close();
      await Promise.all(closed);
      rmSync(root, { recursive: true, force: true });
    },
  };
}
export function rawRequest(path = route(), method = 'GET', extra = '') {
  return `${method} ${path} HTTP/1.1\r\nHost: broker\r\nAuthorization: Bearer ${TOKEN}\r\nX-Broker-Grant: grant-a\r\nConnection: close\r\n${extra}\r\n`;
}
