import { createServer, request } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { lstatSync, realpathSync, chmodSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  canonical,
  capture,
  exact,
  integer,
  str,
  HEX,
  ID,
  SLUG,
  target,
  type Capture,
  type Target,
} from './contract.js';
import type { DispatchAck, EnrolledCaller, LiveIntent, Invalidation } from './live-port.js';
import { parseRuntimeJson } from '../../api/src/runtime/runtime-json.js';
import { dispatchPermit, validateInvalidation } from './dispatch-permit.js';
// Only application jobs cross this private Unix boundary. No upstream method/path/endpoint.
export async function listenApplicationCaller(
  path: string,
  credential: string,
  caller: EnrolledCaller,
  allowedSubject: (subject: string, target: Readonly<Target>, brokerSubject: string) => boolean,
) {
  str(credential, HEX);
  const root = dirname(path);
  const stat = lstatSync(root);
  if (
    realpathSync(root) !== root ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o777) !== 0o700 ||
    process.platform !== 'linux'
  )
    throw new Error('QUALIFICATION_MISSING');
  try {
    lstatSync(path);
    throw new Error('IPC_PATH_EXISTS');
  } catch (e) {
    if (!(e instanceof Error && 'code' in e && e.code === 'ENOENT')) throw e;
  }
  let busy = false;
  let disabled = false;
  const server = createServer({ maxHeaderSize: 4096 }, (req, res) => {
    const deny = () => {
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(403, { 'Content-Type': 'application/json', Connection: 'close' });
        res.end('{"error":"NOT_AUTHORIZED"}');
      }
    };
    const token = req.headers.authorization;
    const seen = new Set<string>();
    let duplicate = false;
    for (let n = 0; n < req.rawHeaders.length; n += 2) {
      const name = req.rawHeaders[n].toLowerCase();
      if (seen.has(name)) duplicate = true;
      seen.add(name);
    }
    if (
      duplicate ||
      req.headers.expect ||
      req.headers.origin ||
      req.headers.cookie ||
      req.headers['sec-fetch-site'] ||
      disabled ||
      busy ||
      req.method !== 'POST' ||
      req.url !== '/runtime-job-v1' ||
      typeof token !== 'string' ||
      !/^Bearer [a-f0-9]{64}$/.test(token) ||
      !timingSafeEqual(Buffer.from(token.slice(7)), Buffer.from(credential)) ||
      !token.startsWith('Bearer ') ||
      req.headers['content-type'] !== 'application/json' ||
      req.headers['transfer-encoding'] ||
      req.headers['content-encoding'] ||
      typeof req.headers['content-length'] !== 'string' ||
      !/^[1-9][0-9]{0,3}$/.test(req.headers['content-length']) ||
      Number(req.headers['content-length']) > 1024
    )
      return deny();
    busy = true;
    const chunks: Buffer[] = [];
    let bytes = 0;
    const abort = new AbortController();
    // A lost outcome can have dispatched a read. Never reopen admission on an uncertain abort.
    const indeterminate = () => {
      disabled = true;
      abort.abort();
      res.destroy();
      req.destroy();
    };
    const timer = setTimeout(indeterminate, 5000);
    const finish = () => {
      busy = false;
      clearTimeout(timer);
    };
    req.on('aborted', indeterminate);
    req.on('error', indeterminate);
    res.on('close', () => {
      if (!res.writableFinished) indeterminate();
    });
    req.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 1024) indeterminate();
      else chunks.push(chunk);
    });
    req.on('end', async () => {
      try {
        if (bytes !== Number(req.headers['content-length']) || abort.signal.aborted) throw new Error();
        const job = parseRuntimeJson(Buffer.concat(chunks));
        const kind = (job as { kind?: unknown })?.kind;
        if (kind === 'invalidate') {
          const b = exact(job, ['kind', 'fence']);
          await caller.invalidate(validateInvalidation(b.fence));
          res.end('{"ack":"invalidated"}');
          return;
        }
        const b = exact(job, ['kind', 'intent', 'permit']);
        str(b.permit, HEX);
        if (b.kind !== 'capture') throw new Error();
        const i = exact(b.intent, [
          'subject',
          'target',
          'consentId',
          'nonce',
          'expiresAt',
          'epoch',
          'brokerSubject',
          'captureId',
          'attempt',
        ]);
        str(i.subject, /^[A-Za-z0-9:_-]{1,128}$/);
        const t = target(i.target);
        str(i.consentId, ID);
        str(i.nonce, HEX);
        integer(i.expiresAt, 1);
        integer(i.epoch, 1);
        str(i.brokerSubject, SLUG);
        str(i.captureId, ID);
        integer(i.attempt, 1);
        if (!allowedSubject(i.subject as string, Object.freeze(t), i.brokerSubject as string))
          throw new Error();
        let ack: DispatchAck | undefined;
        let evidence: Capture;
        try {
          evidence = await caller.inspect(
            i as LiveIntent,
            abort.signal,
            (value) => {
              if (ack) throw new Error('INDETERMINATE');
              ack = value;
            },
            b.permit as string,
          );
        } catch (error: unknown) {
          if (!ack || abort.signal.aborted || disabled) throw new Error('INDETERMINATE');
          const reason =
            error instanceof Error &&
            ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED'].includes(error.message)
              ? error.message
              : 'INDETERMINATE';
          res.setHeader('Content-Type', 'application/json');
          res.end(canonical({ ack, reason }));
          return;
        }
        if (
          !ack ||
          abort.signal.aborted ||
          disabled ||
          !allowedSubject(i.subject as string, Object.freeze(t), i.brokerSubject as string)
        )
          throw new Error();
        res.setHeader('Content-Type', 'application/json');
        res.end(canonical({ ack, capture: capture(evidence) }));
      } catch {
        deny();
      } finally {
        finish();
      }
    });
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.maxConnections = 2;
  server.maxRequestsPerSocket = 1;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => {
      chmodSync(path, 0o600);
      resolve();
    });
  });
  const inode = lstatSync(path).ino;
  return {
    server,
    close: async () => {
      await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
      try {
        if (lstatSync(path).ino === inode) unlinkSync(path);
      } catch {
        // Best-effort inode-fenced cleanup; never unlink a replacement socket.
      }
    },
  };
}
export class UnixApplicationCaller implements EnrolledCaller {
  private readonly inode: number;
  constructor(
    private readonly socket: string,
    private readonly credential: string,
    private readonly dispatchKey: string,
  ) {
    str(dispatchKey, HEX);
    str(credential, HEX);
    const s = lstatSync(socket),
      root = lstatSync(dirname(socket));
    if (
      process.platform !== 'linux' ||
      realpathSync(socket) !== socket ||
      realpathSync(dirname(socket)) !== dirname(socket) ||
      !s.isSocket() ||
      s.uid !== process.getuid?.() ||
      (s.mode & 0o777) !== 0o600 ||
      root.uid !== s.uid ||
      (root.mode & 0o777) !== 0o700
    )
      throw new Error('TRANSPORT_UNSUPPORTED');
    this.inode = s.ino;
  }
  private call(body: unknown, signal?: AbortSignal): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (lstatSync(this.socket).ino !== this.inode) {
        reject(new Error('INDETERMINATE'));
        return;
      }
      const bytes = Buffer.from(canonical(body));
      if (bytes.length > 1024) {
        reject(new Error('INVALID_RUNTIME_INPUT'));
        return;
      }
      const req = request(
        {
          socketPath: this.socket,
          path: '/runtime-job-v1',
          method: 'POST',
          agent: false,
          signal,
          headers: {
            Host: 'runtime-caller',
            'Content-Type': 'application/json',
            'Content-Length': bytes.length,
            Authorization: `Bearer ${this.credential}`,
          },
        },
        (res) => {
          let n = 0;
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => {
            n += chunk.length;
            if (n > 65536) req.destroy(new Error('INDETERMINATE'));
            else chunks.push(chunk);
          });
          res.on('aborted', () => reject(new Error('INDETERMINATE')));
          res.on('error', () => reject(new Error('INDETERMINATE')));
          res.on('end', () => {
            try {
              if (res.statusCode !== 200) throw new Error();
              resolve(parseRuntimeJson(Buffer.concat(chunks, n)));
            } catch {
              reject(new Error('INDETERMINATE'));
            }
          });
        },
      );
      const total = setTimeout(() => req.destroy(new Error('INDETERMINATE')), 5000);
      req.once('close', () => clearTimeout(total));
      req.setTimeout(5000, () => req.destroy(new Error('INDETERMINATE')));
      req.on('error', () => reject(new Error('INDETERMINATE')));
      req.end(bytes);
    });
  }
  async inspect(
    intent: LiveIntent,
    signal: AbortSignal,
    ack: (decision: DispatchAck) => void,
  ): Promise<Capture> {
    const raw = await this.call(
      { kind: 'capture', intent, permit: dispatchPermit(intent, this.dispatchKey) },
      signal,
    );
    const failed = !!raw && typeof raw === 'object' && 'reason' in raw;
    const result = exact(raw, failed ? ['ack', 'reason'] : ['ack', 'capture']);
    if (result.ack !== 'dispatched' && result.ack !== 'aborted') throw new Error('INDETERMINATE');
    ack(result.ack);
    if (failed) {
      if (
        !['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED', 'INDETERMINATE'].includes(
          String(result.reason),
        )
      )
        throw new Error('INDETERMINATE');
      throw new Error(result.reason as string);
    }
    return capture(result.capture);
  }
  async invalidate(fence: Invalidation): Promise<void> {
    validateInvalidation(fence);
    const result = exact(await this.call({ kind: 'invalidate', fence }), ['ack']);
    if (result.ack !== 'invalidated') throw new Error('INDETERMINATE');
  }
}
