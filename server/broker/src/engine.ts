import { request } from 'node:http';
import { isAbsolute, normalize } from 'node:path';
import { HEX_ID, LIMITS, limits, SafeFailure, type Limits } from './contracts.js';
import type { Pin } from './policy.js';
export interface EngineTransport {
  inspect(pin: Pin, signal: AbortSignal, bound: Limits, dispatched: () => void): Promise<Buffer>;
}
export class UnixEngine implements EngineTransport {
  #dispatches = 0;
  get dispatches(): number {
    return this.#dispatches;
  }
  inspect(
    pin: Pin,
    signal: AbortSignal,
    bound: Limits = LIMITS,
    dispatched: () => void = () => {},
  ): Promise<Buffer> {
    try {
      bound = limits(bound);
    } catch {
      return Promise.reject(new SafeFailure('upstream'));
    }
    const c = pin.context;
    if (
      signal.aborted ||
      !HEX_ID.test(pin.id) ||
      c.apiVersion !== '1.47' ||
      c.transport !== 'unix' ||
      !isAbsolute(c.endpoint) ||
      normalize(c.endpoint) !== c.endpoint ||
      /[\x00-\x1f]/.test(c.endpoint)
    ) {
      return Promise.reject(new SafeFailure('upstream'));
    }
    return new Promise((resolve, reject) => {
      let finished = false;
      let bytes = 0;
      // One bounded backing buffer: fragmented one-byte responses cannot grow a chunk-object list.
      let storage = Buffer.allocUnsafe(bound.upstreamBytes);
      let response: import('node:http').IncomingMessage | undefined;
      let req: import('node:http').ClientRequest | undefined;
      let connectTimer: ReturnType<typeof setTimeout> | undefined;
      const cleanup = () => {
        clearTimeout(connectTimer);
        signal.removeEventListener('abort', abort);
      };
      const fail = () => {
        if (finished) return;
        finished = true;
        cleanup();
        storage = Buffer.alloc(0);
        response?.destroy();
        req?.destroy();
        reject(new SafeFailure('upstream'));
      };
      const abort = () => fail();
      try {
        // This is the sole dispatch boundary: no generic method/path/headers parameter.
        this.#dispatches++;
        dispatched();
        req = request(
          {
            socketPath: c.endpoint,
            method: 'GET',
            path: `/v1.47/containers/${pin.id}/json`,
            agent: false,
            headers: { Host: 'engine', Accept: 'application/json', Connection: 'close' },
            maxHeaderSize: LIMITS.ingressBytes,
          },
          (res) => {
            response = res;
            const types = res.rawHeaders.filter(
              (_, i) => i % 2 === 0 && res.rawHeaders[i].toLowerCase() === 'content-type',
            );
            if (
              res.statusCode !== 200 ||
              types.length !== 1 ||
              !/^application\/json(?:;\s*charset=utf-8)?$/i.test(res.headers['content-type'] ?? '') ||
              (res.headers['content-encoding'] !== undefined &&
                res.headers['content-encoding'] !== 'identity')
            )
              return fail();
            res.on('data', (chunk: Buffer) => {
              if (finished) return;
              if (bytes + chunk.length > bound.upstreamBytes) return fail();
              chunk.copy(storage, bytes);
              bytes += chunk.length;
            });
            res.on('error', fail);
            res.on('aborted', fail);
            res.on('end', () => {
              if (finished) return;
              if (!res.complete) return fail();
              finished = true;
              cleanup();
              const body = storage.subarray(0, bytes);
              storage = Buffer.alloc(0);
              resolve(body);
            });
          },
        );
        req.on('error', fail);
        req.on('socket', (socket) => {
          if (!socket.connecting) clearTimeout(connectTimer);
          else socket.once('connect', () => clearTimeout(connectTimer));
        });
        connectTimer = setTimeout(fail, bound.connectMs);
        signal.addEventListener('abort', abort, { once: true });
        req.end();
      } catch {
        fail();
      }
    });
  }
}
