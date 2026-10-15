import { NotAcceptableException, ServiceUnavailableException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import {
  HISTORY,
  bytes,
  cleanText,
  isId,
  type ChatReply,
  type ReportBinding,
  type Source,
  type Turn,
} from './history-contract.js';
import { safeHistoryFinding } from './history-sources.js';
import { exact } from './response.js';

export const DELIVERY = Object.freeze({
  lineBytes: 8192,
  totalBytes: 196608,
  frames: 52,
  deltaBytes: 1024,
  timeoutMs: 5000,
});
export type ChatReceipt = {
  input: number;
  output: number;
  costMicros: number;
  source: 'server-validated-provider-reported-not-invoice';
};
type Binding = ReportBinding & { epoch: string; revision: number; mutationId: string; turnId: string };
// Constructed after an exact admitted attempt's durable terminal history transition; usage requires its successful observation.
export type ChatDelivery = Binding &
  (
    | { outcome: 'completed'; reply: ChatReply; usage: ChatReceipt }
    | { outcome: 'failed'; usage: Readonly<ChatReceipt> }
    | { outcome: 'failed'; receipt: 'unavailable' }
    | { outcome: 'duplicate'; state: Turn['state'] }
  );
export type DeliveryResult = { delivery: ChatDelivery; write(action: () => void): void; release(): void };
const unavailable = () => new ServiceUnavailableException({ errorCode: 'LLM_UNAVAILABLE' });
const count = (value: number) => Number.isSafeInteger(value) && value >= 0;
const same = (a: ReportBinding, b: ReportBinding) =>
  ['scanId', 'digest', 'platform', 'reportVersion'].every(
    (k) => a[k as keyof ReportBinding] === b[k as keyof ReportBinding],
  );

export function chatRepresentation(accept: string | undefined): 'json' | 'ndjson' {
  if (accept === 'application/x-ndjson') return 'ndjson';
  if (accept === undefined || accept === '*/*' || accept === 'application/json') return 'json';
  throw new NotAcceptableException({ errorCode: 'LLM_INVALID_REQUEST' });
}
export function encodeDelivery(value: ChatDelivery) {
  if (
    !isId(value.scanId) ||
    !isId(value.epoch) ||
    !isId(value.mutationId) ||
    !isId(value.turnId) ||
    !count(value.revision) ||
    !/^sha256:[a-f0-9]{64}$/.test(value.digest) ||
    !/^[a-f0-9]{64}$/.test(value.reportVersion) ||
    value.platform !== 'linux/amd64'
  )
    throw unavailable();
  const common = {
    v: 1,
    deliveryMode: 'validated-completed-reply',
    nativeProviderStream: false,
    scanId: value.scanId,
    digest: value.digest,
    platform: value.platform,
    reportVersion: value.reportVersion,
    epoch: value.epoch,
    revision: value.revision,
    mutationId: value.mutationId,
    turnId: value.turnId,
  };
  const line = (seq: number, type: string, payload: object) => {
    const encoded = JSON.stringify({ ...common, type, seq, ...payload }) + '\n';
    if (Buffer.byteLength(encoded) > DELIVERY.lineBytes) throw unavailable();
    return encoded;
  };
  const lines: string[] = [];
  const add = (type: string, payload: object) => lines.push(line(lines.length, type, payload));
  if (value.outcome === 'duplicate') {
    if (!['pending', 'completed', 'failed', 'cancelled', 'interrupted'].includes(value.state))
      throw unavailable();
    add('done', { outcome: 'duplicate', state: value.state });
  } else if (value.outcome === 'failed' && 'receipt' in value) {
    if (
      value.receipt !== 'unavailable' ||
      !exact(value, [
        'scanId',
        'digest',
        'platform',
        'reportVersion',
        'epoch',
        'revision',
        'mutationId',
        'turnId',
        'outcome',
        'receipt',
      ])
    )
      throw unavailable();
    add('error', { errorCode: 'LLM_UNAVAILABLE', receipt: 'unavailable' });
  } else {
    const { usage } = value;
    if (
      !exact(usage, ['input', 'output', 'costMicros', 'source']) ||
      !count(usage.input) ||
      !count(usage.output) ||
      usage.output > 2048 ||
      usage.costMicros !== 0 ||
      usage.source !== 'server-validated-provider-reported-not-invoice'
    )
      throw unavailable();
    if (value.outcome === 'failed') {
      if (
        !exact(value, [
          'scanId',
          'digest',
          'platform',
          'reportVersion',
          'epoch',
          'revision',
          'mutationId',
          'turnId',
          'outcome',
          'usage',
        ])
      )
        throw unavailable();
      add('usage', { usage });
      add('error', { errorCode: 'LLM_UNAVAILABLE', receipt: 'accepted' });
    } else {
      const { reply } = value;
      if (
        !exact(reply, ['scanId', 'digest', 'platform', 'reportVersion', 'kind', 'text', 'sources']) ||
        reply.kind !== 'hypothesis' ||
        !same(reply, value) ||
        !Array.isArray(reply.sources) ||
        !reply.sources.length ||
        reply.sources.length > HISTORY.citations ||
        new Set(reply.sources.map((s) => s.finding.findingId)).size !== reply.sources.length ||
        reply.sources.some(
          (s) =>
            !exact(s, ['scanId', 'digest', 'platform', 'reportVersion', 'finding']) ||
            !same(s, value) ||
            bytes(s) > HISTORY.citationBytes ||
            !safeHistoryFinding(s.finding),
        ) ||
        bytes({ ...reply, usage }) > HISTORY.completionReserve
      )
        throw unavailable();
      cleanText(reply.text, HISTORY.replyBytes);
      add('usage', { usage });
      reply.sources.forEach((source: Source, index: number) => add('citation', { index, source }));
      let chunk = '',
        size = 0,
        index = 0;
      for (const char of reply.text) {
        const n = Buffer.byteLength(char);
        if (size + n > DELIVERY.deltaBytes) {
          add('delta', { index: index++, text: chunk });
          chunk = '';
          size = 0;
        }
        chunk += char;
        size += n;
      }
      if (chunk) add('delta', { index: index++, text: chunk });
      add('done', {
        outcome: 'completed',
        kind: 'hypothesis',
        textBytes: Buffer.byteLength(reply.text),
        citationCount: reply.sources.length,
        deltaCount: index,
      });
    }
  }
  // Reserve room for a bounded terminal error if a pre-terminal write fails.
  const error = (seq: number) =>
    line(seq, 'error', {
      errorCode: 'LLM_UNAVAILABLE',
      receipt: 'usage' in value ? 'accepted' : 'unavailable',
    });
  const size = lines.reduce((n, s) => n + Buffer.byteLength(s), 0);
  if (
    lines.length + 1 > DELIVERY.frames ||
    size + Buffer.byteLength(error(lines.length)) > DELIVERY.totalBytes
  )
    throw unavailable();
  return { lines: Object.freeze(lines), error };
}

export async function writeDelivery(result: DeliveryResult, response: ServerResponse, signal: AbortSignal) {
  let started = false,
    terminal = false,
    seq = 0;
  let plan: ReturnType<typeof encodeDelivery> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stop!: (reason: Error) => void;
  const deadline = Date.now() + DELIVERY.timeoutMs;
  const stopped = new Promise<never>((_, reject) => {
    stop = reject;
  });
  // Also observe rejection while synchronous preflight/guard code is running.
  void stopped.catch(() => {});
  const abort = () => stop(unavailable()),
    closed = () => {
      if (!response.writableFinished) abort();
    };
  const failed = () => stop(unavailable());
  signal.addEventListener('abort', abort, { once: true });
  response.on('close', closed);
  response.on('error', failed);
  const live = () => {
    if (signal.aborted || response.destroyed || Date.now() >= deadline) throw unavailable();
  };
  const wait = async (event: 'drain' | 'finish') => {
    let ready!: () => void;
    const next = new Promise<void>((resolve) => {
      ready = resolve;
      response.once(event, ready);
    });
    try {
      await Promise.race([next, stopped]);
      if (event === 'drain') live();
    } finally {
      response.off(event, ready);
    }
  };
  try {
    plan = encodeDelivery(result.delivery);
    live();
    timer = setTimeout(abort, Math.max(1, deadline - Date.now()));
    result.write(() => {
      live();
      response.writeHead(200, {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-store, no-transform',
        'x-content-type-options': 'nosniff',
      });
      started = true;
    });
    for (const line of plan.lines) {
      let drained = false;
      result.write(() => {
        live();
        drained = response.write(line);
      });
      seq++;
      terminal = seq === plan.lines.length;
      if (!drained) await wait('drain');
    }
    // Register finish before end, including for synchronous synthetic sockets.
    const finished = wait('finish');
    try {
      result.write(() => {
        live();
        response.end();
      });
      await finished;
    } catch (error) {
      stop(unavailable());
      await finished.catch(() => {});
      throw error;
    }
  } catch (error) {
    if (!started) throw error;
    let recovered = false;
    // Without a delivered usage frame the client cannot validate an accepted receipt: close, never invent one.
    if (!terminal && seq > 0 && !signal.aborted && !response.destroyed && Date.now() < deadline) {
      const finished = wait('finish');
      try {
        const line = plan!.error(seq);
        result.write(() => {
          live();
          response.end(line);
        });
        await finished;
        recovered = true;
      } catch {
        stop(unavailable());
        await finished.catch(() => {}); /* Never disclose a stale error/receipt. */
      }
    }
    if (!recovered) response.destroy();
  } finally {
    if (timer) clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    response.off('close', closed);
    response.off('error', failed);
    result.release();
  }
}
