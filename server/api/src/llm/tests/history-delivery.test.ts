import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import type { ServerResponse } from 'node:http';
import {
  DELIVERY,
  chatRepresentation,
  encodeDelivery,
  writeDelivery,
  type ChatDelivery,
} from '../history-delivery.js';

const binding = {
  scanId: '00000000-0000-4000-8000-000000000016',
  digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64' as const,
  reportVersion: 'b'.repeat(64),
};
const outcome: ChatDelivery = {
  ...binding,
  epoch: '00000000-0000-4000-8000-000000000001',
  revision: 2,
  mutationId: '00000000-0000-4000-8000-000000000003',
  turnId: '00000000-0000-4000-8000-000000000002',
  outcome: 'completed',
  reply: {
    ...binding,
    kind: 'hypothesis',
    text: '- ```js\n  unfinished hypothesis',
    sources: [
      {
        ...binding,
        finding: {
          check: 'secret',
          findingId: 'secret-0-1',
          severity: 'UNKNOWN',
          ruleId: 'rule-0123456789abcdef',
          line: 1,
          evidenceRef: 'result-0-secret-1',
        },
      },
    ],
  },
  usage: { input: 500, output: 32, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' },
};
class Socket extends EventEmitter {
  destroyed = false;
  writableFinished = false;
  writableEnded = false;
  lines: string[] = [];
  headers: unknown;
  writes = 0;
  onWrite: (n: number) => boolean = () => true;
  writeHead(_code: number, headers: unknown) {
    this.headers = headers;
  }
  write(value: string) {
    const ready = this.onWrite(++this.writes);
    this.lines.push(value);
    return ready;
  }
  end(value?: string) {
    if (value) this.lines.push(value);
    this.writableEnded = true;
    this.writableFinished = true;
    this.emit('finish');
  }
  destroy() {
    this.destroyed = true;
    this.emit('close');
    return this;
  }
  get response() {
    return this as unknown as ServerResponse;
  }
}
const frame = (line: string) => JSON.parse(line);

test('TASK16 codec exact literal tuple, receipt first, source projections, UTF8 chunks and bounded terminal', () => {
  const text = 'я '.repeat(4096),
    plan = encodeDelivery({ ...outcome, reply: { ...outcome.reply, text } });
  const frames = plan.lines.map(frame);
  assert.deepEqual(
    frames.map((f) => f.seq),
    frames.map((_, i) => i),
  );
  assert.equal(frames[0].type, 'usage');
  assert.equal(frames[0].usage.source, 'server-validated-provider-reported-not-invoice');
  assert.equal(frames[1].type, 'citation');
  assert.deepEqual(frames[1].source, outcome.reply.sources[0]);
  assert.ok(frames.every((f) => f.nativeProviderStream === false && f.mutationId === outcome.mutationId));
  const deltas = frames.filter((f) => f.type === 'delta');
  assert.equal(deltas.map((f) => f.text).join(''), text);
  assert.ok(
    deltas.every((f) => Buffer.byteLength(f.text) <= DELIVERY.deltaBytes && !f.text.includes('\ufffd')),
  );
  assert.equal(frames.at(-1).type, 'done');
  assert.equal(frames.at(-1).textBytes, Buffer.byteLength(text));
  assert.ok(plan.lines.every((l) => Buffer.byteLength(l) <= DELIVERY.lineBytes));
  assert.ok(plan.lines.join('').length < DELIVERY.totalBytes && plan.lines.length < DELIVERY.frames);
  assert.throws(() => encodeDelivery({ ...outcome, usage: { ...outcome.usage, output: 2049 } }));
  assert.throws(() => encodeDelivery({ ...outcome, usage: { ...outcome.usage, costMicros: 1 } }));
  for (const bad of ['<script>', 'javascript:evil', 'https://evil.example', 'x'.repeat(16385)])
    assert.throws(() => encodeDelivery({ ...outcome, reply: { ...outcome.reply, text: bad } }));
});
test('TASK16 exact reply/source/count ceilings and escaped encoded bytes are preflight bounded', () => {
  const sources = Array.from({ length: 32 }, (_, i) => ({
    ...outcome.reply.sources[0],
    finding: {
      ...outcome.reply.sources[0].finding,
      findingId: `secret-0-${i}`,
      evidenceRef: `result-0-secret-${i}`,
    },
  }));
  const text = 'я '.repeat(5461),
    plan = encodeDelivery({ ...outcome, reply: { ...outcome.reply, text, sources } });
  assert.equal(plan.lines.length, 51);
  assert.equal(plan.lines.map(frame).filter((f) => f.type === 'delta').length, 17);
  assert.ok(plan.lines.every((line) => Buffer.byteLength(line) <= DELIVERY.lineBytes));
  assert.throws(() => encodeDelivery({ ...outcome, reply: { ...outcome.reply, text: text + 'я', sources } }));
  assert.throws(() =>
    encodeDelivery({ ...outcome, reply: { ...outcome.reply, sources: [...sources, sources[0]] } }),
  );
  assert.throws(() =>
    encodeDelivery({
      ...outcome,
      reply: { ...outcome.reply, sources: [{ ...sources[0], reportVersion: 'e'.repeat(64) }] },
    }),
  );
  const escaped = encodeDelivery({ ...outcome, reply: { ...outcome.reply, text: '"\\\\\n'.repeat(4096) } });
  assert.ok(escaped.lines.every((line) => Buffer.byteLength(line) <= DELIVERY.lineBytes));
});
test('TASK16 negotiated opt-in only and duplicate status-only plan never fabricates receipt or reply', () => {
  for (const accept of [undefined, '*/*', 'application/json'])
    assert.equal(chatRepresentation(accept), 'json');
  assert.equal(chatRepresentation('application/x-ndjson'), 'ndjson');
  for (const bad of [
    '',
    'text/event-stream',
    'application/x-ndjson, application/json',
    'application/x-ndjson;q=1',
  ])
    assert.throws(() => chatRepresentation(bad));
  const plan = encodeDelivery({
    ...binding,
    epoch: outcome.epoch,
    revision: 2,
    mutationId: outcome.mutationId,
    turnId: outcome.turnId,
    outcome: 'duplicate',
    state: 'completed',
  });
  assert.equal(plan.lines.length, 1);
  const done = frame(plan.lines[0]);
  assert.equal(done.outcome, 'duplicate');
  assert.equal('usage' in done, false);
  assert.equal('textBytes' in done, false);
});
test('TASK16 actual writer rechecks each write and after drain, holds release until finish', async () => {
  const socket = new Socket();
  let guards = 0,
    releases = 0;
  socket.onWrite = (n) => {
    if (n === 1) {
      queueMicrotask(() => {
        assert.equal(releases, 0);
        socket.emit('drain');
      });
      return false;
    }
    return true;
  };
  await writeDelivery(
    {
      delivery: outcome,
      write: (action) => {
        guards++;
        action();
      },
      release: () => releases++,
    },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(guards, encodeDelivery(outcome).lines.length + 2);
  assert.equal(releases, 1);
  assert.equal(socket.destroyed, false);
  assert.equal(socket.writableFinished, true);
  assert.equal(frame(socket.lines.at(-1)!).type, 'done');
});
test('TASK16 loss of trusted write authority during drain closes without success/error disclosure', async () => {
  const socket = new Socket();
  let live = true,
    releases = 0;
  socket.onWrite = () => {
    queueMicrotask(() => {
      live = false;
      socket.emit('drain');
    });
    return false;
  };
  await writeDelivery(
    {
      delivery: outcome,
      write: (action) => {
        if (!live) throw new Error('private auth diagnostic');
        action();
      },
      release: () => releases++,
    },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(socket.lines.length, 1);
  assert.equal(frame(socket.lines[0]).type, 'usage');
  assert.equal(socket.destroyed, true);
  assert.equal(releases, 1);
  assert.doesNotMatch(socket.lines.join(''), /private auth|"done"|"error"/);
});
test('TASK16 usage-write fault closes rather than emitting an unverifiable accepted receipt error', async () => {
  const socket = new Socket();
  let releases = 0;
  socket.onWrite = () => {
    throw new Error('synthetic first frame fault');
  };
  await writeDelivery(
    { delivery: outcome, write: (action) => action(), release: () => releases++ },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(socket.destroyed, true);
  assert.equal(socket.lines.length, 0);
  assert.equal(releases, 1);
});
test('TASK16 later recoverable write fault emits bounded safe terminal error and never done', async () => {
  const socket = new Socket();
  let releases = 0;
  socket.onWrite = (n) => {
    if (n === 2) throw new Error('PRIVATE-disk/path');
    return true;
  };
  await writeDelivery(
    { delivery: outcome, write: (action) => action(), release: () => releases++ },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(socket.lines.length, 2);
  const error = frame(socket.lines[1]);
  assert.equal(error.seq, 1);
  assert.equal(error.type, 'error');
  assert.equal(error.receipt, 'accepted');
  assert.equal(error.errorCode, 'LLM_UNAVAILABLE');
  assert.doesNotMatch(socket.lines.join(''), /PRIVATE|"done"/);
  assert.equal(releases, 1);
});
test('TASK16 abort and absolute stalled-drain deadline close and release once', async (t) => {
  for (const mode of ['abort', 'deadline']) {
    const socket = new Socket(),
      controller = new AbortController();
    let releases = 0;
    socket.onWrite = () => false;
    if (mode === 'deadline') t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const writing = writeDelivery(
      { delivery: outcome, write: (action) => action(), release: () => releases++ },
      socket.response,
      controller.signal,
    );
    if (mode === 'abort') controller.abort();
    else t.mock.timers.tick(DELIVERY.timeoutMs + 1);
    await writing;
    assert.equal(socket.destroyed, true);
    assert.equal(releases, 1);
    assert.equal(socket.lines.length, 1);
    t.mock.timers.reset();
  }
});
test('TASK16 stalled terminal socket finish is bounded and retains the lease until closure', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const socket = new Socket();
  let releases = 0;
  socket.end = () => {
    socket.writableEnded = true;
  };
  const writing = writeDelivery(
    { delivery: outcome, write: (action) => action(), release: () => releases++ },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(releases, 0);
  assert.equal(frame(socket.lines.at(-1)!).type, 'done');
  t.mock.timers.tick(DELIVERY.timeoutMs + 1);
  await writing;
  assert.equal(socket.destroyed, true);
  assert.equal(releases, 1);
});
test('TASK16 prewrite faults throw for existing exception filter with no headers, always releasing', async () => {
  const socket = new Socket();
  let releases = 0;
  await assert.rejects(
    writeDelivery(
      {
        delivery: outcome,
        write: () => {
          throw new Error('private stale');
        },
        release: () => releases++,
      },
      socket.response,
      new AbortController().signal,
    ),
  );
  assert.equal(socket.headers, undefined);
  assert.equal(socket.lines.length, 0);
  assert.equal(releases, 1);
});

const failed: ChatDelivery = Object.freeze({
  ...binding,
  epoch: outcome.epoch,
  revision: outcome.revision,
  mutationId: outcome.mutationId,
  turnId: outcome.turnId,
  outcome: 'failed',
  usage: Object.freeze({ ...outcome.usage }),
});
test('TASK16 R4 failed codec emits exact usage/error only; rejects content and untrusted receipt shapes', () => {
  const plan = encodeDelivery(failed),
    frames = plan.lines.map(frame);
  assert.deepEqual(
    frames.map((f) => [f.type, f.seq]),
    [
      ['usage', 0],
      ['error', 1],
    ],
  );
  assert.deepEqual(frames[0].usage, outcome.usage);
  assert.equal(frames[1].receipt, 'accepted');
  assert.equal(frames[1].errorCode, 'LLM_UNAVAILABLE');
  assert.ok(
    frames.every(
      (f) =>
        f.turnId === failed.turnId && f.mutationId === failed.mutationId && f.revision === failed.revision,
    ),
  );
  assert.ok(plan.lines.every((line) => line.endsWith('\n') && Buffer.byteLength(line) <= DELIVERY.lineBytes));
  assert.doesNotMatch(plan.lines.join(''), /"reply"|"source"\s*:\s*\{|"citation"|"delta"|"done"|unfinished/);
  for (const value of [
    { ...failed, reply: outcome.reply },
    { ...failed, diagnostic: 'PRIVATE' },
    { ...failed, usage: undefined },
    { ...failed, usage: { ...failed.usage, output: 2049 } },
    { ...failed, usage: { ...failed.usage, input: NaN } },
    { ...failed, usage: { ...failed.usage, costMicros: 1 } },
    { ...failed, usage: { ...failed.usage, source: 'cumulative-counters' } },
  ])
    assert.throws(() => encodeDelivery(value as ChatDelivery));
});
test('TASK16 R4 failed writer guards header/usage/error/end, holds lease through drain and finish', async () => {
  const socket = new Socket();
  let guards = 0,
    releases = 0;
  socket.onWrite = (n) => {
    if (n === 1) {
      queueMicrotask(() => {
        assert.equal(releases, 0);
        socket.emit('drain');
      });
      return false;
    }
    return true;
  };
  await writeDelivery(
    {
      delivery: failed,
      write: (action) => {
        guards++;
        assert.equal(releases, 0);
        action();
      },
      release: () => releases++,
    },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(guards, 4);
  assert.equal(releases, 1);
  assert.equal(socket.destroyed, false);
  assert.deepEqual(
    socket.lines.map(frame).map((f) => f.type),
    ['usage', 'error'],
  );
  assert.equal(socket.writableFinished, true);
});
test('TASK16 R4 failed writer authority/abort/deadline loss after usage suppresses stale error and releases', async (t) => {
  for (const mode of ['authority', 'abort', 'deadline']) {
    const socket = new Socket(),
      controller = new AbortController();
    let authorized = true,
      releases = 0;
    socket.onWrite = () => false;
    if (mode === 'deadline') t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const writing = writeDelivery(
      {
        delivery: failed,
        write: (action) => {
          if (!authorized) throw new Error('PRIVATE-head');
          action();
        },
        release: () => releases++,
      },
      socket.response,
      controller.signal,
    );
    if (mode === 'authority') {
      authorized = false;
      socket.emit('drain');
    } else if (mode === 'abort') controller.abort();
    else t.mock.timers.tick(DELIVERY.timeoutMs + 1);
    await writing;
    assert.equal(socket.destroyed, true);
    assert.equal(releases, 1);
    assert.deepEqual(
      socket.lines.map(frame).map((f) => f.type),
      ['usage'],
    );
    assert.doesNotMatch(socket.lines.join(''), /PRIVATE|"error"|"done"/);
    assert.equal(socket.listenerCount('drain'), 0);
    assert.equal(socket.listenerCount('finish'), 0);
    t.mock.timers.reset();
  }
});

const unavailableReceipt: ChatDelivery = Object.freeze({
  ...binding,
  epoch: outcome.epoch,
  revision: outcome.revision,
  mutationId: outcome.mutationId,
  turnId: outcome.turnId,
  outcome: 'failed',
  receipt: 'unavailable',
});
test('TASK16 R5 unavailable codec has exactly error seq0 and rejects any usage/content/accepted receipt', () => {
  const plan = encodeDelivery(unavailableReceipt),
    error = frame(plan.lines[0]);
  assert.equal(plan.lines.length, 1);
  assert.equal(error.type, 'error');
  assert.equal(error.seq, 0);
  assert.equal(error.receipt, 'unavailable');
  assert.equal(error.errorCode, 'LLM_UNAVAILABLE');
  assert.equal(error.mutationId, unavailableReceipt.mutationId);
  assert.equal(error.turnId, unavailableReceipt.turnId);
  assert.equal(error.revision, unavailableReceipt.revision);
  assert.equal(error.nativeProviderStream, false);
  assert.ok(plan.lines[0].endsWith('\n') && Buffer.byteLength(plan.lines[0]) <= DELIVERY.lineBytes);
  assert.doesNotMatch(plan.lines[0], /"usage"|"citation"|"delta"|"done"|"reply"|"text"|accepted/);
  for (const value of [
    { ...unavailableReceipt, usage: outcome.usage },
    { ...unavailableReceipt, reply: outcome.reply },
    { ...unavailableReceipt, diagnostic: 'PRIVATE' },
    { ...unavailableReceipt, receipt: 'accepted' },
    { ...unavailableReceipt, input: 0 },
  ])
    assert.throws(() => encodeDelivery(value as ChatDelivery));
});
test('TASK16 R5 unavailable writer guards header/error/end and retains lease through drain/finish', async () => {
  const socket = new Socket();
  let guards = 0,
    releases = 0;
  socket.onWrite = () => {
    queueMicrotask(() => {
      assert.equal(releases, 0);
      socket.emit('drain');
    });
    return false;
  };
  await writeDelivery(
    {
      delivery: unavailableReceipt,
      write: (action) => {
        guards++;
        assert.equal(releases, 0);
        action();
      },
      release: () => releases++,
    },
    socket.response,
    new AbortController().signal,
  );
  assert.equal(guards, 3);
  assert.equal(releases, 1);
  assert.equal(socket.destroyed, false);
  assert.equal(socket.writableFinished, true);
  assert.deepEqual(
    socket.lines.map(frame).map((f) => [f.type, f.seq, f.receipt]),
    [['error', 0, 'unavailable']],
  );
});
test('TASK16 R5 unavailable writer faults/authority/abort/deadline release without usage or extra terminal', async (t) => {
  for (const mode of [
    'preheader',
    'error-write',
    'after-header',
    'before-end',
    'abort',
    'drain-deadline',
    'finish-deadline',
  ]) {
    const socket = new Socket(),
      controller = new AbortController();
    let guards = 0,
      releases = 0;
    if (mode === 'error-write')
      socket.onWrite = () => {
        throw new Error('PRIVATE-error-write');
      };
    if (mode === 'abort' || mode === 'drain-deadline') socket.onWrite = () => false;
    if (mode === 'finish-deadline')
      socket.end = () => {
        socket.writableEnded = true;
      };
    if (mode.includes('deadline')) t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const writing = writeDelivery(
      {
        delivery: unavailableReceipt,
        write: (action) => {
          guards++;
          if (
            mode === 'preheader' ||
            (mode === 'after-header' && guards === 2) ||
            (mode === 'before-end' && guards === 3)
          )
            throw new Error('PRIVATE-authority');
          action();
        },
        release: () => releases++,
      },
      socket.response,
      controller.signal,
    );
    if (mode === 'preheader') await assert.rejects(writing);
    else {
      if (mode === 'abort') controller.abort();
      if (mode.includes('deadline')) t.mock.timers.tick(DELIVERY.timeoutMs + 1);
      await writing;
      assert.equal(socket.destroyed, true);
    }
    assert.equal(releases, 1);
    assert.ok(socket.lines.length <= 1);
    assert.equal(socket.writableFinished, false);
    assert.doesNotMatch(socket.lines.join(''), /PRIVATE|"usage"|accepted|"done"|"citation"|"delta"/);
    assert.equal(socket.listenerCount('drain'), 0);
    assert.equal(socket.listenerCount('finish'), 0);
    assert.equal(socket.listenerCount('close'), 0);
    assert.equal(socket.listenerCount('error'), 0);
    t.mock.timers.reset();
  }
});
