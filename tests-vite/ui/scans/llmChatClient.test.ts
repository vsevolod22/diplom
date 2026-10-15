import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { ChatError, createChatClient } from '@/shared/api/scans/llmChatClient';

import {
  chatContextSchema,
  chatHistorySchema,
  chatReplySchema,
  validChatText,
  verifiedChatSources,
} from '@/shared/api/scans/llmChatContract';
import {
  binding,
  chatApi,
  context,
  epoch,
  ndjson,
  history,
  json,
  reply,
  receipt,
  source,
  turnId,
  usage,
} from './llmChatFixtures';

// Runtime-only production seam: the backend owns its decorator-enabled TypeScript compilation.
const { encodeDelivery } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'history-delivery.ts'
);
const signal = () => new AbortController().signal;
beforeEach(() => transitionScanSession('alice', new QueryClient(), true));
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
it('uses only the actual five route/method pairs with exact CAS and separate chat consent DTOs', async () => {
  const api = chatApi();
  const client = createChatClient(scanSession(), api.fetcher);
  await client.context(binding.scanId, signal());
  await client.history(binding, signal());
  const counters = await client.usage(binding, signal());
  expect(counters.available && counters.admission.status).toBe('unavailable');
  const mutationId = crypto.randomUUID();
  await client.chat(context, 'Что проверить?', mutationId, signal());
  expect(new Headers(api.requests[3].init.headers).get('Accept')).toBe('application/x-ndjson');
  expect(JSON.parse(String(api.requests[3].init.body))).toEqual({
    epoch,
    revision: 0,
    mutationId,
    reportVersion: binding.reportVersion,
    question: 'Что проверить?',
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  await client.decision(
    { ...context, revision: 2 },
    'Проверить конфигурацию',
    [],
    crypto.randomUUID(),
    signal(),
  );
  expect(
    api.requests.map((r) => [
      r.path.replace(`/api/v1/browser/scans/${binding.scanId}/llm/`, ''),
      r.init.method,
    ]),
  ).toEqual([
    ['chat/context', 'GET'],
    ['history', 'GET'],
    ['chat/usage', 'GET'],
    ['chat', 'POST'],
    ['history/decision', 'POST'],
  ]);
  for (const r of api.requests)
    expect(r.init).toMatchObject({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  expect(Object.keys(JSON.parse(String(api.requests[4].init.body))).sort()).toEqual([
    'epoch',
    'findingIds',
    'mutationId',
    'reportVersion',
    'revision',
    'text',
  ]);
});
it('accepts actual unavailable usage without inventing zero counters or admission', async () => {
  const client = createChatClient(
    scanSession(),
    vi.fn(async () => json({ ...binding, available: false, admission: { status: 'unavailable' } })),
  );
  expect(await client.usage(binding, signal())).toMatchObject({ available: false, reason: 'unavailable' });
});
it('rejects counter arithmetic, paid/changed profile, receipt output >2048 and nonzero cost', async () => {
  const client = createChatClient(
    scanSession(),
    vi.fn(async () =>
      json({ ...usage, user: { ...usage.user, remaining: { ...usage.user.remaining, input: 0 } } }),
    ),
  );
  await expect(client.usage(binding, signal())).rejects.toThrow();
  for (const patch of [
    { model: 'other/free' },
    { providers: ['novita'] },
    { freeOnly: false },
    { requestBudgetUsd: 1 },
    { retention: 'no-training' },
  ])
    expect(
      chatContextSchema.safeParse({ ...context, disclosure: { ...context.disclosure, ...patch } }).success,
    ).toBe(false);
  for (const patch of [{ output: 2049 }, { costMicros: 1 }]) {
    const invalid = createChatClient(
      scanSession(),
      vi.fn(async () =>
        json({
          ...binding,
          epoch,
          revision: 2,
          turnId,
          deliveryMode: 'completed-response',
          reply,
          usage: {
            input: 1,
            output: 1,
            costMicros: 0,
            source: 'server-validated-provider-reported-not-invoice',
            ...patch,
          },
        }),
      ),
    );
    await expect(invalid.chat(context, 'Вопрос', crypto.randomUUID(), signal())).rejects.toThrow();
  }
});
it('matches server UTF8/control/URL/credential input boundaries and sends zero on invalid text', async () => {
  expect(validChatText('я'.repeat(1024))).toBe(true);
  expect(validChatText('я'.repeat(1025))).toBe(false);
  const fetcher = vi.fn();
  const client = createChatClient(scanSession(), fetcher);
  for (const value of [
    '',
    '  ',
    '<script>',
    'https://example.com',
    'password=foo',
    'javascript:foo',
    '\u202efoo',
  ]) {
    expect(validChatText(value)).toBe(false);
    await expect(client.chat(context, value, crypto.randomUUID(), signal())).rejects.toMatchObject({
      code: 'INPUT',
    });
  }
  expect(fetcher).not.toHaveBeenCalled();
});
it('validates source tuple, finding projection and membership, preserving historical sources explicitly', () => {
  expect(verifiedChatSources(reply, [{ findingId: 'secret-0-1', check: 'secret' }])).toBe(true);
  expect(verifiedChatSources(reply, [{ findingId: 'secret-0-0', check: 'secret' }])).toBe(false);
  expect(verifiedChatSources(reply, [{ findingId: 'secret-0-1', check: 'vuln' }])).toBe(false);
  expect(
    chatReplySchema.safeParse({ ...reply, sources: [{ ...source, reportVersion: 'd'.repeat(64) }] }).success,
  ).toBe(false);
  expect(
    chatReplySchema.safeParse({
      ...reply,
      sources: [{ ...source, finding: { ...source.finding, rawEvidence: 'hidden' } }],
    }).success,
  ).toBe(false);
  const old = { ...binding, reportVersion: 'd'.repeat(64) };
  expect(
    chatHistorySchema.safeParse({
      ...history,
      turns: [
        {
          id: turnId,
          mutationId: turnId,
          state: 'completed',
          question: 'Вопрос',
          report: old,
          createdAt: 0,
          reply: { ...reply, ...old, sources: [{ ...source, ...old }] },
        },
      ],
    }).success,
  ).toBe(true);
});
it('rejects public internal fingerprints, duplicate sources/turns, cross-scan history and pending mismatch', () => {
  const completed = {
    id: turnId,
    mutationId: turnId,
    state: 'completed',
    question: 'Вопрос',
    report: binding,
    createdAt: 0,
    reply,
  };
  for (const patch of [
    { inputHash: 'a'.repeat(64) },
    { consentPolicyVersion: 'a'.repeat(64) },
    { requestHash: 'a'.repeat(64) },
  ])
    expect(chatHistorySchema.safeParse({ ...history, turns: [{ ...completed, ...patch }] }).success).toBe(
      false,
    );
  expect(chatHistorySchema.safeParse({ ...history, turns: [completed, completed] }).success).toBe(false);
  expect(chatHistorySchema.safeParse({ ...history, pending: { turnId, state: 'pending' } }).success).toBe(
    false,
  );
  expect(
    chatHistorySchema.safeParse({
      ...history,
      decisions: [
        {
          id: turnId,
          mutationId: turnId,
          kind: 'user-decision',
          text: 'Решение',
          report: { ...binding, scanId: turnId },
          sources: [],
        },
      ],
    }).success,
  ).toBe(false);
  expect(chatReplySchema.safeParse({ ...reply, sources: [source, source] }).success).toBe(false);
});
it('status-only duplicate is rejected, not treated as cached assistant output, and never retried', async () => {
  const fetcher = vi.fn(async (_input, init) => {
    const { mutationId } = JSON.parse(String(init?.body));
    return ndjson([
      {
        ...binding,
        epoch,
        revision: 2,
        mutationId,
        turnId,
        v: 1,
        deliveryMode: 'validated-completed-reply',
        nativeProviderStream: false,
        type: 'done',
        seq: 0,
        outcome: 'duplicate',
        state: 'completed',
      },
    ]);
  });
  const client = createChatClient(scanSession(), fetcher);
  await expect(client.chat(context, 'Вопрос', crypto.randomUUID(), signal())).rejects.toMatchObject({
    code: 'DUPLICATE',
  });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
for (const bad of ['html', 'redirect', 'length', 'actual-size', 'utf8', 'magic-key'] as const) {
  it(`bounds and rejects ${bad} response before publication`, async () => {
    const response =
      bad === 'html'
        ? new Response('<script>', { headers: { 'Content-Type': 'text/html' } })
        : bad === 'actual-size'
          ? new Response('x'.repeat(8193), { headers: { 'Content-Type': 'application/json' } })
          : bad === 'utf8'
            ? new Response(new Uint8Array([255]), { headers: { 'Content-Type': 'application/json' } })
            : bad === 'magic-key'
              ? new Response('{"__proto__":{}}', { headers: { 'Content-Type': 'application/json' } })
              : json(context);
    if (bad === 'redirect') Object.defineProperty(response, 'redirected', { value: true });
    if (bad === 'length') response.headers.set('content-length', '8193');
    const client = createChatClient(
      scanSession(),
      vi.fn(async () => response),
    );
    await expect(client.context(binding.scanId, signal())).rejects.toThrow();
  });
}
it('cancels a stalled body reader and bounds noncooperative fetch with timeout', async () => {
  vi.useFakeTimers();
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ cancel });
  const client = createChatClient(
    scanSession(),
    vi.fn(async () => new Response(stream, { headers: { 'Content-Type': 'application/json' } })),
  );
  const pending = client.context(binding.scanId, signal());
  const assertion = expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' });
  await vi.advanceTimersByTimeAsync(40001);
  await assertion;
  expect(cancel).toHaveBeenCalled();
  const hung = createChatClient(
    scanSession(),
    vi.fn(() => new Promise<Response>(() => {})),
  );
  const hungAssertion = expect(hung.context(binding.scanId, signal())).rejects.toBeInstanceOf(ChatError);
  await vi.advanceTimersByTimeAsync(40001);
  await hungAssertion;
});
it('fences same-owner reauth and abort even when fetch ignores cancellation', async () => {
  let resolve!: (value: Response) => void;
  const client = createChatClient(
    scanSession(),
    vi.fn(
      () =>
        new Promise<Response>((r) => {
          resolve = r;
        }),
    ),
  );
  const controller = new AbortController();
  const pending = client.context(binding.scanId, controller.signal);
  const assertion = expect(pending).rejects.toMatchObject({ code: 'SESSION' });
  transitionScanSession('alice', new QueryClient(), true);
  resolve(json(context));
  await assertion;
  expect(client.current()).toBe(false);
});

function productionLines(mutationId: string, text = reply.text): readonly string[] {
  return encodeDelivery({
    ...binding,
    epoch,
    revision: 2,
    mutationId,
    turnId,
    outcome: 'completed',
    reply: { ...reply, text },
    usage: receipt,
  }).lines;
}
const framedResponse = (text: string | ReadableStream<Uint8Array>) =>
  new Response(text, { headers: { 'Content-Type': 'application/x-ndjson; charset=utf-8' } });

it('R5 unavailable production error-only wire is terminal without usage/reply/retry', async () => {
  const mutationId = crypto.randomUUID();
  const raw = encodeDelivery({
    ...binding,
    epoch,
    revision: context.revision + 2,
    mutationId,
    turnId,
    outcome: 'failed',
    receipt: 'unavailable',
  }).lines.join('');
  const fetcher = vi.fn(async () => framedResponse(raw));
  await expect(
    createChatClient(scanSession(), fetcher).chat(context, 'Вопрос', mutationId, signal()),
  ).rejects.toMatchObject({ code: 'LLM_UNAVAILABLE' });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(raw).not.toMatch(/"usage"|"reply"|"delta"|"citation"|"done"/);
  const forged = JSON.parse(raw);
  forged.receipt = 'accepted';
  const forgedFetcher = vi.fn(async () => framedResponse(JSON.stringify(forged) + '\n'));
  await expect(
    createChatClient(scanSession(), forgedFetcher).chat(context, 'Вопрос', mutationId, signal()),
  ).rejects.toThrow();
  expect(forgedFetcher).toHaveBeenCalledTimes(1);
});
it('framed production encoder -> client handles every UTF8/JSON/LF byte split without native-stream claims', async () => {
  const mutationId = crypto.randomUUID(),
    text = 'я '.repeat(800) + '\n- ~~~js\n  unfinished';
  const bytes = new TextEncoder().encode(productionLines(mutationId, text).join(''));
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
      controller.close();
    },
  });
  const client = createChatClient(
    scanSession(),
    vi.fn(async () => framedResponse(stream)),
  );
  const result = await client.chat(context, 'Вопрос', mutationId, signal());
  expect(result.reply.text).toBe(text);
  expect(result.deliveryMode).toBe('validated-completed-reply');
  expect(result.reply.sources).toEqual([source]);
  expect(result.usage).toEqual(receipt);
});
it('framed parser publishes nothing before done AND clean EOF', async () => {
  const mutationId = crypto.randomUUID(),
    lines = productionLines(mutationId);
  let writer!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      writer = controller;
    },
  });
  const client = createChatClient(
    scanSession(),
    vi.fn(async () => framedResponse(stream)),
  );
  let published = false;
  const pending = client.chat(context, 'Вопрос', mutationId, signal()).then((value) => {
    published = true;
    return value;
  });
  writer.enqueue(new TextEncoder().encode(lines.slice(0, -1).join('')));
  await new Promise((r) => setTimeout(r, 0));
  expect(published).toBe(false);
  writer.enqueue(new TextEncoder().encode(lines.at(-1)!));
  await new Promise((r) => setTimeout(r, 0));
  expect(published).toBe(false);
  writer.close();
  await pending;
  expect(published).toBe(true);
});
it.each([
  'nonce',
  'seq',
  'type',
  'tuple',
  'version',
  'native',
  'receipt-cost',
  'receipt-output',
  'source-url',
  'source-tuple',
  'order',
  'counts',
  'duplicate-delta',
  'after-done',
  'missing-done',
  'attacker-url',
  'script',
  'error-receipt',
])('framed rejects %s before result publication and performs no retry', async (bad) => {
  const mutationId = crypto.randomUUID();
  const frames: Record<string, unknown>[] = productionLines(mutationId).map((line) => JSON.parse(line));
  if (bad === 'nonce') frames[0].mutationId = turnId;
  if (bad === 'seq') frames[1].seq = 0;
  if (bad === 'type') frames[1].type = 'provider-token';
  if (bad === 'tuple') frames[2].turnId = epoch;
  if (bad === 'version') frames[0].v = 2;
  if (bad === 'native') frames[0].nativeProviderStream = true;
  if (bad === 'receipt-cost') frames[0].usage = { ...receipt, costMicros: 1 };
  if (bad === 'receipt-output') frames[0].usage = { ...receipt, output: 2049 };
  if (bad === 'source-url') frames[1].source = { ...source, url: 'javascript:evil' };
  if (bad === 'source-tuple') frames[1].source = { ...source, reportVersion: 'e'.repeat(64) };
  if (bad === 'order') frames.reverse();
  if (bad === 'counts') frames[3].textBytes = 0;
  if (bad === 'duplicate-delta') frames.splice(3, 0, { ...frames[2], seq: 3 });
  if (bad === 'after-done') frames.push({ ...frames[3], seq: 4 });
  if (bad === 'missing-done') frames.pop();
  if (bad === 'attacker-url' || bad === 'script') {
    const text = bad === 'script' ? '<script>alert(1)</script>' : 'javascript:evil';
    frames[2].text = text;
    frames[3].textBytes = new TextEncoder().encode(text).length;
  }
  if (bad === 'error-receipt') {
    frames.splice(1);
    frames.push({
      ...frames[0],
      type: 'error',
      seq: 1,
      receipt: 'unavailable',
      errorCode: 'LLM_UNAVAILABLE',
    });
    delete frames[1].usage;
  }
  const fetcher = vi.fn(async () => ndjson(frames));
  await expect(
    createChatClient(scanSession(), fetcher).chat(context, 'Вопрос', mutationId, signal()),
  ).rejects.toThrow();
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each(['line', 'aggregate', 'truncated-line', 'utf8', 'trailing-byte', 'json-success'])(
  'framed bounds %s and requires terminal LF plus clean EOF',
  async (bad) => {
    const mutationId = crypto.randomUUID(),
      raw = productionLines(mutationId).join('');
    let response: Response;
    if (bad === 'line') response = framedResponse(' '.repeat(8192) + '\n');
    else if (bad === 'aggregate') response = framedResponse(' '.repeat(196609));
    else if (bad === 'truncated-line') response = framedResponse(raw.slice(0, -1));
    else if (bad === 'trailing-byte') response = framedResponse(raw + ' ');
    else if (bad === 'json-success')
      response = json({
        ...binding,
        epoch,
        revision: 2,
        turnId,
        deliveryMode: 'completed-response',
        reply,
        usage: receipt,
      });
    else
      response = new Response(new Uint8Array([255, 10]), {
        headers: { 'Content-Type': 'application/x-ndjson' },
      });
    await expect(
      createChatClient(
        scanSession(),
        vi.fn(async () => response),
      ).chat(context, 'Вопрос', mutationId, signal()),
    ).rejects.toThrow();
  },
);
it('framed terminal error after accepted usage is not a reply/refund and does not retry', async () => {
  const mutationId = crypto.randomUUID(),
    frames = productionLines(mutationId).map((line) => JSON.parse(line));
  const common = { ...frames[0] };
  delete common.usage;
  const fetcher = vi.fn(async () =>
    ndjson([
      frames[0],
      { ...common, type: 'error', seq: 1, errorCode: 'LLM_UNAVAILABLE', receipt: 'accepted' },
    ]),
  );
  await expect(
    createChatClient(scanSession(), fetcher).chat(context, 'Вопрос', mutationId, signal()),
  ).rejects.toMatchObject({ code: 'LLM_UNAVAILABLE' });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('framed stalled EOF remains bounded, cancelled and session-fenced after valid done', async () => {
  vi.useFakeTimers();
  for (const mode of ['timeout', 'session', 'abort']) {
    const mutationId = crypto.randomUUID(),
      controller = new AbortController(),
      cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(writer) {
        writer.enqueue(new TextEncoder().encode(productionLines(mutationId).join('')));
      },
      cancel,
    });
    const pending = createChatClient(
      scanSession(),
      vi.fn(async () => framedResponse(stream)),
    ).chat(context, 'Вопрос', mutationId, controller.signal);
    const assertion = expect(pending).rejects.toMatchObject({
      code: mode === 'timeout' ? 'TIMEOUT' : mode === 'session' ? 'SESSION' : 'ABORTED',
    });
    await vi.advanceTimersByTimeAsync(1);
    if (mode === 'timeout') await vi.advanceTimersByTimeAsync(40001);
    else if (mode === 'session') transitionScanSession('alice', new QueryClient(), true);
    else controller.abort();
    await assertion;
    expect(cancel).toHaveBeenCalled();
  }
});
