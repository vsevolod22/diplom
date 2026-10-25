import { QueryClient } from '@tanstack/react-query';
import { beforeEach, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { chatErrorMessage, createChatClient } from '@/shared/api/scans/llmChatClient';
import {
  createAdvisoryTranslationClient,
  translationErrorMessage,
} from '@/shared/api/scans/advisoryTranslationClient';
import { context, binding, epoch, receipt, turnId, json, ndjson, source } from './llmChatFixtures';
import { contextFor } from './advisoryTranslationFixtures';

// Pure production wire producers only: no provider, credentials, stores or lifecycle calls.
const { encodeDelivery } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'history-delivery.ts'
);
const { safeProviderFailure } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'openrouter-provider.ts'
);
beforeEach(() => transitionScanSession('alice', new QueryClient(), true));
const signal = () => new AbortController().signal;
function failureFor(status: number, retryAfterSeconds?: number) {
  return safeProviderFailure({
    errorCode:
      status === 429 || status === 503
        ? 'LLM_PROVIDER_RATE_LIMITED'
        : status === 401
          ? 'LLM_PROVIDER_AUTH_FAILED'
          : 'LLM_PROVIDER_UNAVAILABLE',
    providerFailure: {
      kind:
        status === 429 || status === 503 ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable',
      status,
      ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
    },
  })!;
}
function failedFrames(mutationId: string, status: number, accepted = false, retryAfterSeconds?: number) {
  return encodeDelivery({
    ...binding,
    epoch,
    revision: context.revision + 2,
    mutationId,
    turnId,
    outcome: 'failed',
    failure: failureFor(status, retryAfterSeconds),
    ...(accepted ? { usage: receipt } : { receipt: 'unavailable' }),
  }).lines.map((line: string) => JSON.parse(line));
}
for (const status of [300, 302, 401, 402, 403, 408, 429, 500, 502, 503, 599]) {
  it.each([false, true])(
    'decodes the actual backend HTTP ' + status + ' error frames, accepted receipt %s',
    async (accepted) => {
      const mutationId = crypto.randomUUID();
      const retry = status === 429 || status === 503 ? 0 : undefined;
      const frames = failedFrames(mutationId, status, accepted, retry);
      expect(frames.map((frame: { type: string }) => frame.type)).toEqual(
        accepted ? ['usage', 'error'] : ['error'],
      );
      const fetcher = vi.fn<typeof fetch>(async () => ndjson(frames));
      const failure = await createChatClient(scanSession(), fetcher)
        .chat(context, 'Что проверить?', mutationId, signal())
        .catch((error) => error);
      expect(failure).toMatchObject({
        code: failureFor(status).errorCode,
        providerFailure: failureFor(status, retry).providerFailure,
      });
      expect(Object.isFrozen(failure.providerFailure)).toBe(true);
      expect(chatErrorMessage(failure)).toContain(`HTTP ${status}`);
      if (retry === 0) expect(chatErrorMessage(failure)).toContain('0 с');
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );
}

it.each([401, 429, 503, 403])(
  'both clients preserve the backend JSON metadata for provider HTTP %s, not the outer API status',
  async (status) => {
    const retry = status === 429 || status === 503 ? 86400 : undefined;
    const body = failureFor(status, retry);
    const apiStatus = status === 401 ? 503 : retry !== undefined ? status : 502;
    const fetcher = vi.fn<typeof fetch>(async () => {
      const response = json(body, apiStatus);
      if (retry !== undefined) response.headers.set('Retry-After', String(retry));
      return response;
    });
    const chat = createChatClient(scanSession(), fetcher);
    const translation = createAdvisoryTranslationClient(scanSession(), fetcher);
    const selected = contextFor();
    const errors = [
      await chat.chat(context, 'Что проверить?', crypto.randomUUID(), signal()).catch((error) => error),
      await translation
        .translate(selected, { accepted: true, policyVersion: selected.policyVersion! }, signal())
        .catch((error) => error),
      await translation.readiness(binding.scanId, signal()).catch((error) => error),
    ];
    for (const failure of errors) {
      expect(failure).toMatchObject({ code: body.errorCode, providerFailure: body.providerFailure });
      expect(Object.isFrozen(failure.providerFailure)).toBe(true);
    }
    expect(chatErrorMessage(errors[0])).toContain(`HTTP ${status}`);
    expect(translationErrorMessage(errors[1])).toContain(`HTTP ${status}`);
    if (retry !== undefined) {
      expect(chatErrorMessage(errors[0])).toContain('86400 с');
      expect(translationErrorMessage(errors[1])).toContain('86400 с');
    }
    if (status === 401) {
      expect(chatErrorMessage(errors[0])).toContain('серверный ключ');
      expect(translationErrorMessage(errors[1])).toContain('серверный ключ');
    }
    expect(fetcher).toHaveBeenCalledTimes(3);
  },
);

it.each(['LLM_PROVIDER_RATE_LIMITED', 'LLM_PROVIDER_AUTH_FAILED', 'LLM_PROVIDER_UNAVAILABLE'])(
  'both JSON clients allow absent optional metadata for %s, without trusting arbitrary Retry-After text',
  async (errorCode) => {
    const selected = contextFor();
    const fetcher = vi.fn<typeof fetch>(async () => {
      const response = json({ errorCode }, errorCode === 'LLM_PROVIDER_UNAVAILABLE' ? 502 : 503);
      response.headers.set('Retry-After', 'PRIVATE unbounded 999999999999');
      return response;
    });
    const chat = createChatClient(scanSession(), fetcher);
    const translation = createAdvisoryTranslationClient(scanSession(), fetcher);
    const failures = [
      await chat.chat(context, 'Что проверить?', crypto.randomUUID(), signal()).catch((error) => error),
      await translation
        .translate(selected, { accepted: true, policyVersion: selected.policyVersion! }, signal())
        .catch((error) => error),
    ];
    for (const failure of failures) {
      expect(failure).toMatchObject({ code: errorCode });
      expect(failure.providerFailure).toBeUndefined();
    }
    expect(chatErrorMessage(failures[0])).not.toMatch(/PRIVATE|HTTP|999999999999/);
    expect(translationErrorMessage(failures[1])).not.toMatch(/PRIVATE|HTTP|999999999999/);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it.each([
  [401, 401],
  [401, 429],
  [429, 503],
  [503, 500],
  [403, 503],
])('rejects provider HTTP %s metadata under mismatched API HTTP %s', async (providerStatus, apiStatus) => {
  const selected = contextFor();
  const fetcher = vi.fn<typeof fetch>(async () => json(failureFor(providerStatus), apiStatus));
  const chat = createChatClient(scanSession(), fetcher);
  const translation = createAdvisoryTranslationClient(scanSession(), fetcher);
  const failures = [
    await chat.chat(context, 'Что проверить?', crypto.randomUUID(), signal()).catch((error) => error),
    await translation
      .translate(selected, { accepted: true, policyVersion: selected.policyVersion! }, signal())
      .catch((error) => error),
  ];
  for (const failure of failures) {
    // API 401 is always the browser session boundary, never a provider authentication hint.
    expect(failure).toMatchObject({ code: apiStatus === 401 ? 'SESSION' : 'INVALID' });
    expect(failure.providerFailure).toBeUndefined();
  }
  expect(fetcher).toHaveBeenCalledTimes(2);
});

const malformed = [
  {
    errorCode: 'LLM_PROVIDER_RATE_LIMITED',
    providerFailure: { kind: 'rate_limited', status: 429, raw: 'PRIVATE' },
  },
  { ...failureFor(429), raw: 'PRIVATE' },
  {
    errorCode: 'LLM_PROVIDER_RATE_LIMITED',
    providerFailure: { kind: 'rate_limited', status: 429, retryAfterSeconds: -1 },
  },
  {
    errorCode: 'LLM_PROVIDER_RATE_LIMITED',
    providerFailure: { kind: 'rate_limited', status: 429, retryAfterSeconds: 86401 },
  },
  {
    errorCode: 'LLM_PROVIDER_RATE_LIMITED',
    providerFailure: { kind: 'rate_limited', status: 429, retryAfterSeconds: 0.5 },
  },
  {
    errorCode: 'LLM_PROVIDER_RATE_LIMITED',
    providerFailure: { kind: 'rate_limited', status: 429, retryAfterSeconds: '60' },
  },
  { errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status: 500 } },
  { errorCode: 'LLM_PROVIDER_AUTH_FAILED', providerFailure: { kind: 'auth_failed', status: 403 } },
  {
    errorCode: 'LLM_PROVIDER_AUTH_FAILED',
    providerFailure: { kind: 'auth_failed', status: 401, retryAfterSeconds: 0 },
  },
  { errorCode: 'LLM_PROVIDER_UNAVAILABLE', providerFailure: { kind: 'unavailable', status: 503 } },
  { errorCode: 'LLM_PROVIDER_UNAVAILABLE', providerFailure: { kind: 'unavailable', status: 299 } },
  { errorCode: 'LLM_PROVIDER_UNAVAILABLE', providerFailure: { kind: 'unavailable', status: 600 } },
  { errorCode: 'LLM_PROVIDER_UNAVAILABLE', providerFailure: { kind: 'unavailable', status: 500.5 } },
  { errorCode: 'LLM_UNAVAILABLE', providerFailure: failureFor(429).providerFailure },
  { errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: null },
];
it.each(malformed.map((body, index) => [index, body] as const))(
  'rejects malformed/unknown provider metadata %s in JSON and NDJSON',
  async (_index, body) => {
    const selected = contextFor();
    const fetcher = vi.fn<typeof fetch>(async () => json(body, 503));
    const chat = createChatClient(scanSession(), fetcher);
    const translation = createAdvisoryTranslationClient(scanSession(), fetcher);
    for (const failure of [
      await chat.chat(context, 'Что проверить?', crypto.randomUUID(), signal()).catch((error) => error),
      await translation
        .translate(selected, { accepted: true, policyVersion: selected.policyVersion! }, signal())
        .catch((error) => error),
    ]) {
      expect(failure).toMatchObject({ code: 'INVALID' });
      expect(failure.providerFailure).toBeUndefined();
      expect(failure.message).not.toContain('PRIVATE');
    }
    const mutationId = crypto.randomUUID();
    const [frame] = failedFrames(mutationId, 429);
    const framed = vi.fn<typeof fetch>(async () => ndjson([{ ...frame, ...body }]));
    await expect(
      createChatClient(scanSession(), framed).chat(context, 'Что проверить?', mutationId, signal()),
    ).rejects.toMatchObject({ code: 'INVALID' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(framed).toHaveBeenCalledTimes(1);
  },
);

it.each([
  'accepted-without-usage',
  'unavailable-with-usage',
  'citation-before-error',
  'delta-before-error',
  'after-error',
  'bad-usage',
  'extra-frame-field',
  'unknown-code',
])('rejects invalid classified error delivery: %s', async (bad) => {
  const mutationId = crypto.randomUUID();
  const frames = failedFrames(mutationId, 503, true, 60);
  if (bad === 'accepted-without-usage') {
    frames.shift();
    frames[0].seq = 0;
  }
  if (bad === 'unavailable-with-usage') frames[1].receipt = 'unavailable';
  if (bad === 'bad-usage') frames[0].usage.costMicros = 1;
  if (bad === 'extra-frame-field') frames[1].raw = 'PRIVATE';
  if (bad === 'unknown-code') frames[1].errorCode = 'UNKNOWN_PROVIDER_ERROR';
  if (bad === 'citation-before-error' || bad === 'delta-before-error') {
    const common = { ...frames[1] };
    delete common.errorCode;
    delete common.providerFailure;
    delete common.receipt;
    frames.splice(1, 0, { ...common, seq: 1, type: 'citation', index: 0, source });
    if (bad === 'delta-before-error')
      frames.splice(2, 0, { ...common, seq: 2, type: 'delta', index: 0, text: 'Не ответ' });
    frames[frames.length - 1].seq = frames.length - 1;
  }
  if (bad === 'after-error') frames.push({ ...frames[1], seq: 2 });
  const fetcher = vi.fn<typeof fetch>(async () => ndjson(frames));
  await expect(
    createChatClient(scanSession(), fetcher).chat(context, 'Что проверить?', mutationId, signal()),
  ).rejects.toMatchObject({ code: 'INVALID' });
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it.each(['LLM_PROVIDER_RATE_LIMITED', 'LLM_PROVIDER_AUTH_FAILED', 'LLM_PROVIDER_UNAVAILABLE'])(
  'accepts optional metadata absence for %s without inventing a status or retry hint',
  async (errorCode) => {
    const mutationId = crypto.randomUUID();
    const [frame] = failedFrames(mutationId, 429);
    delete frame.providerFailure;
    const fetcher = vi.fn<typeof fetch>(async () => ndjson([{ ...frame, errorCode }]));
    const failure = await createChatClient(scanSession(), fetcher)
      .chat(context, 'Что проверить?', mutationId, signal())
      .catch((error) => error);
    expect(failure).toMatchObject({ code: errorCode });
    expect(failure.providerFailure).toBeUndefined();
    expect(chatErrorMessage(failure)).not.toMatch(/HTTP|\d+ с/);
  },
);
