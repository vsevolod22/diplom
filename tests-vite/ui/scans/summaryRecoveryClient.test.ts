import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  createSummaryClient,
  type SummaryClient,
  type SummaryContext,
  type SummaryReply,
} from '@/shared/api/scans/llmSummaryClient';

const queryClient = new QueryClient();
const scanId = '00000000-0000-4000-8000-000000000038';
const tuple = {
  scanId,
  digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64' as const,
  reportVersion: 'b'.repeat(64),
};
const context: SummaryContext = {
  ...tuple,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  disclosure: {
    provider: 'OpenRouter',
    model: 'xingchen-agi/xing4.0-29b-a4b:free',
    providers: ['phala'],
    region: 'global',
    retention: 'no-storage',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0,
    freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 },
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.',
  },
};
const reply: SummaryReply = {
  ...tuple,
  hypotheses: [{ kind: 'hypothesis', text: 'Проверьте исходную находку', citations: ['secret-0-1'] }],
  scannerFacts: [{ findingId: 'secret-0-1', check: 'secret', severity: 'UNKNOWN' }],
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
const signal = () => new AbortController().signal;

beforeEach(() => transitionScanSession('summary-owner', queryClient, true));
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  transitionScanSession(null, queryClient, true);
  queryClient.clear();
});

describe('summary recovery client', () => {
  it('reads the existing DTO with one same-origin no-store GET and never sends consent or generation', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(reply));
    const client = createSummaryClient(scanSession(), fetcher);
    expect(await client.existing(context, signal())).toEqual(reply);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/browser/scans/${scanId}/llm/summary`);
    expect(fetcher.mock.calls[0][1]).toMatchObject({
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      body: undefined,
      headers: undefined,
      signal: expect.any(AbortSignal),
    });
  });

  it('maps only the exact owner-cache-missing error code to null, without a generation fallback', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404));
    expect(await createSummaryClient(scanSession(), fetcher).existing(context, signal())).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1]?.method).toBe('GET');
  });

  it.each([
    [404, 'SCAN_NOT_FOUND'],
    [401, 'AUTH_REQUIRED'],
    [403, 'FORBIDDEN'],
    [409, 'LLM_STALE_REPORT'],
    [409, 'LLM_STALE_POLICY'],
    [503, 'LLM_CONFIGURATION_UNAVAILABLE'],
    [404, 'LLM_SUMMARY_MISSING_EXTRA'],
  ])('does not turn HTTP %s / %s into a cache miss', async (status, errorCode) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ errorCode }, status));
    await expect(
      createSummaryClient(scanSession(), fetcher).existing(context, signal()),
    ).rejects.toMatchObject({ code: errorCode });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('does not swallow network failures, unknown errors, or successful missing-code bodies', async () => {
    const network = new TypeError('Network failed');
    const fetcher = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(network)
      .mockResolvedValueOnce(json({ error: 'missing' }, 404))
      .mockResolvedValueOnce(json({ errorCode: 'LLM_SUMMARY_MISSING' }));
    const client = createSummaryClient(scanSession(), fetcher);
    await expect(client.existing(context, signal())).rejects.toBe(network);
    await expect(client.existing(context, signal())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await expect(client.existing(context, signal())).rejects.toMatchObject({ name: 'ZodError' });
  });

  it.each([
    { scanId: '00000000-0000-4000-8000-000000000039' },
    { digest: `sha256:${'d'.repeat(64)}` },
    { reportVersion: 'e'.repeat(64) },
  ])('rejects a cached reply with a different tuple: %j', async (patch) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ ...reply, ...patch }));
    await expect(
      createSummaryClient(scanSession(), fetcher).existing(context, signal()),
    ).rejects.toMatchObject({ code: 'STALE' });
  });

  it.each([
    { ...reply, platform: 'linux/arm64' },
    { ...reply, hypotheses: [] },
    { ...reply, hypotheses: [{ kind: 'fact', text: 'unsafe', citations: ['secret-0-1'] }] },
    { ...reply, hypotheses: [{ kind: 'hypothesis', text: 'unsafe', citations: ['https://evil.invalid'] }] },
    { ...reply, hypotheses: [{ kind: 'hypothesis', text: 'unsafe\u202e', citations: ['secret-0-1'] }] },
    { ...reply, scannerFacts: null },
  ])('applies the existing reply schema to recovered data', async (value) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(value));
    await expect(
      createSummaryClient(scanSession(), fetcher).existing(context, signal()),
    ).rejects.toMatchObject({ name: 'ZodError' });
  });

  it.each(['another-owner', 'summary-owner'])('fences a late reply after transition to %s', async (owner) => {
    let finish!: (response: Response) => void;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const client = createSummaryClient(scanSession(), fetcher);
    const pending = client.existing(context, signal());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'SESSION' });
    const requestSignal = fetcher.mock.calls[0][1]?.signal;
    transitionScanSession(owner, queryClient, true);
    expect(requestSignal?.aborted).toBe(true);
    await rejected;
    const late = json(reply);
    const cancel = vi.spyOn(late.body!, 'cancel');
    finish(late);
    await vi.waitFor(() => expect(cancel).toHaveBeenCalled());
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('fences a late missing response as SESSION, not null, after logout', async () => {
    let finish!: (response: Response) => void;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const pending = createSummaryClient(scanSession(), fetcher).existing(context, signal());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'SESSION' });
    transitionScanSession(null, queryClient, true);
    await rejected;
    finish(json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404));
    await Promise.resolve();
  });

  it('aborts an in-progress response stream on identity change', async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{'));
      },
      cancel,
    });
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(stream));
    const pending = createSummaryClient(scanSession(), fetcher).existing(context, signal());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'SESSION' });
    await vi.waitFor(() => expect(stream.locked).toBe(true));
    transitionScanSession('another-owner', queryClient, true);
    await rejected;
    await vi.waitFor(() => expect(cancel).toHaveBeenCalled());
  });

  it('retains the 35-second bound even if fetch ignores abort', async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(() => {}));
    const pending = createSummaryClient(scanSession(), fetcher).existing(context, signal());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' });
    await vi.advanceTimersByTimeAsync(35_000);
    await rejected;
    expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('retains bounded streamed bytes and rejects an already-aborted request without fetching', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response('x'.repeat(65_537)));
    const client = createSummaryClient(scanSession(), fetcher);
    await expect(client.existing(context, signal())).rejects.toMatchObject({ code: 'INVALID' });
    const controller = new AbortController();
    controller.abort();
    await expect(client.existing(context, controller.signal)).rejects.toMatchObject({ code: 'ABORTED' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('keeps legacy controlled mocks compatible while the real client always implements recovery', () => {
    const controlled: SummaryClient = {
      current: () => true,
      context: async () => context,
      summary: async () => reply,
    };
    expect(controlled.existing).toBeUndefined();
    expect(createSummaryClient(scanSession(), vi.fn()).existing).toBeTypeOf('function');
  });
});

describe('exact summary disclosure decoding', () => {
  it('preserves the complete allowed disclosure and price DTO', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(context));
    expect(await createSummaryClient(scanSession(), fetcher).context(scanId, signal())).toEqual(context);
  });

  it.each([
    { ...context.disclosure!, widenedEgress: 'raw report content' },
    { ...context.disclosure!, futureProviderRouting: true },
    { ...context.disclosure!, maxPrice: { ...context.disclosure!.maxPrice, futureFee: 0 } },
  ])('rejects rather than strips unknown disclosure or maxPrice keys', async (disclosure) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({ ...context, disclosure }));
    await expect(createSummaryClient(scanSession(), fetcher).context(scanId, signal())).rejects.toMatchObject(
      { name: 'ZodError' },
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1]?.method).toBe('GET');
  });
});
