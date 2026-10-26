import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LlmUsagePanel } from '@/features/scans/LlmUsagePanel';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createUsageClient, type UsageBinding } from '@/shared/api/scans/llmUsageClient';
import { contextFence, type SummaryContext, type SummaryClient } from '@/shared/api/scans/llmSummaryClient';
import type { ScanTransport, ScanStatus } from '@/shared/api/scans/scanTransport';

const binding: UsageBinding = {
  scanId: '00000000-0000-4000-8000-000000000015',
  digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64',
  reportVersion: 'b'.repeat(64),
};
const vector = (input: number, output: number) => ({ input, output, costMicros: 0 });
const scope = {
  limits: vector(1000, 200),
  used: vector(600, 80),
  held: vector(200, 0),
  carried: vector(0, 0),
  remaining: vector(200, 120),
  warning: true,
  exhausted: false,
};
const usage = {
  ...binding,
  integrationEnabled: true,
  quotaEnabled: true,
  available: true as const,
  reason: 'warning' as const,
  window: { start: Date.UTC(2026, 9, 8), end: Date.UTC(2026, 9, 9) },
  signals: [],
  admission: { status: 'unavailable' as const },
  user: scope,
  scan: scope,
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
beforeEach(() => transitionScanSession('owner', new QueryClient(), true));
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('real usage GET is bounded owner/session-bound, no-store, separate from consent context; remaining/warning are actual DOM', async () => {
  const fetcher = vi.fn(async () => json(usage));
  render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить остаток ИИ' }));
  await screen.findByText(/Предупреждение: использовано/);
  expect(screen.getAllByText(/Осталось 200 из 1000/)).toHaveLength(2);
  expect(screen.getAllByText(/Осталось 120 из 200/)).toHaveLength(2);
  expect(fetcher).toHaveBeenCalledWith(
    expect.stringContaining('/llm/usage'),
    expect.objectContaining({
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    }),
  );
  expect(document.querySelector('script')).toBeNull();
});

it('full envelope shortage below warning is meaningful scan/output DOM, not ready; unknown candidate is not readiness', async () => {
  const scan = {
    limits: vector(65536, 8192),
    used: vector(2400, 6300),
    held: vector(0, 0),
    carried: vector(0, 0),
    remaining: vector(63136, 1892),
    warning: false,
    exhausted: false,
  };
  const user = {
    limits: vector(262144, 16384),
    used: vector(2400, 6300),
    held: vector(0, 0),
    carried: vector(0, 0),
    remaining: vector(259744, 10084),
    warning: false,
    exhausted: false,
  };
  const denied = {
    ...usage,
    reason: 'ready',
    signals: [],
    user,
    scan,
    admission: {
      status: 'insufficient',
      reserve: vector(2000, 2048),
      signals: [
        { scope: 'scan', dimension: 'output', reason: 'insufficient', required: 2048, remaining: 1892 },
      ],
    },
  };
  const fetcher = vi.fn(async () => json(denied));
  const view = render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText(/Этот скан · выходные токены: требуется 2048, осталось 1892/);
  expect(screen.queryByText(/Полный резерв текущего запроса помещается/)).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(1);
  view.unmount();
  render(
    <LlmUsagePanel
      binding={binding}
      refreshVersion={0}
      client={createUsageClient(scanSession(), (async () => json(usage)) as typeof fetch)}
    />,
  );
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText(/Ёмкость следующего полного запроса неизвестна/i);
});

it('both user/scan input/output shortages and a genuinely fitting envelope render only safe signals', async () => {
  const limited = {
    limits: vector(10000, 8192),
    used: vector(9000, 6300),
    held: vector(0, 0),
    carried: vector(0, 0),
    remaining: vector(1000, 1892),
    warning: true,
    exhausted: false,
  };
  const signals = (['user', 'scan'] as const).flatMap((scope) =>
    (['input', 'output'] as const).map((dimension) => ({
      scope,
      dimension,
      reason: 'insufficient',
      required: 2048,
      remaining: limited.remaining[dimension],
    })),
  );
  const denied = {
    ...usage,
    user: limited,
    scan: limited,
    admission: { status: 'insufficient', reserve: vector(2048, 2048), signals },
  };
  let payload: unknown = denied;
  const fetcher = vi.fn(async () => json(payload));
  render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText(/Пользователь · входные токены: требуется 2048, осталось 1000/);
  expect(screen.getByText(/Этот скан · входные токены: требуется 2048, осталось 1000/)).toBeTruthy();
  expect(screen.getByText(/Пользователь · выходные токены: требуется 2048, осталось 1892/)).toBeTruthy();
  const ample = {
    limits: vector(65536, 8192),
    used: vector(0, 0),
    held: vector(0, 0),
    carried: vector(0, 0),
    remaining: vector(65536, 8192),
    warning: false,
    exhausted: false,
  };
  payload = {
    ...usage,
    reason: 'ready',
    user: ample,
    scan: ample,
    admission: { status: 'fits', reserve: vector(2048, 2048), signals: [] },
  };
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText(/Полный резерв текущего запроса помещается; снимок не гарантирует допуск/);
  expect(screen.queryByText(/требуется 2048, осталось 1000/)).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('abort/clear on session generation and binding/access changes; ignored late responses cannot resurrect counts', async () => {
  let finish!: (response: Response) => void;
  let signal: AbortSignal | undefined;
  const fetcher = vi.fn((_path, init) => {
    signal = init?.signal as AbortSignal;
    return new Promise<Response>((resolve) => {
      finish = resolve;
    });
  }) as unknown as typeof fetch;
  const client = createUsageClient(scanSession(), fetcher);
  const view = render(<LlmUsagePanel binding={binding} refreshVersion={0} client={client} />);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить остаток ИИ' }));
  act(() => transitionScanSession('owner', new QueryClient(), true));
  expect(signal?.aborted).toBe(true);
  await act(async () => finish(json(usage)));
  expect(screen.queryByText(/Осталось 200/)).toBeNull();
  view.rerender(<LlmUsagePanel binding={null} refreshVersion={1} client={client} />);
  expect(screen.queryByText(/Предупреждение: использовано/)).toBeNull();
  expect((screen.getByRole('button') as HTMLButtonElement).disabled).toBe(true);
});

it('unavailable is unknown not zero; spoofed reason, tuple, arithmetic, body size and redirects fail safely', async () => {
  const unavailable = {
    ...binding,
    available: false,
    quotaEnabled: false,
    integrationEnabled: false,
    reason: 'disabled',
  };
  const view = render(
    <LlmUsagePanel
      binding={binding}
      refreshVersion={0}
      client={createUsageClient(scanSession(), (async () => json(unavailable)) as typeof fetch)}
    />,
  );
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText('Остаток неизвестен, а не равен нулю.');
  expect(screen.queryByText(/Осталось 0/)).toBeNull();
  view.unmount();
  for (const value of [
    { ...usage, reason: '<script>CANARY</script>' },
    { ...usage, scanId: '00000000-0000-4000-8000-000000000016' },
    { ...usage, scan: { ...scope, remaining: vector(1000, 200) } },
    { ...usage, scan: { ...scope, used: vector(-1, 80) } },
    { ...usage, admission: { status: 'fits', reserve: vector(2048, 2048), signals: [] } },
    { ...usage, admission: { status: 'unavailable', raw: 'CANARY-private' } },
    {
      ...usage,
      admission: {
        status: 'insufficient',
        reserve: vector(2048, 2048),
        signals: [
          { scope: 'scan', dimension: 'output', reason: 'insufficient', required: 2048, remaining: 1892 },
        ],
      },
    },
  ])
    await expect(
      createUsageClient(scanSession(), (async () => json(value)) as typeof fetch).get(
        binding,
        new AbortController().signal,
      ),
    ).rejects.toThrow('Учёт ИИ недоступен');
  await expect(
    createUsageClient(scanSession(), (async () => json({ padding: 'x'.repeat(17000) })) as typeof fetch).get(
      binding,
      new AbortController().signal,
    ),
  ).rejects.toThrow();
  await expect(
    createUsageClient(scanSession(), (async () => json(usage, 404)) as typeof fetch).get(
      binding,
      new AbortController().signal,
    ),
  ).rejects.toThrow();
});

it('deadline bounds a noncooperative transport and prevents stale counts', async () => {
  vi.useFakeTimers();
  const client = createUsageClient(
    scanSession(),
    (async () => new Promise<Response>(() => {})) as typeof fetch,
  );
  const operation = client.get(binding, new AbortController().signal);
  const rejected = expect(operation).rejects.toThrow('Учёт ИИ недоступен');
  await vi.advanceTimersByTimeAsync(15001);
  await rejected;
});

it('explicit usage GET and focus revalidation never grant generation intent or enable a server-disabled summary without a consent checkbox', async () => {
  const context: SummaryContext = { ...binding, enabled: false, disclosure: null, policyVersion: null };
  const fence = contextFence(context);
  const summaryClient: SummaryClient = {
    context: vi.fn(async () => context),
    current: () => true,
    summary: vi.fn(),
  } as unknown as SummaryClient;
  const fetcher = vi.fn<typeof fetch>(async () => json(usage));
  vi.stubGlobal('fetch', fetcher);
  render(
    <>
      <p>Исходные findings и coverage</p>
      <ScanSummaryPanel
        status={{ ...binding, state: 'completed', checks: ['secret'], perCheck: {} } as ScanStatus}
        transport={{} as ScanTransport}
        client={summaryClient}
      />
    </>,
  );
  await waitFor(() =>
    expect((screen.getByRole('button', { name: 'Обновить остаток ИИ' }) as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
  expect(screen.queryByRole('checkbox')).toBeNull();
  const generate = screen.getByRole('button', { name: 'Получить сводку' }) as HTMLButtonElement;
  expect(generate.disabled).toBe(true);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить остаток ИИ' }));
  await screen.findByText(/Предупреждение: использовано/);
  expect(contextFence(context)).toBe(fence);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledWith(
    expect.stringContaining('/llm/usage'),
    expect.objectContaining({
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    }),
  );
  expect(generate.disabled).toBe(true);
  fireEvent.click(generate);
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  await act(async () => {});
  expect(summaryClient.context).toHaveBeenCalledTimes(2);
  expect(summaryClient.summary).not.toHaveBeenCalled();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(
    fetcher.mock.calls.every(([path, init]) => String(path).endsWith('/llm/usage') && init?.method === 'GET'),
  ).toBe(true);
  expect(generate.disabled).toBe(true);
  expect(screen.queryByRole('checkbox')).toBeNull();
  expect(screen.getByText('Исходные findings и coverage')).toBeTruthy();
});
