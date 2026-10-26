import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { StrictMode } from 'react';
import { readReportPreferences, saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { usage } from './llmChatFixtures';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  collectSummarySources,
  createSummaryClient,
  type SummaryClient,
  type SummaryContext,
  type SummaryReply,
  verifiedSummarySources,
} from '@/shared/api/scans/llmSummaryClient';
import { type ScanStatus, type ScanTransport } from '@/shared/api/scans/scanTransport';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';

vi.mock('@/features/scans/ScanChatPanel', () => ({ ScanChatPanel: () => null }));

const id = '00000000-0000-4000-8000-000000000038';
const digest = `sha256:${'a'.repeat(64)}`;
const tuple = { scanId: id, digest, platform: 'linux/amd64' as const, reportVersion: 'b'.repeat(64) };
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
const status: ScanStatus = {
  scanId: id,
  digest,
  platform: tuple.platform,
  state: 'completed',
  checks: ['secret'],
  perCheck: { secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 2 } },
};
const publicStatus: ScanStatus = { ...status, profile: PUBLIC_IMAGE_PROFILE };
function transport(): ScanTransport {
  return {
    results: vi.fn(async (_id, cursor) => ({
      findings: [
        {
          findingId: cursor ? 'secret-0-1' : 'secret-0-0',
          category: 'secret',
          ruleId: 'rule-0000000000000000',
          severity: 'unknown',
        },
      ],
      nextCursor: cursor ? null : '1',
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
    })),
  } as unknown as ScanTransport;
}
const json = (value: unknown, httpStatus = 200) =>
  new Response(JSON.stringify(value), {
    status: httpStatus,
    headers: { 'Content-Type': 'application/json' },
  });
const requests: Array<{ path: string; init?: RequestInit }> = [];
function mockApi(
  getContext: () => SummaryContext = () => context,
  summary: () => Response | Promise<Response> = () => json(reply),
  existing: () => Response | Promise<Response> = () => json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404),
) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init?: RequestInit) => {
      requests.push({ path, init });
      if (path.endsWith('/summary') && init?.method === 'GET') return existing();
      if (path.endsWith('/usage'))
        return json({ ...usage, ...tuple, integrationEnabled: true, quotaEnabled: true });
      return path.endsWith('/context') ? json(getContext()) : summary();
    }),
  );
}
function mount(sourceTransport = transport(), value = status) {
  return render(
    <>
      <p>Исходный отчёт · checked не означает безопасность</p>
      <ScanSummaryPanel key={JSON.stringify(value)} status={value} transport={sourceTransport} />
    </>,
  );
}
const posts = () => requests.filter((request) => request.init?.method === 'POST');
async function generate() {
  await waitFor(() => expect(posts()).toHaveLength(1));
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  requests.length = 0;
  transitionScanSession('alice', new QueryClient(), true);
  saveReportPreferences({ language: 'original', autoSummary: true });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each([403, 404])(
  'default legacy client skips a GET-only recovery denial (%s) and still performs guarded generation',
  async (code) => {
    const deniedRecovery = vi.fn(() =>
      json({ errorCode: code === 403 ? 'FORBIDDEN' : 'SCAN_NOT_FOUND' }, code),
    );
    mockApi(undefined, undefined, deniedRecovery);
    mount();
    await screen.findByText('Проверьте исходную находку');
    expect(deniedRecovery).not.toHaveBeenCalled();
    expect(requests.filter((r) => r.path.endsWith('/summary') && r.init?.method === 'GET')).toHaveLength(0);
    expect(posts()).toHaveLength(1);
    expect(JSON.parse(String(posts()[0].init?.body))).toEqual({
      reportVersion: tuple.reportVersion,
      consent: { accepted: true, policyVersion: context.policyVersion },
    });
    expect(requests.filter((r) => r.path.endsWith('/context')).length).toBeGreaterThanOrEqual(3);
    expect(requests.some((r) => r.path.endsWith('/usage'))).toBe(true);
  },
);

it('automatically generates once with saved authorization, exact consent and verified late-page sources', async () => {
  mockApi();
  const source = transport();
  const view = mount(source);
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить условия' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить условия' })).toBeEnabled());
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
  expect(JSON.parse(String(posts()[0].init?.body))).toEqual({
    reportVersion: tuple.reportVersion,
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  expect(posts()[0].init).toMatchObject({ cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  expect(source.results).toHaveBeenCalledTimes(2);
  const link = screen.getByRole('link', { name: 'Находка secret-0-1' });
  expect(document.getElementById(link.getAttribute('href')!.slice(1))).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Получить сводку' })).toBeNull();
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  view.unmount();
  mount();
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toMatch(/^\["[a-f0-9]{64}"\]$/);
  expect(localStorage.getItem('report-preferences:v1:alice')).not.toContain('Проверьте');
});

it.each(['before-post', 'before-publication'] as const)(
  'cross-tab revocation %s aborts synchronously despite the unchanged consent-version string',
  async (phase) => {
    mockApi();
    const client = createSummaryClient(scanSession());
    const accepted = readReportPreferences();
    let abortedImmediately: boolean | undefined;
    let observedRevision: typeof accepted.revision | undefined;
    const revoke = (signal: AbortSignal) => {
      localStorage.setItem(
        'report-preferences:v1:alice',
        JSON.stringify({
          version: 1,
          automationRevision: 'report-automation-v1',
          language: 'original',
          autoSummary: false,
        }),
      );
      window.dispatchEvent(
        new StorageEvent('storage', { key: 'report-preferences:v1:alice', storageArea: localStorage }),
      );
      abortedImmediately = signal.aborted;
      observedRevision = readReportPreferences().revision;
    };
    const read = client.context;
    let reads = 0;
    vi.spyOn(client, 'context').mockImplementation(async (id, signal) => {
      if (++reads === 2 && phase === 'before-post') revoke(signal);
      return read(id, signal);
    });
    const summary = vi.spyOn(client, 'summary').mockImplementation(async (_context, signal) => {
      if (phase === 'before-publication') revoke(signal);
      return reply;
    });
    render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
    await waitFor(() => expect(abortedImmediately).toBeDefined());
    expect(abortedImmediately).toBe(true);
    expect(observedRevision).toBe(accepted.revision);
    await act(async () => {});
    expect(summary).toHaveBeenCalledTimes(phase === 'before-post' ? 0 : 1);
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  },
);

it('fresh preference equality blocks POST even before another-tab storage event is delivered', async () => {
  mockApi();
  const fetcher = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/usage'))
      localStorage.setItem(
        'report-preferences:v1:alice',
        JSON.stringify({
          version: 1,
          automationRevision: 'report-automation-v1',
          language: 'original',
          autoSummary: false,
        }),
      );
    return fetcher(input, init);
  });
  mount();
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(0);
});

it.each([
  { model: 'other/model:free' },
  { providers: ['phala', 'other'] },
  { providers: ['other'] },
  { provider: 'Other' },
  { region: 'other' },
  { retention: 'no-training' },
  { freeOnly: false },
  { requestBudgetUsd: 0.1 },
  { maxPrice: { prompt: 1, completion: 0, request: 0 } },
  { maxPrice: { prompt: 0, completion: 0, request: null } },
  { data: 'All raw evidence, credentials and chat history.' },
  { widenedEgress: true },
])(
  'account consent never permits the unallowed disclosure %j, even with a fresh policy hash',
  async (changed) => {
    const client = createSummaryClient(scanSession());
    const unsafe = {
      ...context,
      policyVersion: 'f'.repeat(64),
      disclosure: { ...context.disclosure, ...changed },
    } as unknown as SummaryContext;
    vi.spyOn(client, 'context').mockResolvedValue(unsafe);
    vi.spyOn(client, 'existing').mockResolvedValue(null);
    const summary = vi.spyOn(client, 'summary').mockResolvedValue(reply);
    render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('не совпадают с разрешением аккаунта');
    expect(summary).not.toHaveBeenCalled();
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  },
);

it('same report/policy identity never sends again if disclosure changes without a new policy version', async () => {
  let current = context;
  mockApi(() => current);
  const view = mount();
  await screen.findByText('Проверьте исходную находку');
  view.unmount();
  current = { ...context, disclosure: { ...context.disclosure!, model: 'different/model' } };
  mount();
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(1);
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
});

it.each(['unsaved', 'off', 'anonymous'] as const)(
  'does not generate when authorization is %s; account link is not a generation prerequisite',
  async (mode) => {
    if (mode === 'unsaved') localStorage.clear();
    if (mode === 'off') saveReportPreferences({ language: 'original', autoSummary: false });
    if (mode === 'anonymous') transitionScanSession(null, new QueryClient(), true);
    mockApi();
    mount();
    expect(screen.getByRole('link', { name: 'настройках аккаунта' })).toHaveAttribute('href', '/account');
    await act(async () => {});
    expect(posts()).toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Получить сводку' })).toBeNull();
  },
);

it('controlled clients without the optional recovery method retain guarded once-only generation', async () => {
  mockApi();
  const real = createSummaryClient(scanSession());
  const client: SummaryClient = { current: real.current, context: real.context, summary: real.summary };
  render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
  expect(requests.some((r) => r.path.endsWith('/summary') && r.init?.method === 'GET')).toBe(false);
});

it('StrictMode mount replay makes only one summary POST', async () => {
  mockApi();
  render(
    <StrictMode>
      <ScanSummaryPanel status={status} transport={transport()} />
    </StrictMode>,
  );
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
});

it('a failed automatic attempt is retained across focus, reconnect and remount; only explicit retry can send again', async () => {
  let fail = true;
  mockApi(undefined, () => (fail ? json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 503) : json(reply)));
  const view = mount();
  await screen.findByRole('alert');
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  view.unmount();
  mount();
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(1);
  fail = false;
  fireEvent.click(screen.getByRole('button', { name: 'Повторить сводку' }));
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(2);
});

it('reload/fresh-login recovery reads the owner cache before the retained tab marker and never repeats POST', async () => {
  let cached: SummaryReply | null = null;
  mockApi(
    undefined,
    () => {
      cached = reply;
      return json(reply);
    },
    () => (cached ? json(cached) : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404)),
  );
  mount(transport(), publicStatus);
  await screen.findByText('Проверьте исходную находку');
  const marker = sessionStorage.getItem('report-automation-v1:attempts');
  expect(marker).not.toBeNull();
  act(() => transitionScanSession('alice', new QueryClient(), true));
  await screen.findByText('Сводка восстановлена из кэша процесса сервера; это не долговечная история.');
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
  expect(requests.filter((r) => r.path.endsWith('/summary') && r.init?.method === 'GET')).toHaveLength(2);
  expect(posts()).toHaveLength(1);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBe(marker);
});

it('a server-cache miss after process restart or eviction never bypasses the tab attempt marker', async () => {
  mockApi();
  mount(transport(), publicStatus);
  await screen.findByText('Проверьте исходную находку');
  act(() => transitionScanSession('alice', new QueryClient(), true));
  await screen.findByText(/Автоматический запрос уже выполнялся/);
  expect(posts()).toHaveLength(1);
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(requests.filter((r) => r.path.endsWith('/summary') && r.init?.method === 'GET')).toHaveLength(2);
});

it.each(['off', 'unsaved'] as const)(
  'passive recovery with %s automation reads sources and fresh context but never requests quota or consent',
  async (setting) => {
    if (setting === 'off') saveReportPreferences({ language: 'original', autoSummary: false });
    else localStorage.clear();
    mockApi(undefined, undefined, () => json(reply));
    const source = transport();
    mount(source, publicStatus);
    await screen.findByText('Проверьте исходную находку');
    expect(screen.getByText(/Сводка восстановлена из кэша процесса сервера/)).toBeVisible();
    expect(source.results).toHaveBeenCalledTimes(2);
    expect(requests.filter((r) => r.path.endsWith('/context'))).toHaveLength(2);
    expect(requests.some((r) => r.path.endsWith('/usage'))).toBe(false);
    expect(posts()).toHaveLength(0);
    expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
    expect(document.body.textContent).toContain('Это не долговечное хранение');
    expect(document.body.textContent).toContain('перезапуска процесса или вытеснения');
  },
);

it('an explicit error retry first recovers a completed server result without an extra provider POST', async () => {
  let cached: SummaryReply | null = null;
  mockApi(
    undefined,
    () => json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 503),
    () => (cached ? json(cached) : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404)),
  );
  mount(transport(), publicStatus);
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(1);
  cached = reply;
  fireEvent.click(screen.getByRole('button', { name: 'Повторить сводку' }));
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
});

it.each(['foreign-access', 'scan', 'report', 'digest', 'sources', 'invalid'] as const)(
  'invalid recovery %s cannot publish private output or fall back to POST',
  async (kind) => {
    const value =
      kind === 'scan'
        ? { ...reply, scanId: '00000000-0000-4000-8000-000000000039' }
        : kind === 'report'
          ? { ...reply, reportVersion: 'f'.repeat(64) }
          : kind === 'digest'
            ? { ...reply, digest: `sha256:${'f'.repeat(64)}` }
            : kind === 'sources'
              ? { ...reply, hypotheses: [{ ...reply.hypotheses[0], citations: ['secret-99-99'] }] }
              : kind === 'invalid'
                ? { privateText: 'OTHER_OWNER_CANARY' }
                : reply;
    mockApi(undefined, undefined, () =>
      kind === 'foreign-access' ? json({ errorCode: 'SCAN_NOT_FOUND' }, 404) : json(value),
    );
    mount(transport(), publicStatus);
    await screen.findByRole('alert');
    expect(posts()).toHaveLength(0);
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
    expect(document.body.textContent).not.toContain('OTHER_OWNER_CANARY');
    expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
  },
);

it('a policy changed while reading the server cache withholds recovery and does not create a new generation intent', async () => {
  let current = context;
  mockApi(
    () => current,
    undefined,
    () => {
      current = { ...context, policyVersion: 'f'.repeat(64) };
      return json(reply);
    },
  );
  mount(transport(), publicStatus);
  await screen.findByRole('alert');
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(0);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
});

it.each(['cancel', 'preferences', 'owner', 'same-owner'] as const)(
  '%s cancels a noncooperative recovery and prevents late private publication',
  async (kind) => {
    mockApi();
    const client = createSummaryClient(scanSession());
    let finish!: (reply: SummaryReply) => void;
    const existing = vi
      .spyOn(client, 'existing')
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      )
      .mockResolvedValue(null);
    const source = transport();
    render(<ScanSummaryPanel status={publicStatus} transport={source} client={client} />);
    await waitFor(() => expect(existing).toHaveBeenCalledTimes(1));
    await act(async () => {
      if (kind === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Отменить запрос сводки' }));
      else if (kind === 'preferences') saveReportPreferences({ language: 'original', autoSummary: false });
      else transitionScanSession(kind === 'owner' ? 'bob' : 'alice', new QueryClient(), true);
    });
    await waitFor(() => expect(existing.mock.calls[0][1].aborted).toBe(true));
    await act(async () => finish(reply));
    expect(source.results).not.toHaveBeenCalled();
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
    expect(posts()).toHaveLength(0);
  },
);

it('fresh preference identity fences recovery publication even before storage notification', async () => {
  mockApi();
  saveReportPreferences({ language: 'original', autoSummary: false });
  const client = createSummaryClient(scanSession());
  vi.spyOn(client, 'existing').mockImplementation(async () => {
    localStorage.setItem(
      'report-preferences:v1:alice',
      JSON.stringify({
        version: 1,
        automationRevision: 'report-automation-v1',
        language: 'ru',
        autoSummary: false,
      }),
    );
    return reply;
  });
  render(<ScanSummaryPanel status={publicStatus} transport={transport()} client={client} />);
  await waitFor(() => expect(client.existing).toHaveBeenCalledTimes(1));
  await act(async () => {});
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(0);
});

it('noncooperative recovery is bounded at 45 seconds and cannot continue reading sources after timeout', async () => {
  mockApi();
  const client = createSummaryClient(scanSession());
  let finish!: (reply: SummaryReply) => void;
  const existing = vi.spyOn(client, 'existing').mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const source = transport();
  const timers = vi.spyOn(globalThis, 'setTimeout');
  render(<ScanSummaryPanel status={publicStatus} transport={source} client={client} />);
  await waitFor(() => expect(existing).toHaveBeenCalledTimes(1));
  const deadline = timers.mock.calls.filter(([, delay]) => delay === 45_000).at(-1)![0] as () => void;
  await act(async () => deadline());
  await screen.findByRole('alert');
  await waitFor(() => expect(existing.mock.calls[0][1].aborted).toBe(true));
  await act(async () => finish(reply));
  expect(source.results).not.toHaveBeenCalled();
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(0);
});

it.each(['policy', 'report', 'digest'] as const)(
  'fresh %s mismatch before POST consumes no provider request',
  async (changed) => {
    let reads = 0;
    mockApi(() => {
      if (++reads === 1) return context;
      if (changed === 'policy') return { ...context, policyVersion: 'f'.repeat(64) };
      if (changed === 'report') return { ...context, reportVersion: 'f'.repeat(64) };
      return { ...context, digest: `sha256:${'f'.repeat(64)}` };
    });
    mount();
    await screen.findByRole('alert');
    expect(posts()).toHaveLength(0);
  },
);

it('post-response policy change withholds generated text', async () => {
  let current = context;
  mockApi(
    () => current,
    () => {
      current = { ...context, policyVersion: 'f'.repeat(64) };
      return json(reply);
    },
  );
  mount();
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(1);
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
});

it('unknown or exhausted quota never grants automatic generation', async () => {
  mockApi();
  const fetcher = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn((input, init) =>
      String(input).endsWith('/usage')
        ? Promise.resolve(
            json({
              ...tuple,
              integrationEnabled: true,
              quotaEnabled: true,
              available: false,
              reason: 'unavailable',
            }),
          )
        : fetcher(input, init),
    ),
  );
  mount();
  await screen.findByRole('alert');
  expect(posts()).toHaveLength(0);
});

it.each(['original', 'off', 'owner', 'reauth'] as const)(
  'preference/session change %s aborts delivery and cannot publish a late reply',
  async (change) => {
    let finish!: () => void;
    mockApi(
      undefined,
      () =>
        new Promise((resolve) => {
          finish = () => resolve(json(reply));
        }),
    );
    mount();
    await generate();
    const signal = posts()[0].init!.signal!;
    await act(async () => {
      if (change === 'owner') transitionScanSession('bob', new QueryClient(), true);
      else if (change === 'reauth') transitionScanSession('alice', new QueryClient(), true);
      else
        saveReportPreferences({
          language: change === 'original' ? 'ru' : 'original',
          autoSummary: change !== 'off',
        });
      finish();
    });
    expect(signal.aborted).toBe(true);
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
    expect(posts()).toHaveLength(1);
  },
);

it('cancel suppresses late output and never retries automatically', async () => {
  let finish!: () => void;
  mockApi(
    undefined,
    () =>
      new Promise((resolve) => {
        finish = () => resolve(json(reply));
      }),
  );
  mount();
  await generate();
  fireEvent.click(screen.getByRole('button', { name: 'Отменить запрос сводки' }));
  await act(async () => finish());
  expect(posts()[0].init!.signal!.aborted).toBe(true);
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(1);
});

it('bounds a noncooperative generation at 45 seconds and never continues source reads after timeout', async () => {
  mockApi();
  const client = createSummaryClient(scanSession());
  let finish!: (value: SummaryReply) => void;
  const summary = vi.spyOn(client, 'summary').mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const source = transport();
  const timers = vi.spyOn(globalThis, 'setTimeout');
  render(<ScanSummaryPanel status={status} transport={source} client={client} />);
  await waitFor(() => expect(summary).toHaveBeenCalledTimes(1));
  const deadline = timers.mock.calls.filter(([, delay]) => delay === 45_000).at(-1)![0] as () => void;
  await act(async () => {
    deadline();
  });
  expect(screen.getByRole('alert')).toBeTruthy();
  expect(summary.mock.calls[0][1].aborted).toBe(true);
  await act(async () => {
    finish(reply);
  });
  expect(source.results).not.toHaveBeenCalled();
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(summary).toHaveBeenCalledTimes(1);
});

it('bounded timeout finishes even when fetch ignores abort', async () => {
  vi.useFakeTimers();
  vi.stubGlobal(
    'fetch',
    vi.fn(() => new Promise(() => {})),
  );
  const promise = createSummaryClient(scanSession()).context(id, new AbortController().signal);
  const assertion = expect(promise).rejects.toMatchObject({ code: 'TIMEOUT' });
  await vi.advanceTimersByTimeAsync(35_000);
  await assertion;
});
it('bounded streamed bytes reject oversize and foreign scan/digest/version replies', async () => {
  const client = () => createSummaryClient(scanSession());
  const signal = new AbortController().signal;
  mockApi(undefined, () => new Response('x'.repeat(65_537)));
  await expect(client().summary(context, signal)).rejects.toMatchObject({ code: 'INVALID' });
  for (const value of [
    { ...reply, scanId: '00000000-0000-4000-8000-000000000039' },
    { ...reply, digest: `sha256:${'d'.repeat(64)}` },
    { ...reply, reportVersion: 'd'.repeat(64) },
  ]) {
    mockApi(undefined, () => json(value));
    await expect(client().summary(context, signal)).rejects.toMatchObject({ code: 'STALE' });
  }
});
it('freeOnly uses the new server field and zero-price contract, no model suffix inference', async () => {
  const free = {
    ...context,
    disclosure: {
      ...context.disclosure!,
      model: 'vendor/model:free',
      freeOnly: true,
      requestBudgetUsd: 0,
      maxPrice: { prompt: 0, completion: 0, request: 0 },
    },
  };
  mockApi(() => free);
  mount();
  await screen.findByText(/только бесплатный режим/);
  mockApi(() => ({
    ...free,
    disclosure: { ...free.disclosure, maxPrice: { prompt: 0, completion: 1, request: 0 } },
  }));
  const client = createSummaryClient(scanSession());
  await expect(client.context(id, new AbortController().signal)).rejects.toThrow();
});
it('hostile generated text remains literal plaintext, not HTML, Markdown, URL or executable link', async () => {
  mockApi(undefined, () =>
    json({
      ...reply,
      hypotheses: [
        {
          ...reply.hypotheses[0],
          text: '<img src=x onerror=alert(1)> **bold** [evil](javascript:alert(1)) https://evil.test',
        },
      ],
    }),
  );
  mount();
  await generate();
  await screen.findByText(/<img src=x/);
  expect(document.querySelector('img')).toBeNull();
  expect(screen.queryByRole('link', { name: 'evil' })).toBeNull();
});
it('invented citations fail closed; sources across categories and pages verified independently', async () => {
  const sources = await collectSummarySources(transport(), status, new AbortController().signal);
  expect(sources).toHaveLength(2);
  expect(() =>
    verifiedSummarySources(
      { ...reply, hypotheses: [{ ...reply.hypotheses[0], citations: ['secret-99-99'] }] },
      sources,
    ),
  ).toThrow();
  expect(() =>
    verifiedSummarySources(
      { ...reply, scannerFacts: [{ ...reply.scannerFacts[0], check: 'vuln' }] },
      sources,
    ),
  ).toThrow();
  const vulnId = `vuln-${'e'.repeat(64)}`;
  const mixed = {
    ...reply,
    hypotheses: [{ ...reply.hypotheses[0], citations: ['secret-0-1', vulnId, digest] }],
    scannerFacts: [
      ...reply.scannerFacts,
      { findingId: vulnId, check: 'vuln' as const, severity: 'HIGH' },
      { findingId: digest, check: 'config' as const, severity: 'MEDIUM' },
    ],
  };
  expect(
    verifiedSummarySources(mixed, [
      ...sources,
      { findingId: vulnId, check: 'vuln', label: 'CVE' },
      { findingId: digest, check: 'config', label: 'Config' },
    ]),
  ).toHaveLength(3);
});
it('already aborted requests do not start a POST', async () => {
  mockApi();
  const client = createSummaryClient(scanSession());
  const controller = new AbortController();
  controller.abort();
  await expect(client.summary(context, controller.signal)).rejects.toMatchObject({ code: 'ABORTED' });
  expect(requests).toHaveLength(0);
});
it('config hash citation resolves a local source anchor without URL decoding mismatch', async () => {
  const configStatus: ScanStatus = {
    ...status,
    checks: ['config'],
    perCheck: {},
    config: {
      checksVersion: 'image-config-user-v1',
      resourcePolicyVersion: 'image-config-policy-v1',
      supportedRuleIds: ['IMGCFG_USER_ROOT'],
      completedRuleIds: ['IMGCFG_USER_ROOT'],
      config: { outcome: 'checked' },
      rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'checked' }],
      history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' },
      dockerfile: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
      iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
      findings: [
        {
          findingId: digest,
          ruleId: 'IMGCFG_USER_ROOT',
          category: 'image-config',
          severity: 'MEDIUM',
          severitySource: 'image-config-user-v1',
          classification: 'DEFAULT_ROOT',
          message: 'Image metadata uses the default root user.',
          recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.',
          location: '/config/User',
          manifestDigest: digest,
          configDigest: digest,
          platform: { os: 'linux', architecture: 'amd64' },
        },
      ],
    },
  };
  mockApi(undefined, () =>
    json({
      ...reply,
      hypotheses: [{ ...reply.hypotheses[0], citations: [digest] }],
      scannerFacts: [{ findingId: digest, check: 'config', severity: 'MEDIUM' }],
    }),
  );
  const sources = transport();
  mount(sources, configStatus);
  await generate();
  const link = await screen.findByRole('link', { name: `Находка ${digest}` });
  expect(
    document.getElementById(decodeURIComponent(link.getAttribute('href')!.slice(1)))?.textContent,
  ).toContain('IMGCFG_USER_ROOT');
  expect(sources.results).not.toHaveBeenCalled();
});
it('CVE source collection verifies every page and target, independent of the current category', async () => {
  const sources = transport();
  sources.vuln = vi.fn<ScanTransport['vuln']>(async (_id, cursor) => ({
    outcome: 'checked',
    coverage: 'image',
    image: `registry-1.docker.io/library/alpine@${digest}`,
    platform: 'linux/amd64',
    findingCount: 2,
    scannerVersion: '0.69.3',
    checkedAt: '2026-10-07T00:00:00.000Z',
    nextCursor: cursor ? null : '1',
    findings: [
      {
        findingId: `vuln-${(cursor ? 'e' : 'd').repeat(64)}`,
        cveId: 'CVE-2026-1234',
        ecosystem: 'apk',
        packageName: 'example',
        installedVersion: '1',
        severity: 'HIGH',
        fixedVersion: null,
      },
    ],
  }));
  const mixed: ScanStatus = {
    ...status,
    checks: ['secret', 'vuln'],
    perCheck: {
      ...status.perCheck,
      vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 2 },
    },
  };
  const result = await collectSummarySources(sources, mixed, new AbortController().signal);
  expect(result).toHaveLength(4);
  expect(sources.vuln).toHaveBeenCalledTimes(2);
  expect(result.some((source) => source.findingId === `vuln-${'e'.repeat(64)}`)).toBe(true);
  await expect(
    collectSummarySources(
      sources,
      { ...mixed, digest: `sha256:${'f'.repeat(64)}` },
      new AbortController().signal,
    ),
  ).rejects.toMatchObject({ code: 'STALE' });
});
it('pagination duplicates, stalled cursor and count mismatch refuse publication', async () => {
  const base = transport();
  base.results = vi.fn<ScanTransport['results']>(async () => ({
    findings: [{ findingId: 'secret-0-0', category: 'secret', ruleId: 'rule-a', severity: 'unknown' }],
    nextCursor: '1',
    coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
  }));
  await expect(collectSummarySources(base, status, new AbortController().signal)).rejects.toThrow();
  base.results = vi.fn<ScanTransport['results']>(async () => ({
    findings: [],
    nextCursor: '0',
    coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
  }));
  await expect(collectSummarySources(base, status, new AbortController().signal)).rejects.toThrow();
  base.results = vi.fn<ScanTransport['results']>(async () => ({
    findings: [],
    nextCursor: null,
    coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
  }));
  await expect(collectSummarySources(base, status, new AbortController().signal)).rejects.toThrow();
});
