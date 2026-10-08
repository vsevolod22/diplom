import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  collectSummarySources,
  createSummaryClient,
  type SummaryContext,
  type SummaryReply,
  verifiedSummarySources,
} from '@/shared/api/scans/llmSummaryClient';
import { type ScanStatus, type ScanTransport } from '@/shared/api/scans/scanTransport';

const id = '00000000-0000-4000-8000-000000000038';
const digest = `sha256:${'a'.repeat(64)}`;
const tuple = { scanId: id, digest, platform: 'linux/amd64' as const, reportVersion: 'b'.repeat(64) };
const context: SummaryContext = {
  ...tuple,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  disclosure: {
    provider: 'OpenRouter',
    model: 'vendor/model',
    providers: ['vendor'],
    region: 'global',
    retention: 'no-training',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0.1,
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
) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init?: RequestInit) => {
      requests.push({ path, init });
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
async function consentAndGenerate() {
  const checkbox = await screen.findByRole('checkbox');
  await waitFor(() => expect((checkbox as HTMLInputElement).disabled).toBe(false));
  fireEvent.click(checkbox);
  fireEvent.click(screen.getByRole('button', { name: 'Получить сводку' }));
}
beforeEach(() => {
  requests.length = 0;
  transitionScanSession('alice', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('mount/focus only GET, disclosure is explicit, absent free field never implies free and consent starts unchecked', async () => {
  mockApi();
  mount();
  await screen.findByText(/Бесплатный режим не подтверждён/);
  expect(screen.getByText(/global: регион не ограничен/)).toBeTruthy();
  expect(screen.getByText(/декларация не доказывают/)).toBeTruthy();
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
  expect((screen.getByRole('button', { name: 'Получить сводку' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.focus(window);
  await waitFor(() => expect(requests.length).toBe(2));
  expect(requests.every((request) => request.init?.method === 'GET')).toBe(true);
});
it('exact opt-in POST DTO, pending double-click prevention, per-request consent reset and late-page finding link', async () => {
  mockApi();
  const source = transport();
  mount(source);
  await consentAndGenerate();
  fireEvent.click(screen.getByRole('button', { name: 'Получить сводку' }));
  await screen.findByText('Проверьте исходную находку');
  const post = requests.filter((request) => request.init?.method === 'POST');
  expect(post).toHaveLength(1);
  expect(post[0].path).toBe(`/api/v1/browser/scans/${id}/llm/summary`);
  expect(JSON.parse(String(post[0].init?.body))).toEqual({
    reportVersion: tuple.reportVersion,
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  expect(post[0].init).toMatchObject({ cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  expect(source.results).toHaveBeenCalledTimes(2);
  const link = screen.getByRole('link', { name: 'Находка secret-0-1' });
  expect(document.getElementById(link.getAttribute('href')!.slice(1))?.textContent).toContain('Secrets');
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
});
for (const change of ['policy', 'report', 'disclosure', 'disabled'] as const) {
  it(`context ${change} change before POST resets consent with zero POST`, async () => {
    let current = context;
    mockApi(() => current);
    mount();
    await screen.findByText(/Бесплатный режим не подтверждён/);
    current =
      change === 'policy'
        ? { ...context, policyVersion: 'd'.repeat(64) }
        : change === 'report'
          ? { ...context, reportVersion: 'd'.repeat(64) }
          : change === 'disclosure'
            ? { ...context, disclosure: { ...context.disclosure!, model: 'vendor/new' } }
            : { ...context, enabled: false, policyVersion: null, disclosure: null };
    await consentAndGenerate();
    await screen.findByRole('alert');
    expect(requests.some((request) => request.init?.method === 'POST')).toBe(false);
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
  });
}
it('policy changes after POST discard the result and retain original report', async () => {
  let reads = 0;
  mockApi(() => (++reads > 2 ? { ...context, policyVersion: 'd'.repeat(64) } : context));
  mount();
  await consentAndGenerate();
  await screen.findByRole('alert');
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
});
for (const [code, message] of [
  ['LLM_NO_EVIDENCE', /Нет подтверждённых находок/],
  ['LLM_CAPACITY', /Достигнут лимит/],
  ['LLM_CONFIGURATION_UNAVAILABLE', /ИИ не настроен/],
  ['LLM_REQUEST_ABORTED', /не получена вовремя/],
  ['LLM_PROVIDER_UNAVAILABLE', /безопасно получить/],
] as const) {
  it(`safe ${code} does not echo raw diagnostic or hide scanner report`, async () => {
    mockApi(undefined, () => json({ errorCode: code, message: 'PRIVATE_CANARY' }, 503));
    mount();
    await consentAndGenerate();
    expect((await screen.findByRole('alert')).textContent).toMatch(message);
    expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
    expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeTruthy();
  });
}
it('cancel aborts POST and ignores a late response even if transport ignores abort', async () => {
  let resolve!: (response: Response) => void;
  mockApi(
    undefined,
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  mount();
  await consentAndGenerate();
  await waitFor(() => expect(requests.some((request) => request.init?.method === 'POST')).toBe(true));
  const signal = requests.find((request) => request.init?.method === 'POST')!.init!.signal!;
  fireEvent.click(screen.getByRole('button', { name: 'Отменить запрос сводки' }));
  expect(signal.aborted).toBe(true);
  await act(async () => resolve(json(reply)));
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
});
it('same-subject session generation change aborts immediately and clears consent/result', async () => {
  let resolve!: (response: Response) => void;
  mockApi(
    undefined,
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  mount();
  await consentAndGenerate();
  await waitFor(() => expect(requests.some((request) => request.init?.method === 'POST')).toBe(true));
  const signal = requests.find((request) => request.init?.method === 'POST')!.init!.signal!;
  act(() => transitionScanSession('alice', new QueryClient(), true));
  expect(signal.aborted).toBe(true);
  await act(async () => resolve(json(reply)));
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(screen.getByText(/Сессия изменилась/)).toBeTruthy();
});
it('route/status remount aborts old request and drops its response', async () => {
  let resolve!: (response: Response) => void;
  mockApi(
    undefined,
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const view = mount();
  await consentAndGenerate();
  await waitFor(() => expect(requests.some((request) => request.init?.method === 'POST')).toBe(true));
  const signal = requests.find((request) => request.init?.method === 'POST')!.init!.signal!;
  view.unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => resolve(json(reply)));
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
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
  await consentAndGenerate();
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
  await consentAndGenerate();
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
