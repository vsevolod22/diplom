import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { StrictMode } from 'react';
import {
  readReportPreferences,
  REPORT_AUTOMATION_REVISION,
  saveReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { usage } from './llmChatFixtures';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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

const id = '00000000-0000-4000-8000-000000000038';
const digest = `sha256:${'a'.repeat(64)}`;
const tuple = { scanId: id, digest, platform: 'linux/amd64' as const, reportVersion: 'b'.repeat(64) };
const context: SummaryContext = {
  ...tuple,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  disclosure: {
    provider: 'OpenRouter',
    model: 'dots-studio/dots-3-note-preview:free',
    providers: ['atlas-cloud/fp8'],
    region: 'global',
    retention: 'no-training',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0,
    freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 },
    data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.',
  },
};
const openRouterDisclosure = context.disclosure;
if (openRouterDisclosure?.provider !== 'OpenRouter') throw new Error('Expected OpenRouter fixture');
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
const navigateSource = vi.fn(() => true);
function mount(sourceTransport = transport(), value = status) {
  return render(
    <>
      <p>Исходный отчёт · checked не означает безопасность</p>
      <ScanSummaryPanel key={JSON.stringify(value)} status={value} transport={sourceTransport} onNavigateSource={navigateSource} />
    </>,
  );
}
const posts = () => requests.filter((request) => request.init?.method === 'POST');
async function generate() {
  await waitFor(() => expect(posts()).toHaveLength(1));
}
function openExplanation() {
  const toggle = screen.getByText('Прочитать объяснение и проверить его источники');
  const details = toggle.closest('details')!;
  expect(details.open).toBe(false);
  fireEvent.click(toggle);
  expect(details.open).toBe(true);
  return details;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}
function expectProgress(phase: string, label: string) {
  const progress = screen.getByRole('progressbar', { name: 'Подготовка ИИ-отчёта' });
  expect(progress).not.toHaveAttribute('value');
  expect(progress).not.toHaveAttribute('aria-valuenow');
  expect(progress.closest('[data-phase]')).toHaveAttribute('data-phase', phase);
  expect(screen.getByRole('status')).toHaveTextContent(`Готовим разбор… ${label}`);
  expect(screen.getByText('Готовим разбор…')).toHaveClass('sr-only');
  expect(screen.queryByText(/\d+\s*%/)).not.toBeInTheDocument();
  expect(screen.queryByText('ИИ-разбор готов')).not.toBeInTheDocument();
  expect(screen.queryByText('Проверьте исходную находку')).not.toBeInTheDocument();
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  requests.length = 0;
  navigateSource.mockClear();
  transitionScanSession('alice', new QueryClient(), true);
  saveReportPreferences({ language: 'original', autoSummary: true });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each([false, true])('B2 recovered summary context selection is visible and legacy never implies coverage: metadata=%s', async metadata => {
  saveReportPreferences({ language: 'original', autoSummary: false });
  const unknown = { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' };
  const meta = { findingCount: 2, findingCounts: {
    byCheck: { secret: 2, sbom: null, vuln: null, config: null },
    bySeverity: { UNKNOWN: 1, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  }, coverage: { secret: { outcome: 'checked', scope: 'image', reason: null, errorCode: null, findingCount: 2,
    os: unknown, node: unknown, db: unknown }, sbom: unknown, vuln: unknown, config: unknown } };
  const existing = vi.fn(async () => json({ ...reply, ...(metadata ? { ...meta, scannerFacts: [{ ...reply.scannerFacts[0], ruleId: 'rule-0000000000000000', line: null, evidenceRef: 'result-0-secret-1' }], contextSelection: {
    totalFindings: 2, selectedFindings: 1, omittedFindings: 1,
    strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: ['secret-0-1'],
  } } : {}) }));
  mockApi(() => ({ ...context, summaryResultRead: true }), undefined, existing);
  const view = mount();
  await screen.findByText('ИИ-разбор готов');
  const copy = metadata ? 'Модель получила 1 из 2 находок; 1 не включены в контекст.' : /Объём контекста модели неизвестен/;
  expect(screen.getByText(copy)).toBeVisible();
  const full = screen.getByRole('link', { name: 'Полный отчёт сканеров · находки и исправления' });
  expect(full).toHaveAttribute('href', '#scan-a1-findings');
  expect(screen.getByText('Прочитать объяснение и проверить его источники').closest('details')).not.toHaveAttribute('open');
  expect(posts()).toHaveLength(0);
  view.unmount();
  mount();
  await screen.findByText('ИИ-разбор готов'); expect(posts()).toHaveLength(0); expect(existing).toHaveBeenCalledTimes(2);
});

it.each(['unsaved', 'off', 'disabled-policy'] as const)('legacy capability=true restores via passive GET with %s and no consent/POST/translation', async setting => {
  if (setting === 'off') saveReportPreferences({ language: 'ru', autoSummary: false });
  else localStorage.clear();
  const capable: SummaryContext = setting === 'disabled-policy'
    ? { ...context, enabled: false, policyVersion: null, disclosure: null, summaryResultRead: true }
    : { ...context, summaryResultRead: true };
  mockApi(() => capable, undefined, () => json(reply));
  const source = transport(); const originalStatus = JSON.stringify(status);
  mount(source, status);
  await screen.findByText('Проверьте исходную находку');
  expect(status.profile).toBeUndefined(); expect(JSON.stringify(status)).toBe(originalStatus);
  expect(source.results).toHaveBeenCalledTimes(2);
  expect(requests.filter(request => request.path.endsWith('/summary') && request.init?.method === 'GET')).toHaveLength(1);
  expect(requests.filter(request => request.path.endsWith('/context'))).toHaveLength(2);
  expect(posts()).toHaveLength(0);
  expect(requests.some(request => /translation|usage/.test(request.path))).toBe(false);
  expect(screen.queryByRole('button', { name: 'Включить авторазбор' })).toBeNull();
  expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeVisible();
  expect(readReportPreferences().autoSummary).toBe(false);
});

it.each([
  { profile: 'legacy', capability: false }, { profile: 'public', capability: false },
  { profile: 'legacy', capability: undefined },
] as const)('recovery gate honors explicit false and absent legacy contract: $profile / $capability', async ({ profile, capability }) => {
  localStorage.clear();
  mockApi(() => ({ ...context, ...(capability === undefined ? {} : { summaryResultRead: capability }) }), undefined, () => json(reply));
  mount(transport(), profile === 'public' ? publicStatus : status);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Включить авторазбор' })).toBeEnabled());
  expect(requests.filter(request => request.path.endsWith('/summary'))).toHaveLength(0);
  expect(posts()).toHaveLength(0); expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
});

it('legacy missing cache permits exactly one POST only with current opt-in, not on focus/reconnect', async () => {
  mockApi(() => ({ ...context, summaryResultRead: true }));
  mount();
  await screen.findByText('Проверьте исходную находку');
  expect(requests.filter(request => request.path.endsWith('/summary') && request.init?.method === 'GET')).toHaveLength(1);
  expect(posts()).toHaveLength(1);
  expect(JSON.parse(String(posts()[0].init?.body))).toEqual({ reportVersion: tuple.reportVersion, consent: { accepted: true, policyVersion: context.policyVersion } });
  fireEvent.focus(window); fireEvent(window, new Event('online')); await act(async () => {});
  expect(posts()).toHaveLength(1);
});

it.each(['off', 'unsaved'] as const)('legacy exact cache miss with %s consent never grants generation', async setting => {
  if (setting === 'off') saveReportPreferences({ language: 'original', autoSummary: false }); else localStorage.clear();
  mockApi(() => ({ ...context, summaryResultRead: true })); mount();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Включить авторазбор' })).toBeEnabled());
  expect(requests.filter(request => request.path.endsWith('/summary') && request.init?.method === 'GET')).toHaveLength(1);
  expect(posts()).toHaveLength(0);
});

it.each([[404, 'SCAN_NOT_FOUND'], [403, 'FORBIDDEN'], [404, 'LLM_SUMMARY_MISSING_EXTRA']] as const)(
  'legacy capability=true denial %s/%s never becomes a generation cache miss', async (code, errorCode) => {
    mockApi(() => ({ ...context, summaryResultRead: true }), undefined, () => json({ errorCode }, code)); mount();
    await screen.findByRole('alert'); expect(posts()).toHaveLength(0);
    expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  },
);

it.each(['context', 'http', 'generation'] as const)('unsupported legacy report from %s shows specific message without opt-in/retry, keeps original results', async from => {
  if (from !== 'generation') localStorage.clear();
  const unsupported: SummaryContext = { ...context, enabled: false, policyVersion: null, disclosure: null, summaryResultRead: false, unavailableReason: 'LLM_SUMMARY_UNSUPPORTED_REPORT' };
  if (from === 'context') mockApi(() => unsupported);
  else if (from === 'generation') mockApi(undefined, () => json({ errorCode: 'LLM_SUMMARY_UNSUPPORTED_REPORT' }, 409));
  else mockApi(() => ({ ...context, summaryResultRead: true }), undefined, () => json({ errorCode: 'LLM_SUMMARY_UNSUPPORTED_REPORT' }, 409));
  mount();
  expect(await screen.findByRole('alert')).toHaveTextContent('ИИ-разбор недоступен для этого формата отчёта. Исходные результаты доступны в разделе «Находки и исправления».');
  expect(screen.queryByRole('button', { name: 'Включить авторазбор' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Повторить разбор' })).toBeNull();
  expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeVisible();
  expect(posts()).toHaveLength(from === 'generation' ? 1 : 0);
  fireEvent.focus(window); fireEvent(window, new Event('online')); await act(async () => {});
  expect(posts()).toHaveLength(from === 'generation' ? 1 : 0);
});

it('disabled legacy configuration without unsupported reason stays neutral', async () => {
  localStorage.clear();
  mockApi(() => ({ ...context, enabled: false, policyVersion: null, disclosure: null, summaryResultRead: false }));
  mount();
  expect(await screen.findByRole('alert')).toHaveTextContent('ИИ-разбор сейчас недоступен. Отчёт сканеров доступен.');
  expect(screen.getByRole('button', { name: 'Включить авторазбор' })).toBeDisabled();
  expect(screen.queryByText(/для этого формата отчёта/)).toBeNull(); expect(posts()).toHaveLength(0);
});

it.each(['bob', 'alice'] as const)('legacy passive recovery cannot publish after owner/generation switch to %s', async owner => {
  localStorage.clear(); mockApi(() => ({ ...context, summaryResultRead: true }));
  const client = createSummaryClient(scanSession()); const pending = deferred<SummaryReply | null>();
  const existing = vi.spyOn(client, 'existing').mockImplementation(() => pending.promise);
  render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
  await waitFor(() => expect(existing).toHaveBeenCalledTimes(1));
  act(() => transitionScanSession(owner, new QueryClient(), true));
  expect(existing.mock.calls[0][1].aborted).toBe(true);
  await act(async () => pending.resolve(reply));
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull(); expect(posts()).toHaveLength(0);
});

it('legacy capability does not relax stale-report verification or fall back to POST', async () => {
  mockApi(() => ({ ...context, summaryResultRead: true }), undefined, () => json({ ...reply, reportVersion: 'f'.repeat(64) }));
  mount(); await screen.findByRole('alert');
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull(); expect(posts()).toHaveLength(0);
});

it('reports real deferred context, recovery, generation and verification without premature success', async () => {
  mockApi();
  const client = createSummaryClient(scanSession());
  const initial = deferred<SummaryContext>();
  const recovered = deferred<SummaryReply | null>();
  const generated = deferred<SummaryReply>();
  const finalContext = deferred<SummaryContext>();
  const contexts = vi.spyOn(client, 'context').mockResolvedValue(context);
  contexts.mockImplementationOnce(() => initial.promise);
  const existing = vi.spyOn(client, 'existing').mockImplementation(() => recovered.promise);
  const summary = vi.spyOn(client, 'summary').mockImplementation(() => generated.promise);
  const source = transport();
  const firstPage = deferred<Awaited<ReturnType<ScanTransport['results']>>>();
  const readPage = source.results;
  vi.mocked(source.results).mockImplementationOnce(() => firstPage.promise);
  render(<ScanSummaryPanel status={publicStatus} transport={source} client={client} />);

  expectProgress('context', 'Проверяем доступность разбора');
  expect(existing).not.toHaveBeenCalled();
  expect(summary).not.toHaveBeenCalled();
  await act(async () => initial.resolve(context));
  await waitFor(() => expect(existing).toHaveBeenCalledTimes(1));
  expectProgress('recovery', 'Ищем сохранённый разбор');
  expect(summary).not.toHaveBeenCalled();
  await act(async () => recovered.resolve(null));
  await waitFor(() => expect(summary).toHaveBeenCalledTimes(1));
  expectProgress('generation', 'Модель готовит рекомендации');
  expect(source.results).not.toHaveBeenCalled();
  contexts.mockImplementationOnce(() => finalContext.promise);
  await act(async () => generated.resolve(reply));
  await waitFor(() => expect(source.results).toHaveBeenCalledTimes(1));
  expectProgress('verification', 'Проверяем источники и готовим результат');
  await act(async () =>
    firstPage.resolve({
      findings: [
        { findingId: 'secret-0-0', category: 'secret', ruleId: 'rule-0000000000000000', severity: 'unknown' },
      ],
      nextCursor: '1',
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
    }),
  );
  await waitFor(() => expect(readPage).toHaveBeenCalledTimes(2));
  expectProgress('verification', 'Проверяем источники и готовим результат');
  await act(async () => finalContext.resolve(context));
  await screen.findByText('Проверьте исходную находку');
  openExplanation();
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
  expect(screen.getByRole('status')).toHaveTextContent('ИИ-разбор готов');
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(summary).toHaveBeenCalledTimes(1);
});

it.each(['invalid-citation', 'unknown-source-error'] as const)(
  'deferred verification failure %s never announces success or leaks unverified content',
  async (failure) => {
    mockApi(undefined, () =>
      json(
        failure === 'invalid-citation'
          ? {
              ...reply,
              hypotheses: [{ ...reply.hypotheses[0], citations: ['secret-0-99'] }],
              scannerFacts: [{ ...reply.scannerFacts[0], findingId: 'secret-0-99' }],
            }
          : reply,
      ),
    );
    const source = transport();
    const page = deferred<Awaited<ReturnType<ScanTransport['results']>>>();
    vi.mocked(source.results).mockImplementationOnce(() => page.promise);
    mount(source);
    await waitFor(() => expect(source.results).toHaveBeenCalledTimes(1));
    expectProgress('verification', 'Проверяем источники и готовим результат');
    await act(async () => {
      if (failure === 'unknown-source-error') page.reject(new Error('private-source-token internal.example'));
      else
        page.resolve({
          findings: [
            {
              findingId: 'secret-0-0',
              category: 'secret',
              ruleId: 'rule-0000000000000000',
              severity: 'unknown',
            },
          ],
          nextCursor: '1',
          coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
        });
    });
    const alert = await screen.findByRole('alert');
    expect(alert).not.toHaveTextContent(/private-source-token|internal\.example/);
    if (failure === 'invalid-citation')
      expect(alert).toHaveTextContent(
        'Ответ ИИ не прошёл проверку достоверности или формата и не показан. Исходные находки сохранены; можно повторить разбор вручную.',
      );
    expect(screen.queryByText('ИИ-разбор готов')).not.toBeInTheDocument();
    expect(screen.queryByText('Проверьте исходную находку')).not.toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeVisible();
    fireEvent(window, new Event('focus'));
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(posts()).toHaveLength(1);
  },
);

it('recovered output stays private until deferred source verification finishes and sends no POST', async () => {
  const recovered = deferred<Response>();
  mockApi(undefined, undefined, () => recovered.promise);
  const source = transport();
  const page = deferred<Awaited<ReturnType<ScanTransport['results']>>>();
  vi.mocked(source.results).mockImplementationOnce(() => page.promise);
  mount(source, publicStatus);
  await waitFor(() => expect(requests.some((request) => request.path.endsWith('/summary'))).toBe(true));
  expectProgress('recovery', 'Ищем сохранённый разбор');
  await act(async () => recovered.resolve(json(reply)));
  await waitFor(() => expect(source.results).toHaveBeenCalledTimes(1));
  expectProgress('verification', 'Проверяем источники и готовим результат');
  expect(posts()).toHaveLength(0);
  await act(async () =>
    page.resolve({
      findings: [
        { findingId: 'secret-0-0', category: 'secret', ruleId: 'rule-0000000000000000', severity: 'unknown' },
      ],
      nextCursor: '1',
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
    }),
  );
  await screen.findByText('Проверьте исходную находку');
  openExplanation();
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
  expect(screen.getByRole('status')).toHaveTextContent('ИИ-разбор готов');
  expect(posts()).toHaveLength(0);
});

it('shows elapsed time only after ten seconds while context remains unresolved', async () => {
  mockApi();
  const client = createSummaryClient(scanSession());
  vi.spyOn(client, 'context').mockImplementation(() => new Promise(() => {}));
  vi.useFakeTimers();
  render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
  await act(async () => vi.advanceTimersByTimeAsync(9_999));
  expect(screen.queryByText(/Ожидание:/)).not.toBeInTheDocument();
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(screen.getByText('Ожидание: 10 с')).toBeVisible();
  expectProgress('context', 'Проверяем доступность разбора');
  expect(posts()).toHaveLength(0);
});

it('cancel during source verification aborts delivery and never publishes a late verified reply', async () => {
  mockApi();
  const source = transport();
  const page = deferred<Awaited<ReturnType<ScanTransport['results']>>>();
  vi.mocked(source.results).mockImplementationOnce(() => page.promise);
  mount(source);
  await waitFor(() => expect(source.results).toHaveBeenCalledTimes(1));
  expectProgress('verification', 'Проверяем источники и готовим результат');
  fireEvent.click(screen.getByRole('button', { name: 'Отменить разбор' }));
  await act(async () => page.resolve({ findings: [], nextCursor: null, coverage: [] }));
  fireEvent(window, new Event('focus'));
  fireEvent(window, new Event('online'));
  expect(source.results).toHaveBeenCalledTimes(1);
  expect(screen.queryByText('ИИ-разбор готов')).not.toBeInTheDocument();
  expect(screen.queryByText('Проверьте исходную находку')).not.toBeInTheDocument();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('Разбор отменён');
  expect(posts()).toHaveLength(1);
});

it.each(['LLM_INVALID_RESPONSE', 'PRIVATE_PROVIDER_ERROR'])(
  'safe %s failure retains findings and only a manual retry generates again',
  async (code) => {
    let failing = true;
    mockApi(undefined, () =>
      failing
        ? json({ errorCode: code, message: 'secret-provider-token internal.example stack trace' }, 502)
        : json(reply),
    );
    mount();
    const alert = await screen.findByRole('alert');
    if (code === 'LLM_INVALID_RESPONSE')
      expect(alert).toHaveTextContent(
        'Ответ ИИ не прошёл проверку достоверности или формата и не показан. Исходные находки сохранены; можно повторить разбор вручную.',
      );
    expect(alert).not.toHaveTextContent(
      /secret-provider-token|internal\.example|stack trace|PRIVATE_PROVIDER_ERROR/,
    );
    expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeVisible();
    expect(screen.queryByText('ИИ-разбор готов')).not.toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    fireEvent(window, new Event('focus'));
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(posts()).toHaveLength(1);
    failing = false;
    fireEvent.click(screen.getByRole('button', { name: 'Повторить разбор' }));
    await screen.findByText('Проверьте исходную находку');
  openExplanation();
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
    expect(posts()).toHaveLength(2);
    expect(screen.getByRole('status')).toHaveTextContent('ИИ-разбор готов');
  },
);

it('one opt-in click persists the existing language and generates once; later reports autoload without another button', async () => {
  saveReportPreferences({ language: 'ru', autoSummary: false });
  mockApi();
  const view = mount();
  const button = await screen.findByRole('button', { name: 'Включить авторазбор' });
  await waitFor(() => expect(button).toBeEnabled());
  expect(posts()).toHaveLength(0);
  expect(screen.getByText(/Находки отчёта, имена пакетов и версии/)).toBeVisible();
  fireEvent.click(button);
  await screen.findByText('Проверьте исходную находку');
  expect(readReportPreferences()).toMatchObject({
    language: 'ru',
    autoSummary: true,
    revision: 'report-automation-v4-remediation',
  });
  expect(posts()).toHaveLength(1);
  expect(screen.queryByRole('button', { name: 'Включить авторазбор' })).toBeNull();
  expect(screen.queryByRole('button', { name: /Получить отчёт|Получить сводку/ })).toBeNull();
  view.unmount();
  const next = { ...tuple, scanId: '00000000-0000-4000-8000-000000000039' };
  mockApi(
    () => ({ ...context, ...next }),
    () => json({ ...reply, ...next }),
  );
  const nextFetch = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn((input, init) =>
      String(input).endsWith('/usage')
        ? Promise.resolve(json({ ...usage, ...next, integrationEnabled: true, quotaEnabled: true }))
        : nextFetch(input, init),
    ),
  );
  mount(transport(), { ...status, scanId: next.scanId });
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(2);
});

it('does not silently renew stale consent and only saves v4 after an explicit opt-in', async () => {
  const raw = JSON.stringify({
    version: 1,
    automationRevision: 'report-automation-v3-dots-no-training',
    language: 'original',
    autoSummary: true,
  });
  localStorage.setItem('report-preferences:v1:alice', raw);
  mockApi();
  mount();
  const button = await screen.findByRole('button', { name: 'Включить авторазбор' });
  await waitFor(() => expect(button).toBeEnabled());
  expect(localStorage.getItem('report-preferences:v1:alice')).toBe(raw);
  expect(posts()).toHaveLength(0);
  fireEvent.click(button);
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
  expect(readReportPreferences().revision).toBe('report-automation-v4-remediation');
});

it.each(['unsaved', 'off'] as const)(
  'a failed opt-in save from %s never generates or grants in-memory consent',
  async (setting) => {
    localStorage.clear();
    if (setting === 'off') saveReportPreferences({ language: 'ru', autoSummary: false });
    mockApi();
    mount();
    const button = await screen.findByRole('button', { name: 'Включить авторазбор' });
    await waitFor(() => expect(button).toBeEnabled());
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('Unavailable');
    });
    fireEvent.click(button);
    expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось сохранить настройку');
    expect(readReportPreferences().authorized).toBe(false);
    expect(posts()).toHaveLength(0);
  },
);

it('a stale opt-in click cannot grant authorization after a silent preference change', async () => {
  saveReportPreferences({ language: 'original', autoSummary: false });
  mockApi();
  mount();
  const button = await screen.findByRole('button', { name: 'Включить авторазбор' });
  await waitFor(() => expect(button).toBeEnabled());
  const raw = JSON.stringify({
    version: 1,
    automationRevision: REPORT_AUTOMATION_REVISION,
    language: 'ru',
    autoSummary: false,
  });
  localStorage.setItem('report-preferences:v1:alice', raw);
  fireEvent.click(button);
  expect(localStorage.getItem('report-preferences:v1:alice')).toBe(raw);
  expect(posts()).toHaveLength(0);
});

it('renders only actual model paragraphs, with sources collapsed and no duplicate chat or policy wall', async () => {
  const paragraphs = [
    'Сначала проверьте наиболее серьёзную находку сканера.',
    'Определите, затрагивает ли она используемый образ.',
    'После изменения пересоберите образ и повторите проверку.',
    'Неизвестное покрытие не позволяет считать образ безопасным.',
  ];
  mockApi(undefined, () =>
    json({
      ...reply,
      hypotheses: paragraphs.map((text) => ({ kind: 'hypothesis', text, citations: ['secret-0-1'] })),
    }),
  );
  mount();
  await screen.findByText(paragraphs[0]);
  const output = screen.getByLabelText('ИИ-разбор отчёта');
  const details = output.querySelector('details')!;
  expect(details.open).toBe(false);
  const blocks = [...details.querySelectorAll(':scope > div')];
  expect(blocks.map(block => block.querySelector(':scope > p')?.textContent)).toEqual(paragraphs);
  openExplanation();
  for (const [index, block] of blocks.entries()) {
    const sources = within(block as HTMLElement).getByLabelText(`Источники абзаца ${index + 1}`);
    expect(sources.querySelectorAll(':scope > ul > li')).toHaveLength(1);
    expect(sources.querySelector('strong')?.textContent).toBe('rule-0000000000000000 · Секреты');
    const link = within(sources).getByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
    expect(link).toHaveAttribute('href', '#scan-report-secrets');
    fireEvent.click(link);
    expect(navigateSource).toHaveBeenLastCalledWith('secret');
  }
  expect(within(output).getByLabelText('Объём контекста модели')).toHaveTextContent('Полнота охвата не подтверждена');
  expect(screen.queryByRole('region', { name: 'Чат по отчёту' })).toBeNull();
  expect(document.body.textContent).not.toMatch(
    /OpenRouter|dots-studio|atlas-cloud|маршрутизация|политика|бюджет|квота|receipt|Пункт 1/i,
  );
});

it('shows honest failure without generated fallback text and retries initial context errors manually', async () => {
  let failing = true;
  mockApi();
  const real = createSummaryClient(scanSession());
  const client = {
    ...real,
    context: vi.fn((scanId: string, signal: AbortSignal) => {
      if (failing) return Promise.reject(new Error('PRIVATE_PROVIDER_DIAGNOSTIC'));
      return real.context(scanId, signal);
    }),
  };
  render(<ScanSummaryPanel status={status} transport={transport()} client={client} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось получить разбор ИИ');
  expect(screen.queryByLabelText('ИИ-разбор отчёта')).toBeNull();
  expect(document.body.textContent).not.toContain('PRIVATE_PROVIDER_DIAGNOSTIC');
  expect(posts()).toHaveLength(0);
  failing = false;
  fireEvent.click(screen.getByRole('button', { name: 'Повторить разбор' }));
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
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

it('explains a missing saved summary and rechecks with GET only when automation is off', async () => {
  saveReportPreferences({ language: 'original', autoSummary: false });
  mockApi(() => ({ ...context, summaryResultRead: true }));
  mount();
  await screen.findByText(/Сохранённого ИИ-разбора пока нет/);
  expect(posts()).toHaveLength(0);
  expect(screen.getByText('Исходный отчёт · checked не означает безопасность')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Проверить сохранённый разбор' }));
  await waitFor(() => expect(requests.filter(r => r.path.endsWith('/summary') && r.init?.method === 'GET')).toHaveLength(2));
  await screen.findByText(/Сохранённого ИИ-разбора пока нет/);
  expect(posts()).toHaveLength(0);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Создать платный ИИ-разбор' })).toBeNull();
});

it('automatically generates once with saved authorization, exact consent and verified late-page sources', async () => {
  mockApi();
  const source = transport();
  const view = mount(source);
  await screen.findByText('Проверьте исходную находку');
  expect(posts()).toHaveLength(1);
  expect(screen.getByRole('heading', { name: 'Объяснение ИИ' })).toBeVisible();
  const sources = screen.getByLabelText('Источники абзаца 1');
  expect(sources.parentElement?.querySelector(':scope > p')?.textContent).toBe(reply.hypotheses[0].text);
  const details = sources.closest('details')!;
  expect(details.open).toBe(false);
  expect(document.body.textContent).not.toMatch(
    /OpenRouter|no-training|ZDR|политика|бюджет|Пункт 1|гипотеза/i,
  );
  expect(screen.queryByRole('region', { name: 'Чат по отчёту' })).toBeNull();
  openExplanation();
  expect(screen.getByText('Проверьте исходную находку')).toBeVisible();
  expect(JSON.parse(String(posts()[0].init?.body))).toEqual({
    reportVersion: tuple.reportVersion,
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  expect(posts()[0].init).toMatchObject({ cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  expect(source.results).toHaveBeenCalledTimes(2);
  const citedPage = await vi.mocked(source.results).mock.results[1].value;
  const citedFinding = citedPage.findings[0];
  expect(citedFinding.findingId).toBe(reply.hypotheses[0].citations[0]);
  expect(citedFinding.findingId).toBe('secret-0-1');
  expect(sources.querySelectorAll(':scope > ul > li')).toHaveLength(1);
  expect(sources.querySelector('strong')?.textContent).toBe(`${citedFinding.ruleId} · Секреты`);
  fireEvent.click(within(sources).getByRole('link', { name: 'Открыть раздел «Возможные секреты»' }));
  expect(navigateSource).toHaveBeenLastCalledWith('secret');
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

it.each([
  'report-automation-v1',
  'report-automation-v2-nvidia-no-training',
  'report-automation-v3-dots-no-training',
])('old account consent %s never authorizes a Dots summary POST', async (automationRevision) => {
  localStorage.setItem(
    'report-preferences:v1:alice',
    JSON.stringify({
      version: 1,
      automationRevision,
      language: 'ru',
      autoSummary: true,
    }),
  );
  mockApi();
  mount();
  await act(async () => {});
  expect(readReportPreferences().authorized).toBe(false);
  expect(posts()).toHaveLength(0);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
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
          automationRevision: REPORT_AUTOMATION_REVISION,
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
  let revoked = false;
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/usage')) {
      revoked = true;
      localStorage.setItem(
        'report-preferences:v1:alice',
        JSON.stringify({
          version: 1,
          automationRevision: REPORT_AUTOMATION_REVISION,
          language: 'original',
          autoSummary: false,
        }),
      );
    }
    return fetcher(input, init);
  });
  mount();
  await waitFor(() => expect(revoked).toBe(true));
  await waitFor(() => expect(screen.queryByRole('progressbar', { name: 'Подготовка ИИ-отчёта' })).toBeNull());
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(0);
});

it.each([
  { model: 'other/model:free' },
  { providers: ['atlas-cloud/fp8', 'other'] },
  { model: 'nvidia/nemotron-3.5-super-vl:free', providers: ['nvidia'], retention: 'no-training' },
  { providers: ['phala'] },
  { model: 'xingchen-agi/xing4.0-29b-a4b:free', providers: ['phala'], retention: 'no-storage' },
  { providers: ['other'] },
  { provider: 'Other' },
  { region: 'other' },
  { retention: 'no-storage' },
  { freeOnly: false },
  { requestBudgetUsd: 0.1 },
  { maxPrice: { prompt: 1, completion: 0, request: 0 } },
  { maxPrice: { prompt: 0, completion: 0, request: null } },
  { data: 'All raw evidence, credentials and chat history.' },
  { data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.' },
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
    expect(await screen.findByRole('alert')).toHaveTextContent('Условия ИИ-разбора изменились');
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
  current = { ...context, disclosure: { ...openRouterDisclosure, model: 'different/model' } };
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
    expect(screen.getAllByRole('button', { name: 'Включить авторазбор' })).toHaveLength(1);
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
  fireEvent.click(screen.getByRole('button', { name: 'Повторить разбор' }));
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
  await waitFor(() =>
    expect(requests.filter((r) => r.path.endsWith('/summary') && r.init?.method === 'GET')).toHaveLength(2),
  );
  await screen.findByText('Проверьте исходную находку');
  openExplanation();
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
  await screen.findByText(/Не удалось подготовить разбор/);
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
    expect(screen.queryByText(/кэша процесса/)).toBeNull();
    expect(source.results).toHaveBeenCalledTimes(2);
    expect(requests.filter((r) => r.path.endsWith('/context'))).toHaveLength(2);
    expect(requests.some((r) => r.path.endsWith('/usage'))).toBe(false);
    expect(posts()).toHaveLength(0);
    expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Включить авторазбор' })).toBeNull();
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
  fireEvent.click(screen.getByRole('button', { name: 'Повторить разбор' }));
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
      if (kind === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Отменить разбор' }));
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
        automationRevision: REPORT_AUTOMATION_REVISION,
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
  expect(screen.getByRole('status')).toHaveTextContent('Готовим разбор…');
  fireEvent.click(screen.getByRole('button', { name: 'Отменить разбор' }));
  await act(async () => finish());
  expect(posts()[0].init!.signal!.aborted).toBe(true);
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(posts()).toHaveLength(1);
});

it('bounds a noncooperative generation at 120 seconds and never continues source reads after timeout', async () => {
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
  vi.useFakeTimers();

  render(<ScanSummaryPanel status={status} transport={source} client={client} />);
  await act(async () => {
    await vi.waitFor(() => expect(summary).toHaveBeenCalledTimes(1));
  });
  await act(async () => vi.advanceTimersByTimeAsync(45_001));
  expect(summary.mock.calls[0][1].aborted).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
  await act(async () => vi.advanceTimersByTimeAsync(60_000));
  expect(summary.mock.calls[0][1].aborted).toBe(false);
  await act(async () => vi.advanceTimersByTimeAsync(15_000));
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
it('freeOnly requires an exact approved profile as well as zero prices, not merely a free model suffix', async () => {
  const free = {
    ...context,
    disclosure: {
      ...context.disclosure!,
      ...openRouterDisclosure,
      model: 'vendor/model:free',
      freeOnly: true,
      requestBudgetUsd: 0,
      maxPrice: { prompt: 0, completion: 0, request: 0 },
    },
  };
  mockApi(() => free);
  const client = createSummaryClient(scanSession());
  await expect(client.context(id, new AbortController().signal)).rejects.toThrow();
  mockApi(() => ({
    ...context,
    disclosure: { ...context.disclosure!, maxPrice: { prompt: 0, completion: 1, request: 0 } },
  }));
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
it('config hash citation resolves only its paragraph-local source details', async () => {
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
  const sourceTransport = transport();
  mount(sourceTransport, configStatus);
  await generate();
  await screen.findByText('Проверьте исходную находку');
  const sources = screen.getByLabelText('Источники абзаца 1');
  expect(sources.parentElement?.querySelector(':scope > p')?.textContent).toBe(reply.hypotheses[0].text);
  openExplanation();
  expect(sources.querySelectorAll(':scope > ul > li')).toHaveLength(1);
  const configFinding = configStatus.config!.findings[0];
  expect(configFinding.findingId).toBe(digest);
  expect(sources.querySelector('strong')?.textContent).toBe(`${configFinding.ruleId} · Средняя`);
  expect(sources).not.toHaveTextContent('Секреты');
  const link = within(sources).getByRole('link', { name: 'Открыть раздел «Настройки образа»' });
  expect(link).toHaveAttribute('href', '#scan-report-config');
  fireEvent.click(link);
  expect(navigateSource).toHaveBeenLastCalledWith('config');
  expect(sourceTransport.results).not.toHaveBeenCalled();
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
