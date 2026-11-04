import '@testing-library/jest-dom/vitest';
import { Profiler } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanContext, type LiveContext } from '@/features/scans/liveScanContext';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import {
  ReportSourceLink,
  isReportSourceCategory,
  reportSourceTargets,
} from '@/features/scans/reportSourceNavigation';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { publicSafeFinding } from '@/shared/api/scans/llmFindingContract';
import { imageConfigReport } from '@/shared/api/scans/imageConfigReport';
import { summaryReplySchema } from '@/shared/api/scans/llmSummaryClient';
import { parseCurrentVuln, type ScanStatus, type ScanTransport } from '@/shared/api/scans/scanTransport';
import { binding, context, json, source as secretSource } from './llmChatFixtures';

const vuln = publicSafeFinding.parse({
  check: 'vuln',
  findingId: `vuln-${'f'.repeat(64)}`,
  cveId: 'CVE-2026-9876',
  identifierKind: 'cve',
  ecosystem: 'apk',
  severity: 'HIGH',
  packageName: 'libssl3',
  installedVersion: '1.0-1',
  fixedVersion: '2.0-1',
  fixedVersionReported: true,
  severitySources: ['alpine'],
  provenanceRef: `target-${'d'.repeat(64)}`,
  advisoryState: 'unknown',
});
const config = {
  check: 'config',
  findingId: `sha256:${'e'.repeat(64)}`,
  severity: 'MEDIUM',
  ruleId: 'IMGCFG_USER_ROOT',
  classification: 'NUMERIC_ROOT',
  configDigest: `sha256:${'c'.repeat(64)}`,
  manifestDigest: binding.digest,
  location: '/config/User',
} as const;
const configReport = imageConfigReport.parse({
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
      ...config,
      check: undefined,
      category: 'image-config',
      severitySource: 'image-config-user-v1',
      message: 'Image metadata declares numeric UID 0.',
      recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.',
      platform: { os: 'linux', architecture: 'amd64' },
    },
  ].map(({ check: _check, ...value }) => {
    void _check;
    return value;
  }),
});
const completed: ScanStatus = {
  scanId: binding.scanId,
  digest: binding.digest,
  platform: binding.platform,
  state: 'completed',
  checks: ['secret', 'vuln', 'config'],
  config: configReport,
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 1 },
    config: { check: 'config', coverage: 'image', outcome: 'checked', findingCount: 1 },
    vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 1 },
  },
};
const prose = 'Сверьте находки с исходным отчётом перед обновлением пакетов.';
const recovered = summaryReplySchema.parse({
  ...binding,
  hypotheses: [
    {
      kind: 'hypothesis',
      text: prose,
      citations: [vuln.findingId, secretSource.finding.findingId, config.findingId],
    },
  ],
  scannerFacts: [vuln, secretSource.finding, config],
});
const clients: QueryClient[] = [];
let requests: Array<{ path: string; method: string }>;
let scroll: ReturnType<typeof vi.fn>;
const originalScroll = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollIntoView');
function transportFor(): ScanTransport {
  if (vuln.check !== 'vuln') throw Error('Expected typed vulnerability');
  return {
    ...unavailableScanTransport,
    kind: 'live',
    capabilities: { list: true, create: false, cancel: false, events: false },
    get: vi.fn(async () => completed),
    results: vi.fn<ScanTransport['results']>(async () => ({
      findings: [
        {
          findingId: secretSource.finding.findingId,
          category: 'secret',
          ruleId: 'rule-0000000000000000',
          severity: 'unknown',
          line: 1,
          evidenceRef: 'result-0-secret-1',
        },
      ],
      nextCursor: null,
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 1 }],
    })),
    vuln: vi.fn<ScanTransport['vuln']>(async () =>
      parseCurrentVuln({
        outcome: 'checked',
        coverage: 'image',
        image: `registry-1.docker.io/library/alpine@${binding.digest}`,
        platform: binding.platform,
        findingCount: 1,
        scannerVersion: '0.69.3',
        checkedAt: '2026-01-01T00:00:00.000Z',
        nextCursor: null,
        findings: [
          {
            findingId: vuln.findingId,
            cveId: vuln.cveId,
            ecosystem: vuln.ecosystem,
            packageName: vuln.packageName!,
            installedVersion: vuln.installedVersion!,
            fixedVersion: vuln.fixedVersion!,
            severity: vuln.severity,
          },
        ],
      }),
    ),
  };
}
function mount(commitProbe?: () => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  transitionScanSession('navigation-owner', client, true);
  saveReportPreferences({ language: 'ru', autoSummary: false });
  const session = scanSession();
  const scope: LiveContext['scope'] = ['live-scans', session.generation, session.subject!];
  const transport = transportFor();
  const view = render(
    <QueryClientProvider client={client}>
      <LiveScanContext.Provider value={{ scope, transport }}>
        <MemoryRouter initialEntries={[`/scans/${binding.scanId}`]}>
          <Routes>
            <Route
              path="/scans/:scanId"
              element={
                commitProbe ? (
                  <Profiler id="source-navigation-race" onRender={commitProbe}>
                    <ScanDetailPage />
                  </Profiler>
                ) : (
                  <ScanDetailPage />
                )
              }
            />
          </Routes>
        </MemoryRouter>
      </LiveScanContext.Provider>
    </QueryClientProvider>,
  );
  return { ...view, client, scope, transport };
}
async function explanation() {
  await screen.findByText(prose);
  const summary = screen.getByText('Прочитать объяснение и проверить его источники', { selector: 'summary' });
  expect(summary.closest('details')).not.toHaveAttribute('open');
  fireEvent.click(summary);
  return screen.getByLabelText('Источники абзаца 1');
}
function assertNoDispatch() {
  expect(requests.some((call) => call.method !== 'GET')).toBe(false);
  expect(requests.some((call) => /translation/.test(call.path))).toBe(false);
}
beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  requests = [];
  scroll = vi.fn();
  vi.stubGlobal(
    'IntersectionObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: scroll });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? 'GET';
      requests.push({ path, method });
      if (method !== 'GET') throw Error('Automatic mutation forbidden');
      if (path.endsWith('/llm/context')) {
        if (context.disclosure?.provider !== 'OpenRouter') throw Error('Expected free test fixture');
        const { sentData: _sent, localRetention: _local, ...disclosure } = context.disclosure;
        void _sent;
        void _local;
        return json({
          ...binding,
          enabled: true,
          policyVersion: context.policyVersion,
          summaryResultRead: true,
          disclosure,
        });
      }
      if (path.endsWith('/llm/summary')) return json(recovered);
      return json({ errorCode: 'LLM_UNAVAILABLE' }, 503);
    }),
  );
});
afterEach(() => {
  if (originalScroll) Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', originalScroll);
  else Reflect.deleteProperty(HTMLElement.prototype, 'scrollIntoView');
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  transitionScanSession(null, new QueryClient(), true);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

it('category allowlist and links are fixed local sections, with no usable anchor without a reveal handler', () => {
  expect(reportSourceTargets).toEqual({
    all: 'scan-a1-findings',
    vuln: 'scan-report-vulnerabilities',
    secret: 'scan-report-secrets',
    config: 'scan-report-config',
  });
  for (const value of ['__proto__', 'constructor', 'https://unsafe.invalid', '#scan-report-secrets', null, 1])
    expect(isReportSourceCategory(value)).toBe(false);
  for (const value of ['all', 'vuln', 'secret', 'config']) expect(isReportSourceCategory(value)).toBe(true);
  const navigate = vi.fn(() => true);
  const view = render(<ReportSourceLink category="vuln" />);
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  view.rerender(<ReportSourceLink category="vuln" onNavigate={navigate} disabled />);
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(navigate).not.toHaveBeenCalled();
  assertNoDispatch();
});

it.each([
  {
    from: 'secret',
    category: 'vuln',
    value: 'cve',
    label: 'Уязвимости пакетов',
    id: 'scan-report-vulnerabilities-heading',
  },
  {
    from: 'cve',
    category: 'secret',
    value: 'secret',
    label: 'Возможные секреты',
    id: 'scan-report-secrets-heading',
  },
])(
  'recovered AI citation reveals hidden $category section THEN focuses its real canonical heading without auto POST/translation',
  async (test) => {
    mount();
    const sources = await explanation();
    fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
      target: { value: test.from },
    });
    const heading = document.getElementById(test.id)!;
    expect(heading).not.toBeVisible();
    const link = within(sources).getByRole('link', { name: `Открыть раздел «${test.label}»` });
    expect(link).toHaveAttribute('href', `#${reportSourceTargets[test.category as 'secret' | 'vuln']}`);
    expect(sources).toHaveTextContent('Переход к разделу, не к точной находке');
    expect(sources.querySelector('details')).toBeNull();
    fireEvent.click(link);
    await waitFor(() => expect(heading).toHaveFocus());
    expect(heading).toBeVisible();
    expect(screen.getByRole('combobox', { name: 'Показать находки' })).toHaveValue(test.value);
    expect(scroll).toHaveBeenCalled();
    expect(document.querySelectorAll('.scan-vuln-row details[open]')).toHaveLength(0);
    assertNoDispatch();
  },
);

it('configuration citation resets the category and focuses the real configuration heading, not AI duplicate details', async () => {
  mount();
  const sources = await explanation();
  fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
    target: { value: 'secret' },
  });
  fireEvent.click(within(sources).getByRole('link', { name: 'Открыть раздел «Настройки образа»' }));
  await waitFor(() => expect(document.getElementById('scan-report-config-heading')).toHaveFocus());
  expect(screen.getByRole('combobox', { name: 'Показать находки' })).toHaveValue('all');
  expect(document.getElementById('scan-report-config-heading')).toBeVisible();
  assertNoDispatch();
});

it('full-report source link resets a hidden category and focuses findings, not an exact off-page finding', async () => {
  mount();
  await explanation();
  fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
    target: { value: 'secret' },
  });
  fireEvent.click(screen.getByRole('link', { name: 'Полный отчёт сканеров · находки и исправления' }));
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Находки и исправления' })).toHaveFocus());
  expect(screen.getByRole('combobox', { name: 'Показать находки' })).toHaveValue('all');
  expect(document.getElementById('scan-report-vulnerabilities-heading')).toBeVisible();
  assertNoDispatch();
});

it.each(['snapshot', 'session'] as const)(
  'click-time %s replacement fences an already rendered citation before category change/focus',
  async (change) => {
    const view = mount();
    const sources = await explanation();
    fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
      target: { value: 'secret' },
    });
    const select = screen.getByRole('combobox', { name: 'Показать находки' });
    select.focus();
    const heading = document.getElementById('scan-report-vulnerabilities-heading')!;
    const link = within(sources).getByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' });
    link.addEventListener(
      'click',
      () => {
        if (change === 'session') transitionScanSession('another-navigation-owner', view.client, true);
        else
          view.client.setQueryData([...view.scope, 'scan', binding.scanId], {
            ...completed,
            updatedAt: '2026-11-04T13:43:00.000Z',
          });
      },
      { once: true },
    );
    fireEvent.click(link);
    expect(heading).not.toHaveFocus();
    expect(select).toHaveValue('secret');
    expect(scroll).not.toHaveBeenCalled();
    assertNoDispatch();
  },
);

it('query error retaining identical data before the old link handler cannot change category or focus', async () => {
  const view = mount();
  const sources = await explanation();
  fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
    target: { value: 'secret' },
  });
  const select = screen.getByRole('combobox', { name: 'Показать находки' });
  select.focus();
  const heading = document.getElementById('scan-report-vulnerabilities-heading')!;
  const focus = vi.spyOn(heading, 'focus');
  const link = within(sources).getByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' });
  const queryKey = [...view.scope, 'scan', binding.scanId];
  const query = view.client.getQueryCache().find({ queryKey, exact: true })!;
  const identicalData = query.state.data;
  expect(query.state.status).toBe('success');
  expect(heading).not.toBeVisible();
  let oldRenderedLinkObserved = false;
  link.addEventListener(
    'click',
    () => {
      // The native target listener runs before React's delegated onClick and observer rerender.
      query.setState({
        status: 'error',
        error: new ScanHttpError(503, 'SCANNER_UNAVAILABLE'),
        fetchStatus: 'idle',
      });
      oldRenderedLinkObserved =
        query.state.status === 'error' &&
        query.state.data === identicalData &&
        link.isConnected &&
        (select as HTMLSelectElement).value === 'secret' &&
        !select.matches(':disabled');
    },
    { once: true },
  );
  fireEvent.click(link);
  expect(oldRenderedLinkObserved).toBe(true);
  expect(view.client.getQueryState(queryKey)?.data).toBe(identicalData);
  expect(select).toHaveValue('secret');
  expect(focus).not.toHaveBeenCalled();
  expect(heading).not.toHaveFocus();
  expect(scroll).not.toHaveBeenCalled();
  assertNoDispatch();
});

it('query error retaining identical data after category commit fences the pending passive focus effect', async () => {
  let beforeFocus: (() => void) | undefined;
  const view = mount(() => beforeFocus?.());
  const sources = await explanation();
  fireEvent.change(screen.getByRole('combobox', { name: 'Показать находки' }), {
    target: { value: 'secret' },
  });
  const select = screen.getByRole('combobox', { name: 'Показать находки' });
  select.focus();
  const heading = document.getElementById('scan-report-vulnerabilities-heading')!;
  const focus = vi.spyOn(heading, 'focus');
  const queryKey = [...view.scope, 'scan', binding.scanId];
  const query = view.client.getQueryCache().find({ queryKey, exact: true })!;
  const identicalData = query.state.data;
  expect(query.state.status).toBe('success');
  let admittedCommitObserved = false;
  beforeFocus = () => {
    // Profiler fires during commit, after category reveal but before passive navigation focus.
    if ((select as HTMLSelectElement).value !== 'cve') return;
    beforeFocus = undefined;
    admittedCommitObserved =
      query.state.status === 'success' &&
      query.state.data === identicalData &&
      heading.isConnected &&
      !heading.closest('[hidden]') &&
      document.activeElement === select;
    query.setState({
      status: 'error',
      error: new ScanHttpError(503, 'SCANNER_UNAVAILABLE'),
      fetchStatus: 'idle',
    });
  };
  fireEvent.click(within(sources).getByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' }));
  expect(admittedCommitObserved).toBe(true);
  expect(query.state.status).toBe('error');
  expect(query.state.data).toBe(identicalData);
  expect(select).toHaveValue('cve');
  expect(focus).not.toHaveBeenCalled();
  expect(heading).not.toHaveFocus();
  expect(scroll).not.toHaveBeenCalled();
  assertNoDispatch();
});

it('recoverable stale status removes AI navigation and leaves retained scanner controls disabled', async () => {
  const view = mount();
  await explanation();
  vi.mocked(view.transport.get).mockRejectedValueOnce(new ScanHttpError(503, 'SCANNER_UNAVAILABLE'));
  await act(async () => {
    await view.client.invalidateQueries({ queryKey: [...view.scope, 'scan', binding.scanId] });
  });
  await waitFor(() =>
    expect(view.client.getQueryState([...view.scope, 'scan', binding.scanId])?.status).toBe('error'),
  );
  expect(screen.queryByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' })).not.toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Показать находки' })).toBeDisabled();
  expect(
    screen
      .getAllByRole('alert')
      .some((alert) => /последн|устар|не удалось обнов|актуальност/i.test(alert.textContent ?? '')),
  ).toBe(true);
  assertNoDispatch();
});
