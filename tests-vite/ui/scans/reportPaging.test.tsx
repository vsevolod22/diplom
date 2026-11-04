import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render as renderUi, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CursorReportPager } from '@/pages/scans/CursorReportPager';
import { fingerprintReportRows } from '@/pages/scans/reportRowFingerprint';
import type { PageDescription } from '@/pages/scans/CursorReportPager';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { LiveScanContext } from '@/features/scans/liveScanContext';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import type { ReportKind, ReportPages } from '@/shared/api/scans/reportView';
import type {
  ScanResults,
  ScanSbom,
  ScanStatus,
  ScanTransport,
  ScanVuln,
  VulnFinding,
} from '@/shared/api/scans/scanTransport';

vi.mock('@/features/scans/ScanSummaryPanel', () => ({
  ScanSummaryPanel: () => <p>Отдельная панель сводки</p>,
}));
class Observer {
  observe() {}
  unobserve() {}
  disconnect() {}
}
let queryClient: QueryClient;
beforeEach(() => {
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  vi.stubGlobal('IntersectionObserver', Observer);
});
function render(ui: ReactNode) {
  const view = renderUi(ui, { wrapper: ({ children }) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider> });
  // Integration scenarios inspect the inventory: take the same explicit disclosure action as a user.
  const inventory = screen.queryByLabelText('Пакеты SBOM');
  if (inventory instanceof HTMLDetailsElement && !inventory.open)
    fireEvent.click(within(inventory).getByText(/^Состав образа · найти пакет и его версию/, { selector: 'summary' }));
  return view;
}
afterEach(() => {
  cleanup();
  queryClient.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}
type TestPage = {
  rows: string[];
  next: string | null;
  version?: string;
  total?: number | null;
  checked?: boolean;
};
const describe = (data: TestPage): PageDescription => ({
  checked: data.checked ?? true,
  identity: data.version ?? 'report-1',
  rowIds: data.rows,
  rowFingerprint: fingerprintReportRows(data.rows),
  total: data.total === undefined ? 3 : data.total,
  nextCursor: data.next,
});
const rows = (page: TestPage) => (
  <ul>
    {page.rows.map((row) => (
      <li key={row}>{row}</li>
    ))}
  </ul>
);
function pager(
  load: (cursor: string | undefined, signal: AbortSignal) => Promise<TestPage>,
  reportKey = 'alice:1:scan:report',
  queryKey: readonly unknown[] = ['live-scans', 1, 'alice', 'report-page', 'scan', 'vuln', null, reportKey],
) {
  return (
    <CursorReportPager
      label="CVE"
      reportKey={reportKey}
      queryKey={queryKey}
      enabled
      waiting="Ожидание"
      load={load}
      describe={describe}
    >
      {rows}
    </CursorReportPager>
  );
}
it('atomically confirms three sequential pages, repeats stored cursors on back, never prefetches', async () => {
  const pages = [
    { rows: ['first'], next: 'opaque-a' },
    { rows: ['second'], next: 'opaque-b' },
    { rows: ['third'], next: null },
  ];
  const load = vi.fn(
    async (cursor?: string) => pages[cursor === 'opaque-b' ? 2 : cursor === 'opaque-a' ? 1 : 0],
  );
  render(pager(load));
  await screen.findByText('Строки 1–1');
  expect(load).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Назад · CVE' }).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('Строки 2–2');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('Строки 3–3');
  expect(screen.getByRole('button', { name: 'Далее · CVE' }).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
  await screen.findByText('second');
  await screen.findByText('Страница 2');
  fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
  await screen.findByText('first');
  expect(load.mock.calls.map((call) => call[0])).toEqual([
    undefined,
    'opaque-a',
    'opaque-b',
    'opaque-a',
    undefined,
  ]);
  expect(screen.queryByText(/из 3 страниц/)).toBeNull();
});
it('uses the existing client but never reuses even freshly primed pages or retries/refetches implicitly', async () => {
  const key = ['live-scans', 1, 'alice', 'report-page', 'scan', 'vuln', null, 'report-1'];
  queryClient.setQueryDefaults(['live-scans'], { staleTime: Infinity, gcTime: Infinity, retry: 3 });
  queryClient.setQueryData([...key, null], { rows: ['cached-private'], next: null, total: 1 });
  const fetchQuery = vi.spyOn(queryClient, 'fetchQuery');
  const load = vi.fn().mockResolvedValueOnce({ rows: ['first'], next: 'next', total: 2 })
    .mockResolvedValueOnce({ rows: ['second'], next: null, total: 2 })
    .mockResolvedValueOnce({ rows: ['changed-first'], next: 'next', total: 2 });
  render(pager(load, 'report-1', key));
  await screen.findByText('first');
  expect(screen.queryByText('cached-private')).toBeNull();
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('second');
  fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
  await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
  expect(fetchQuery.mock.calls.map(([options]) => options.queryKey)).toEqual([
    [...key, null], [...key, 'next'], [...key, null],
  ]);
  for (const [options] of fetchQuery.mock.calls) {
    expect(options).toMatchObject({ staleTime: 0, gcTime: 0, retry: false, networkMode: 'always' });
  }
  await act(async () => { await queryClient.invalidateQueries(); });
  fireEvent.focus(window);
  fireEvent.online(window);
  expect(load).toHaveBeenCalledTimes(3);
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
});

it.each(['unmount', 'auth'] as const)('cancels the QueryClient request on %s, ignores a transport that resolves after abort, and removes private cache data', async (reason) => {
  const slow = deferred<TestPage>();
  const load = vi.fn<(cursor: string | undefined, signal: AbortSignal) => Promise<TestPage>>().mockReturnValue(slow.promise);
  const cancel = vi.spyOn(queryClient, 'cancelQueries');
  const view = render(pager(load));
  const signal = load.mock.calls[0][1];
  const active = queryClient.getQueryCache().getAll();
  expect(active).toHaveLength(1);
  expect(active[0].state.fetchStatus).toBe('fetching');
  if (reason === 'unmount') view.unmount();
  else await act(async () => { transitionScanSession(null, queryClient, true); });
  expect(cancel).toHaveBeenCalledWith(reason === 'unmount'
    ? { queryKey: active[0].queryKey, exact: true }
    : { queryKey: ['live-scans'] });
  expect(signal.aborted).toBe(true);
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
  await act(async () => { slow.resolve({ rows: ['late-private'], next: null, total: 1 }); });
  expect(screen.queryByText('late-private')).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
  expect(load).toHaveBeenCalledTimes(1);
});

it('cancels a changed normalized query even with the same report key and ignores a late aborted rejection', async () => {
  const slow = deferred<TestPage>();
  const load = vi.fn().mockImplementationOnce(() => slow.promise)
    .mockResolvedValueOnce({ rows: ['filtered-first'], next: null, total: 1 });
  const key = ['live-scans', 1, 'alice', 'report-page', 'scan', 'vuln'];
  const cancel = vi.spyOn(queryClient, 'cancelQueries');
  const view = render(pager(load, 'report-1', [...key, { severity: null }, 'identity']));
  const signal = load.mock.calls[0][1] as AbortSignal;
  const oldKey = queryClient.getQueryCache().getAll()[0].queryKey;
  view.rerender(pager(load, 'report-1', [...key, { severity: ['HIGH'] }, 'identity']));
  expect(signal.aborted).toBe(true);
  expect(cancel).toHaveBeenCalledWith({ queryKey: oldKey, exact: true });
  await screen.findByText('filtered-first');
  await act(async () => { slow.reject(new Error('ignored aborted transport')); });
  expect(screen.getByText('filtered-first')).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(load.mock.calls.map(call => call[0])).toEqual([undefined, undefined]);
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
});

it('a failed query does not inherit client retries or refetch on invalidation', async () => {
  queryClient.setQueryDefaults(['live-scans'], { retry: 3, retryDelay: 0 });
  const load = vi.fn().mockRejectedValue(new Error('offline'));
  render(pager(load));
  await screen.findByRole('alert');
  await act(async () => { await queryClient.invalidateQueries(); });
  expect(load).toHaveBeenCalledTimes(1);
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
});

it('keeps confirmed rows/range during pending and errors; duplicate click cannot double request; retry targets failed cursor', async () => {
  const slow = deferred<TestPage>();
  const load = vi
    .fn()
    .mockResolvedValueOnce({ rows: ['first'], next: 'next' })
    .mockImplementationOnce(() => slow.promise)
    .mockRejectedValueOnce(new Error('offline'))
    .mockResolvedValueOnce({ rows: ['third'], next: null });
  render(pager(load));
  await screen.findByText('first');
  const next = screen.getByRole('button', { name: 'Далее · CVE' });
  fireEvent.click(next);
  fireEvent.click(next);
  expect(load).toHaveBeenCalledTimes(2);
  expect(next.hasAttribute('disabled')).toBe(true);
  expect(screen.getByText('Строки 1–1')).toBeTruthy();
  expect(screen.getByText('first')).toBeTruthy();
  await act(async () => slow.resolve({ rows: ['second'], next: 'third' }));
  await screen.findByText('Строки 2–2');
  fireEvent.click(next);
  await screen.findByRole('alert');
  expect(screen.getByText('second')).toBeTruthy();
  expect(screen.getByText('Строки 2–2')).toBeTruthy();
  expect(screen.queryByText('Страница 3')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
  await screen.findByText('third');
  expect(load.mock.calls.map((call) => call[0])).toEqual([undefined, 'next', 'third', 'third']);
});
it.each(['version', 'total'])(
  'clears confirmed rows and cursor stack on %s drift, retry starts first page',
  async (field) => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ rows: ['private-old'], next: 'next' })
      .mockResolvedValueOnce({
        rows: ['untrusted-new'],
        next: null,
        [field]: field === 'version' ? 'report-2' : 20,
      })
      .mockResolvedValueOnce({ rows: ['fresh-first'], next: null, version: 'report-2', total: 1 });
    render(pager(load));
    await screen.findByText('private-old');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
    expect(screen.queryByText('private-old')).toBeNull();
    expect(screen.queryByText('untrusted-new')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
    await screen.findByText('fresh-first');
    expect(load.mock.calls[2][0]).toBeUndefined();
    expect(screen.getByText('Страница 1')).toBeTruthy();
  },
);
it.each([401, 403] as const)(
  'fails closed on access %i rather than retaining confirmed private data',
  async (code) => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ rows: ['private'], next: 'next' })
      .mockRejectedValueOnce(new ScanAccessError(code));
    render(pager(load));
    await screen.findByText('private');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText(/Доступ к отчёту утрачен/);
    expect(screen.queryByText('private')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Повторить загрузку CVE' })).toBeNull();
  },
);
it.each([
  { rows: ['second'], next: 'next' },
  { rows: ['first'], next: null },
  { rows: ['duplicate', 'duplicate'], next: null },
  { rows: [], next: 'more' },
])('rejects looping cursor/overlapping row IDs/duplicate IDs/empty continuations: %j', async (invalid) => {
  const load = vi
    .fn()
    .mockResolvedValueOnce({ rows: ['first'], next: 'next' })
    .mockResolvedValueOnce(invalid);
  render(pager(load));
  await screen.findByText('first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByRole('alert');
  expect(screen.getByText('Строки 1–1')).toBeTruthy();
  expect(screen.queryByText('Страница 2')).toBeNull();
});
it('aborts pending work on subject/session/scan/report key change and ignores a late response', async () => {
  const slow = deferred<TestPage>();
  const load = vi
    .fn()
    .mockResolvedValueOnce({ rows: ['alice-first'], next: 'next' })
    .mockImplementationOnce(() => slow.promise)
    .mockResolvedValueOnce({ rows: ['bob-first'], next: null, total: 1 });
  const view = render(pager(load));
  await screen.findByText('alice-first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  const oldSignal = load.mock.calls[1][1] as AbortSignal;
  view.rerender(pager(load, 'bob:2:other-scan:new-report'));
  expect(oldSignal.aborted).toBe(true);
  expect(screen.queryByText('alice-first')).toBeNull();
  await screen.findByText('bob-first');
  await act(async () => slow.resolve({ rows: ['alice-late'], next: null }));
  expect(screen.queryByText('alice-late')).toBeNull();
  expect(screen.getByText('Страница 1')).toBeTruthy();
  expect(load.mock.calls[2][0]).toBeUndefined();
});

const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const stamp = '2026-10-08T00:00:00.000Z';
const reportTotal = 26;
function reportPage<K extends ReportKind>(
  kind: K,
  offset = 0,
  returnedCount = offset ? 1 : 25,
  totalCount: number | null = reportTotal,
): ReportPages[K] {
  const common = { version: 1 as const, limit: 25 as const, offset, returnedCount, totalCount, matchedCount: totalCount };
  const pages: ReportPages = {
    vuln: { ...common, sort: 'severity:desc', filters: { severity: null } },
    sbom: { ...common, sort: 'name:asc', filters: { ecosystem: null, name: null } },
    secret: { ...common, sort: 'ruleId:asc', filters: { ruleId: null, linePresence: null } },
  };
  return pages[kind];
}
// Live report-v1 continuations require a full default-limit page before the terminal row.
function firstPageRows<T>(first: T, filler: (index: number) => T): T[] {
  return [first, ...Array.from({ length: 24 }, (_, index) => filler(index + 1))];
}
const status: ScanStatus = {
  scanId: '00000000-0000-4000-8000-000000000039',
  state: 'completed',
  digest,
  imageReference: image,
  platform: 'linux/amd64',
  checks: ['secret', 'sbom', 'vuln'],
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: reportTotal },
    sbom: { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: reportTotal, checkedAt: stamp },
    vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: reportTotal, checkedAt: stamp },
  },
};
function fixtureTransport(): ScanTransport {
  return {
    ...unavailableScanTransport,
    kind: 'live',
    capabilities: { list: true, create: false, cancel: false, events: false },
    get: vi.fn(async () => status),
    vuln: vi.fn(
      async (_, cursor): Promise<ScanVuln> => ({
        outcome: 'checked',
        coverage: 'image',
        image,
        platform: 'linux/amd64',
        findingCount: reportTotal,
        checkedAt: stamp,
        scannerVersion: '0.69.3',
        nextCursor: cursor ? null : 'paging:25/+==',
        page: reportPage('vuln', cursor ? 25 : 0),
        findings: [
          {
            findingId: cursor ? 'vuln-second' : 'vuln-first',
            cveId: cursor ? 'CVE-2026-1235' : 'CVE-2026-1234',
            severity: 'CRITICAL',
            ecosystem: 'apk',
            packageName: cursor ? 'second-package' : 'first-package',
            installedVersion: '1.0',
            fixedVersion: null,
          },
          ...(!cursor ? Array.from({ length: 24 }, (_, index): VulnFinding => ({
            findingId: `vuln-filler-${index}`, cveId: `CVE-2026-${2000 + index}`, severity: 'HIGH',
            ecosystem: 'apk', packageName: `filler-package-${index}`, installedVersion: '1.0', fixedVersion: null,
          })) : []),
        ],
      }),
    ),
    sbom: vi.fn(
      async (_, cursor): Promise<ScanSbom> => ({
        outcome: 'checked',
        coverage: 'image',
        image,
        platform: 'linux/amd64',
        componentCount: reportTotal,
        checkedAt: stamp,
        scannerVersion: '0.69.3',
        os: { name: 'alpine', version: '3.21' },
        nextCursor: cursor ? null : 'paging:25/+==',
        page: reportPage('sbom', cursor ? 25 : 0),
        components: cursor ? [{ name: 'sbom-second', ecosystem: 'apk', version: '1.0' }] : firstPageRows(
          { name: 'sbom-first', ecosystem: 'apk' as const, version: '1.0' },
          index => ({ name: `sbom-first-${String(index).padStart(2, '0')}`, ecosystem: 'apk', version: '1.0' }),
        ),
      }),
    ),
    results: vi.fn(
      async (_, cursor): Promise<ScanResults> => ({
        findings: [
          {
            findingId: cursor ? 'secret-second' : 'secret-first',
            category: 'secret',
            ruleId: 'redacted-rule',
            severity: 'unknown',
            line: null,
          },
          ...(!cursor ? Array.from({ length: 24 }, (_, index) => ({
            findingId: `secret-filler-${index}`, category: 'secret', ruleId: 'redacted-rule', severity: 'unknown', line: null,
          })) : []),
        ],
        coverage: [{ check: 'Secrets', status: 'checked', findingCount: reportTotal }],
        nextCursor: cursor ? null : 'paging:25/+==',
        page: reportPage('secret', cursor ? 25 : 0),
      }),
    ),
  };
}
function sections(
  transport: ScanTransport,
  snapshot = status,
  scope: readonly (string | number)[] = ['live-scans', 1, 'alice'],
  filter = 'all',
) {
  return (
    <ScanReportSections
      status={snapshot}
      transport={transport}
      scope={scope}
      demo={false}
      filter={filter}
      onResetFilter={() => {}}
    />
  );
}
function batch4ControlTransport() {
  const transport = fixtureTransport();
  const { vuln, sbom, results } = transport;
  transport.vuln = vi.fn(async (...args: Parameters<ScanTransport['vuln']>): Promise<ScanVuln> => {
    const page = await vuln(...args);
    return { ...page, page: { ...page.page!, sort: args[3]?.sort ?? 'severity:desc', filters: { severity: args[3]?.severity ?? null } } };
  });
  transport.results = vi.fn(async (...args: Parameters<ScanTransport['results']>): Promise<ScanResults> => {
    const page = await results(...args);
    return { ...page, page: { ...page.page!, sort: args[3]?.sort ?? 'ruleId:asc', filters: { ruleId: args[3]?.ruleId ?? null, linePresence: args[3]?.linePresence ?? null } } };
  });
  transport.sbom = vi.fn(async (...args: Parameters<ScanTransport['sbom']>): Promise<ScanSbom> => {
    const page = await sbom(...args);
    if (page.outcome !== 'checked') throw new Error('Expected checked SBOM fixture');
    return { ...page, ...(args[3]?.name ? { components: page.components.map((row, index) => ({ ...row, name: `${args[3]!.name}-${index}` })) } : {}),
      page: { ...page.page!, sort: args[3]?.sort ?? 'name:asc', filters: { ecosystem: args[3]?.ecosystem ?? null, name: args[3]?.name ?? null } } };
  });
  return transport;
}

async function openBatch4Controls(user: ReturnType<typeof userEvent.setup>, label: 'CVE' | 'Secrets' | 'SBOM') {
  const pageLabel = label === 'CVE' ? 'Уязвимости' : label === 'Secrets' ? 'Возможные секреты' : 'Пакеты';
  const region = label === 'SBOM' ? screen.getByLabelText('Пакеты SBOM')
    : screen.getByRole('region', { name: label === 'CVE' ? 'Результаты Уязвимости' : 'Возможные секреты' });
  if (region instanceof HTMLDetailsElement && !region.open)
    await user.click(within(region).getByText(/^Состав образа · найти пакет и его версию/, { selector: 'summary' }));
  const summary = within(region).getByText(`Фильтры и сортировка · ${pageLabel}`, { selector: 'summary' });
  if (!summary.closest('details')?.open) await user.click(summary);
  return { region, pageLabel };
}

it.each(['CVE', 'Secrets', 'SBOM'] as const)('batch4 regression: %s sort query reset keeps the exact focused control while resetting pager to first cursor', async label => {
  const user = userEvent.setup();
  const transport = batch4ControlTransport();
  render(sections(transport));
  const { region, pageLabel } = await openBatch4Controls(user, label);
  const load = label === 'CVE' ? transport.vuln : label === 'Secrets' ? transport.results : transport.sbom;
  await within(region).findByText('Страница 1');
  await user.click(within(region).getByRole('button', { name: `Далее · ${pageLabel}` }));
  await within(region).findByText('Страница 2');
  const select = within(region).getByRole('combobox', { name: `Сортировка · ${pageLabel}` });
  await user.selectOptions(select, label === 'CVE' ? 'severity:asc' : label === 'Secrets' ? 'ruleId:desc' : 'name:desc');
  expect(within(region).getByRole('combobox', { name: `Сортировка · ${pageLabel}` })).toBe(select);
  expect(document.activeElement).toBe(select);
  await within(region).findByText('Страница 1');
  expect(vi.mocked(load).mock.calls.map(call => call[1])).toEqual([undefined, 'paging:25/+==', undefined]);
  expect(within(region).getByRole('button', { name: `Назад · ${pageLabel}` })).toBeDisabled();
  expect(queryClient.getQueryCache().getAll().some(query => query.queryKey.includes('report-page'))).toBe(false);
});

it('batch4 regression: SBOM unapplied draft survives sort/query reset without implicit apply, but not owner-scope replacement', async () => {
  const user = userEvent.setup();
  const transport = batch4ControlTransport();
  const view = render(sections(transport));
  const { region } = await openBatch4Controls(user, 'SBOM');
  await within(region).findByText('Страница 1');
  const input = within(region).getByRole('textbox', { name: 'Название пакета' });
  await user.type(input, 'unapplied-package');
  expect(transport.sbom).toHaveBeenCalledTimes(1);
  const select = within(region).getByRole('combobox', { name: 'Сортировка · Пакеты' });
  await user.selectOptions(select, 'name:desc');
  await waitFor(() => expect(transport.sbom).toHaveBeenCalledTimes(2));
  await within(region).findByText('Страница 1');
  expect(within(region).getByRole('textbox', { name: 'Название пакета' })).toBe(input);
  expect(input).toHaveValue('unapplied-package');
  expect(document.activeElement).toBe(select);
  expect(vi.mocked(transport.sbom).mock.calls[1][1]).toBeUndefined();
  expect(vi.mocked(transport.sbom).mock.calls[1][3]).toMatchObject({ sort: 'name:desc', name: null });
  await user.click(within(region).getByRole('button', { name: 'Найти пакет' }));
  await waitFor(() => expect(transport.sbom).toHaveBeenCalledTimes(3));
  expect(vi.mocked(transport.sbom).mock.calls[2][3]).toMatchObject({ sort: 'name:desc', name: 'unapplied-package' });
  await within(region).findByText('Страница 1');
  view.rerender(sections(transport, status, ['live-scans', 2, 'other-owner']));
  const { region: freshRegion } = await openBatch4Controls(user, 'SBOM');
  const fresh = within(freshRegion).getByRole('textbox', { name: 'Название пакета' });
  expect(fresh).not.toBe(input); expect(fresh).toHaveValue('');
});

it('CVE/Secrets/SBOM paginate independently and category visibility preserves each cursor without extra GET', async () => {
  const transport = fixtureTransport();
  const fetchQuery = vi.spyOn(queryClient, 'fetchQuery');
  const view = render(sections(transport));
  await screen.findByText('CVE-2026-1234');
  await screen.findByText('ID: secret-first');
  await screen.findByText('sbom-first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
  await screen.findByText('CVE-2026-1235');
  expect(
    within(screen.getByRole('region', { name: 'Возможные секреты' })).getByText('Страница 1'),
  ).toBeTruthy();
  expect(within(screen.getByLabelText('Пакеты SBOM')).getByText('Страница 1')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Возможные секреты' }));
  await screen.findByText('ID: secret-second');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Пакеты' }));
  await screen.findByText('sbom-second');
  view.rerender(sections(transport, status, ['live-scans', 1, 'alice'], 'secret'));
  expect(screen.queryByRole('region', { name: 'Результаты Уязвимости' })).toBeNull();
  view.rerender(sections(transport));
  expect(screen.getByText('CVE-2026-1235')).toBeTruthy();
  expect(transport.vuln).toHaveBeenCalledTimes(2);
  for (const label of ['Уязвимости', 'Возможные секреты', 'Пакеты']) {
    expect(screen.getByText(`Совпадений во всём отчёте ${label}: ${reportTotal}`)).toBeTruthy();
    expect(screen.queryByText(`Полный итог ${label}: ${reportTotal}`)).toBeNull();
  }
  for (const method of [transport.vuln, transport.results, transport.sbom]) {
    expect(vi.mocked(method).mock.calls.map(call => call[1])).toEqual([undefined, 'paging:25/+==']);
    expect(vi.mocked(method).mock.calls[0][3]).toMatchObject({ view: 'report-v1', limit: 25 });
  }
  const identity = JSON.stringify([false, ['live-scans', 1, 'alice'], status.scanId, status.state,
    status.digest, status.platform, status.imageReference, status.updatedAt, status.checks, status.perCheck]);
  const normalized = {
    vuln: { view: 'report-v1', limit: 25, sort: 'severity:desc', filters: { severity: null } },
    sbom: { view: 'report-v1', limit: 25, sort: 'name:asc', filters: { ecosystem: null, name: null } },
    secret: { view: 'report-v1', limit: 25, sort: 'ruleId:asc', filters: { ruleId: null, linePresence: null } },
  };
  for (const dataset of ['vuln', 'secret', 'sbom'] as const) {
    expect(fetchQuery.mock.calls.map(([options]) => options.queryKey).filter(key => key[5] === dataset)).toEqual([
      ...[null, 'paging:25/+=='].map(cursor => ['live-scans', 1, 'alice', 'report-page', status.scanId,
        dataset, normalized[dataset], `${identity}:${dataset}`, cursor]),
    ]);
  }
  expect(queryClient.getQueryCache().getAll()).toEqual([]);
});
it.each(['digest', 'platform', 'checkedAt', 'scope', 'scanId', 'count'])(
  'actual report sections reset paging immediately on %s change',
  async (field) => {
    const transport = fixtureTransport();
    const fetchQuery = vi.spyOn(queryClient, 'fetchQuery');
    const view = render(sections(transport));
    await screen.findByText('CVE-2026-1234');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
    await screen.findByText('CVE-2026-1235');
    const previousKey = fetchQuery.mock.calls.find(([options]) => options.queryKey[5] === 'vuln')![0].queryKey;
    const slow = deferred<ScanVuln>();
    vi.mocked(transport.vuln).mockImplementationOnce(() => slow.promise);
    const updated = {
      ...status,
      ...(field === 'digest'
        ? {
            digest: `sha256:${'b'.repeat(64)}`,
            imageReference: `registry-1.docker.io/library/alpine@sha256:${'b'.repeat(64)}`,
          }
        : field === 'platform'
          ? { platform: 'linux/arm64' }
          : field === 'scanId'
            ? { scanId: 'other' }
            : {}),
      perCheck:
        field === 'checkedAt' || field === 'count'
          ? {
              ...status.perCheck,
              vuln: {
                ...status.perCheck!.vuln!,
                ...(field === 'count' ? { findingCount: 9 } : { checkedAt: 'new' }),
              },
            }
          : status.perCheck,
    };
    view.rerender(
      sections(transport, updated, field === 'scope' ? ['live-scans', 2, 'bob'] : ['live-scans', 1, 'alice']),
    );
    expect(screen.queryByText('CVE-2026-1235')).toBeNull();
    expect(vi.mocked(transport.vuln).mock.calls[2][1]).toBeUndefined();
    const currentKey = queryClient.getQueryCache().getAll().find(query => query.state.fetchStatus === 'fetching' && query.queryKey[5] === 'vuln')!.queryKey;
    expect(currentKey.slice(0, 3)).toEqual(field === 'scope' ? ['live-scans', 2, 'bob'] : ['live-scans', 1, 'alice']);
    expect(currentKey[4]).toBe(updated.scanId);
    expect(currentKey[5]).toBe('vuln');
    expect(currentKey[6]).toEqual(previousKey[6]);
    expect(currentKey[7]).not.toEqual(previousKey[7]);
    expect(currentKey[8]).toBeNull();
  },
);
it.each(['image', 'platform', 'checkedAt', 'findingCount'])(
  'rejects CVE %s mismatch against confirmed status',
  async (field) => {
    const transport = fixtureTransport();
    const load = transport.vuln;
    transport.vuln = async (...args) => {
      const page = await load(...args);
      return { ...page, [field]: field === 'findingCount' ? 99 : 'wrong' } as ScanVuln;
    };
    render(sections(transport));
    const cve = within(screen.getByRole('region', { name: 'Результаты Уязвимости' }));
    await cve.findByText(/Не удалось подтвердить, что ответ относится к текущему отчёту/);
    expect(cve.queryByText('CVE-2026-1234')).toBeNull();
    expect(cve.queryByText(`Полный итог Уязвимости: ${reportTotal}`)).toBeNull();
    expect(cve.queryByRole('navigation')).toBeNull();
  },
);
it('failed/unsupported/unknown counts stay unknown, checked zero is distinct', async () => {
  const transport = fixtureTransport();
  transport.vuln = async () => ({
    outcome: 'unsupported',
    coverage: 'image',
    reason: 'OS_UNKNOWN',
    findings: [],
    nextCursor: null,
    page: reportPage('vuln', 0, 0, null),
  });
  transport.sbom = async () => ({
    outcome: 'failed',
    coverage: 'image',
    errorCode: 'SCAN_FAILED',
    components: [],
    nextCursor: null,
    page: reportPage('sbom', 0, 0, null),
  });
  render(sections(transport));
  await screen.findByText('Проверка уязвимостей не поддерживается');
  await screen.findByText(/Состав образа не проверен/);
  expect(screen.queryByText(/(Совпадений во всём отчёте|Полный итог) (CVE|SBOM): 0/)).toBeNull();
  expect(screen.getByText('Число Уязвимости неизвестно до подтверждения выполненной проверки.')).toBeTruthy();
  expect(screen.getByText('Число Пакеты неизвестно до подтверждения выполненной проверки.')).toBeTruthy();
  cleanup();
  const zero = fixtureTransport();
  zero.vuln = async () => ({
    outcome: 'checked',
    coverage: 'image',
    image,
    platform: 'linux/amd64',
    findingCount: 0,
    findings: [],
    nextCursor: null,
    scannerVersion: '0.69.3',
    checkedAt: stamp,
    page: reportPage('vuln', 0, 0, 0),
  });
  render(
    sections(zero, {
      ...status,
      perCheck: { ...status.perCheck, vuln: { ...status.perCheck!.vuln!, findingCount: 0 } },
    }),
  );
  await screen.findByText('Совпадений во всём отчёте Уязвимости: 0');
  expect(screen.getByText('Совпадений во всём отчёте Уязвимости: 0')).toBeTruthy();
  expect(screen.getByText(/0 находок в выполненной проверенной области/)).toBeTruthy();
});
it('ScanDetail scope remount aborts a late private page and never stores report rows in QueryCache', async () => {
  const transport = fixtureTransport();
  const slow = deferred<ScanVuln>();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const cancel = vi.spyOn(client, 'cancelQueries');
  const renderPage = (subject: string) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/scans/${status.scanId}`]}>
        <LiveScanContext.Provider value={{ scope: ['live-scans', 1, subject], transport }}>
          <Routes>
            <Route path="/scans/:scanId" element={<ScanDetailPage />} />
          </Routes>
        </LiveScanContext.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  const view = render(renderPage('alice'));
  await screen.findByText('CVE-2026-1234');
  vi.mocked(transport.vuln).mockImplementationOnce(() => slow.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
  const signal = vi.mocked(transport.vuln).mock.calls[1][2]!;
  const oldKey = client.getQueryCache().getAll().find(query => query.queryKey.includes('report-page'))!.queryKey;
  expect(oldKey.slice(0, 6)).toEqual(['live-scans', 1, 'alice', 'report-page', status.scanId, 'vuln']);
  expect(oldKey.at(-1)).toBe('paging:25/+==');
  view.rerender(renderPage('bob'));
  expect(signal.aborted).toBe(true);
  expect(cancel).toHaveBeenCalledWith({ queryKey: oldKey, exact: true });
  expect(client.getQueryState(oldKey)).toBeUndefined();
  expect(screen.queryByText('CVE-2026-1234')).toBeNull();
  await waitFor(() => expect(transport.vuln).toHaveBeenCalledTimes(3));
  expect(
    client
      .getQueryCache()
      .getAll()
      .some((query) => String(JSON.stringify(query.state.data)).includes('vuln-first')),
  ).toBe(false);
  await act(async () =>
    slow.resolve({
      outcome: 'failed',
      coverage: 'image',
      errorCode: 'SCAN_FAILED',
      findings: [],
      nextCursor: null,
    }),
  );
  await screen.findByText('CVE-2026-1234');
  expect(client.getQueryCache().getAll().some(query => query.queryKey.includes('report-page'))).toBe(false);
});

it.each(['Скан недоступен', 'Сессия изменилась: ответ отклонён'])(
  'hides confirmed rows on transport access loss: %s',
  async (message) => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ rows: ['private'], next: 'next' })
      .mockRejectedValueOnce(new Error(message));
    render(pager(load));
    await screen.findByText('private');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText(/Доступ к отчёту утрачен/);
    expect(screen.queryByText('private')).toBeNull();
  },
);
it('rejects changed row identity on a freshly reloaded previous page', async () => {
  const load = vi
    .fn()
    .mockResolvedValueOnce({ rows: ['first'], next: 'next', total: 2 })
    .mockResolvedValueOnce({ rows: ['second'], next: null, total: 2 })
    .mockResolvedValueOnce({ rows: ['changed-first'], next: 'next', total: 2 });
  render(pager(load));
  await screen.findByText('first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('second');
  fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
  await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
  expect(screen.queryByText('second')).toBeNull();
  expect(screen.queryByText('changed-first')).toBeNull();
});
it.each(['row IDs', 'continuation'] as const)(
  'preserves forward fingerprints after Back and resets changed %s on replay',
  async (field) => {
    const first = { rows: ['first'], next: 'next' };
    const second = { rows: ['second'], next: 'last' };
    const load = vi
      .fn()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second)
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(
        field === 'row IDs'
          ? { ...second, rows: ['changed-second'] }
          : { ...second, next: 'changed-continuation' },
      )
      .mockResolvedValueOnce(first);
    render(pager(load));
    await screen.findByText('first');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText('second');
    fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
    await screen.findByText('first');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
    expect(screen.queryByText('first')).toBeNull();
    expect(screen.queryByText('second')).toBeNull();
    expect(screen.queryByText('changed-second')).toBeNull();
    expect(screen.queryByText('Строки 2–2')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
    await screen.findByText('first');
    expect(load.mock.calls.map((call) => call[0])).toEqual([undefined, 'next', undefined, 'next', undefined]);
  },
);
it('accepts unchanged forward replay after Back without counting future fingerprints as earlier rows', async () => {
  const pages = [
    { rows: ['first'], next: 'next' },
    { rows: ['second'], next: 'last' },
    { rows: ['third'], next: null },
  ];
  const load = vi.fn(async (cursor?: string) => pages[cursor === 'last' ? 2 : cursor === 'next' ? 1 : 0]);
  render(pager(load));
  await screen.findByText('first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('second');
  fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE' }));
  await screen.findByText('first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('second');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByText('Строки 3–3');
  expect(screen.queryByRole('alert')).toBeNull();
});
it.each([
  { name: 'premature terminal', rows: ['missing-third'], next: null },
  { name: 'empty terminal with remaining count', rows: [], next: null },
  { name: 'continuation at confirmed total', rows: ['second', 'third'], next: 'extra' },
])('rejects $name and retries that cursor while retaining confirmed rows/range', async (invalid) => {
  const load = vi
    .fn()
    .mockResolvedValueOnce({ rows: ['first'], next: 'next' })
    .mockResolvedValueOnce(invalid)
    .mockResolvedValueOnce({ rows: ['second', 'third'], next: null });
  render(pager(load));
  await screen.findByText('first');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
  await screen.findByRole('alert');
  expect(screen.getByText('first')).toBeTruthy();
  expect(screen.getByText('Строки 1–1')).toBeTruthy();
  expect(screen.getByText('Подтверждённый итог CVE: 3')).toBeTruthy();
  expect(screen.queryByText('Страница 2')).toBeNull();
  expect(screen.queryByText('missing-third')).toBeNull();
  expect(screen.queryByText('second')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
  await screen.findByText('Строки 2–3');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByRole('button', { name: 'Далее · CVE' }).hasAttribute('disabled')).toBe(true);
  expect(load.mock.calls.map((call) => call[0])).toEqual([undefined, 'next', 'next']);
});
it.each([{ rows: ['last'] }, { rows: [] }])(
  'allows unknown-total terminal rows %j without claiming zero',
  async ({ rows: terminalRows }) => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ rows: ['first'], next: 'next', total: null })
      .mockResolvedValueOnce({ rows: terminalRows, next: null, total: null });
    render(pager(load));
    await screen.findByText('first');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE' }));
    await screen.findByText('Страница 2');
    expect(screen.getByText('Итог CVE неизвестен')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByText('Подтверждённый итог CVE: 0')).toBeNull();
  },
);
it('does not impose checked-count completion on nonchecked coverage', async () => {
  const load = vi.fn(async () => ({ rows: [], next: null, checked: false, total: 3 }));
  render(pager(load));
  await waitFor(() => expect(screen.queryByText(/Загружаем CVE/)).toBeNull());
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByText('Число CVE неизвестно до подтверждения выполненной проверки.')).toBeTruthy();
});
function secretPage(scannerVersion: string): ScanResults {
  return {
    findings: [
      {
        findingId: `scanner-${scannerVersion}`,
        ruleId: 'redacted-rule',
        category: 'secret',
        severity: 'unknown',
        line: null,
      },
    ],
    coverage: [{ check: 'Secrets', status: 'checked', findingCount: 1, scannerVersion }],
    nextCursor: null,
    page: reportPage('secret', 0, 1, 1),
  };
}
function secretStatus(scannerVersion?: string): ScanStatus {
  return {
    ...status,
    checks: ['secret'],
    perCheck: { secret: { ...status.perCheck!.secret!, findingCount: 1, scannerVersion } },
  };
}
it('rejects initial Secrets scanner mismatch against confirmed status, retry starts first cursor', async () => {
  const transport = fixtureTransport();
  transport.results = vi
    .fn()
    .mockResolvedValueOnce(secretPage('0.69.2'))
    .mockResolvedValueOnce(secretPage('0.69.3'));
  render(sections(transport, secretStatus('0.69.3')));
  await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
  expect(screen.queryByText('ID: scanner-0.69.2')).toBeNull();
  expect(screen.queryByText('Полный итог Возможные секреты: 1')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Возможные секреты' }));
  await screen.findByText('ID: scanner-0.69.3');
  expect(vi.mocked(transport.results).mock.calls.map((call) => call[1])).toEqual([undefined, undefined]);
});
it('rejects stale Secrets scanner after status-key reset and never republishes old rows', async () => {
  const transport = fixtureTransport();
  transport.results = vi
    .fn()
    .mockResolvedValueOnce(secretPage('0.69.2'))
    .mockResolvedValueOnce(secretPage('0.69.2'))
    .mockResolvedValueOnce(secretPage('0.69.3'));
  const view = render(sections(transport, secretStatus('0.69.2')));
  await screen.findByText('ID: scanner-0.69.2');
  view.rerender(sections(transport, secretStatus('0.69.3')));
  expect(screen.queryByText('ID: scanner-0.69.2')).toBeNull();
  await screen.findByText(/Прежние данные скрыты; повторите загрузку с первой страницы/);
  expect(screen.queryByText('ID: scanner-0.69.2')).toBeNull();
  expect(screen.queryByText('Полный итог Возможные секреты: 1')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Возможные секреты' }));
  await screen.findByText('ID: scanner-0.69.3');
  expect(vi.mocked(transport.results).mock.calls.map((call) => call[1])).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
});
it('does not invent a status scanner version when metadata is absent', async () => {
  const transport = fixtureTransport();
  transport.results = vi.fn(async () => secretPage('0.69.2'));
  render(sections(transport, secretStatus()));
  await screen.findByText('ID: scanner-0.69.2');
  expect(screen.queryByRole('alert')).toBeNull();
});
it.each([undefined, null, 0])(
  'demo empty Secrets count %s is zero only when explicitly confirmed',
  async (findingCount) => {
    const transport = fixtureTransport();
    transport.results = vi.fn(
      async (): Promise<ScanResults> => ({
        findings: [],
        nextCursor: null,
        coverage: [
          { check: 'Secrets', status: 'checked', ...(findingCount === undefined ? {} : { findingCount }) },
        ],
      }),
    );
    render(
      <ScanReportSections
        status={secretStatus()}
        transport={transport}
        scope={['demo']}
        demo
        filter="all"
        onResetFilter={() => {}}
      />,
    );
    if (findingCount === 0) {
      await screen.findByText('Подтверждённый итог Возможные секреты: 0');
      expect(screen.getByText(/В выполненной проверке секретов находок нет/)).toBeTruthy();
      expect(screen.queryByText('Итог Возможные секреты неизвестен')).toBeNull();
      expect(screen.queryByText(/это не значит, что их нет во всём отчёте/)).toBeNull();
    } else {
      await screen.findByText('Итог Возможные секреты неизвестен');
      expect(screen.getByText(/это не значит, что их нет во всём отчёте/)).toBeTruthy();
      expect(screen.queryByText(/0 находок в выполненной проверенной области/)).toBeNull();
      expect(screen.queryByText('Подтверждённый итог Возможные секреты: 0')).toBeNull();
    }
  },
);
function c4Page(index: number): Extract<ScanVuln, { outcome: 'checked' }> {
  const wire: { findings: VulnFinding[] } & Record<string, unknown> = {
    outcome: 'checked',
    coverage: 'image',
    image,
    platform: 'linux/amd64',
    findingCount: reportTotal,
    checkedAt: stamp,
    scannerVersion: '0.69.3',
    nextCursor: index === 0 ? 'paging:25/+==' : null,
    page: reportPage('vuln', index === 0 ? 0 : 25),
    findings: [
      {
        findingId: `stable-${index}`,
        cveId: `CVE-2026-123${index}`,
        ecosystem: 'apk',
        packageName: `c4-package-${index}`,
        installedVersion: '1.0',
        severity: 'CRITICAL',
        fixedVersion: '9.0',
        severitySources: ['nvd'],
        provenanceRef: `target-${'b'.repeat(64)}`,
        advisory: {
          schemaVersion: 1,
          state: 'available',
          references: [],
          conflicts: [],
          conflictState: 'none',
          limitations: [],
          assessments: [
            {
              source: 'nvd',
              provenanceRef: `target-${'b'.repeat(64)}`,
              language: 'en',
              severity: 'CRITICAL',
              fixedVersion: '9.0',
              title: { value: 'Original title', state: 'available', redacted: false },
              description: { value: 'Original description', state: 'available', redacted: false },
              cvss: {
                family: 'v3',
                version: '3.1',
                versionState: 'available',
                reportedScore: 9.8,
                scoreState: 'available',
                vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                vectorState: 'available',
              },
            },
          ],
        },
      },
    ],
  };
  if (index === 0) wire.findings.push(...Array.from({ length: 24 }, (_, fillerIndex): VulnFinding => ({
    ...wire.findings[0], findingId: `c4-filler-${fillerIndex}`, cveId: `CVE-2026-${2000 + fillerIndex}`,
    packageName: `filler-package-${fillerIndex}`, severity: 'HIGH', fixedVersion: null, advisory: null,
  })));
  const page = parseCurrentVuln(wire, { view: 'report-v1', limit: 25 }, index === 0 ? undefined : 'paging:25/+==');
  if (page.outcome !== 'checked') throw new Error('Invalid test page');
  return page;
}
const c4Changes = [
  'severity/fix',
  'package/version',
  'CVE ID',
  'provenance',
  'source severity/fix',
  'source title/description',
  'source text states',
  'source provenance',
  'source CVSS',
  'source language',
  'source contributors',
  'conflicts',
  'limitations',
] as const;
function changeC4Row(row: VulnFinding, field: (typeof c4Changes)[number]) {
  switch (field) {
    case 'severity/fix':
      row.severity = 'LOW';
      row.fixedVersion = '1.1';
      break;
    case 'package/version':
      row.packageName = 'changed-package';
      row.installedVersion = '2.0';
      break;
    case 'CVE ID':
      row.cveId = 'CVE-2026-9999';
      break;
    case 'provenance':
      row.provenanceRef = `target-${'c'.repeat(64)}`;
      break;
    case 'source severity/fix':
      row.advisory!.assessments[0].severity = 'LOW';
      row.advisory!.assessments[0].fixedVersion = '1.1';
      break;
    case 'source title/description':
      row.advisory!.assessments[0].title.value = 'Changed title';
      row.advisory!.assessments[0].description.value = 'Changed description';
      break;
    case 'source text states':
      row.advisory!.assessments[0].title = { value: null, state: 'redacted', redacted: true };
      break;
    case 'source provenance':
      row.advisory!.assessments[0].provenanceRef = `target-${'c'.repeat(64)}`;
      break;
    case 'source CVSS':
      row.advisory!.assessments[0].cvss!.reportedScore = 3.1;
      break;
    case 'source language':
      row.advisory!.assessments[0].language = 'ru';
      break;
    case 'source contributors':
      row.severitySources = ['alpine', 'nvd'];
      break;
    case 'conflicts':
      row.advisory!.conflicts = ['severity'];
      row.advisory!.conflictState = 'present';
      break;
    case 'limitations':
      row.advisory!.limitations = ['field_limit'];
      break;
  }
}
it.each(['Back', 'forward'] as const)(
  'C4 same-ID %s replay rejects every normalized display-content change and retains last confirmed page',
  async (direction) => {
    for (const field of c4Changes) {
      const first = c4Page(0);
      const second = c4Page(1);
      const altered = structuredClone(direction === 'Back' ? first : second);
      changeC4Row(altered.findings[0], field);
      const transport = fixtureTransport();
      const sequence = direction === 'Back' ? [first, second, altered] : [first, second, first, altered];
      transport.vuln = vi.fn();
      for (const page of sequence) vi.mocked(transport.vuln).mockResolvedValueOnce(page);
      vi.mocked(transport.vuln)
        .mockRejectedValueOnce(new Error('retry offline'))
        .mockResolvedValueOnce(first);
      const view = render(sections(transport, { ...status, checks: ['vuln'] }));
      await screen.findByText('c4-package-0');
      fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
      await screen.findByText('c4-package-1');
      if (direction === 'forward') {
        fireEvent.click(screen.getByRole('button', { name: 'Назад · Уязвимости' }));
        await screen.findByText('c4-package-0');
      }
      const retainedIndex = direction === 'Back' ? 1 : 0;
      const retainedRow = c4Page(retainedIndex).findings[0];
      const before = screen.getByRole('list', { name: 'Находки Уязвимости' }).textContent;
      fireEvent.click(
        screen.getByRole('button', { name: direction === 'Back' ? 'Назад · Уязвимости' : 'Далее · Уязвимости' }),
      );
      await screen.findByText(/Содержимое отчёта изменилось/);
      expect(screen.getByRole('list', { name: 'Находки Уязвимости' }).textContent, field).toBe(before);
      expect(screen.getByText(retainedRow.packageName), field).toBeTruthy();
      expect(screen.getByText(retainedIndex === 0 ? 'Строки 1–25' : 'Строки 26–26'), field).toBeTruthy();
      expect(screen.getByText(`Страница ${retainedIndex + 1}`), field).toBeTruthy();
      expect(screen.getByText(/Сохранён прежний подтверждённый снимок/), field).toBeTruthy();
      expect(screen.queryByText('LOW', { exact: true }), field).toBeNull();
      expect(screen.queryByText('1.1', { exact: true }), field).toBeNull();
      expect(screen.getByRole('button', { name: 'Назад · Уязвимости' }).hasAttribute('disabled')).toBe(true);
      expect(screen.getByRole('button', { name: 'Далее · Уязвимости' }).hasAttribute('disabled')).toBe(true);
      fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Уязвимости' }));
      await screen.findByText(/Не удалось подтвердить страницу Уязвимости/);
      expect(screen.getByText(/Показана предыдущая подтверждённая страница/)).toBeTruthy();
      expect(screen.getByRole('list', { name: 'Находки Уязвимости' }).textContent).toBe(before);
      fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Уязвимости' }));
      await screen.findByText('Страница 1');
      await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
      expect(
        vi
          .mocked(transport.vuln)
          .mock.calls.slice(-2)
          .map((call) => call[1]),
      ).toEqual([undefined, undefined]);
      expect(screen.getByRole('button', { name: 'Далее · Уязвимости' }).hasAttribute('disabled')).toBe(false);
      view.unmount();
    }
  },
);
it('C4 accepts benign stable normalized content on Back and forward replay with reordered row keys', async () => {
  const first = c4Page(0);
  const second = c4Page(1);
  const { advisory: firstAdvisory, ...firstRow } = first.findings[0];
  const reorderedFirst = { ...first, findings: [{ advisory: firstAdvisory, ...firstRow }, ...first.findings.slice(1)] };
  const { advisory, provenanceRef, ...secondRow } = second.findings[0];
  const reorderedSecond = { ...second, findings: [{ advisory, provenanceRef, ...secondRow }, ...second.findings.slice(1)] };
  const transport = fixtureTransport();
  transport.vuln = vi
    .fn()
    .mockResolvedValueOnce(first)
    .mockResolvedValueOnce(second)
    .mockResolvedValueOnce(reorderedFirst)
    .mockResolvedValueOnce(reorderedSecond);
  render(sections(transport, { ...status, checks: ['vuln'] }));
  await screen.findByText('c4-package-0');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
  await screen.findByText('c4-package-1');
  fireEvent.click(screen.getByRole('button', { name: 'Назад · Уязвимости' }));
  await screen.findByText('Строки 1–25');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
  await screen.findByText('Строки 26–26');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByText('Критическая оценка', { exact: true })).toBeTruthy();
  expect(screen.getByText('9.0', { exact: true })).toBeTruthy();
  expect(vi.mocked(transport.vuln).mock.calls.map((call) => call[1])).toEqual([
    undefined,
    'paging:25/+==',
    undefined,
    'paging:25/+==',
  ]);
});
it('C4 canonical fingerprints ignore nested object-key ordering/undefined optionals, not values or array order', () => {
  const original = [
    {
      id: 'same',
      details: { value: 'Plain description', state: 'available', optional: undefined },
      sources: ['nvd', 'alpine'],
    },
  ];
  const reordered = [
    { sources: ['nvd', 'alpine'], details: { state: 'available', value: 'Plain description' }, id: 'same' },
  ];
  expect(fingerprintReportRows(original)).toBe(fingerprintReportRows(reordered));
  expect(
    fingerprintReportRows([
      { ...reordered[0], details: { ...reordered[0].details, value: 'Changed description' } },
    ]),
  ).not.toBe(fingerprintReportRows(original));
  expect(fingerprintReportRows([{ ...reordered[0], sources: ['alpine', 'nvd'] }])).not.toBe(
    fingerprintReportRows(original),
  );
  expect(
    fingerprintReportRows([{ ...reordered[0], details: { ...reordered[0].details, optional: null } }]),
  ).not.toBe(fingerprintReportRows(original));
});
it('C4 fingerprint size is bounded and oversized content is rejected rather than stripped or truncated', () => {
  expect(() => fingerprintReportRows([{ description: 'x'.repeat(2 * 1024 * 1024) }])).toThrow(
    'Report page fingerprint limit',
  );
});
it.each(['Back', 'forward'] as const)(
  'C4 Secrets same-ID %s replay rejects changed normalized finding content',
  async (direction) => {
    for (const field of ['ruleId', 'severity', 'category', 'line'] as const) {
      const first: ScanResults = {
        findings: firstPageRows(
          { findingId: 'same-first', ruleId: 'original-rule', severity: 'unknown', category: 'secret', line: null as number | null },
          index => ({ findingId: `same-first-${index}`, ruleId: 'original-rule', severity: 'unknown', category: 'secret', line: null }),
        ),
        coverage: [{ check: 'Secrets', status: 'checked', findingCount: reportTotal }],
        nextCursor: 'paging:25/+==',
        page: reportPage('secret'),
      };
      const second: ScanResults = {
        ...first,
        findings: [{ ...first.findings[0], findingId: 'same-second' }],
        nextCursor: null,
        page: reportPage('secret', 25),
      };
      const altered = structuredClone(direction === 'Back' ? first : second);
      if (field === 'line') altered.findings[0].line = 123;
      else altered.findings[0][field] = 'changed-content';
      const transport = fixtureTransport();
      const sequence = direction === 'Back' ? [first, second, altered] : [first, second, first, altered];
      transport.results = vi.fn();
      for (const page of sequence) vi.mocked(transport.results).mockResolvedValueOnce(page);
      vi.mocked(transport.results).mockResolvedValueOnce(first);
      const view = render(sections(transport, { ...status, checks: ['secret'] }));
      await screen.findByText('ID: same-first');
      fireEvent.click(screen.getByRole('button', { name: 'Далее · Возможные секреты' }));
      await screen.findByText('ID: same-second');
      if (direction === 'forward') {
        fireEvent.click(screen.getByRole('button', { name: 'Назад · Возможные секреты' }));
        await screen.findByText('ID: same-first');
      }
      fireEvent.click(
        screen.getByRole('button', { name: direction === 'Back' ? 'Назад · Возможные секреты' : 'Далее · Возможные секреты' }),
      );
      await screen.findByText(/Содержимое отчёта изменилось/);
      expect(screen.queryByText(/changed-content/), field).toBeNull();
      expect(screen.queryByText('Строка 123'), field).toBeNull();
      expect(
        screen.getByText(direction === 'Back' ? 'ID: same-second' : 'ID: same-first'),
        field,
      ).toBeTruthy();
      fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Возможные секреты' }));
      await screen.findByText('Страница 1');
      await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
      expect(vi.mocked(transport.results).mock.calls.at(-1)?.[1]).toBeUndefined();
      view.unmount();
    }
  },
);
it.each(['access loss', 'scope reset'] as const)(
  'C4 retained replay snapshot still clears on %s',
  async (boundary) => {
    const first = c4Page(0);
    const second = c4Page(1);
    const changed = c4Page(0);
    changed.findings[0].severity = 'LOW';
    const transport = fixtureTransport();
    transport.vuln = vi
      .fn()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second)
      .mockResolvedValueOnce(changed);
    const view = render(sections(transport, { ...status, checks: ['vuln'] }));
    await screen.findByText('c4-package-0');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · Уязвимости' }));
    await screen.findByText('c4-package-1');
    fireEvent.click(screen.getByRole('button', { name: 'Назад · Уязвимости' }));
    await screen.findByText(/Содержимое отчёта изменилось/);
    expect(screen.getByText('c4-package-1')).toBeTruthy();
    if (boundary === 'access loss') {
      vi.mocked(transport.vuln).mockRejectedValueOnce(new ScanAccessError(403));
      fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Уязвимости' }));
      await screen.findByText(/Доступ к отчёту утрачен/);
      expect(screen.queryByRole('button', { name: 'Повторить загрузку Уязвимости' })).toBeNull();
    } else {
      vi.mocked(transport.vuln).mockImplementationOnce(() => deferred<ScanVuln>().promise);
      view.rerender(sections(transport, { ...status, checks: ['vuln'] }, ['live-scans', 2, 'bob']));
      expect(vi.mocked(transport.vuln).mock.calls.at(-1)?.[1]).toBeUndefined();
    }
    expect(screen.queryByText('c4-package-0')).toBeNull();
    expect(screen.queryByText('c4-package-1')).toBeNull();
  },
);
it.each(['sbom', 'results'] as const)(
  'preserves confirmed %s rows and retries only that failed cursor',
  async (kind) => {
    const transport = fixtureTransport();
    const original = transport[kind];
    transport[kind] = vi
      .fn()
      .mockImplementationOnce(original)
      .mockRejectedValueOnce(new Error('offline'))
      .mockImplementation(original);
    render(sections(transport));
    const label = kind === 'sbom' ? 'Пакеты' : 'Возможные секреты';
    const region = kind === 'sbom' ? screen.getByLabelText('Пакеты SBOM')
      : screen.getByRole('region', { name: 'Возможные секреты' });
    await within(region).findByText('Строки 1–25');
    fireEvent.click(within(region).getByRole('button', { name: 'Далее · ' + label }));
    await within(region).findByRole('alert');
    expect(within(region).getByText('Строки 1–25')).toBeTruthy();
    expect(within(region).getByText(kind === 'sbom' ? 'sbom-first' : 'ID: secret-first')).toBeTruthy();
    fireEvent.click(within(region).getByRole('button', { name: 'Повторить загрузку ' + label }));
    await within(region).findByText('Строки 26–26');
    expect(vi.mocked(transport[kind]).mock.calls.map((call) => call[1])).toEqual([undefined, 'paging:25/+==', 'paging:25/+==']);
  },
);
