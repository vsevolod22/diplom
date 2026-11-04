import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render as renderUi, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { fixtureScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { BROWSER_SCANS_PATH } from '@/shared/api/scans/scanTransport';
import type { ScanCheck, ScanStatus } from '@/shared/api/scans/scanTransport';
import { REPORT_SEVERITIES } from '@/shared/api/scans/reportView';
import { meta, scanId, sbomRows, sbomWire, secretRows, secretWire, status, v2Evidence, vulnRows, vulnWire } from './reportViewSynthetic';

type Override = (wire: ReturnType<typeof vulnWire>) => Response | Promise<Response>;
const json = (wire: unknown, status = 200) => new Response(JSON.stringify(wire), { status });
let queryClient: QueryClient;
function render(ui: ReactNode) {
  const view = renderUi(ui, { wrapper: ({ children }) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider> });
  // Exercise disclosed inventory and filters through the same summaries as a user.
  for (const summary of screen.queryAllByText(/^(Состав образа · найти пакет и его версию|Фильтры и сортировка ·)/, { selector: 'summary' })) {
    if (!summary.closest('details')!.open) fireEvent.click(summary);
  }
  return view;
}
let requests: URL[];
let overrides: Override[];
let secretOverride: ((wire: ReturnType<typeof secretWire>) => Response) | null;
beforeEach(() => {
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  requests = [];
  overrides = [];
  secretOverride = null;
  // Closed synthetic endpoint dispatcher; unexpected requests fail instead of reaching any network.
  vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
    const url = new URL(path, 'https://synthetic.invalid');
    if (url.origin !== 'https://synthetic.invalid' || options.method !== 'GET' || !url.pathname.startsWith(`${BROWSER_SCANS_PATH}/${scanId}/`)) throw new Error('Unexpected synthetic endpoint');
    requests.push(url);
    const params = url.searchParams;
    const kind = url.pathname.endsWith('/vuln') ? 'vuln' : url.pathname.endsWith('/sbom') ? 'sbom' : url.pathname.endsWith('/results') ? 'secret' : null;
    if (!kind || params.get('view') !== 'report-v1') throw new Error('Unexpected report request');
    // Contract-canonical echo, independent of the client query normalizer.
    const selectedSeverity = params.get('severity')?.split(',');
    const severity = selectedSeverity && !REPORT_SEVERITIES.every(item => selectedSeverity.includes(item))
      ? REPORT_SEVERITIES.filter(item => selectedSeverity.includes(item)) : null;
    const normalized = { limit: Number(params.get('limit')), sort: params.get('sort'),
      filters: kind === 'vuln' ? { severity } : kind === 'sbom'
        ? { ecosystem: params.get('ecosystem'), name: params.get('name')?.toLowerCase() ?? null }
        : { ruleId: params.get('ruleId'), linePresence: params.get('linePresence') } };
    const cursor = params.get('cursor');
    const offset = cursor === null ? 0 : Number(/^opaque:(\d+)\/\+==$/.exec(cursor)?.[1]);
    if (!Number.isFinite(offset)) throw new Error('Unexpected synthetic cursor');
    const source = kind === 'vuln' ? vulnRows : kind === 'sbom' ? sbomRows : secretRows;
    let rows: (typeof source)[number][] = [...source];
    if (kind === 'vuln') {
      const selected = params.get('severity')?.split(',');
      rows = vulnRows.filter(item => !selected || selected.includes(item.severity));
      if (params.get('sort') === 'severity:asc') rows.reverse();
    } else if (kind === 'sbom') {
      rows = sbomRows.filter(item => (!params.get('ecosystem') || item.ecosystem === params.get('ecosystem')) && (!params.get('name') || item.name.toUpperCase().includes(params.get('name')!.toUpperCase())));
      if (params.get('sort')?.endsWith(':desc')) rows.reverse();
    } else {
      rows = secretRows.filter(item => (!params.get('ruleId') || item.ruleId === params.get('ruleId')) && (!params.get('linePresence') || (item.line !== null) === (params.get('linePresence') === 'known')));
      if (params.get('sort')?.endsWith(':desc')) rows.reverse();
    }
    const selected = rows.slice(offset, offset + normalized.limit);
    const page = { ...meta(), ...normalized, offset, returnedCount: selected.length, matchedCount: rows.length };
    const nextCursor = offset + selected.length < rows.length ? `opaque:${offset + selected.length}/+==` : null;
    const wire = kind === 'vuln' ? vulnWire({ findings: selected, page, nextCursor }) : kind === 'sbom' ? sbomWire({ components: selected, page, nextCursor }) : secretWire({ findings: selected, page, nextCursor });
    if (kind === 'secret' && secretOverride) {
      const override = secretOverride;
      secretOverride = null;
      return override(wire as ReturnType<typeof secretWire>);
    }
    return kind === 'vuln' && overrides.length ? overrides.shift()!(wire as ReturnType<typeof vulnWire>) : json(wire);
  }));
});
afterEach(() => { cleanup(); queryClient.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const transport = () => createAuthorizedScanTransport({ subject: 'synthetic', currentSubject: () => 'synthetic' });
function mount(checks: ScanCheck[] = ['vuln'], scanStatus: ScanStatus = status) {
  const props = { status: { ...scanStatus, checks }, transport: transport(), scope: ['synthetic', 1], demo: false, filter: 'all', onResetFilter: vi.fn() };
  return { ...render(<ScanReportSections {...props} />), props };
}
const cve = () => within(screen.getByRole('region', { name: 'Результаты Уязвимости' }));
const next = async () => { fireEvent.click(cve().getByRole('button', { name: 'Далее · Уязвимости · сверху' })); await screen.findByText('CVE-2026-1025'); };
const retry = () => fireEvent.click(cve().getByRole('button', { name: 'Повторить загрузку Уязвимости' }));
const lastVulnRequest = () => requests.filter(url => url.pathname.endsWith('/vuln')).at(-1)!;

describe('actual parser → opt-in HTTP transport → sections / dual cursor pagers', () => {
  it('loads all saved cancelled datasets, pages them independently and reloads without discarding results', async () => {
    const cancelled: ScanStatus = { ...status, state: 'cancelled' };
    const view = mount(['secret', 'sbom', 'vuln'], cancelled);
    const sbom = within(screen.getByLabelText('Пакеты SBOM'));
    const secrets = within(screen.getByRole('region', { name: 'Возможные секреты' }));
    await screen.findByText('CVE-2026-1000');
    await sbom.findByText('package-00');
    await secrets.findByText('ID: secret-0');
    await next();
    fireEvent.click(sbom.getByRole('button', { name: 'Далее · Пакеты · сверху' }));
    await sbom.findByText('package-25');
    fireEvent.click(secrets.getByRole('button', { name: 'Далее · Возможные секреты · сверху' }));
    await secrets.findByText('ID: secret-25');
    for (const section of [cve(), sbom, secrets]) expect(section.getByText('Страница 2')).toBeVisible();
    view.unmount();
    mount(['secret', 'sbom', 'vuln'], cancelled);
    await screen.findByText('CVE-2026-1000');
    await screen.findByText('package-00');
    await screen.findByText('ID: secret-0');
    expect(cve().getByText('Страница 1')).toBeVisible();
  });
  it.each(['secret', 'sbom', 'vuln'] as const)('loads only the saved cancelled %s subset, without treating absent siblings as zero', async check => {
    mount(['secret', 'sbom', 'vuln'], { ...status, state: 'cancelled', perCheck: {
      secret: null, sbom: null, vuln: null, [check]: status.perCheck![check],
    } });
    await screen.findByText(check === 'secret' ? 'ID: secret-0' : check === 'sbom' ? 'package-00' : 'CVE-2026-1000');
    expect(requests).toHaveLength(1);
    expect(requests[0].pathname.endsWith(check === 'secret' ? '/results' : `/${check}`)).toBe(true);
    for (const absent of (['secret', 'sbom', 'vuln'] as const).filter(kind => kind !== check)) {
      const label = absent === 'secret' ? 'Возможные секреты' : absent === 'sbom' ? 'Пакеты SBOM' : 'Результаты Уязвимости';
      expect(within(screen.getByLabelText(label)).getByText(/не сохранён/)).toHaveTextContent(/неизвестно/);
    }
    expect(screen.queryByText(/Ожидаем результат Уязвимости/)).not.toBeInTheDocument();
  });
  it('retains a completed failed checkpoint as failed after cancellation, never a checked zero', async () => {
    overrides.push(wire => json({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_TIMEOUT', findings: [], nextCursor: null,
      page: { ...wire.page, returnedCount: 0, totalCount: null, matchedCount: null } }));
    mount(['vuln'], { ...status, state: 'cancelled', perCheck: { vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' } } });
    await screen.findByText('Не удалось проверить уязвимости');
    expect(requests).toHaveLength(1);
    expect(screen.queryByText(/0 находок в выполненной|Совпадений во всём отчёте Уязвимости: 0|Всего находок в проверенной области:/)).not.toBeInTheDocument();
  });
  it('does not request cancelled reports without checkpoints or invent checked zero', () => {
    mount(['secret', 'sbom', 'vuln'], { ...status, state: 'cancelled', perCheck: { secret: null, sbom: null, vuln: null } });
    expect(requests).toHaveLength(0);
    expect(screen.getAllByText(/не сохранён/)).toHaveLength(3);
    for (const message of screen.getAllByText(/не сохранён/)) expect(message).toHaveTextContent(/неизвестно/);
    expect(screen.queryByText(/Совпадений во всём отчёте|Всего находок в проверенной области|0 находок/)).not.toBeInTheDocument();
  });
  it('preserves top/bottom pagers; page-size5 resets cursors, truthful range and totals', async () => {
    mount();
    await screen.findByText('CVE-2026-1000');
    expect(cve().getAllByRole('navigation')).toHaveLength(2);
    expect(cve().getByText('Строки 1–25')).toBeVisible();
    await next();
    expect(cve().getByText('Страница 2')).toBeVisible();
    fireEvent.change(cve().getByLabelText('Строк на странице · Уязвимости'), { target: { value: '5' } });
    await screen.findByText('CVE-2026-1000');
    expect(cve().getByText('Строки 1–5')).toBeVisible();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    expect(lastVulnRequest().searchParams.get('limit')).toBe('5');
    expect(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' })).toBeDisabled();
  });
  it('uses matched count for checked filtered pagination and whole report for coverage; zero matches is not zero report', async () => {
    mount();
    await screen.findByText('CVE-2026-1000');
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические' }));
    await waitFor(() => expect(cve().getByText('Совпадений во всём отчёте Уязвимости: 20')).toBeVisible());
    expect(cve().getByText(/Всего находок в проверенной области:/)).toHaveTextContent('30');
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    fireEvent.change(cve().getByLabelText('Уровень опасности · Уязвимости'), { target: { value: 'UNKNOWN' } });
    await cve().findByText(/По выбранному фильтру находок нет/);
    expect(cve().getByText('Совпадений во всём отчёте Уязвимости: 0')).toBeVisible();
    expect(cve().queryByText(/0 находок в выполненной/)).not.toBeInTheDocument();
  });
  it('sends independent global SBOM name/ecosystem and meaningful Secrets rule/line/sort controls', async () => {
    const fetchQuery = vi.spyOn(queryClient, 'fetchQuery');
    mount(['secret', 'sbom', 'vuln']);
    await screen.findByText('CVE-2026-1000');
    const sbom = within(screen.getByLabelText('Пакеты SBOM'));
    const secrets = within(screen.getByRole('region', { name: 'Возможные секреты' }));
    await sbom.findByText('package-00');
    await secrets.findByText('ID: secret-0');
    fireEvent.change(sbom.getByLabelText('Тип пакетов'), { target: { value: 'npm' } });
    await sbom.findByText('Совпадений во всём отчёте Пакеты: 15');
    fireEvent.change(sbom.getByLabelText('Название пакета'), { target: { value: 'PACKAGE-2' } });
    expect(requests.filter(url => url.searchParams.has('name'))).toHaveLength(0);
    fireEvent.submit(sbom.getByLabelText('Название пакета').closest('form')!);
    await sbom.findByText('Совпадений во всём отчёте Пакеты: 10');
    expect(requests.at(-1)?.searchParams.get('name')).toBe('package-2');
    const sbomKey = fetchQuery.mock.calls.at(-1)![0].queryKey;
    expect(sbomKey.slice(0, 5)).toEqual(['synthetic', 1, 'report-page', status.scanId, 'sbom']);
    expect(sbomKey[5]).toEqual({ view: 'report-v1', limit: 25, sort: 'name:asc', filters: { ecosystem: 'npm', name: 'package-2' } });
    expect(sbomKey.at(-1)).toBeNull();
    fireEvent.change(secrets.getByLabelText('Номер строки'), { target: { value: 'known' } });
    await secrets.findByText('Совпадений во всём отчёте Возможные секреты: 15');
    fireEvent.change(secrets.getByLabelText('Код правила'), { target: { value: 'RULE_B' } });
    fireEvent.submit(secrets.getByLabelText('Код правила').closest('form')!);
    await secrets.findByText('Совпадений во всём отчёте Возможные секреты: 8');
    expect(requests.at(-1)?.searchParams.get('ruleId')).toBe('RULE_B');
    const secretKey = fetchQuery.mock.calls.at(-1)![0].queryKey;
    expect(secretKey.slice(0, 5)).toEqual(['synthetic', 1, 'report-page', status.scanId, 'secret']);
    expect(secretKey[5]).toEqual({ view: 'report-v1', limit: 25, sort: 'ruleId:asc', filters: { ruleId: 'RULE_B', linePresence: 'known' } });
    expect(secretKey.at(-1)).toBeNull();
    expect(queryClient.getQueryCache().getAll()).toEqual([]);
    expect(secrets.queryByText(/severity:/)).not.toBeInTheDocument();
    expect(cve().getByText('Строки 1–25')).toBeVisible();
  });
  it('renders a known Secrets line zero without exposing its evidence payload', async () => {
    secretOverride = wire => json({
      ...wire,
      findings: wire.findings.map((finding, index) => index === 0 ? { ...finding, line: 0 } : finding),
    });
    mount(['secret']);
    const secrets = within(screen.getByRole('region', { name: 'Возможные секреты' }));
    await secrets.findByText('ID: secret-0');
    expect(secrets.getByText('Строка 0', { exact: true })).toBeVisible();
    expect(secrets.queryByText('redacted:0', { exact: false })).not.toBeInTheDocument();
  });
  it.each([[400, 'REPORT_CURSOR_QUERY_MISMATCH'], [409, 'REPORT_CURSOR_STALE']])('clears rows/history and retries FIRST on query-bound %s/%s', async (code, errorCode) => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => json({ errorCode }, Number(code)));
    fireEvent.click(cve().getByRole('button', { name: 'Далее · Уязвимости · сверху' }));
    await cve().findByRole('alert');
    expect(cve().queryByText('CVE-2026-1000')).not.toBeInTheDocument();
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    retry(); await screen.findByText('CVE-2026-1000');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('ordinary503 retains last confirmed rows and retries attempted opaque cursor; selection after error resets first', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Далее · Уязвимости · сверху' }));
    await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1000')).toBeVisible();
    retry(); await screen.findByText('CVE-2026-1025');
    expect(lastVulnRequest().searchParams.get('cursor')).toBe('opaque:25/+==');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' }));
    await cve().findByRole('alert');
    fireEvent.change(cve().getByLabelText('Сортировка · Уязвимости'), { target: { value: 'severity:asc' } });
    await cve().findByText('Строки 1–25');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    expect(cve().queryByRole('alert')).not.toBeInTheDocument();
  });
  it('C4 remains content-only last-confirmed historical retention; failed recovery retains it, selection discards it', async () => {
    mount(); await screen.findByText('CVE-2026-1000'); await next();
    overrides.push(wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, fixedVersion: '9.9' } : item) }));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' }));
    await cve().findByText(/Сохранён прежний подтверждённый снимок/);
    expect(cve().getByText('CVE-2026-1025')).toBeVisible();
    expect(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' })).toBeDisabled();
    overrides.push(() => json({}, 503)); retry(); await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1025')).toBeVisible();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    fireEvent.change(cve().getByLabelText('Строк на странице · Уязвимости'), { target: { value: '5' } });
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    await screen.findByText('CVE-2026-1000');
    expect(cve().queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it.each(['metadata', 'access', 'stale', 'query', 'invalid-json'])('clears even retained C4 historical snapshot on %s failure', async mode => {
    mount(); await screen.findByText('CVE-2026-1000'); await next();
    overrides.push(wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, fixedVersion: '9.9' } : item) }));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' }));
    await cve().findByText(/Сохранён прежний подтверждённый снимок/);
    overrides.push(wire => mode === 'access' ? json({}, 403) : mode === 'stale' ? json({ errorCode: 'REPORT_CURSOR_STALE' }, 409) : mode === 'query' ? json({ errorCode: 'REPORT_CURSOR_QUERY_MISMATCH' }, 400) : mode === 'invalid-json' ? new Response('{bad-json') : json({ ...wire, page: { ...wire.page, version: 2 } }));
    retry();
    await waitFor(() => expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument());
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    expect(cve().queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
    if (mode !== 'access') { retry(); await screen.findByText('CVE-2026-1000'); expect(lastVulnRequest().searchParams.has('cursor')).toBe(false); }
  });
  it('does not downgrade malformed v2 on revisited cursor; strictly clears and first-recovers', async () => {
    const evidence = v2Evidence();
    overrides.push(wire => json({ ...wire, ...evidence }));
    mount(['vuln'], { ...status, perCheck: { vuln: { ...status.perCheck!.vuln!, ...evidence } as NonNullable<ScanStatus['perCheck']>['vuln'] } });
    await screen.findByText('CVE-2026-1000');
    overrides.push(wire => json({ ...wire, ...evidence })); await next();
    overrides.push(wire => json({ ...wire, ...evidence, dbPolicy: null }));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' }));
    await cve().findByRole('alert');
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    overrides.push(wire => json({ ...wire, ...evidence })); retry(); await screen.findByText('CVE-2026-1000');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('unchanged Back/forward revisit and subject-remount isolation preserve existing fences', async () => {
    const mounted = mount(); await screen.findByText('CVE-2026-1000'); await next();
    fireEvent.click(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' })); await screen.findByText('CVE-2026-1000');
    await next(); expect(cve().queryByRole('alert')).not.toBeInTheDocument();
    mounted.rerender(<ScanReportSections {...mounted.props} scope={['other-synthetic', 2]} />);
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    await screen.findByText('CVE-2026-1000'); expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('reapplying the SAME selection resets history even after an error', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические' }));
    await cve().findByText('Совпадений во всём отчёте Уязвимости: 20');
    fireEvent.change(cve().getByLabelText('Строк на странице · Уязвимости'), { target: { value: '5' } });
    await cve().findByText('Строки 1–5');
    fireEvent.click(cve().getByRole('button', { name: 'Далее · Уязвимости · сверху' }));
    await screen.findByText('CVE-2026-1005');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические' }));
    expect(cve().queryByText('CVE-2026-1005')).not.toBeInTheDocument();
    await cve().findByRole('alert');
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические' }));
    await screen.findByText('CVE-2026-1000');
    expect(cve().getByRole('button', { name: 'Назад · Уязвимости · сверху' })).toBeDisabled();
  });
  it('disables controls while pending', async () => {
      overrides.push(() => new Promise<Response>(() => {}));
      mount();
      await waitFor(() => expect(requests).toHaveLength(1));
      expect(cve().getByLabelText('Строк на странице · Уязвимости')).toBeDisabled();
    });
    it('ignores late old-scope responses', async () => {
    let complete!: (response: Response) => void;
    overrides.push(wire => new Promise<Response>(resolve => { complete = response => resolve(response); void wire; }));
    const mounted = mount();
    await waitFor(() => expect(requests).toHaveLength(1));
    mounted.rerender(<ScanReportSections {...mounted.props} scope={['other-synthetic', 2]} />);
    await screen.findByText('CVE-2026-1000');
    await act(async () => complete(json(vulnWire({ findings: vulnRows.slice(0, 25).map((item, index) => index === 0 ? { ...item, cveId: 'CVE-2026-9999' } : item), page: meta({ limit: 25, returnedCount: 25 }), nextCursor: 'opaque:25/+==' }))));
    expect(cve().queryByText('CVE-2026-9999')).not.toBeInTheDocument();
    expect(cve().getByText('Страница 1')).toBeVisible();
  });
  it('same-ID secret line drift uses C4 retention, then line selection clears historical data', async () => {
    mount(['secret']);
    const secrets = within(screen.getByRole('region', { name: 'Возможные секреты' }));
    await secrets.findByText('ID: secret-0');
    fireEvent.click(secrets.getByRole('button', { name: 'Далее · Возможные секреты · сверху' }));
    await secrets.findByText('ID: secret-26');
    secretOverride = wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, line: 123 } : item) });
    fireEvent.click(secrets.getByRole('button', { name: 'Назад · Возможные секреты · сверху' }));
    await secrets.findByText(/Сохранён прежний подтверждённый снимок/);
    const retainedId = secrets.getByText('ID: secret-26');
        fireEvent.click(within(retainedId.closest('li')!).getByText('Подробности · правило и место находки', { selector: 'summary' }));
        expect(retainedId).toBeVisible();
    expect(secrets.getByRole('button', { name: 'Назад · Возможные секреты · сверху' })).toBeDisabled();
    fireEvent.change(secrets.getByLabelText('Номер строки'), { target: { value: 'known' } });
    expect(secrets.queryByText('ID: secret-26')).not.toBeInTheDocument();
    await secrets.findByText('ID: secret-1');
    expect(secrets.queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
    expect(requests.at(-1)?.searchParams.has('cursor')).toBe(false);
  });
  it('ordinary network failure retains confirmation and same-cursor retry', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => { throw new TypeError('Synthetic offline'); });
    fireEvent.click(cve().getByRole('button', { name: 'Далее · Уязвимости · сверху' }));
    await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1000')).toBeVisible();
    retry(); await screen.findByText('CVE-2026-1025');
    expect(lastVulnRequest().searchParams.get('cursor')).toBe('opaque:25/+==');
  });
  it('unknown nonchecked totals do not become zero or no-match claims', async () => {
    overrides.push(() => json({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', findings: [], nextCursor: null, page: meta({ limit: 25, returnedCount: 0, totalCount: null, matchedCount: null }) }));
    mount(['vuln'], { ...status, perCheck: { vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED' } } });
    await cve().findByText(/Не удалось проверить уязвимости/);
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    expect(cve().queryByText(/Совпадений во всём отчёте Уязвимости: 0/)).not.toBeInTheDocument();
    expect(cve().queryByText(/По выбранному фильтру находок нет/)).not.toBeInTheDocument();
  });
  it('labels fixture controls unsupported and never sends view options', async () => {
    render(<ScanReportSections status={{ scanId: 'partial-demo', state: 'partial' }} transport={fixtureScanTransport} scope={['demo']} demo filter="all" onResetFilter={vi.fn()} />);
    await screen.findByText('Правило: SECRET_DETECTED · категория: secret');
    expect(screen.getByText('Демонстрационные данные. Фильтры и размер страницы в этом режиме недоступны.')).toBeVisible();
    expect(screen.queryByLabelText('Строк на странице · Возможные секреты')).not.toBeInTheDocument();
    expect(requests).toHaveLength(0);
  });
});
