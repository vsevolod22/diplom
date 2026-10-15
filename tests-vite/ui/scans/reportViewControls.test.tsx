import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { fixtureScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { BROWSER_SCANS_PATH } from '@/shared/api/scans/scanTransport';
import type { ScanCheck, ScanStatus } from '@/shared/api/scans/scanTransport';
import { REPORT_SEVERITIES } from '@/shared/api/scans/reportView';
import { meta, scanId, sbomRows, sbomWire, secretRows, secretWire, status, v2Evidence, vulnRows, vulnWire } from './reportViewSynthetic';

type Override = (wire: ReturnType<typeof vulnWire>) => Response | Promise<Response>;
const json = (wire: unknown, status = 200) => new Response(JSON.stringify(wire), { status });
let requests: URL[];
let overrides: Override[];
let secretOverride: ((wire: ReturnType<typeof secretWire>) => Response) | null;
beforeEach(() => {
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
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const transport = () => createAuthorizedScanTransport({ subject: 'synthetic', currentSubject: () => 'synthetic' });
function mount(checks: ScanCheck[] = ['vuln'], scanStatus: ScanStatus = status) {
  const props = { status: { ...scanStatus, checks }, transport: transport(), scope: ['synthetic', 1], demo: false, filter: 'all', onResetFilter: vi.fn() };
  return { ...render(<ScanReportSections {...props} />), props };
}
const cve = () => within(screen.getByRole('region', { name: 'Результаты CVE' }));
const next = async () => { fireEvent.click(cve().getByRole('button', { name: 'Далее · CVE · сверху' })); await screen.findByText('CVE-2026-1025'); };
const retry = () => fireEvent.click(cve().getByRole('button', { name: 'Повторить загрузку CVE' }));
const lastVulnRequest = () => requests.filter(url => url.pathname.endsWith('/vuln')).at(-1)!;

describe('actual parser → opt-in HTTP transport → sections / dual cursor pagers', () => {
  it('preserves top/bottom pagers; page-size5 resets cursors, truthful range and totals', async () => {
    mount();
    await screen.findByText('CVE-2026-1000');
    expect(cve().getAllByRole('navigation')).toHaveLength(2);
    expect(cve().getByText('Строки 1–25')).toBeVisible();
    await next();
    expect(cve().getByText('Страница 2')).toBeVisible();
    fireEvent.change(cve().getByLabelText('Строк на странице · CVE'), { target: { value: '5' } });
    await screen.findByText('CVE-2026-1000');
    expect(cve().getByText('Строки 1–5')).toBeVisible();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    expect(lastVulnRequest().searchParams.get('limit')).toBe('5');
    expect(cve().getByRole('button', { name: 'Назад · CVE · сверху' })).toBeDisabled();
  });
  it('uses matched count for checked filtered pagination and whole report for coverage; zero matches is not zero report', async () => {
    mount();
    await screen.findByText('CVE-2026-1000');
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические (HIGH + CRITICAL)' }));
    await waitFor(() => expect(cve().getByText('Совпадений во всём отчёте CVE: 20')).toBeVisible());
    expect(cve().getByText('Полный итог CVE: 30')).toBeVisible();
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    fireEvent.change(cve().getByLabelText('Уровень опасности (severity) · CVE'), { target: { value: 'UNKNOWN' } });
    await cve().findByText(/Нет совпадений глобального фильтра CVE/);
    expect(cve().getByText('Совпадений во всём отчёте CVE: 0')).toBeVisible();
    expect(cve().queryByText(/0 CVE в выполненной/)).not.toBeInTheDocument();
  });
  it('sends independent global SBOM name/ecosystem and meaningful Secrets rule/line/sort controls', async () => {
    mount(['secret', 'sbom', 'vuln']);
    await screen.findByText('CVE-2026-1000');
    const sbom = within(screen.getByRole('region', { name: 'Пакеты SBOM' }));
    const secrets = within(screen.getByRole('region', { name: 'Результаты Secrets' }));
    await sbom.findByText('package-00');
    await secrets.findByText('ID: secret-0');
    fireEvent.change(sbom.getByLabelText('Экосистема · SBOM'), { target: { value: 'npm' } });
    await sbom.findByText('Совпадений во всём отчёте SBOM: 15');
    fireEvent.change(sbom.getByLabelText('Имя пакета · SBOM'), { target: { value: 'PACKAGE-2' } });
    expect(requests.filter(url => url.searchParams.has('name'))).toHaveLength(0);
    fireEvent.submit(sbom.getByLabelText('Имя пакета · SBOM').closest('form')!);
    await sbom.findByText('Совпадений во всём отчёте SBOM: 10');
    expect(requests.at(-1)?.searchParams.get('name')).toBe('package-2');
    fireEvent.change(secrets.getByLabelText('Номер строки · Secrets'), { target: { value: 'known' } });
    await secrets.findByText('Совпадений во всём отчёте Secrets: 15');
    fireEvent.change(secrets.getByLabelText('Rule ID · Secrets'), { target: { value: 'RULE_B' } });
    fireEvent.submit(secrets.getByLabelText('Rule ID · Secrets').closest('form')!);
    await secrets.findByText('Совпадений во всём отчёте Secrets: 8');
    expect(requests.at(-1)?.searchParams.get('ruleId')).toBe('RULE_B');
    expect(secrets.queryByText(/severity:/)).not.toBeInTheDocument();
    expect(cve().getByText('Строки 1–25')).toBeVisible();
  });
  it.each([[400, 'REPORT_CURSOR_QUERY_MISMATCH'], [409, 'REPORT_CURSOR_STALE']])('clears rows/history and retries FIRST on query-bound %s/%s', async (code, errorCode) => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => json({ errorCode }, Number(code)));
    fireEvent.click(cve().getByRole('button', { name: 'Далее · CVE · сверху' }));
    await cve().findByRole('alert');
    expect(cve().queryByText('CVE-2026-1000')).not.toBeInTheDocument();
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    retry(); await screen.findByText('CVE-2026-1000');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('ordinary503 retains last confirmed rows and retries attempted opaque cursor; selection after error resets first', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Далее · CVE · сверху' }));
    await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1000')).toBeVisible();
    retry(); await screen.findByText('CVE-2026-1025');
    expect(lastVulnRequest().searchParams.get('cursor')).toBe('opaque:25/+==');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · CVE · сверху' }));
    await cve().findByRole('alert');
    fireEvent.change(cve().getByLabelText('Сортировка · CVE'), { target: { value: 'severity:asc' } });
    await cve().findByText('Строки 1–25');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    expect(cve().queryByRole('alert')).not.toBeInTheDocument();
  });
  it('C4 remains content-only last-confirmed historical retention; failed recovery retains it, selection discards it', async () => {
    mount(); await screen.findByText('CVE-2026-1000'); await next();
    overrides.push(wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, fixedVersion: '9.9' } : item) }));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · CVE · сверху' }));
    await cve().findByText(/Сохранён прежний подтверждённый снимок/);
    expect(cve().getByText('CVE-2026-1025')).toBeVisible();
    expect(cve().getByRole('button', { name: 'Назад · CVE · сверху' })).toBeDisabled();
    overrides.push(() => json({}, 503)); retry(); await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1025')).toBeVisible();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    fireEvent.change(cve().getByLabelText('Строк на странице · CVE'), { target: { value: '5' } });
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    await screen.findByText('CVE-2026-1000');
    expect(cve().queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it.each(['metadata', 'access', 'stale', 'query', 'invalid-json'])('clears even retained C4 historical snapshot on %s failure', async mode => {
    mount(); await screen.findByText('CVE-2026-1000'); await next();
    overrides.push(wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, fixedVersion: '9.9' } : item) }));
    fireEvent.click(cve().getByRole('button', { name: 'Назад · CVE · сверху' }));
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
    fireEvent.click(cve().getByRole('button', { name: 'Назад · CVE · сверху' }));
    await cve().findByRole('alert');
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    overrides.push(wire => json({ ...wire, ...evidence })); retry(); await screen.findByText('CVE-2026-1000');
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('unchanged Back/forward revisit and subject-remount isolation preserve existing fences', async () => {
    const mounted = mount(); await screen.findByText('CVE-2026-1000'); await next();
    fireEvent.click(cve().getByRole('button', { name: 'Назад · CVE · сверху' })); await screen.findByText('CVE-2026-1000');
    await next(); expect(cve().queryByRole('alert')).not.toBeInTheDocument();
    mounted.rerender(<ScanReportSections {...mounted.props} scope={['other-synthetic', 2]} />);
    expect(cve().queryByText('CVE-2026-1025')).not.toBeInTheDocument();
    await screen.findByText('CVE-2026-1000'); expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
  });
  it('reapplying the SAME selection resets history even after an error', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические (HIGH + CRITICAL)' }));
    await cve().findByText('Совпадений во всём отчёте CVE: 20');
    fireEvent.change(cve().getByLabelText('Строк на странице · CVE'), { target: { value: '5' } });
    await cve().findByText('Строки 1–5');
    fireEvent.click(cve().getByRole('button', { name: 'Далее · CVE · сверху' }));
    await screen.findByText('CVE-2026-1005');
    overrides.push(() => json({}, 503));
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические (HIGH + CRITICAL)' }));
    expect(cve().queryByText('CVE-2026-1005')).not.toBeInTheDocument();
    await cve().findByRole('alert');
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    expect(lastVulnRequest().searchParams.has('cursor')).toBe(false);
    fireEvent.click(cve().getByRole('button', { name: 'Высокие и критические (HIGH + CRITICAL)' }));
    await screen.findByText('CVE-2026-1000');
    expect(cve().getByRole('button', { name: 'Назад · CVE · сверху' })).toBeDisabled();
  });
  it('disables controls while pending and ignores late old-scope responses', async () => {
    let complete!: (response: Response) => void;
    overrides.push(wire => new Promise<Response>(resolve => { complete = response => resolve(response); void wire; }));
    const mounted = mount();
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(cve().getByLabelText('Строк на странице · CVE')).toBeDisabled();
    mounted.rerender(<ScanReportSections {...mounted.props} scope={['other-synthetic', 2]} />);
    await screen.findByText('CVE-2026-1000');
    await act(async () => complete(json(vulnWire({ findings: vulnRows.slice(0, 25).map((item, index) => index === 0 ? { ...item, cveId: 'CVE-2026-9999' } : item), page: meta({ limit: 25, returnedCount: 25 }), nextCursor: 'opaque:25/+==' }))));
    expect(cve().queryByText('CVE-2026-9999')).not.toBeInTheDocument();
    expect(cve().getByText('Страница 1')).toBeVisible();
  });
  it('same-ID secret line drift uses C4 retention, then line selection clears historical data', async () => {
    mount(['secret']);
    const secrets = within(screen.getByRole('region', { name: 'Результаты Secrets' }));
    await secrets.findByText('ID: secret-0');
    fireEvent.click(secrets.getByRole('button', { name: 'Далее · Secrets · сверху' }));
    await secrets.findByText('ID: secret-26');
    secretOverride = wire => json({ ...wire, findings: wire.findings.map((item, index) => index === 0 ? { ...item, line: 123 } : item) });
    fireEvent.click(secrets.getByRole('button', { name: 'Назад · Secrets · сверху' }));
    await secrets.findByText(/Сохранён прежний подтверждённый снимок/);
    expect(secrets.getByText('ID: secret-26')).toBeVisible();
    expect(secrets.getByRole('button', { name: 'Назад · Secrets · сверху' })).toBeDisabled();
    fireEvent.change(secrets.getByLabelText('Номер строки · Secrets'), { target: { value: 'known' } });
    expect(secrets.queryByText('ID: secret-26')).not.toBeInTheDocument();
    await secrets.findByText('ID: secret-1');
    expect(secrets.queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
    expect(requests.at(-1)?.searchParams.has('cursor')).toBe(false);
  });
  it('ordinary network failure retains confirmation and same-cursor retry', async () => {
    mount(); await screen.findByText('CVE-2026-1000');
    overrides.push(() => { throw new TypeError('Synthetic offline'); });
    fireEvent.click(cve().getByRole('button', { name: 'Далее · CVE · сверху' }));
    await cve().findByRole('alert');
    expect(cve().getByText('CVE-2026-1000')).toBeVisible();
    retry(); await screen.findByText('CVE-2026-1025');
    expect(lastVulnRequest().searchParams.get('cursor')).toBe('opaque:25/+==');
  });
  it('unknown nonchecked totals do not become zero or no-match claims', async () => {
    overrides.push(() => json({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', findings: [], nextCursor: null, page: meta({ limit: 25, returnedCount: 0, totalCount: null, matchedCount: null }) }));
    mount(['vuln'], { ...status, perCheck: { vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED' } } });
    await cve().findByText(/CVE не проверены: SCAN_FAILED/);
    expect(cve().queryAllByRole('navigation')).toHaveLength(0);
    expect(cve().queryByText(/Совпадений во всём отчёте CVE: 0/)).not.toBeInTheDocument();
    expect(cve().queryByText(/Нет совпадений глобального/)).not.toBeInTheDocument();
  });
  it('labels fixture controls unsupported and never sends view options', async () => {
    render(<ScanReportSections status={{ scanId: 'partial-demo', state: 'partial' }} transport={fixtureScanTransport} scope={['demo']} demo filter="all" onResetFilter={vi.fn()} />);
    await screen.findByText('SECRET_DETECTED');
    expect(screen.getByText(/Демо: размер страницы/)).toBeVisible();
    expect(screen.queryByLabelText('Строк на странице · Secrets')).not.toBeInTheDocument();
    expect(requests).toHaveLength(0);
  });
});
