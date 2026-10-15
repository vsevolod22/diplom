import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, cleanup, screen, waitFor, within } from '@testing-library/react';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { CursorReportPager } from '@/pages/scans/CursorReportPager';
import { SecretReportControls } from '@/pages/scans/ReportViewControls';
import { fingerprintReportRows } from '@/pages/scans/reportRowFingerprint';
import { createAuthorizedScanTransport, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { BROWSER_SCANS_PATH, parseCurrentResults, parseCurrentSbom, parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { REPORT_SEVERITIES, ReportViewContractError, normalizeReportQuery, reportViewIdentity, reportViewSearch } from '@/shared/api/scans/reportView';
import type { ReportKind } from '@/shared/api/scans/reportView';
import { checkedAt, meta, scanId, status, sbomRows, sbomWire, secretRows, secretWire, vulnRows, vulnWire } from './reportViewSynthetic';

// Explicit contract-canonical echoes from the reviewed contract; no backend imports,
// no frontend normalizer generates expected response metadata, no other test imports.
type Wire = Record<string, unknown>;
const endpoints = { vuln: 'vuln', sbom: 'sbom', secret: 'results' };
const labels = { vuln: 'CVE', sbom: 'SBOM', secret: 'Secrets' };
const regions = { vuln: 'Результаты CVE', sbom: 'Пакеты SBOM', secret: 'Результаты Secrets' };
const firstText = { vuln: 'CVE-2026-1000', sbom: 'package-00', secret: 'ID: secret-0' };
const tailText = { vuln: 'CVE-2026-1025', sbom: 'package-25', secret: 'ID: secret-25' };
const changedAt = '2026-01-03T00:00:00.000Z';
const json = (body: unknown, code = 200) => new Response(JSON.stringify(body), { status: code });
let requests: URL[];
beforeEach(() => {
  requests = [];
  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Unexpected network request'); }));
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource']) vi.stubGlobal(name, class { constructor() { throw new Error('Network forbidden'); } });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const transport = () => createAuthorizedScanTransport({ subject: 'r2-synthetic', currentSubject: () => 'r2-synthetic' });
function responses(kind: ReportKind, replies: Response[]) {
  vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
    const url = new URL(path, 'https://r2-synthetic.invalid');
    if (url.origin !== 'https://r2-synthetic.invalid' || url.pathname !== `${BROWSER_SCANS_PATH}/${scanId}/${endpoints[kind]}` || options.method !== 'GET' || options.body) throw new Error('Unexpected synthetic endpoint');
    requests.push(url);
    const reply = replies.shift();
    if (!reply) throw new Error('Unexpected extra synthetic request');
    return reply;
  }));
}
function wire(kind: ReportKind, offset = 0, limit = 25): Wire {
  const rows = (kind === 'vuln' ? vulnRows : kind === 'sbom' ? sbomRows : secretRows).slice(offset, offset + limit);
  const nextCursor = offset + rows.length < 30 ? `r2-cursor:${offset + rows.length}` : null;
  const page = { ...meta(), limit, offset, returnedCount: rows.length, sort: kind === 'vuln' ? 'severity:desc' : kind === 'sbom' ? 'name:asc' : 'ruleId:asc',
    filters: kind === 'vuln' ? { severity: null } : kind === 'sbom' ? { ecosystem: null, name: null } : { ruleId: null, linePresence: null } };
  return kind === 'vuln' ? vulnWire({ findings: rows, nextCursor, page }) : kind === 'sbom' ? sbomWire({ components: rows, nextCursor, page }) : secretWire({ findings: rows, nextCursor, page });
}
function corruptRows(kind: ReportKind, original: Wire, mode: 'duplicate' | 'overlap' | 'content'): Wire {
  const key = kind === 'sbom' ? 'components' : 'findings';
  const rows = original[key] as Record<string, unknown>[];
  const initialRows = wire(kind)[key] as Record<string, unknown>[];
  const corrupt = mode === 'duplicate' ? [rows[0], rows[0], ...rows.slice(2)] : mode === 'overlap' ? [initialRows[0], ...rows.slice(1)] :
    [{ ...rows[0], ...(kind === 'vuln' ? { fixedVersion: '9.9' } : { line: 123 }) }, ...rows.slice(1)];
  return { ...original, [key]: corrupt };
}
function stamped(at: string | undefined, offset = 0): Wire {
  const page = wire('secret', offset);
  return { ...page, coverage: { ...(page.coverage as object), ...(at === undefined ? {} : { checkedAt: at }) } };
}
function mount(kind: ReportKind, authorizedStatus: ScanStatus = status) {
  return render(<ScanReportSections status={{ ...authorizedStatus, checks: [kind] }} transport={transport()} scope={['r2-synthetic']} demo={false} filter="all" onResetFilter={vi.fn()} />);
}
const section = (kind: ReportKind) => within(screen.getByRole('region', { name: regions[kind] }));
const navigate = (kind: ReportKind, direction: 'Назад' | 'Далее') => fireEvent.click(section(kind).getByRole('button', { name: `${direction} · ${labels[kind]} · сверху` }));
const retry = (kind: ReportKind) => fireEvent.click(section(kind).getByRole('button', { name: `Повторить загрузку ${labels[kind]}` }));
const expectCleared = (kind: ReportKind) => {
  expect(section(kind).queryByText(firstText[kind])).not.toBeInTheDocument();
  expect(section(kind).queryByText(tailText[kind])).not.toBeInTheDocument();
  expect(section(kind).queryAllByRole('navigation')).toHaveLength(0);
  expect(section(kind).queryByText(/Сохранён прежний подтверждённый снимок/)).not.toBeInTheDocument();
};
const errors = ['INVALID_PAGINATION', 'INVALID_REPORT_QUERY'] as const;

describe('R2 canonical query seam with explicit backend-normalized echoes', () => {
  it('accepts lowercase SBOM metadata for mixed-case input and equivalent continuation spellings', () => {
    const query = { view: 'report-v1' as const, limit: 5 as const, name: 'PaCkAgE-' };
    const first = sbomWire({ page: { ...meta(), sort: 'name:asc', filters: { ecosystem: null, name: 'package-' } } });
    const second = sbomWire({ components: sbomRows.slice(5, 10), nextCursor: 'r2-next', page: { ...meta({ offset: 5 }), sort: 'name:asc', filters: { ecosystem: null, name: 'package-' } } });
    const a = parseCurrentSbom(first, query);
    const b = parseCurrentSbom(second, { ...query, name: 'PACKAGE-' }, 'opaque:5/+==');
    expect(a.page?.filters.name).toBe('package-');
    expect(reportViewIdentity(a.page)).toBe(reportViewIdentity(b.page));
    expect(reportViewSearch('sbom', query)).toBe(reportViewSearch('sbom', { ...query, name: 'package-' }));
    expect(() => parseCurrentSbom(first, { ...query, name: 'different' })).toThrow(ReportViewContractError);
  });
  it('canonicalizes the complete distinct severity set to null/all before serialization and comparison', () => {
    const all = { view: 'report-v1' as const, limit: 5 as const, severity: [...REPORT_SEVERITIES].reverse() };
    const first = parseCurrentVuln(vulnWire(), all);
    const second = parseCurrentVuln(vulnWire({ findings: vulnRows.slice(5, 10), nextCursor: 'r2-next', page: meta({ offset: 5 }) }), { ...all, severity: null }, 'opaque:5/+==');
    expect(normalizeReportQuery('vuln', all).filters.severity).toBeNull();
    expect(reportViewSearch('vuln', all)).toBe(reportViewSearch('vuln', { view: 'report-v1', limit: 5 }));
    expect(reportViewIdentity(first.page)).toBe(reportViewIdentity(second.page));
    expect(() => parseCurrentVuln(vulnWire(), { ...all, severity: ['HIGH'] })).toThrow(ReportViewContractError);
  });
  it('actual SBOM form submits lowercase query and renders a hardcoded canonical server echo', async () => {
    const matching = sbomRows.slice(20, 30);
    responses('sbom', [json(wire('sbom')), json(sbomWire({ components: matching, nextCursor: null, page: { ...meta(), limit: 25, returnedCount: 10, matchedCount: 10, sort: 'name:asc', filters: { ecosystem: null, name: 'package-2' } } }))]);
    mount('sbom'); await section('sbom').findByText('package-00');
    fireEvent.change(section('sbom').getByLabelText('Имя пакета · SBOM'), { target: { value: 'PaCkAgE-2' } });
    fireEvent.submit(section('sbom').getByLabelText('Имя пакета · SBOM').closest('form')!);
    await section('sbom').findByText('Совпадений во всём отчёте SBOM: 10');
    expect(requests.at(-1)?.searchParams.get('name')).toBe('package-2');
    expect(section('sbom').queryByRole('alert')).not.toBeInTheDocument();
  });
  it.each(['rule/path', 'rule:bad', 'rule bad', 'a'.repeat(81), 'é'])('rejects noncontract ruleId %s before sending', ruleId => {
    expect(() => reportViewSearch('secret', { view: 'report-v1', ruleId })).toThrow(ReportViewContractError);
  });
  it('accepts the exact80 ASCII rule grammar and enforces the same grammar in response filters', () => {
    const ruleId = 'A' + 'a'.repeat(76) + '._-';
    expect(ruleId).toHaveLength(80);
    expect(new URLSearchParams(reportViewSearch('secret', { view: 'report-v1', ruleId })).get('ruleId')).toBe(ruleId);
    const canonical = secretWire({ page: { ...meta(), sort: 'ruleId:asc', filters: { ruleId: 'RULE_A', linePresence: null }, matchedCount: 15 } });
    expect(parseCurrentResults(canonical, { view: 'report-v1', limit: 5, ruleId: 'RULE_A' }).page?.filters.ruleId).toBe('RULE_A');
    expect(() => parseCurrentResults({ ...canonical, page: { ...canonical.page, filters: { ruleId: 'rule/path', linePresence: null } } }, { view: 'report-v1', limit: 5, ruleId: 'RULE_A' })).toThrow(ReportViewContractError);
  });
  it('Rule ID input validates locally with a fixed message and no query/raw-value echo', () => {
    const change = vi.fn();
    render(<SecretReportControls query={{ view: 'report-v1' }} disabled={false} onChange={change} />);
    const input = screen.getByLabelText('Rule ID · Secrets');
    expect(input).toHaveAttribute('maxlength', '80');
    fireEvent.change(input, { target: { value: 'rule/path' } });
    fireEvent.submit(input.closest('form')!);
    expect(change).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/80/);
    expect(screen.getByRole('alert')).not.toHaveTextContent('rule/path');
    fireEvent.change(input, { target: { value: 'RULE.A_1-2' } });
    fireEvent.submit(input.closest('form')!);
    expect(change).toHaveBeenCalledWith({ view: 'report-v1', ruleId: 'RULE.A_1-2' });
  });
});

describe('R2 deterministic HTTP errors and corrupt pagination strictly reset report-v1 only', () => {
  for (const kind of ['vuln', 'sbom', 'secret'] as const) {
    it(`${kind}: duplicate first page cannot establish confirmation and recovery omits cursor`, async () => {
      responses(kind, [json(corruptRows(kind, wire(kind), 'duplicate')), json(wire(kind))]);
      mount(kind); await section(kind).findByRole('alert'); expectCleared(kind);
      retry(kind); await section(kind).findByText(firstText[kind]);
      expect(requests.every(url => !url.searchParams.has('cursor'))).toBe(true);
    });
    it.each(errors)(`${kind}: exact400 %s clears confirmation and recovers FIRST`, async errorCode => {
      responses(kind, [json(wire(kind)), json({ errorCode }, 400), json(wire(kind))]);
      mount(kind); await section(kind).findByText(firstText[kind]);
      navigate(kind, 'Далее'); await section(kind).findByRole('alert');
      expectCleared(kind);
      if (errorCode === 'INVALID_REPORT_QUERY') expect(section(kind).getByRole('alert')).toHaveTextContent(/Исправьте/);
      retry(kind); await section(kind).findByText(firstText[kind]);
      expect(requests[1].searchParams.has('cursor')).toBe(true);
      expect(requests[2].searchParams.has('cursor')).toBe(false);
    });
    it.each(['duplicate', 'overlap'] as const)(`${kind}: %s on unseen next page clears and first-resets`, async mode => {
      responses(kind, [json(wire(kind)), json(corruptRows(kind, wire(kind, 25), mode)), json(wire(kind))]);
      mount(kind); await section(kind).findByText(firstText[kind]);
      navigate(kind, 'Далее'); await section(kind).findByRole('alert');
      expectCleared(kind);
      retry(kind); await section(kind).findByText(firstText[kind]);
      expect(requests[2].searchParams.has('cursor')).toBe(false);
    });
  }
  for (const kind of ['vuln', 'secret'] as const) {
    it.each([...errors, 'duplicate'])(`${kind}: retained C4 → %s clears historical data as well`, async mode => {
      const failure = mode === 'duplicate' ? json(corruptRows(kind, wire(kind), 'duplicate')) : json({ errorCode: mode }, 400);
      responses(kind, [json(wire(kind)), json(wire(kind, 25)), json(corruptRows(kind, wire(kind), 'content')), failure, json(wire(kind))]);
      mount(kind); await section(kind).findByText(firstText[kind]);
      navigate(kind, 'Далее'); await section(kind).findByText(tailText[kind]);
      navigate(kind, 'Назад'); await section(kind).findByText(/Сохранён прежний подтверждённый снимок/);
      expect(section(kind).getByText(tailText[kind])).toBeVisible();
      retry(kind); await waitFor(() => expect(section(kind).queryByText(tailText[kind])).not.toBeInTheDocument());
      expectCleared(kind);
      retry(kind); await section(kind).findByText(firstText[kind]);
      expect(requests[3].searchParams.has('cursor')).toBe(false);
      expect(requests[4].searchParams.has('cursor')).toBe(false);
    });
  }
  it.each(errors)('keeps legacy %s errors as ScanHttpError rather than opt-in contract errors', async errorCode => {
    responses('vuln', [json({ errorCode }, 400)]);
    await expect(transport().vuln(scanId, '5')).rejects.toBeInstanceOf(ScanHttpError);
  });
  it.each([[409, 'INVALID_PAGINATION'], [503, 'INVALID_REPORT_QUERY'], [400, 'UNRELATED_ERROR']])('does not widen exact status/code classification: %s/%s', async (code, errorCode) => {
    responses('vuln', [json({ errorCode }, Number(code))]);
    await expect(transport().vuln(scanId, undefined, undefined, { view: 'report-v1' })).rejects.toBeInstanceOf(ScanHttpError);
  });
  it('ordinary503 and C4 failed recovery still retain their permitted snapshots', async () => {
    responses('vuln', [json(wire('vuln')), json({}, 503), json(wire('vuln', 25)), json(corruptRows('vuln', wire('vuln'), 'content')), json({}, 503), json(wire('vuln'))]);
    mount('vuln'); await section('vuln').findByText(firstText.vuln);
    navigate('vuln', 'Далее'); await section('vuln').findByRole('alert');
    expect(section('vuln').getByText(firstText.vuln)).toBeVisible();
    retry('vuln'); await section('vuln').findByText(tailText.vuln);
    expect(requests[1].searchParams.get('cursor')).toBe(requests[2].searchParams.get('cursor'));
    navigate('vuln', 'Назад'); await section('vuln').findByText(/Сохранён прежний подтверждённый снимок/);
    retry('vuln'); await section('vuln').findByRole('alert');
    expect(section('vuln').getByText(tailText.vuln)).toBeVisible();
    expect(section('vuln').getByRole('button', { name: 'Далее · CVE · сверху' })).toBeDisabled();
    retry('vuln'); await section('vuln').findByText(firstText.vuln);
    expect(requests[4].searchParams.has('cursor')).toBe(false);
    expect(requests[5].searchParams.has('cursor')).toBe(false);
  });
  it.each(['cycle', 'total'] as const)('pager %s consistency is typed strict for view coordinates', async mode => {
    type Page = { ids: string[]; nextCursor: string | null; offset: number };
    const first: Page = { ids: ['a'], nextCursor: 'cursor-a', offset: 0 };
    const second: Page = { ids: ['b'], nextCursor: 'cursor-b', offset: 1 };
    const third: Page = { ids: ['c'], nextCursor: mode === 'cycle' ? 'cursor-a' : null, offset: 2 };
    const load = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(second).mockResolvedValueOnce(third).mockResolvedValueOnce(first);
    render(<CursorReportPager reportKey="r2-direct-view" label="CVE" enabled waiting="waiting" load={load}
      describe={(page: Page) => ({ checked: true, identity: 'constant', rowIds: page.ids, rowFingerprint: fingerprintReportRows(page.ids), total: 4, wholeTotal: 4, offset: page.offset, nextCursor: page.nextCursor })}>
      {page => <p>{page.ids.join(',')}</p>}
    </CursorReportPager>);
    await screen.findByText('a');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await screen.findByText('b');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await screen.findByRole('alert');
    expect(screen.queryByText('b')).not.toBeInTheDocument();
    expect(screen.queryByText('c')).not.toBeInTheDocument();
    expect(screen.queryAllByRole('navigation')).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
    await screen.findByText('a');
    expect(load.mock.calls[3][0]).toBeUndefined();
  });
  it('legacy generic pagination error still retains confirmation and the attempted cursor', async () => {
    type Page = { ids: string[]; nextCursor: string | null };
    const first: Page = { ids: ['a'], nextCursor: '5' };
    const bad: Page = { ids: ['b', 'b'], nextCursor: null };
    const load = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(bad).mockResolvedValueOnce(bad);
    render(<CursorReportPager reportKey="r2-direct-legacy" label="CVE" enabled waiting="waiting" load={load}
      describe={(page: Page) => ({ checked: true, identity: 'constant', rowIds: page.ids, rowFingerprint: fingerprintReportRows(page.ids), total: 3, nextCursor: page.nextCursor })}>
      {page => <p>{page.ids.join(',')}</p>}
    </CursorReportPager>);
    await screen.findByText('a');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await screen.findByRole('alert');
    expect(screen.getByText('a')).toBeVisible();
    expect(screen.getAllByRole('navigation')).toHaveLength(2);
    fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(3));
    expect(load.mock.calls[2][0]).toBe('5');
  });
});

describe('R2 supplied Secrets checkedAt metadata fences, no invented stamps', () => {
  it('preserves provided valid stamp only on opt-in, and missing stamps remain absent', () => {
    const query = { view: 'report-v1' as const, limit: 25 as const };
    const a = parseCurrentResults(stamped(checkedAt), query);
    const b = parseCurrentResults(stamped(changedAt), query);
    expect(a.coverage.find(item => item.check === 'Secrets')?.checkedAt).toBe(checkedAt);
    expect(a.coverage).not.toEqual(b.coverage);
    const missing = parseCurrentResults(stamped(undefined), query);
    expect(missing.coverage.find(item => item.check === 'Secrets')).not.toHaveProperty('checkedAt');
    const { page, ...legacy } = stamped(checkedAt);
        expect(page).toMatchObject({ version: 1 });
    expect(parseCurrentResults({ ...legacy, nextCursor: null }).coverage.find(item => item.check === 'Secrets')).not.toHaveProperty('checkedAt');
  });
  it('terminal identical rows with distinct supplied stamps remain distinct normalized metadata', () => {
    const terminal = wire('secret', 0, 50);
    const a = parseCurrentResults({ ...terminal, coverage: { ...(terminal.coverage as object), checkedAt } }, { view: 'report-v1', limit: 50 });
    const b = parseCurrentResults({ ...terminal, coverage: { ...(terminal.coverage as object), checkedAt: changedAt } }, { view: 'report-v1', limit: 50 });
    expect(a.nextCursor).toBeNull();
    expect(a.findings).toEqual(b.findings);
    expect(a.coverage).not.toEqual(b.coverage);
    expect(JSON.stringify([a.coverage, reportViewIdentity(a.page)])).not.toBe(JSON.stringify([b.coverage, reportViewIdentity(b.page)]));
  });
  it('compares provided first-page stamp with provided authorized status and first-recovers', async () => {
    responses('secret', [json(stamped(changedAt)), json(stamped(checkedAt))]);
    const authorized = { ...status, perCheck: { secret: { ...status.perCheck!.secret!, checkedAt } } };
    mount('secret', authorized);
    await section('secret').findByRole('alert'); expectCleared('secret');
    retry('secret'); await section('secret').findByText(firstText.secret);
    expect(requests[1].searchParams.has('cursor')).toBe(false);
  });
  it('changed supplied stamp on continuation is metadata drift, not content-only C4', async () => {
    responses('secret', [json(stamped(checkedAt)), json(stamped(changedAt, 25)), json(stamped(changedAt))]);
    mount('secret'); await section('secret').findByText(firstText.secret);
    navigate('secret', 'Далее'); await section('secret').findByRole('alert'); expectCleared('secret');
    retry('secret'); await section('secret').findByText(firstText.secret);
    expect(requests[2].searchParams.has('cursor')).toBe(false);
  });
  it('stamp drift also clears retained C4 recovery; unavailable stamps are not manufactured', async () => {
    responses('secret', [json(stamped(checkedAt)), json(stamped(checkedAt, 25)), json(corruptRows('secret', stamped(checkedAt), 'content')), json(stamped(changedAt))]);
    mount('secret', { ...status, perCheck: { secret: { ...status.perCheck!.secret!, checkedAt } } });
    await section('secret').findByText(firstText.secret);
    navigate('secret', 'Далее'); await section('secret').findByText(tailText.secret);
    navigate('secret', 'Назад'); await section('secret').findByText(/Сохранён прежний подтверждённый снимок/);
    retry('secret'); await waitFor(() => expect(section('secret').queryByText(tailText.secret)).not.toBeInTheDocument());
    expectCleared('secret');
  });
});
