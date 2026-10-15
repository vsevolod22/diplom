import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CursorReportPager } from '@/pages/scans/CursorReportPager';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { parseCurrentStatus, parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import { createAuthorizedScanTransport, ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import type { PageDescription } from '@/pages/scans/CursorReportPager';
import type { ScanTransport } from '@/shared/api/scans/scanTransport';

const reportCursor = 'task39:25/+==';
const pageMetadata = (offset: number, returnedCount: number, totalCount: number) => ({
  version: 1 as const, limit: 25 as const, offset, returnedCount, totalCount, matchedCount: totalCount,
  sort: 'severity:desc' as const, filters: { severity: null },
});
const fillerFindings = (offset: number) => Array.from({ length: 24 }, (_, index) => ({
  findingId: `filler-${offset + index}`, cveId: `CVE-2026-${2000 + offset + index}`,
  ecosystem: 'apk' as const, packageName: `fixture-${offset + index}`, installedVersion: '1', fixedVersion: null, severity: 'HIGH' as const,
}));

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const describe = (page: { rows: string[]; next: string | null; checked?: boolean }): PageDescription => ({
  checked: page.checked ?? true, identity: 'identity', rowIds: page.rows, rowFingerprint: JSON.stringify(page.rows), total: page.checked === false ? null : 2, nextCursor: page.next,
});
it('shows labelled top/bottom actual pagers with one atomic announcement; both pending controls share one request', async () => {
  let finish!: (page: { rows: string[]; next: string | null }) => void;
  const load = vi.fn().mockResolvedValueOnce({ rows: ['first'], next: '1' }).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<CursorReportPager reportKey="test" label="CVE" enabled waiting="waiting" load={load} describe={describe}>{page => <p>{page.rows.join()}</p>}</CursorReportPager>);
  await screen.findByText('first');
  const top = screen.getByRole('navigation', { name: 'Пагинация CVE · сверху' });
  const bottom = screen.getByRole('navigation', { name: 'Пагинация CVE · снизу' });
  expect(screen.getAllByRole('status')).toHaveLength(1);
  fireEvent.click(within(top).getByRole('button', { name: 'Далее · CVE · сверху' }));
  fireEvent.click(within(bottom).getByRole('button', { name: 'Далее · CVE' }));
  expect(load).toHaveBeenCalledTimes(2);
  expect(within(bottom).getByRole('button', { name: 'Далее · CVE' }).hasAttribute('disabled')).toBe(true);
  finish({ rows: ['second'], next: null });
  await screen.findByText('Строки 2–2');
});
it.each(['unsupported', 'missing', 'scanning', 'zero', 'single'])('has no meaningless navigation: %s', async mode => {
  const checked = !['unsupported'].includes(mode);
  const page = { rows: mode === 'single' ? ['only'] : [], next: null, checked };
  const load = vi.fn(async () => page);
  render(<CursorReportPager reportKey="test" label="CVE" enabled={!['missing', 'scanning'].includes(mode)} waiting="waiting" load={load}
    describe={data => ({ ...describe(data), total: checked ? data.rows.length : null })}>{() => <p>actual result</p>}</CursorReportPager>);
  if (!['missing', 'scanning'].includes(mode)) await screen.findByText('actual result');
  expect(screen.queryByRole('navigation')).toBeNull();
  expect(screen.queryByRole('button')).toBeNull();
  expect(load).toHaveBeenCalledTimes(['missing', 'scanning'].includes(mode) ? 0 : 1);
});
it('clears rows and both pagers on access loss', async () => {
  const load = vi.fn().mockResolvedValueOnce({ rows: ['private'], next: '1' }).mockRejectedValueOnce(new ScanAccessError(403));
  render(<CursorReportPager reportKey="test" label="CVE" enabled waiting="waiting" load={load} describe={describe}>{page => <p>{page.rows.join()}</p>}</CursorReportPager>);
  await screen.findByText('private');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
  await screen.findByText(/Доступ к отчёту утрачен/);
  expect(screen.queryByText('private')).toBeNull(); expect(screen.queryByRole('navigation')).toBeNull();
});

const clock = Date.parse('2026-10-08T12:00:00.000Z');
const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', schemaVersion: 2, source: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`, manifestDigest: `sha256:${'b'.repeat(64)}`, artifactSha256: 'c'.repeat(64), metadataSha256: 'd'.repeat(64), dbSha256: 'e'.repeat(64), updatedAt: '2026-10-06T12:00:00.000000001Z', downloadedAt: '2026-10-06T13:00:00.000Z', nextUpdate: '2026-10-07T12:00:00.000Z' };
const metadata = { resultContractVersion: 2, db, dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: clock, status: 'stale-but-usable', warnings: ['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE'] }, workerCheckedAt: clock, checkedAt: new Date(clock).toISOString(), usableUntil: '2026-10-20T12:00:00.000000001Z' };
const target = { image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64' };
function mountV2(patch: Record<string, unknown> = {}, multiple = false) {
  const count = multiple ? 26 : 1;
  const check = { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: count, scannerVersion: '0.69.3' };
  const status = parseCurrentStatus({ scanId: 'test', state: 'completed', digest: `sha256:${'a'.repeat(64)}`, ...target, imageReference: target.image, checks: ['vuln'], perCheck: { vuln: check }, result: check });
  const transport = { ...unavailableScanTransport, kind: 'live' as const, vuln: vi.fn(async (...args: Parameters<ScanTransport['vuln']>) => {
    const [, cursor, , query] = args;
    expect(query).toMatchObject({ view: 'report-v1', limit: 25 });
    const wire: Record<string, unknown> = { ...metadata, ...target, outcome: 'checked', coverage: 'image', findingCount: count, scannerVersion: '0.69.3', findings: [{ findingId: cursor ? 'row2' : 'row1', cveId: cursor ? 'CVE-2026-1235' : 'CVE-2026-1234', ecosystem: 'apk', packageName: 'fixture', installedVersion: '1', fixedVersion: null, severity: 'HIGH' }, ...(multiple && !cursor ? fillerFindings(0) : [])], nextCursor: multiple && !cursor ? reportCursor : null,
          page: pageMetadata(cursor ? 25 : 0, multiple && !cursor ? 25 : 1, count), ...(!multiple || cursor ? patch : {}) };
    for (const [key, value] of Object.entries(wire)) if (value === undefined) delete wire[key];
    return parseCurrentVuln(wire, query, cursor);
  }) };
  render(<ScanReportSections status={status} transport={transport} demo={false} scope={['alice',1]} filter="all" onResetFilter={() => {}} />);
}
it('shows warnings/saved clocks visibly and publication vs usableUntil in metadata without current-clock inference', async () => {
  mountV2();
  await screen.findByText(/DB_DATA_OLDER_THAN_24H:/);
  expect(screen.getByText(/DB_PUBLICATION_OVERDUE:/)).toBeTruthy();
  expect(screen.getByText(/47 полных ч/)).toBeTruthy();
  expect(screen.getByText(/usableUntil · предел политики/)).toBeTruthy();
  expect(screen.getByText(/NextUpdate · ожидаемая публикация/)).toBeTruthy();
});
it('fails closed when page receipt differs from confirmed status, including valid independently evaluated metadata', async () => {
  mountV2({ dbPolicy: { ...metadata.dbPolicy, evaluatedAt: clock + 1 } });
  await screen.findByText(/Прежние данные и cursors сброшены/);
  expect(screen.queryByText('CVE-2026-1234')).toBeNull();
});
it('clears confirmed rows on cross-page v2 receipt drift, not the content-only stale exception', async () => {
  mountV2({ dbPolicy: { ...metadata.dbPolicy, evaluatedAt: clock + 1 } }, true);
  await screen.findByText('CVE-2026-1234');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
  await screen.findByText(/Прежние данные и cursors сброшены/);
  expect(screen.queryByText('CVE-2026-1234')).toBeNull();
  expect(screen.queryByText('CVE-2026-1235')).toBeNull();
  expect(screen.queryByText(/Сохранён прежний подтверждённый снимок/)).toBeNull();
});
it('rejects stripped entire v2 receipt relative to the v2 status', async () => {
  mountV2({ resultContractVersion: undefined, dbPolicy: undefined, workerCheckedAt: undefined, usableUntil: undefined });
  await screen.findByRole('alert'); expect(screen.queryByText('CVE-2026-1234')).toBeNull();
});

const receiptMutations: [string, Record<string, unknown>][] = [
  ['unknown result version', { resultContractVersion: 3 }],
  ['unknown policy version', { dbPolicy: { ...metadata.dbPolicy, version: 3 } }],
  ['missing policy', { dbPolicy: undefined }],
  ['partially stripped receipt', { workerCheckedAt: undefined, usableUntil: undefined }],
  ['inconsistent warnings', { dbPolicy: { ...metadata.dbPolicy, warnings: [] } }],
  ['inexact usableUntil', { usableUntil: '2026-10-20T12:00:00.000Z' }],
  ['mutated checkedAt', { checkedAt: '2026-10-08T12:00:00.001Z' }],
  ['mutated worker clock', { workerCheckedAt: clock + 1 }],
  ['mutated evaluation clock', { dbPolicy: { ...metadata.dbPolicy, evaluatedAt: clock - 1 } }],
  ['mutated DB timestamp', { db: { ...db, updatedAt: '2026-10-06T12:00:00.000000002Z' } }],
];
const reportId = '00000000-0000-4000-8000-000000000039';
function wirePage(cursor: string | null, patch: Record<string, unknown> = {}) {
  const index = cursor === 'task39:50/+==' ? 2 : cursor ? 1 : 0;
  const page: Record<string, unknown> = { ...metadata, ...target, outcome: 'checked', coverage: 'image', findingCount: 51,
    scannerVersion: '0.69.3', findings: [{ findingId: `row${index}`, cveId: `CVE-2026-123${index}`,
      ecosystem: 'apk', packageName: 'fixture', installedVersion: '1', fixedVersion: '9', severity: 'CRITICAL' }, ...(cursor === 'task39:50/+==' ? [] : fillerFindings(cursor ? 25 : 0))],
    nextCursor: cursor === 'task39:50/+==' ? null : cursor ? 'task39:50/+==' : reportCursor,
    page: pageMetadata(cursor === 'task39:50/+==' ? 50 : cursor ? 25 : 0, cursor === 'task39:50/+==' ? 1 : 25, 51), ...patch };
  for (const [key, value] of Object.entries(page)) if (value === undefined) delete page[key];
  return page;
}
function archiveStatus(legacy = false) {
  const check: Record<string, unknown> = { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked',
    findingCount: 51, scannerVersion: '0.69.3', checksVersion: 'archive1', errorCode: null };
  if (legacy) for (const key of ['resultContractVersion', 'dbPolicy', 'usableUntil', 'workerCheckedAt']) delete check[key];
  return { scanId: reportId, state: 'completed', digest: `sha256:${'a'.repeat(64)}`, platform: target.platform,
    imageReference: target.image, checks: ['vuln'], perCheck: { vuln: check }, result: check };
}
async function mountAuthorized(reply: (cursor: string | null, call: number) => Response | Promise<Response>, legacy = false) {
  const cursors: (string | null)[] = [];
  let subject: string | null = 'alice';
  const fetchMock = vi.fn(async (path: string) => {
    const url = new URL(path, window.location.origin);
    if (url.pathname.endsWith('/vuln')) {
          expect(url.pathname).toBe(`/api/v1/browser/scans/${reportId}/vuln`);
          expect(url.searchParams.get('view')).toBe('report-v1');
          expect(url.searchParams.get('limit')).toBe('25');
          expect(url.searchParams.get('sort')).toBe('severity:desc');
          const cursor = url.searchParams.get('cursor'); cursors.push(cursor); return reply(cursor, cursors.length);
        }
    expect(url.pathname).toBe(`/api/v1/browser/scans/${reportId}`);
    return new Response(JSON.stringify(archiveStatus(legacy)), { status: 200 });
  });
  vi.stubGlobal('fetch', fetchMock);
  const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => subject });
  const status = await transport.get(reportId);
  render(<ScanReportSections status={status} transport={transport} demo={false} scope={['alice', 1]} filter="all" onResetFilter={() => {}} />);
  await screen.findByText('CVE-2026-1230');
  return { cursors, fetchMock, changeSubject: () => { subject = 'bob'; } };
}
const response = (page: unknown, status = 200) => new Response(JSON.stringify(page), { status });
const next = () => fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
const back = () => fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE · сверху' }));
const retry = () => fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
async function expectStrictReset() {
  await screen.findByText(/Прежние данные и cursors сброшены/);
  expect(screen.queryByRole('list', { name: 'Находки CVE' })).toBeNull();
  expect(screen.queryByRole('navigation')).toBeNull();
  expect(screen.queryByText(/Сохранён прежний подтверждённый снимок/)).toBeNull();
  expect(screen.queryByText(/(Совпадений во всём отчёте|Полный итог) CVE:/)).toBeNull();
}

it.each(receiptMutations)('P2 authorized decoder→pager strictly resets %s after a confirmed continuation', async (_name, patch) => {
  const { cursors } = await mountAuthorized((cursor, call) => response(wirePage(cursor, call === 2 ? patch : {})));
  next(); await expectStrictReset();
  retry(); await screen.findByText('CVE-2026-1230');
  expect(cursors).toEqual([null, reportCursor, null]);
  expect(screen.getAllByRole('navigation')).toHaveLength(2);
});
it.each(['Back', 'forward'] as const)('P2 resets malformed receipt on %s revisit and establishes a new first-page baseline', async direction => {
  const { cursors } = await mountAuthorized((cursor, call) => response(wirePage(cursor, call === (direction === 'Back' ? 3 : 4) ? { dbPolicy: undefined } : {})));
  next(); await screen.findByText('CVE-2026-1231'); back();
  if (direction === 'forward') { await screen.findByText('CVE-2026-1230'); next(); }
  await expectStrictReset(); retry(); await screen.findByText('CVE-2026-1230');
  expect(cursors).toEqual(direction === 'Back' ? [null, reportCursor, null, null] : [null, reportCursor, null, reportCursor, null]);
  next(); await screen.findByText('CVE-2026-1231');
  expect(screen.queryByRole('alert')).toBeNull();
});
it('P2 clears C4 retained historical rows too when first-cursor recovery rejects metadata', async () => {
  const { cursors } = await mountAuthorized((cursor, call) => response(wirePage(cursor, call === 3
    ? { findings: [{ ...(wirePage(cursor).findings as Record<string, unknown>[])[0], severity: 'LOW', fixedVersion: '1.1' }, ...(wirePage(cursor).findings as Record<string, unknown>[]).slice(1)] }
    : call === 4 ? { usableUntil: 'bad' } : {})));
  next(); await screen.findByText('CVE-2026-1231'); back();
  await screen.findByText(/Сохранён прежний подтверждённый снимок/);
  expect(screen.getByText('CVE-2026-1231')).toBeTruthy();
  for (const button of screen.getAllByRole('button', { name: /^(Назад|Далее) · CVE/ })) expect(button.hasAttribute('disabled')).toBe(true);
  retry(); await expectStrictReset(); retry(); await screen.findByText('CVE-2026-1230');
  expect(cursors).toEqual([null, reportCursor, null, null, null]);
});
it.each(['503', 'network'] as const)('P2 control retains confirmed rows/navigation and retries the same cursor for %s', async mode => {
  const { cursors } = await mountAuthorized((cursor, call) => {
    if (call === 2) { if (mode === 'network') throw new TypeError('Synthetic offline'); return response({ errorCode: 'SCAN_UNAVAILABLE' }, 503); }
    return response(wirePage(cursor));
  });
  next(); await screen.findByText(/Показана предыдущая подтверждённая страница/);
  expect(screen.getByText('CVE-2026-1230')).toBeTruthy(); expect(screen.getAllByRole('navigation')).toHaveLength(2);
  retry(); await screen.findByText('CVE-2026-1231'); expect(cursors).toEqual([null, reportCursor, reportCursor]);
});
it('P2 control rejects independently valid receipt drift and retries first', async () => {
  const { cursors } = await mountAuthorized((cursor, call) => response(wirePage(cursor, call === 2 ? { dbPolicy: { ...metadata.dbPolicy, evaluatedAt: clock + 1 } } : {})));
  next(); await expectStrictReset(); retry(); await screen.findByText('CVE-2026-1230'); expect(cursors).toEqual([null, reportCursor, null]);
});
it('P2 control accepts stable full-content Back/forward revisits', async () => {
  const { cursors } = await mountAuthorized(cursor => response(wirePage(cursor)));
  next(); await screen.findByText('CVE-2026-1231'); back(); await screen.findByText('CVE-2026-1230');
  next(); await screen.findByText('CVE-2026-1231'); expect(screen.queryByRole('alert')).toBeNull();
  expect(cursors).toEqual([null, reportCursor, null, reportCursor]);
});
it.each(['403', 'session'] as const)('P2 control clears confirmed rows/navigation on %s without recovery fetch', async mode => {
  const { cursors, changeSubject } = await mountAuthorized((cursor, call) => response(call === 2 ? {} : wirePage(cursor), call === 2 ? 403 : 200));
  if (mode === 'session') changeSubject();
  next(); await screen.findByText(/Доступ к отчёту утрачен/);
  expect(screen.queryByText('CVE-2026-1230')).toBeNull(); expect(screen.queryByRole('navigation')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Повторить загрузку CVE' })).toBeNull();
  expect(cursors).toEqual(mode === 'session' ? [null] : [null, reportCursor]);
});
it.each(['503', '403', 'session'] as const)('P2 C4 historical recovery control preserves or clears only as appropriate: %s', async mode => {
  const { cursors, changeSubject } = await mountAuthorized((cursor, call) => {
    if (call === 4) return response({}, mode === '503' ? 503 : 403);
    return response(wirePage(cursor, call === 3 ? { findings: [{ ...(wirePage(cursor).findings as Record<string, unknown>[])[0], severity: 'LOW' }, ...(wirePage(cursor).findings as Record<string, unknown>[]).slice(1)] } : {}));
  });
  next(); await screen.findByText('CVE-2026-1231'); back(); await screen.findByText(/Сохранён прежний подтверждённый снимок/);
  if (mode === 'session') changeSubject();
  retry();
  if (mode === '503') {
    await screen.findByText(/Показана предыдущая подтверждённая страница/);
    expect(screen.getByText('CVE-2026-1231')).toBeTruthy();
    expect(screen.getByText(/Сохранён прежний подтверждённый снимок/)).toBeTruthy();
    for (const button of screen.getAllByRole('button', { name: /^(Назад|Далее) · CVE/ })) expect(button.hasAttribute('disabled')).toBe(true);
    retry(); await screen.findByText('CVE-2026-1230'); expect(cursors).toEqual([null, reportCursor, null, null, null]);
  } else {
    await screen.findByText(/Доступ к отчёту утрачен/);
    expect(screen.queryByText('CVE-2026-1231')).toBeNull(); expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByText(/Сохранён прежний подтверждённый снимок/)).toBeNull();
    expect(cursors).toEqual(mode === 'session' ? [null, reportCursor, null] : [null, reportCursor, null, null]);
  }
});
it('P2 all-copy fully stripped checked archive is legacy-equivalent with explicit unconfirmed policy', async () => {
  await mountAuthorized(cursor => { const page = wirePage(cursor); for (const key of ['resultContractVersion', 'dbPolicy', 'usableUntil', 'workerCheckedAt']) delete page[key]; return response(page); }, true);
  expect(screen.getByText(/Legacy CVE: versioned policy evidence не предоставлено/)).toBeTruthy();
  expect(screen.queryByText(/DB_DATA_OLDER_THAN_24H:/)).toBeNull(); expect(screen.queryByText(/usableUntil · предел политики/)).toBeNull();
  next(); await screen.findByText('CVE-2026-1231'); expect(screen.queryByRole('alert')).toBeNull();
});
