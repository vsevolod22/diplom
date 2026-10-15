import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { parseReportQuery, ReportViewError } from '../../../../server/api/src/scans/report-query';
import { pageSbom, pageSecrets, pageVuln } from '../../../../server/api/src/scans/report-page';
import { parseCurrentResults, parseCurrentSbom, parseCurrentVuln, parseCurrentStatus, BROWSER_SCANS_PATH } from '@/shared/api/scans/scanTransport';
import { reportViewSearch, reportViewIdentity, ReportQueryError } from '@/shared/api/scans/reportView';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { CursorReportPager } from '@/pages/scans/CursorReportPager';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { fingerprintReportRows } from '@/pages/scans/reportRowFingerprint';

// R2 positive corrective assertions. No import/execution of R1 observed-defect tests.
// Only pure backend query/page + local frontend schema/UI; never ledger/runtime/env/real HTTP.
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() => { throw Error('Unexpected network request'); }));
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource']) vi.stubGlobal(name, class { constructor() { throw Error('Network forbidden'); } });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const context = { subject: 'independent-r2', scanId: '10000000-0000-4000-8000-000000000001' };
const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
const metadata = { image, platform: 'linux/amd64', scannerVersion: '0.69.3', checkedAt: '2026-01-02T00:00:00.000Z' };
const changedAt = '2026-01-03T00:00:00.000Z';
const vulns = Array.from({ length: 12 }, (_, i) => ({ findingId: `vuln-${String(i).padStart(3, '0')}`, cveId: `CVE-2026-${1000 + i}`, ecosystem: 'apk' as const, packageName: `pkg-${i}`, installedVersion: '1', fixedVersion: null, severity: 'HIGH' as const }));
const components = Array.from({ length: 12 }, (_, i) => ({ ecosystem: 'apk' as const, name: `package-${String(i).padStart(2, '0')}`, version: '1' }));
const secrets = Array.from({ length: 12 }, (_, i) => ({ findingId: `secret-${i}-0`, ruleId: 'RULE_A', line: i === 0 ? 0 : i % 2 ? null : i, evidenceRef: `result-${i}-secret-0` }));
const raw = (search: string) => Object.fromEntries(new URLSearchParams(search));
function vulnWire(query: Parameters<typeof pageVuln>[1]) {
  const { items, ...paging } = pageVuln(vulns, query, context, { metadata, findings: vulns });
  return { ...metadata, outcome: 'checked', coverage: 'image', findingCount: vulns.length, findings: items, ...paging };
}
function sbomWire(query: Parameters<typeof pageSbom>[1]) {
  const { items, ...paging } = pageSbom(components, query, context, { metadata, components });
  return { ...metadata, os: { name: 'alpine', version: '3.20' }, outcome: 'checked', coverage: 'image', componentCount: components.length, components: items, ...paging };
}
function secretWire(at: string = metadata.checkedAt) {
  const coverage = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: secrets.length, errorCode: null, scannerVersion: metadata.scannerVersion, checkedAt: at };
  const query = parseReportQuery('secret', { view: 'report-v1', limit: '25' })!;
  if (query.kind !== 'secret') throw Error('Wrong kind');
  const { items, ...paging } = pageSecrets(secrets, query, context, { coverage, findings: secrets });
  return { findings: items, coverage, ...paging };
}
const vulnClient = { view: 'report-v1' as const, limit: 5 as const };
const getVuln = (cursor?: string) => {
  const query = parseReportQuery('vuln', raw(reportViewSearch('vuln', vulnClient, cursor)))!;
  if (query.kind !== 'vuln') throw Error('Wrong kind');
  return vulnWire(query);
};
const describeVuln = (page: ReturnType<typeof parseCurrentVuln>) => {
  if (page.outcome !== 'checked') throw Error('Synthetic checked expected');
  return { checked: true, identity: reportViewIdentity(page.page)!, rowIds: page.findings.map(row => row.findingId), rowFingerprint: fingerprintReportRows(page.findings), total: page.page!.matchedCount, wholeTotal: page.page!.totalCount, offset: page.page!.offset, nextCursor: page.nextCursor };
};
function pager(load: (cursor?: string) => Promise<ReturnType<typeof parseCurrentVuln>>) {
  return render(<CursorReportPager reportKey="independent-r2" label="CVE" enabled waiting="waiting" load={load} describe={describeVuln}>
    {page => page.outcome === 'checked' ? <div>{page.findings.map(row => <span key={row.findingId}>{row.findingId}</span>)}</div> : null}
  </CursorReportPager>);
}

it('R1 corrected: actual backend accepts mixed-case SBOM and equivalent-case continuation decodes', () => {
  const client = { view: 'report-v1' as const, limit: 5 as const, name: 'PaCkAgE-' };
  const query = parseReportQuery('sbom', raw(reportViewSearch('sbom', client)))!;
  if (query.kind !== 'sbom') throw Error('Wrong kind');
  const first = sbomWire(query);
  const decoded = parseCurrentSbom(first, client);
  expect(decoded.page!.filters.name).toBe('package-');
  expect(decoded.page!.matchedCount).toBe(12);
  const equivalent = { ...client, name: 'PACKAGE-' };
  const nextQuery = parseReportQuery('sbom', raw(reportViewSearch('sbom', equivalent, first.nextCursor!)))!;
  if (nextQuery.kind !== 'sbom') throw Error('Wrong kind');
  expect(parseCurrentSbom(sbomWire(nextQuery), equivalent, first.nextCursor!).page!.offset).toBe(5);
});
it('R2 corrected: full severity set and omitted all share actual backend continuation binding', () => {
  const client = { ...vulnClient, severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as ('CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN')[] };
  const query = parseReportQuery('vuln', raw(reportViewSearch('vuln', client)))!;
  if (query.kind !== 'vuln') throw Error('Wrong kind');
  const first = vulnWire(query);
  expect(parseCurrentVuln(first, client).page!.filters.severity).toBeNull();
  const next = getVuln(first.nextCursor!);
  expect(parseCurrentVuln(next, vulnClient, first.nextCursor!).page!.offset).toBe(5);
  const changed = parseReportQuery('vuln', raw(reportViewSearch('vuln', { ...vulnClient, severity: ['LOW'] }, first.nextCursor!)))!;
  if (changed.kind !== 'vuln') throw Error('Wrong kind');
  expect(() => vulnWire(changed)).toThrow(ReportViewError);
});
it('R3 corrected: invalid Rule ID rejected locally; exact80 ASCII remains backend-compatible', () => {
  for (const ruleId of ['rule/path', 'a'.repeat(81)]) expect(() => reportViewSearch('secret', { view: 'report-v1', ruleId })).toThrow(ReportQueryError);
  const ruleId = 'A'.repeat(77) + '._-';
  expect(parseReportQuery('secret', raw(reportViewSearch('secret', { view: 'report-v1', ruleId })))!.filters).toEqual({ ruleId, linePresence: null });
});
it('R4 corrected: actual-page overlap strictly clears data/navigation and recovers omitted-first', async () => {
  const cursors: (string | undefined)[] = [];
  let corrupt = true;
  pager(async cursor => {
    cursors.push(cursor);
    const wire = getVuln(cursor);
    if (cursor && corrupt) { wire.findings = [vulns[0], ...wire.findings.slice(1)]; corrupt = false; }
    return parseCurrentVuln(wire, vulnClient, cursor);
  });
  await screen.findByText('vuln-000');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
  await screen.findByRole('alert');
  expect(screen.queryByText('vuln-000')).toBeNull();
  expect(screen.queryAllByRole('navigation')).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
  await screen.findByText('vuln-000');
  expect(cursors[1]).toBeTruthy();
  expect(cursors[2]).toBeUndefined();
});
it('R5 corrected: terminal metadata differs; line0 stays meaningful, evidence stripped, legacy stamp absent', () => {
  const client = { view: 'report-v1' as const, limit: 25 as const };
  const a = parseCurrentResults(secretWire(), client), b = parseCurrentResults(secretWire(changedAt), client);
  expect(a.nextCursor).toBeNull();
  expect(a.findings).toEqual(b.findings);
  expect(a.coverage).not.toEqual(b.coverage);
  expect(a.findings[0].line).toBe(0);
  expect(a.findings[0].evidenceRef).toBeUndefined();
  const { page, ...legacy } = secretWire();
    expect(page.version).toBe(1);
  expect(parseCurrentResults(legacy).coverage[0].checkedAt).toBeUndefined();
});
it('R5 archive parity: decoded archive-shaped status rejects mismatched supplied stamp and recovers FIRST', async () => {
  const perCheck = { check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, findingCount: 12, scannerVersion: '0.69.3', checksVersion: 'synthetic-archive-v1', checkedAt: metadata.checkedAt };
  const status = parseCurrentStatus({ scanId: context.scanId, state: 'completed', digest: 'sha256:' + 'a'.repeat(64), platform: 'linux/amd64', imageReference: image, checks: ['secret'], perCheck: { secret: perCheck }, result: perCheck });
  expect(status.perCheck!.secret!.checkedAt).toBe(metadata.checkedAt);
  const replies = [secretWire(changedAt), secretWire()];
  const requests: URL[] = [];
  vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
    const url = new URL(path, 'https://synthetic.invalid');
    if (url.origin !== 'https://synthetic.invalid' || url.pathname !== `${BROWSER_SCANS_PATH}/${context.scanId}/results` || options.method !== 'GET') throw Error('Unexpected endpoint');
    requests.push(url);
    const reply = replies.shift(); if (!reply) throw Error('Unexpected extra request');
    return new Response(JSON.stringify(reply));
  }));
  const transport = createAuthorizedScanTransport({ subject: context.subject, currentSubject: () => context.subject });
  render(<ScanReportSections status={status} transport={transport} scope={['independent-r2-archive']} demo={false} filter="all" onResetFilter={() => {}} />);
  await screen.findByRole('alert');
  expect(screen.queryByText('ID: secret-0-0')).toBeNull();
  expect(screen.queryAllByRole('navigation')).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку Secrets' }));
  await screen.findByText('ID: secret-0-0');
  expect(requests).toHaveLength(2);
  expect(requests.every(url => !url.searchParams.has('cursor'))).toBe(true);
});
for (const mode of ['403', 'session'] as const) {
  it(`C4 access fence remains strict after retained snapshot: ${mode}`, async () => {
    let subject: string | null = context.subject;
    let calls = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
      const url = new URL(path, 'https://synthetic.invalid');
      if (url.origin !== 'https://synthetic.invalid' || url.pathname !== `${BROWSER_SCANS_PATH}/${context.scanId}/vuln` || options.method !== 'GET') throw Error('Unexpected endpoint');
      calls++;
      if (calls === 4) return new Response('{}', { status: 403 });
      const wire = getVuln(url.searchParams.get('cursor') ?? undefined);
      if (calls === 3) wire.findings = wire.findings.map((row, i) => i === 0 ? { ...row, fixedVersion: '9' } : row);
      return new Response(JSON.stringify(wire));
    }));
    const transport = createAuthorizedScanTransport({ subject: context.subject, currentSubject: () => subject });
    pager(cursor => transport.vuln(context.scanId, cursor, undefined, vulnClient));
    await screen.findByText('vuln-000');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await screen.findByText('vuln-005');
    fireEvent.click(screen.getByRole('button', { name: 'Назад · CVE · сверху' }));
    await screen.findByText(/Сохранён прежний подтверждённый снимок/);
    expect(screen.queryByText('vuln-005')).not.toBeNull();
    expect((screen.getByRole('button', { name: 'Далее · CVE · сверху' }) as HTMLButtonElement).disabled).toBe(true);
    if (mode === 'session') subject = 'other-synthetic';
    fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
    await waitFor(() => expect(screen.queryByText('vuln-005')).toBeNull());
    expect(screen.queryAllByRole('navigation')).toHaveLength(0);
    expect(screen.queryByText(/Сохранён прежний подтверждённый снимок/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Повторить загрузку CVE' })).toBeNull();
    expect(calls).toBe(mode === 'session' ? 3 : 4);
  });
}
