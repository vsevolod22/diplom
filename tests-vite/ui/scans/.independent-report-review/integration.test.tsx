import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { parseReportQuery, ReportViewError } from '../../../../server/api/src/scans/report-query';
import { pageSbom, pageSecrets, pageVuln } from '../../../../server/api/src/scans/report-page';
import { parseCurrentResults, parseCurrentSbom, parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import { reportViewSearch, reportViewIdentity, ReportViewContractError } from '@/shared/api/scans/reportView';
import { CursorReportPager } from '@/pages/scans/CursorReportPager';
import { fingerprintReportRows } from '@/pages/scans/reportRowFingerprint';

// Independent regressions for the corrected R1–R5 defects, using actual pure backend pages.
// Only pure query/page + local schema/UI leaves; no runtime/ledger/env/HTTP/test imports.
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() => { throw Error('Network forbidden'); }));
  vi.stubGlobal('XMLHttpRequest', class { constructor() { throw Error('Network forbidden'); } });
  vi.stubGlobal('WebSocket', class { constructor() { throw Error('Network forbidden'); } });
  vi.stubGlobal('EventSource', class { constructor() { throw Error('Network forbidden'); } });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const context = { subject: 'independent-synthetic', scanId: '10000000-0000-4000-8000-000000000001' };
const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
const metadata = { image, platform: 'linux/amd64', scannerVersion: '0.69.3', checkedAt: '2026-01-02T00:00:00.000Z' };
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
function secretWire(query: Parameters<typeof pageSecrets>[1], checkedAt = metadata.checkedAt) {
  const coverage = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: secrets.length, errorCode: null, scannerVersion: metadata.scannerVersion, checkedAt };
  const { items, ...paging } = pageSecrets(secrets, query, context, { coverage, findings: secrets });
  return { findings: items, coverage, ...paging };
}

it('R1 regression: uppercase SBOM queries accept the canonical lowercase server echo', () => {
  const client = { view: 'report-v1' as const, limit: 5 as const, name: 'PACKAGE-' };
  const server = parseReportQuery('sbom', raw(reportViewSearch('sbom', client)))!;
  if (server.kind !== 'sbom') throw Error('Wrong kind');
  const wire = sbomWire(server);
  expect(wire.page.filters).toEqual({ ecosystem: null, name: 'package-' });
  expect(wire.page.matchedCount).toBe(12);
  const decoded = parseCurrentSbom(wire, client);
  expect(decoded.page).toEqual(wire.page);
  expect(decoded.outcome).toBe('checked');
  if (decoded.outcome !== 'checked') throw Error('Synthetic checked expected');
  expect(decoded.components).toEqual(wire.components);
  expect(() => parseCurrentSbom(wire, { ...client, name: 'different' })).toThrow(ReportViewContractError);
});
it('R2 regression: the full severity set accepts the canonical null/all server echo', () => {
  const client = { view: 'report-v1' as const, limit: 5 as const, severity: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const };
  const query = { ...client, severity: [...client.severity] };
  const server = parseReportQuery('vuln', raw(reportViewSearch('vuln', query)))!;
  if (server.kind !== 'vuln') throw Error('Wrong kind');
  const wire = vulnWire(server);
  expect(wire.page.filters).toEqual({ severity: null });
  const decoded = parseCurrentVuln(wire, query);
  expect(decoded.page).toEqual(wire.page);
  expect(decoded.findings).toEqual(wire.findings);
  expect(reportViewSearch('vuln', query)).toBe(reportViewSearch('vuln', { view: 'report-v1', limit: 5 }));
  expect(() => parseCurrentVuln(wire, { ...query, severity: ['HIGH'] })).toThrow(ReportViewContractError);
});
it('R3 regression: frontend and backend reject unsupported Secrets rule IDs', () => {
  for (const ruleId of ['rule/path', 'a'.repeat(81)]) {
    expect(() => reportViewSearch('secret', { view: 'report-v1', ruleId })).toThrow(ReportViewContractError);
    expect(() => parseReportQuery('secret', { view: 'report-v1', ruleId })).toThrow(ReportViewError);
  }
  const ruleId = 'A'.repeat(77) + '._-';
    const search = reportViewSearch('secret', { view: 'report-v1', ruleId });
    expect(new URLSearchParams(search).get('ruleId')).toBe(ruleId);
    expect(parseReportQuery('secret', raw(search))?.filters).toEqual({ ruleId, linePresence: null });
});
it('R4 regression: inter-page duplicate IDs clear data/navigation and retry the first cursor', async () => {
  const client = { view: 'report-v1' as const, limit: 5 as const };
  const cursors: (string | undefined)[] = [];
  const load = async (cursor: string | undefined) => {
    cursors.push(cursor);
    const server = parseReportQuery('vuln', raw(reportViewSearch('vuln', client, cursor)))!;
    if (server.kind !== 'vuln') throw Error('Wrong kind');
    const wire = vulnWire(server);
    if (cursor) wire.findings = [vulns[0], ...wire.findings.slice(1)];
    return parseCurrentVuln(wire, client, cursor);
  };
  const describe = (page: ReturnType<typeof parseCurrentVuln>) => {
    if (page.outcome !== 'checked') throw Error('Synthetic checked expected');
    return { checked: true, identity: reportViewIdentity(page.page)!, rowIds: page.findings.map(row => row.findingId), rowFingerprint: fingerprintReportRows(page.findings), total: page.page!.matchedCount, wholeTotal: page.page!.totalCount, offset: page.page!.offset, nextCursor: page.nextCursor };
  };
  render(<CursorReportPager reportKey="independent-synthetic-v1" label="CVE" enabled waiting="waiting" load={load} describe={describe}>
    {page => page.outcome === 'checked' ? <div>{page.findings.map(row => <span key={row.findingId}>{row.findingId}</span>)}</div> : null}
  </CursorReportPager>);
  await screen.findByText('vuln-000');
  fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
  await screen.findByRole('alert');
  expect(screen.queryByText('vuln-000')).toBeNull();
  expect(screen.queryByText('vuln-005')).toBeNull();
  expect(screen.queryByRole('navigation')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Далее · CVE · сверху' })).toBeNull();
  expect(screen.getByRole('alert').textContent).toMatch(/Прежние данные и cursors сброшены/);
  fireEvent.click(screen.getByRole('button', { name: 'Повторить загрузку CVE' }));
  await screen.findByText('vuln-000');
  await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  expect(cursors).toHaveLength(3);
  expect(cursors[1]).toBeTruthy();
  expect(cursors[2]).toBeUndefined();
  expect(screen.getAllByRole('navigation')).toHaveLength(2);
  expect(screen.getByText('Строки 1–5')).toBeTruthy();
});
it('R5 regression: meaningful Secrets checkedAt survives normalization as an identity fence', () => {
  const client = { view: 'report-v1' as const, limit: 25 as const };
  const server = parseReportQuery('secret', raw(reportViewSearch('secret', client)))!;
  if (server.kind !== 'secret') throw Error('Wrong kind');
  const a = parseCurrentResults(secretWire(server), client);
  const b = parseCurrentResults(secretWire(server, '2026-01-03T00:00:00.000Z'), client);
  expect(a.nextCursor).toBeNull();
  expect(a).not.toEqual(b);
  expect(a.coverage.find(item => item.check === 'Secrets')?.checkedAt).toBe(metadata.checkedAt);
  expect(b.coverage.find(item => item.check === 'Secrets')?.checkedAt).toBe('2026-01-03T00:00:00.000Z');
  expect(a.coverage).not.toEqual(b.coverage);
  expect(JSON.stringify([a.coverage, reportViewIdentity(a.page)])).not.toBe(JSON.stringify([b.coverage, reportViewIdentity(b.page)]));
  expect(reportViewIdentity(a.page)).toEqual(reportViewIdentity(b.page));
  expect(fingerprintReportRows(a.findings)).toEqual(fingerprintReportRows(b.findings));
  expect(a.findings).toEqual(b.findings);
    const legacy = secretWire(server);
    expect(parseCurrentResults({ findings: legacy.findings, coverage: legacy.coverage, nextCursor: null }).coverage.find(item => item.check === 'Secrets')).not.toHaveProperty('checkedAt');
});
it('positive seam: actual pure backend pages decode for all kinds, all limits, natural cursor walks and checked no-match', () => {
  for (const limit of [5, 10, 25, 50] as const) {
    for (const kind of ['vuln', 'sbom', 'secret'] as const) {
      let cursor: string | undefined;
      let returned = 0;
      do {
        const client = { view: 'report-v1' as const, limit };
        const server = parseReportQuery(kind, raw(reportViewSearch(kind, client, cursor)))!;
        const wire = server.kind === 'vuln' ? vulnWire(server) : server.kind === 'sbom' ? sbomWire(server) : secretWire(server);
        const decoded = kind === 'vuln' ? parseCurrentVuln(wire, client, cursor) : kind === 'sbom' ? parseCurrentSbom(wire, client, cursor) : parseCurrentResults(wire, client, cursor);
        returned += decoded.page!.returnedCount;
        expect(decoded.page!.totalCount).toBe(12);
        cursor = decoded.nextCursor ?? undefined;
      } while (cursor);
      expect(returned).toBe(12);
    }
  }
  const client = { view: 'report-v1' as const, name: 'absent' };
  const server = parseReportQuery('sbom', raw(reportViewSearch('sbom', client)))!;
  if (server.kind !== 'sbom') throw Error('Wrong kind');
  const result = parseCurrentSbom(sbomWire(server), client);
  expect(result.page!.matchedCount).toBe(0);
  expect(result.page!.totalCount).toBe(12);
});
