import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCurrentResults, parseCurrentSbom, parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import { createAuthorizedScanTransport, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { fixtureScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { normalizeReportQuery, reportViewIdentity, reportViewSearch, ReportCursorResetError, ReportViewContractError } from '@/shared/api/scans/reportView';
import type { SbomReportQuery, SecretReportQuery, VulnReportQuery } from '@/shared/api/scans/reportView';
import { finding, meta, scanId, sbomWire, secretWire, v2Evidence, vulnWire } from './reportViewSynthetic';
const jsonResponse = (value: unknown) => new Response(JSON.stringify(value));
const query: VulnReportQuery = { view: 'report-v1', limit: 5 };
const sbomQuery: SbomReportQuery = { view: 'report-v1', limit: 5 };
const secretQuery: SecretReportQuery = { view: 'report-v1', limit: 5 };
beforeEach(() => vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('Unexpected network request')))));
afterEach(() => vi.unstubAllGlobals());

describe('opt-in report-view decoding', () => {
  it('preserves whole totals and opaque cursors, bridges only the strict legacy payload decoder', () => {
    const page = parseCurrentVuln(vulnWire(), query);
    expect(page.page?.totalCount).toBe(30);
    expect(page.nextCursor).toBe('opaque:5/+==');
    expect(page.findings).toHaveLength(5);
    const second = parseCurrentVuln(vulnWire({ findings: page.findings, page: meta({ offset: 5 }) }), query, 'another-opaque');
    expect(reportViewIdentity(second.page)).toBe(reportViewIdentity(page.page));
  });
  it.each([5, 10, 25, 50] as const)('accepts supported limit %s within the complete bounded1000 report', size => {
    const page = parseCurrentVuln(vulnWire({ findingCount: 1000, findings: Array.from({ length: size }, (_, index) => finding(index)), page: meta({ limit: size, returnedCount: size, totalCount: 1000, matchedCount: 1000 }) }), { view: 'report-v1', limit: size });
    expect(page.findings).toHaveLength(size);
    expect(page.page?.totalCount).toBe(1000);
    expect(() => parseCurrentVuln(vulnWire({ findingCount: 1001, page: meta({ totalCount: 1001, matchedCount: 1001 }) }), query)).toThrow(ReportViewContractError);
  });
  it('accepts checked-zero and the max512 opaque cursor, rejecting absent metadata without fallback', () => {
    const zero = parseCurrentVuln(vulnWire({ findingCount: 0, findings: [], nextCursor: null, page: meta({ returnedCount: 0, totalCount: 0, matchedCount: 0 }) }), query);
    expect(zero.page?.totalCount).toBe(0);
    expect(parseCurrentVuln(vulnWire({ nextCursor: 'x'.repeat(512) }), query).nextCursor).toHaveLength(512);
    expect(() => parseCurrentSbom(sbomWire({ page: undefined }), sbomQuery)).toThrow(ReportViewContractError);
    expect(() => parseCurrentResults(secretWire({ page: undefined }), secretQuery)).toThrow(ReportViewContractError);
  });
  it('distinguishes checked global-no-match from whole-report zero and nonchecked unknown', () => {
    const selected: VulnReportQuery = { ...query, severity: ['UNKNOWN'] };
    const page = parseCurrentVuln(vulnWire({ findings: [], nextCursor: null, page: meta({ returnedCount: 0, matchedCount: 0, filters: { severity: ['UNKNOWN'] } }) }), selected);
    expect(page.page?.matchedCount).toBe(0);
    expect(page.page?.totalCount).toBe(30);
    const failed = parseCurrentVuln({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', findings: [], nextCursor: null, page: meta({ returnedCount: 0, totalCount: null, matchedCount: null }) }, query);
    expect(failed.page?.matchedCount).toBeNull();
  });
  it.each([
    ['missing', undefined], ['version', meta({ version: 2 as 1 })], ['limit', meta({ limit: 10 })],
    ['sort', meta({ sort: 'severity:asc' })], ['whole count', meta({ totalCount: 29 })],
    ['matched greater than whole', meta({ matchedCount: 31 })], ['wrong rows', meta({ returnedCount: 4 })],
    ['first offset', meta({ offset: 5 })], ['checked null', meta({ matchedCount: null })],
    ['unfiltered incomplete', meta({ matchedCount: 20 })], ['filter mismatch', meta({ filters: { severity: ['HIGH'] } })],
    ['extra metadata', { ...meta(), extra: true }], ['extra filter', { ...meta(), filters: { severity: null, bogus: true } }],
  ])('rejects malformed/coherence metadata: %s', (_name, page) => {
    expect(() => parseCurrentVuln(vulnWire({ page }), query)).toThrow(ReportViewContractError);
  });
  it.each([1, '', 'x'.repeat(513)])('rejects malformed opaque continuation %s', nextCursor => {
    expect(() => parseCurrentVuln(vulnWire({ nextCursor }), query)).toThrow(ReportViewContractError);
  });
  it('rejects terminal underflow, partial nonterminal pages and repeated cursors', () => {
    expect(() => parseCurrentVuln(vulnWire({ nextCursor: null }), query)).toThrow(ReportViewContractError);
    expect(() => parseCurrentVuln(vulnWire({ findings: [], page: meta({ returnedCount: 0 }) }), query)).toThrow(ReportViewContractError);
    expect(() => parseCurrentVuln(vulnWire({ page: meta({ offset: 5 }) }), query, 'opaque:5/+==')).toThrow(ReportViewContractError);
  });
  it('does not downgrade partial/invalid v2 metadata to legacy in the opt-in bridge', () => {
    expect(parseCurrentVuln(vulnWire(v2Evidence()), query).page?.version).toBe(1);
    for (const mutation of [{ resultContractVersion: 3 }, { dbPolicy: undefined }, { usableUntil: 'wrong' }, { dbPolicy: { ...v2Evidence().dbPolicy, warnings: ['DB_PUBLICATION_OVERDUE'] } }]) {
      expect(() => parseCurrentVuln(vulnWire({ ...v2Evidence(), ...mutation }), query)).toThrow(ReportViewContractError);
    }
  });
  it('validates normalized filter subset and retained stored severity, not advisory maximum', () => {
    const selected: VulnReportQuery = { ...query, severity: ['HIGH', 'CRITICAL'] };
    expect(() => parseCurrentVuln(vulnWire({ page: meta({ filters: { severity: ['CRITICAL', 'HIGH'] } }) }), selected)).toThrow(ReportViewContractError);
    expect(() => parseCurrentVuln(vulnWire({ page: meta({ filters: { severity: ['HIGH', 'CRITICAL'] }, matchedCount: 20 }), findings: [{ ...vulnWire().findings[0], severity: 'LOW' }, ...vulnWire().findings.slice(1)] }), selected)).toThrow(ReportViewContractError);
  });
  it('validates literal ASCII case-insensitive SBOM substring, metadata and strict rows', () => {
    const selected: SbomReportQuery = { ...sbomQuery, ecosystem: 'apk', name: 'PACKAGE-' };
    const page = parseCurrentSbom(sbomWire({ page: { ...meta({ matchedCount: 15 }), sort: 'name:asc', filters: { ecosystem: 'apk', name: 'package-' } } }), selected);
    expect(page.outcome).toBe('checked');
    expect(() => parseCurrentSbom(sbomWire({ components: [{ ecosystem: 'apk', name: 'other', version: '1.0' }, ...sbomWire().components.slice(1)], page: page.page }), selected)).toThrow(ReportViewContractError);
    expect(() => reportViewSearch('sbom', { ...sbomQuery, name: '.*' })).toThrow();
    expect(() => parseCurrentSbom(sbomWire({ components: [{ ...sbomWire().components[0], extra: true }] }), sbomQuery)).toThrow(ReportViewContractError);
  });
  it('preserves meaningful nullable secret line without exposing evidence, and rejects unknown envelope fields', () => {
    const page = parseCurrentResults(secretWire(), secretQuery);
    expect(page.findings[0].line).toBeNull();
    expect(page.findings[1].line).toBe(2);
    expect(page.findings[0].evidenceRef).toBeUndefined();
    expect(() => parseCurrentResults(secretWire({ unexpected: true }), secretQuery)).toThrow(ReportViewContractError);
    expect(() => parseCurrentResults(secretWire({ findings: [{ ...secretWire().findings[0], extra: true }, ...secretWire().findings.slice(1)] }), secretQuery)).toThrow(ReportViewContractError);
    expect(() => parseCurrentResults(secretWire({ page: { ...meta(), sort: 'ruleId:asc', filters: { ruleId: null, linePresence: 'known' } } }), { ...secretQuery, linePresence: 'known' })).toThrow(ReportViewContractError);
  });
  it('keeps no-view legacy parser behavior and numeric cursor contract unchanged', () => {
    const { page: vulnPage, ...legacyVuln } = vulnWire({ nextCursor: 5 });
        expect(vulnPage.version).toBe(1);
    expect(parseCurrentVuln(legacyVuln).nextCursor).toBe('5');
    const { page: sbomPage, ...legacySbom } = sbomWire({ nextCursor: 5 });
        expect(sbomPage.version).toBe(1);
    expect(parseCurrentSbom(legacySbom).nextCursor).toBe('5');
    const { page: secretPage, ...legacySecret } = secretWire({ nextCursor: 5, extra: true });
        expect(secretPage.version).toBe(1);
    expect(parseCurrentResults(legacySecret).findings[1].line).toBeUndefined();
    expect(parseCurrentResults(legacySecret).nextCursor).toBe('5');
  });
});
describe('query serialization and transport boundary', () => {
  const transport = () => createAuthorizedScanTransport({ subject: 'synthetic', currentSubject: () => 'synthetic' });
  it('canonicalizes severity and defaults to 25; encodes opaque cursor safely', () => {
    const params = new URLSearchParams(reportViewSearch('vuln', { view: 'report-v1', severity: ['CRITICAL', 'HIGH', 'HIGH'] }, 'opaque/+?=&'));
    expect(params.get('limit')).toBe('25');
    expect(params.get('sort')).toBe('severity:desc');
    expect(params.get('severity')).toBe('HIGH,CRITICAL');
    expect(params.get('cursor')).toBe('opaque/+?=&');
    expect(normalizeReportQuery('sbom', { view: 'report-v1' }).sort).toBe('name:asc');
    expect(normalizeReportQuery('secret', { view: 'report-v1' }).sort).toBe('ruleId:asc');
  });
  it.each([0, 1, 100])('rejects unsupported requested limit %s', limit => {
    expect(() => reportViewSearch('vuln', { ...query, limit: limit as 5 })).toThrow();
  });
  it('issues opt-in fourth-argument GET with encoded opaque continuation and no-store/session fences', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(vulnWire({ page: meta({ offset: 5 }), nextCursor: 'next-new' }))));
    vi.stubGlobal('fetch', fetchMock);
    await transport().vuln(scanId, 'opaque/+?=&', undefined, query);
    const [path, options] = fetchMock.mock.calls[0];
    expect(new URL(String(path), 'https://synthetic.invalid').searchParams.get('cursor')).toBe('opaque/+?=&');
    expect(options).toMatchObject({ method: 'GET', cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  });
  it.each([[400, 'REPORT_CURSOR_QUERY_MISMATCH'], [409, 'REPORT_CURSOR_STALE']])('classifies query-bound reset %s/%s only in opt-in calls', async (status, errorCode) => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({ errorCode }), { status: Number(status) }))));
    await expect(transport().vuln(scanId, undefined, undefined, query)).rejects.toBeInstanceOf(ReportCursorResetError);
    await expect(transport().vuln(scanId)).rejects.toBeInstanceOf(ScanHttpError);
  });
  it('ordinary503 is not a contract reset; invalid JSON is', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response('{}', { status: 503 })).mockResolvedValueOnce(new Response('{bad-json')));
    await expect(transport().vuln(scanId, undefined, undefined, query)).rejects.toBeInstanceOf(ScanHttpError);
    await expect(transport().vuln(scanId, undefined, undefined, query)).rejects.toBeInstanceOf(ReportViewContractError);
  });
  it('legacy transport keeps numeric cursor/limit50 and does not opt in implicitly', async () => {
    const { page, ...legacy } = vulnWire({ nextCursor: 10 });
        expect(page.version).toBe(1);
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(legacy));
    vi.stubGlobal('fetch', fetchMock);
    await transport().vuln(scanId, '5');
    const url = new URL(String(fetchMock.mock.calls[0][0]), 'https://synthetic.invalid');
    expect(url.searchParams.get('limit')).toBe('50');
    expect(url.searchParams.get('cursor')).toBe('5');
    expect(url.searchParams.has('view')).toBe(false);
    await expect(transport().vuln(scanId, 'opaque-token')).rejects.toThrow('Недопустимая страница');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it('fixture rejects options rather than silently pretending to globally filter', async () => {
    await expect(fixtureScanTransport.results('partial-demo', undefined, undefined, secretQuery)).rejects.toThrow('не поддерживаются');
    expect((await fixtureScanTransport.results('partial-demo')).findings).toHaveLength(1);
    await expect(fixtureScanTransport.sbom('partial-demo', undefined, undefined, sbomQuery)).rejects.toThrow('не поддерживаются');
    await expect(fixtureScanTransport.vuln('partial-demo', undefined, undefined, query)).rejects.toThrow('не поддерживаются');
  });
});
