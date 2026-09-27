import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { parseCurrentResults, parseCurrentStatus, parseScanReceipt, parseScanResults, parseScanStatus, reconcileSnapshot, sameOriginScanUrl } from '@/shared/api/scans/scanTransport';

afterEach(() => vi.unstubAllGlobals());
describe('scan transport boundary', () => {
  it('rejects malformed states and findings rather than claiming a checked scan', () => {
    expect(() => parseScanStatus({ scanId: 'x', state: 'safe' })).toThrow();
    expect(() => parseScanResults({ findings: [{ findingId: 'a', category: 'secret', ruleId: 'b', severity: 'high', secretValue: 'raw' }], nextCursor: null, coverage: [{ check: 'CVE', status: 'ok' }] })).toThrow();
    expect(() => parseScanReceipt({ scanId: 'x' })).toThrow();
  });
  it('maps the current internal wire shape without leaking evidence or inventing CVE coverage', () => {
    expect(parseCurrentStatus({ scanId: 'x', state: 'completed', result: null })).toEqual({ scanId: 'x', state: 'completed', percent: null });
    const report = parseCurrentResults({ findings: [{ findingId: 'secret-0-0', ruleId: 'rule', line: 3, evidenceRef: 'result-0-secret-0', secretValue: 'must never leak' }], nextCursor: null, coverage: { findingCount: 1, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3' } });
    expect(report.coverage.map((item) => item.status)).toEqual(['checked', 'unsupported', 'unsupported']);
    expect(JSON.stringify(report)).not.toContain('must never leak');
    expect(() => parseCurrentResults({ findings: [], nextCursor: null, coverage: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'safe', errorCode: null, scannerVersion: null } })).toThrow();
  });
  it('rejects cross-origin and unexpected scan URLs', () => {
    expect(sameOriginScanUrl('/api/v1/scans/abc', 'abc')).toBe('/api/v1/scans/abc');
    expect(() => sameOriginScanUrl('https://evil.example/api/v1/scans/abc', 'abc')).toThrow();
    expect(() => sameOriginScanUrl('//evil.example/api/v1/scans/abc', 'abc')).toThrow();
    expect(() => sameOriginScanUrl('/api/v1/scans/abc?token=secret', 'abc')).toThrow();
  });
  it('keeps authorization in headers, rejects missing session before network, and never uses external URLs', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ scanId: 'abc', state: 'running', result: null }) });
    vi.stubGlobal('fetch', fetchMock);
    const inactive = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice', token: () => null });
    await expect(inactive.get('abc')).rejects.toThrow('Нет авторизованной сессии');
    expect(fetchMock).not.toHaveBeenCalled();
    const active = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice', token: () => 'session-token' });
    await active.get('abc');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/scans/abc', expect.objectContaining({ headers: { Authorization: 'Bearer session-token' }, credentials: 'omit', redirect: 'error' }));
    expect(active.capabilities).toEqual({ list: false, create: true, cancel: false, events: false });
    const changed = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'bob', token: () => 'session-token' });
    await expect(changed.get('abc')).rejects.toThrow('Сессия изменилась');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it('never regresses terminal state or mixes IDs, and never derives 100% from a closed event stream', () => {
    const partial = parseScanStatus({ scanId: 'abc', state: 'partial', percent: null });
    expect(reconcileSnapshot(partial, parseScanStatus({ scanId: 'abc', state: 'running', percent: 99 }))).toEqual(partial);
    expect(reconcileSnapshot(partial, parseScanStatus({ scanId: 'other', state: 'completed', percent: 100 }))).toEqual(partial);
    expect(partial.percent).toBeNull();
  });
});
