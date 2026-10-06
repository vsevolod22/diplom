import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { parseCurrentList, parseCurrentResults, parseCurrentSbom, parseCurrentVuln, parseCurrentStatus, parseScanReceipt, parseScanResults, parseScanStatus, reconcileSnapshot, sameOriginScanUrl } from '@/shared/api/scans/scanTransport';

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
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
  it('maps pinned status and paginated wire list without mistaking unknown progress for zero', () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    expect(parseCurrentStatus({ scanId: 'x', state: 'queued', digest, platform: 'linux/amd64', result: null })).toEqual({ scanId: 'x', state: 'queued', percent: null, digest, platform: 'linux/amd64' });
    const scanId = '00000000-0000-4000-8000-000000000001';
    const { scans, nextCursor } = parseCurrentList({ scans: [{ scanId, state: 'running', digest, platform: 'linux/amd64', targetLabel: `registry-1.docker.io/library/alpine@${digest}`, idempotencyKey: 'secret' }], nextCursor: null });
    expect(nextCursor).toBeNull();
    expect(scans[0]).toMatchObject({ scanId, percent: null, digest });
    expect(JSON.stringify(scans)).not.toContain('idempotencyKey');
    expect(() => parseCurrentList({ scans: [{ scanId, state: 'safe', digest, platform: 'linux/amd64', targetLabel: 'x' }], nextCursor: null })).toThrow();
  });
  it('loads every authorized page and rejects a subject change while the response is pending', async () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    const row = (id: string) => ({ scanId: id, state: 'queued', digest, platform: 'linux/amd64', targetLabel: `library/alpine@${digest}` });
    const first = { scans: [row('00000000-0000-4000-8000-000000000001')], nextCursor: '2:2' };
    const second = { scans: [row('00000000-0000-4000-8000-000000000002')], nextCursor: null };
    const fetchMock = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => first }).mockResolvedValueOnce({ ok: true, json: async () => second });
    vi.stubGlobal('fetch', fetchMock);
    const session = { subject: 'alice', currentSubject: () => 'alice' };
    const transport = createAuthorizedScanTransport(session);
    expect((await transport.list()).map(item => item.scanId)).toEqual(first.scans.concat(second.scans).map(item => item.scanId));
    expect(fetchMock.mock.calls.map(call => call[0])).toEqual(['/api/v1/browser/scans?limit=100', '/api/v1/browser/scans?limit=100&cursor=2:2']);
    let subject = 'alice';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => { subject = 'bob'; return first; } }));
    await expect(createAuthorizedScanTransport({ ...session, currentSubject: () => subject }).list()).rejects.toThrow('Сессия изменилась');
  });
  it('strips internal receipt URLs and constructs only browser-scoped follow-up routes', async () => {
    const scanId = '00000000-0000-4000-8000-000000000001';
    const internalUrl = `/api/v1/scans/${scanId}`;
    expect(parseScanReceipt({ scanId, statusUrl: internalUrl, eventsUrl: `${internalUrl}/events` })).toEqual({ scanId });
    expect(parseScanReceipt({ scanId })).toEqual({ scanId });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ scanId, statusUrl: internalUrl, eventsUrl: 'https://evil.example/events' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ scanId, state: 'queued', result: null }) });
    vi.stubGlobal('fetch', fetchMock);
    const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    expect(await transport.create({ imageReference: 'library/alpine:3.21', scope: 'image', checks: ['secret'], idempotencyKey: scanId })).toEqual({ scanId });
    await transport.get(scanId);
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(['/api/v1/browser/scans', `/api/v1/browser/scans/${scanId}`]);
  });
  it('parses bounded SBOM pages and failed coverage without retaining raw fields', async () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const checked = { outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, componentCount: 51, scannerVersion: '0.69.3', checkedAt: '2026-01-01', components: [{ ecosystem: 'apk', name: 'busybox', version: '1.0' }], nextCursor: 50 };
    expect(parseCurrentStatus({ scanId: id, state: 'completed', result: { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 51, scannerVersion: '0.69.3', checkedAt: '2026-01-01' } }).check).toBe('sbom');
    expect(parseCurrentStatus({ scanId: id, state: 'queued', check: 'sbom', result: null }).check).toBe('sbom');
    expect(parseCurrentStatus({ scanId: id, state: 'queued', result: null }).check).toBeUndefined();
    expect(parseCurrentSbom(checked).nextCursor).toBe('50');
    expect(parseCurrentSbom({ coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null })).toMatchObject({ outcome: 'failed', errorCode: 'SCAN_TIMEOUT' });
    for (const invalid of [{ ...checked, rawSbom: 'private' }, { ...checked, os: { name: 'ubuntu', version: '1' } }, { ...checked, nextCursor: -1 }, { ...checked, components: [{ ecosystem: 'apk', name: 'x', version: '1', raw: 'secret' }] }, { coverage: 'image', outcome: 'failed', errorCode: 'UNKNOWN', components: [], nextCursor: null }]) {
      expect(() => parseCurrentSbom(invalid)).toThrow();
    }
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => checked });
    vi.stubGlobal('fetch', fetchMock);
    const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    expect((await transport.sbom(id, '50')).components[0].name).toBe('busybox');
    expect(fetchMock).toHaveBeenCalledWith(`/api/v1/browser/scans/${id}/sbom?limit=50&cursor=50`, expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' }));
    await expect(transport.sbom(id, '../evil')).rejects.toThrow('Недопустимая страница');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it('allowlists archive SBOM failure reasons without weakening its strict boundary', () => {
    const failed = { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_TIMEOUT', reason: 'SCAN_TIMEOUT', components: [], nextCursor: null };
    expect(parseCurrentSbom(failed)).toEqual(failed);
    expect(parseCurrentSbom({ ...failed, errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE' })).toMatchObject({ reason: 'DB_UNAVAILABLE' });
    for (const invalid of [{ ...failed, reason: 'SECRET_CANARY' }, { ...failed, reason: 'OS_EOL' },
      { ...failed, errorCode: 'SCAN_FAILED' }, { ...failed, raw: 'SECRET_CANARY' }]) {
      expect(() => parseCurrentSbom(invalid)).toThrow();
    }
  });
  it('retains only consistent allowlisted CVE failure reasons for unknown counts', () => {
    const failed = { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE', findings: [], nextCursor: null };
    expect(parseCurrentVuln(failed)).toEqual(failed);
    expect(parseCurrentVuln({ ...failed, reason: undefined })).toMatchObject({ errorCode: 'SCAN_FAILED' });
    for (const invalid of [{ ...failed, reason: 'PRIVATE_DB_CANARY' }, { ...failed, reason: 'OS_EOL' },
      { ...failed, errorCode: 'SCAN_TIMEOUT' }, { ...failed, raw: 'SECRET_CANARY' }]) {
      expect(() => parseCurrentVuln(invalid)).toThrow();
    }
  });
  it('keeps simultaneous outcomes independent and strips vulnerability evidence', async () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const checked = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    const failed = { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' };
    expect(parseCurrentStatus({ scanId: id, state: 'partial', checks: ['secret', 'sbom', 'vuln'], perCheck: { secret: checked, sbom: null, vuln: failed }, result: null })).toMatchObject({ state: 'partial', checks: ['secret', 'sbom', 'vuln'], perCheck: { sbom: null, vuln: failed } });
    expect(() => parseCurrentStatus({ scanId: id, state: 'completed', checks: ['vuln', 'secret'], perCheck: {}, result: null })).toThrow();
    const finding = { findingId: 'vuln-1', cveId: 'CVE-2026-1', ecosystem: 'apk', packageName: 'busybox', installedVersion: '1', severity: 'HIGH', fixedVersion: null, provenanceRef: 'private', severitySources: ['private'] };
    const report = parseCurrentVuln({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', findingCount: 2, scannerVersion: '0.69.3', checkedAt: 'today', findings: [finding], nextCursor: 1 });
    expect(report.nextCursor).toBe('1');
    expect(JSON.stringify(report)).not.toContain('private');
    expect(parseCurrentVuln({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_UNAVAILABLE', findings: [], nextCursor: null }).outcome).toBe('failed');
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', findingCount: 2, scannerVersion: '0.69.3', checkedAt: 'today', findings: [finding], nextCursor: 1 }) });
    vi.stubGlobal('fetch', fetchMock);
    const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    await transport.vuln(id, '1');
    expect(fetchMock.mock.calls[0][0]).toBe(`/api/v1/browser/scans/${id}/vuln?limit=50&cursor=1`);
    await expect(transport.vuln(id, '../other')).rejects.toThrow('Недопустимая страница');
    await expect(transport.create({ imageReference: 'alpine', scope: 'image', checks: ['vuln', 'secret'], idempotencyKey: id })).rejects.toThrow('Недопустимый набор');
  });
  it('parses the exact archive report and retains independent OS/Node outcomes without raw evidence', () => {
    const image = 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3';
    const os = { outcome: 'checked' }, node = { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' };
    const report = { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', findingCount: 1,
      scannerVersion: '0.69.3', checkedAt: '2026-10-04T21:00:00.000Z', findings: [], nextCursor: null, os, node };
    expect(parseCurrentVuln(report)).toMatchObject({ image, os, node });
    expect(parseCurrentSbom({ outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64',
      os: { name: 'alpine', version: '3.23.3' }, componentCount: 72, scannerVersion: '0.69.3', checkedAt: report.checkedAt,
      components: [{ ecosystem: 'apk', name: 'busybox', version: '1' }], nextCursor: 50 })).toMatchObject({ image });
    for (const invalidImage of [image.replace('0dcc', '1dcc'), image.replace('nginx', 'node'), image.replace('@sha256:', ':')]) {
      expect(() => parseCurrentVuln({ ...report, image: invalidImage })).toThrow();
    }
    expect(() => parseCurrentVuln({ ...report, node: { outcome: 'safe' } })).toThrow();
    const perCheck = { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 1, scannerVersion: '0.69.3',
      checksVersion: 'trivy-0.69.3-archive-v1', checkedAt: report.checkedAt, errorCode: null, os, node };
    const status = { scanId: 'x', state: 'completed', imageReference: image, checks: ['vuln'], perCheck: { vuln: perCheck }, result: perCheck };
    expect(parseCurrentStatus(status)).toMatchObject({ imageReference: image, perCheck: { vuln: { os, node } } });
    expect(() => parseCurrentStatus({ ...status, perCheck: { vuln: { ...perCheck, checkedAt: 123 } } })).toThrow();
    expect(() => parseCurrentStatus({ ...status, perCheck: { vuln: { ...perCheck, node: { outcome: 'safe' } } } })).toThrow();
    expect(parseCurrentVuln({ outcome: 'unsupported', coverage: 'image', reason: 'OS_EOL', os: { outcome: 'unsupported', reason: 'OS_EOL' }, node,
      findings: [], nextCursor: null })).toMatchObject({ outcome: 'unsupported', reason: 'OS_EOL', node });
  });
  it('rejects cross-origin and unexpected scan URLs', () => {
    expect(sameOriginScanUrl('/api/v1/browser/scans/abc', 'abc')).toBe('/api/v1/browser/scans/abc');
    expect(() => sameOriginScanUrl('/api/v1/scans/abc', 'abc')).toThrow();
    expect(() => sameOriginScanUrl('https://evil.example/api/v1/browser/scans/abc', 'abc')).toThrow();
    expect(() => sameOriginScanUrl('//evil.example/api/v1/browser/scans/abc', 'abc')).toThrow();
    expect(() => sameOriginScanUrl('/api/v1/browser/scans/abc?token=secret', 'abc')).toThrow();
  });
  it('uses same-origin cookies without exposing tokens, and rejects changed subjects before network', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ scanId: 'abc', state: 'running', result: null }) });
    vi.stubGlobal('fetch', fetchMock);
    const active = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    await active.get('abc');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/browser/scans/abc', expect.objectContaining({ credentials: 'same-origin', redirect: 'error', cache: 'no-store' }));
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain('Authorization');
    expect(active.capabilities).toEqual({ list: true, create: true, cancel: true, events: true });
    const changed = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'bob' });
    await expect(changed.get('abc')).rejects.toThrow('Сессия изменилась');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it('uses native cookie EventSource and accepts only matching scan hints without retaining event data', () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const listeners = new Map<string, (event: MessageEvent) => void>();
    const close = vi.fn();
    const source = vi.fn(function (this: object, path: string) {
      void path;
      return { addEventListener: (type: string, fn: (event: MessageEvent) => void) => listeners.set(type, fn), close };
    });
    vi.stubGlobal('EventSource', source);
    let subject = 'alice';
    const transport = createAuthorizedScanTransport({ subject, currentSubject: () => subject });
    const hint = vi.fn(); const error = vi.fn(); const open = vi.fn();
    const dispose = transport.subscribeEvents!(id, hint, error, open);
    expect(source).toHaveBeenCalledWith(`/api/v1/browser/scans/${id}/events`);
    listeners.get('open')!(new MessageEvent('open'));
    expect(open).toHaveBeenCalledTimes(1);
    for (const data of [
      { scanId: '00000000-0000-4000-8000-000000000002', state: 'completed', percent: null },
      { scanId: id, state: 'completed', percent: 100 },
      { scanId: id, state: 'unknown', percent: null },
    ]) listeners.get('scan')!(new MessageEvent('scan', { data: JSON.stringify(data) }));
    expect(hint).not.toHaveBeenCalled();
    listeners.get('scan')!(new MessageEvent('scan', { data: JSON.stringify({ scanId: id, state: 'completed', percent: null, secretValue: 'ignored' }) }));
    expect(hint).toHaveBeenCalledTimes(1);
    subject = 'bob';
    listeners.get('scan')!(new MessageEvent('scan', { data: JSON.stringify({ scanId: id, state: 'running', percent: null }) }));
    expect(close).toHaveBeenCalledTimes(1);
    expect(hint).toHaveBeenCalledTimes(1);
    dispose();
    expect(() => transport.subscribeEvents!('abc/../../evil', hint, error, open)).toThrow();
    expect(source).toHaveBeenCalledTimes(1);
  });
  it('permits native Last-Event-ID reconnect briefly and releases an unrecoverable stream', () => {
    vi.useFakeTimers();
    const id = '00000000-0000-4000-8000-000000000001';
    const listeners = new Map<string, () => void>();
    const close = vi.fn();
    vi.stubGlobal('EventSource', class {
      close = close;
      addEventListener(type: string, fn: () => void) { listeners.set(type, fn); }
    });
    const hint = vi.fn(); const error = vi.fn(); const open = vi.fn();
    const stream = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    const dispose = stream.subscribeEvents!(id, hint, error, open);
    listeners.get('error')!();
    expect(error).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
    vi.advanceTimersByTime(5000);
    listeners.get('open')!();
    expect(open).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(15000);
    expect(close).not.toHaveBeenCalled();
    listeners.get('error')!();
    vi.advanceTimersByTime(15000);
    expect(close).toHaveBeenCalledTimes(1);
    listeners.get('open')!();
    expect(open).toHaveBeenCalledTimes(1);
    dispose();
    expect(close).toHaveBeenCalledTimes(1);
  });
  it('posts an empty JSON body to a same-origin cancel route with cookies and validates the receipt', async () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ scanId: id, state: 'cancelled' }) });
    vi.stubGlobal('fetch', fetchMock);
    const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    await expect(transport.cancel(id)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(`/api/v1/browser/scans/${id}/cancel`, expect.objectContaining({
      method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', Origin: window.location.origin },
      credentials: 'same-origin', redirect: 'error', cache: 'no-store',
    }));
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain('Authorization');
    for (const invalid of [null, [], {}, { scanId: id, state: 'running' }, { scanId: 'other', state: 'cancelled' }, { scanId: id, state: 'cancelled', token: 'secret' }]) {
      fetchMock.mockResolvedValueOnce({ ok: true, json: async () => invalid });
      await expect(transport.cancel(id)).rejects.toThrow('Недопустимый ответ отмены');
    }
    await expect(transport.cancel('abc/../../evil')).rejects.toThrow('Недопустимый адрес скана');
    expect(fetchMock).toHaveBeenCalledTimes(7);
  });
  it('rejects cancel errors and session changes without trusting an error response', async () => {
    const id = 'abc';
    const fetchMock = vi.fn().mockResolvedValueOnce({ ok: false, status: 409 }).mockResolvedValueOnce({ ok: false, status: 404 });
    vi.stubGlobal('fetch', fetchMock);
    const transport = createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' });
    await expect(transport.cancel(id)).rejects.toThrow('Отмена невозможна');
    await expect(transport.cancel(id)).rejects.toThrow('Скан недоступен');
    let subject = 'alice';
    fetchMock.mockResolvedValueOnce({ ok: true, json: async () => { subject = 'bob'; return { scanId: id, state: 'cancelled' }; } });
    await expect(createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => subject }).cancel(id)).rejects.toThrow('Сессия изменилась');
    await expect(createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'bob' }).cancel(id)).rejects.toThrow('Сессия изменилась');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
  it('never regresses terminal state or mixes IDs, and never derives 100% from a closed event stream', () => {
    const partial = parseScanStatus({ scanId: 'abc', state: 'partial', percent: null });
    expect(reconcileSnapshot(partial, parseScanStatus({ scanId: 'abc', state: 'running', percent: 99 }))).toEqual(partial);
    expect(reconcileSnapshot(partial, parseScanStatus({ scanId: 'other', state: 'completed', percent: 100 }))).toEqual(partial);
    expect(partial.percent).toBeNull();
  });
});
