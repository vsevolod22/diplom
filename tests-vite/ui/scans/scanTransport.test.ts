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
  it('keeps simultaneous outcomes independent and retains bounded vulnerability provenance', async () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const checked = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    const failed = { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' };
    expect(parseCurrentStatus({ scanId: id, state: 'partial', checks: ['secret', 'sbom', 'vuln'], perCheck: { secret: checked, sbom: null, vuln: failed }, result: null })).toMatchObject({ state: 'partial', checks: ['secret', 'sbom', 'vuln'], perCheck: { sbom: null, vuln: failed } });
    expect(() => parseCurrentStatus({ scanId: id, state: 'completed', checks: ['vuln', 'secret'], perCheck: {}, result: null })).toThrow();
    const finding = { findingId: 'vuln-1', cveId: 'CVE-2026-1', ecosystem: 'apk', packageName: 'busybox', installedVersion: '1', severity: 'HIGH', fixedVersion: null, provenanceRef: `target-${'a'.repeat(64)}`, severitySources: ['alpine'] };
    const report = parseCurrentVuln({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', findingCount: 2, scannerVersion: '0.69.3', checkedAt: 'today', findings: [finding], nextCursor: 1 });
    expect(report.nextCursor).toBe('1');
    expect(report.findings[0]).toMatchObject({ provenanceRef: finding.provenanceRef, severitySources: ['alpine'] });
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

const advisoryFixture = () => ({
  schemaVersion: 1, state: 'available', assessments: [{ source: 'alpine', provenanceRef: `target-${'a'.repeat(64)}`,
    title: { value: 'Package advisory', state: 'available', redacted: false }, description: { value: null, state: 'missing', redacted: false },
    language: null, severity: 'HIGH', fixedVersion: null,
    cvss: { family: 'v3', version: '3.1', versionState: 'available', reportedScore: 0, scoreState: 'available', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vectorState: 'available' } }],
  references: [{ kind: 'canonical', authority: 'cve', url: 'https://www.cve.org/CVERecord?id=CVE-2026-1234' },
    { kind: 'canonical', authority: 'nvd', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234' },
    { kind: 'calculator', authority: 'first', url: 'https://www.first.org/cvss/calculator/3.1' }], conflicts: [], conflictState: 'none', limitations: [],
});
const advisoryFinding = () => ({ findingId: 'vuln-1', cveId: 'CVE-2026-1234', ecosystem: 'apk', packageName: 'busybox', installedVersion: '1', severity: 'HIGH', fixedVersion: null,
  severitySources: ['alpine'], provenanceRef: `target-${'a'.repeat(64)}`, advisory: advisoryFixture() });
const advisoryPage = (findings: unknown[] = [advisoryFinding()]) => ({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64', findingCount: findings.length, scannerVersion: '0.69.3', checkedAt: '2026-10-07T08:00:00.000Z', findings, nextCursor: null });

describe('frozen advisory-v1 browser wire', () => {
  it('retains all nine core fields, score zero, nullable advisory and seven-field legacy', () => {
    const finding = advisoryFinding();
    expect(parseCurrentVuln(advisoryPage()).findings[0]).toEqual(finding);
    const legacy = { findingId: finding.findingId, cveId: finding.cveId, ecosystem: finding.ecosystem, packageName: finding.packageName, installedVersion: finding.installedVersion, severity: finding.severity, fixedVersion: finding.fixedVersion };
    expect(parseCurrentVuln(advisoryPage([legacy])).findings[0]).toEqual(legacy);
    expect(parseCurrentVuln(advisoryPage([{ ...legacy, advisory: null }])).findings[0]).toEqual({ ...legacy, advisory: null });
  });
  it('bounds core identities and requires nonempty stable source provenance when supplied', () => {
    const f = advisoryFinding();
    for (const finding of [{ ...f, findingId: 'x'.repeat(70) }, { ...f, cveId: 'x'.repeat(22) }, { ...f, cveId: 'invalid-id', advisory: { ...f.advisory, references: [] } }, { ...f, severitySources: [] }, { ...f, severitySources: ['nvd', 'alpine'] }]) expect(() => parseCurrentVuln(advisoryPage([finding]))).toThrow();
  });
  it('rejects unknown versions/keys at every nesting level and never falls back to raw data', () => {
    const a = advisoryFixture();
    const f = advisoryFinding();
    const bad = [
      { ...advisoryPage(), raw: true }, { ...advisoryPage(), os: { outcome: 'checked', raw: true } },
      advisoryPage([{ ...f, raw: true }]), advisoryPage([{ ...f, advisory: { ...a, schemaVersion: 2 } }]),
      advisoryPage([{ ...f, advisory: { ...a, raw: true } }]),
      advisoryPage([{ ...f, advisory: { ...a, assessments: [{ ...a.assessments[0], raw: true }] } }]),
      advisoryPage([{ ...f, advisory: { ...a, assessments: [{ ...a.assessments[0], title: { ...a.assessments[0].title, raw: true } }] } }]),
      advisoryPage([{ ...f, advisory: { ...a, assessments: [{ ...a.assessments[0], cvss: { ...a.assessments[0].cvss, raw: true } }] } }]),
      advisoryPage([{ ...f, advisory: { ...a, references: [{ ...a.references[0], raw: true }] } }]),
    ];
    bad.forEach(value => expect(() => parseCurrentVuln(value)).toThrow());
    expect(() => parseCurrentVuln({ outcome: 'unsupported', coverage: 'image', reason: 'OS_EOL', findings: [], nextCursor: null, node: { outcome: 'checked', raw: true } })).toThrow();
  });
  it('rejects prototype-bearing objects, magic own keys, accessors and cycles without executing getters', () => {
    const inherited = Object.assign(Object.create({ attacker: true }), advisoryFixture());
    const getter = vi.fn(() => 1);
    const accessor = Object.defineProperty(advisoryFixture(), 'state', { get: getter });
    const magic = JSON.parse('{"__proto__":{"attacker":true}}');
    for (const advisory of [inherited, accessor, { ...advisoryFixture(), ...magic }]) {
      expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory }]))).toThrow();
    }
    expect(getter).not.toHaveBeenCalled();
    const cycle: Record<string, unknown> = {}; cycle.self = cycle;
    expect(() => parseCurrentVuln(cycle)).toThrow();
  });
  it('enforces UTF-8 field limits and safe normalized plaintext states', () => {
    const a = advisoryFixture(), source = a.assessments[0];
    const parse = (title: unknown, description: unknown = source.description) => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, assessments: [{ ...source, title, description }] } }]));
    expect(() => parse({ value: 'я'.repeat(256), state: 'truncated', redacted: true })).not.toThrow();
    for (const value of ['я'.repeat(257), '<script>alert(1)</script>', 'text\u202eevil', 'https://host.test/?token=x', 'CANARY_PAYLOAD', 'password=private', 'x\u0000y']) expect(() => parse({ value, state: 'available', redacted: false })).toThrow();
    for (const field of [{ value: '', state: 'available', redacted: false }, { value: 'x', state: 'missing', redacted: false }, { value: null, state: 'redacted', redacted: false }]) expect(() => parse(field)).toThrow();
    expect(() => parse(source.title, { value: 'я'.repeat(2048), state: 'truncated', redacted: false })).not.toThrow();
    expect(() => parse(source.title, { value: 'я'.repeat(2049), state: 'truncated', redacted: false })).toThrow();
  });
  it('rejects quoted credential labels and multiword payloads rather than trusting normalized flags', () => {
    const a = advisoryFixture(), source = a.assessments[0];
    for (const value of ['Safe {"password":"PRIVATE_SENTINEL words"} tail', "Safe {'api_key':'PRIVATE_SENTINEL words'} tail", 'Safe password="PRIVATE_SENTINEL words" tail', 'Safe credentials: PRIVATE_SENTINEL words']) {
      const title = { value, state: 'available', redacted: true };
      expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, assessments: [{ ...source, title }] } }]))).toThrow();
    }
  });
  it('enforces vector family/version/metrics and preserves score with missing vector without inventing 3.1', () => {
    const a = advisoryFixture(), source = a.assessments[0], c = source.cvss;
    const parse = (cvss: unknown) => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, references: [], assessments: [{ ...source, cvss }] } }]));
    expect(() => parse({ ...c, version: null, versionState: 'missing', vector: null, vectorState: 'missing' })).not.toThrow();
    expect(() => parse({ ...c, family: 'v2', version: '2.0', vector: null, vectorState: 'unsupported' })).not.toThrow();
    expect(() => parse({ ...c, version: '3.0', vector: c.vector.replace('3.1', '3.0') })).not.toThrow();
    for (const score of ['0', NaN, Infinity, -1, 11]) expect(() => parse({ ...c, reportedScore: score })).toThrow();
    for (const vector of [c.vector.replace('3.1', '3.0'), c.vector.replace('3.1', '4.0'), c.vector + '/AV:N', c.vector + '/E:X', c.vector.replace('/A:H', ''), c.vector.replace('AV:N', 'AV:X'), c.vector + '/constructor:X']) expect(() => parse({ ...c, vector })).toThrow();
    expect(() => parse({ ...c, family: 'v2' })).toThrow();
  });
  it('allows only exact canonical links and the basic calculator for an actual 3.1 vector', () => {
    const a = advisoryFixture();
    const parse = (references: unknown[]) => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, references } }]));
    for (const url of ['http://www.cve.org/CVERecord?id=CVE-2026-1234', 'https://www.cve.org.evil/CVERecord?id=CVE-2026-1234', 'https://user@www.cve.org/CVERecord?id=CVE-2026-1234', 'https://www.cve.org:443/CVERecord?id=CVE-2026-1234', 'https://127.0.0.1/', 'https://www.cve.org/CVERecord?id=CVE-2026-1234#x', 'https://www.cve.org/CVERecord?id=CVE-2026-1234&token=x', 'https://www.cve.org/CVERecord?id=CVE-2026-1234%0a', 'https://www.cve.org\\evil', 'https://ｗｗｗ.cve.org/', 'https://nvd.nist.gov/vuln/detail/CVE-2026-9999']) expect(() => parse([{ ...a.references[0], url }])).toThrow();
    expect(() => parse([...a.references].reverse())).toThrow();
    expect(() => parse([a.references[0], a.references[0]])).toThrow();
    expect(() => parse([{ ...a.references[2], url: a.references[2].url + '#CVSS:3.1' }])).toThrow();
    expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, assessments: [] } }]))).toThrow();
  });
  it('enforces serialized finding and aggregate page budgets including JSON escapes', () => {
    const a = advisoryFixture();
    const source = a.assessments[0];
    const large = (count: number) => ({ ...a, assessments: Array.from({ length: count }, (_, n) => ({ ...source, provenanceRef: `target-${String(n).padStart(64, '0')}`, description: { value: '"'.repeat(4096), state: 'available', redacted: false } })) });
    expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: large(1) }]))).not.toThrow();
    expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: large(2) }]))).toThrow();
    const almostFull = { ...a, assessments: Array.from({ length: 3 }, (_, n) => ({ ...source, provenanceRef: `target-${String(n).padStart(64, '0')}`, description: { value: 'x'.repeat(4096), state: 'available', redacted: false } })) };
    expect(() => parseCurrentVuln(advisoryPage(Array.from({ length: 70 }, (_, n) => ({ ...advisoryFinding(), findingId: `vuln-${n}`, advisory: almostFull }))))).not.toThrow();
    expect(() => parseCurrentVuln(advisoryPage(Array.from({ length: 100 }, (_, n) => ({ ...advisoryFinding(), findingId: `vuln-${n}`, advisory: almostFull }))))).toThrow();
    expect(() => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory: { ...a, assessments: Array.from({ length: 17 }, (_, n) => ({ ...source, provenanceRef: `target-${String(n).padStart(64, '0')}` })) } }]))).toThrow();
  });
  it('rejects exactly one serialized byte over the complete finding cap', () => {
    const a = advisoryFixture(), source = a.assessments[0];
    const f = { ...advisoryFinding(), advisory: { ...a, assessments: Array.from({ length: 4 }, (_, n) => ({ ...source, provenanceRef: `target-${String(n).padStart(64, '0')}`, description: { value: n < 3 ? 'x'.repeat(4096) : 'x', state: 'available', redacted: false } })) } };
    const tail = f.advisory.assessments[3].description;
    const remaining = 16384 - new TextEncoder().encode(JSON.stringify(f)).length;
    expect(remaining).toBeGreaterThan(0);
    tail.value += 'x'.repeat(remaining);
    expect(new TextEncoder().encode(JSON.stringify(f))).toHaveLength(16384);
    expect(() => parseCurrentVuln(advisoryPage([f]))).not.toThrow();
    tail.value += 'x';
    expect(() => parseCurrentVuln(advisoryPage([f]))).toThrow();
  });
  it('keeps closed known DB evidence without treating historical nextUpdate as current freshness', () => {
    const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'a'.repeat(64)}`, schemaVersion: 2,
      manifestDigest: `sha256:${'a'.repeat(64)}`, artifactSha256: 'b'.repeat(64), metadataSha256: 'c'.repeat(64), dbSha256: 'd'.repeat(64),
      updatedAt: '2025-01-01T00:00:00.000Z', downloadedAt: '2025-01-01T00:00:00.000Z', nextUpdate: '2025-01-02T00:00:00.000Z' };
    expect(parseCurrentVuln({ ...advisoryPage(), db })).toMatchObject({ db });
    for (const invalid of [{ ...db, schemaVersion: 99 }, { ...db, signer: 'publisher' }, { ...db, raw: true }, { ...db, source: db.source.replace('ghcr.io', 'evil.test') }]) expect(() => parseCurrentVuln({ ...advisoryPage(), db: invalid })).toThrow();
  });
  it('retains omitted and conflict-unknown evidence, rejects malformed conflicts and duplicate observations', () => {
    const a = advisoryFixture();
    const parse = (advisory: unknown) => parseCurrentVuln(advisoryPage([{ ...advisoryFinding(), advisory }]));
    expect(() => parse({ ...a, conflicts: ['severity'], conflictState: 'unknown', limitations: ['assessment_limit'] })).not.toThrow();
    expect(() => parse({ ...a, state: 'omitted', assessments: [], references: [], conflictState: 'unknown', limitations: ['scan_budget'] })).not.toThrow();
    for (const advisory of [{ ...a, state: 'omitted' }, { ...a, conflictState: 'present' }, { ...a, conflicts: ['severity'] }, { ...a, assessments: [a.assessments[0], a.assessments[0]] }, { ...a, conflicts: ['cvss', 'title'], conflictState: 'present' }]) expect(() => parse(advisory)).toThrow();
  });
  it('accepts archive Secrets null/absent nonchecked counts while requiring checked counts', () => {
    const coverage = { check: 'secret', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED', scannerVersion: '0.69.3', reason: 'SCAN_FAILED' };
    for (const value of [coverage, { ...coverage, findingCount: null }, { ...coverage, findingCount: 0 }]) {
      expect(parseCurrentResults({ findings: [], nextCursor: null, coverage: value }).coverage[0].findingCount).toBeUndefined();
      expect(parseCurrentStatus({ scanId: 'x', state: 'failed', result: value }).perCheck?.secret?.outcome).toBe('failed');
    }
    const checked = { ...coverage, outcome: 'checked', reason: undefined, errorCode: null, findingCount: 0, checkedAt: '2026-10-07T08:00:00.000Z' };
    expect(parseCurrentResults({ findings: [], nextCursor: null, coverage: checked }).coverage[0].findingCount).toBe(0);
    for (const value of [{ ...checked, findingCount: null }, { ...checked, findingCount: undefined }, { ...coverage, findingCount: 1 }]) expect(() => parseCurrentResults({ findings: [], nextCursor: null, coverage: value })).toThrow();
  });
});
