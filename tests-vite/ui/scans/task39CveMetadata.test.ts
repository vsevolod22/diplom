import { afterEach, expect, it, vi } from 'vitest';
import { parseCurrentStatus, parseCurrentVuln, parseScanStatus } from '@/shared/api/scans/scanTransport';
import { CveReportContractError } from '@/shared/api/scans/cveDbMetadata';

export const stamp = '2026-10-08T12:00:00.000Z';
export const metadata = {
  resultContractVersion: 2 as const,
  db: { envelopeVersion: 1 as const, signer: 'local-db-operator-v1' as const, schemaVersion: 2 as const,
    manifestDigest: `sha256:${'b'.repeat(64)}`, source: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`,
    artifactSha256: 'c'.repeat(64), metadataSha256: 'd'.repeat(64), dbSha256: 'e'.repeat(64),
    updatedAt: '2026-10-06T12:00:00.000000001Z', downloadedAt: '2026-10-06T13:00:00.000Z', nextUpdate: '2026-10-07T12:00:00.000Z' },
  dbPolicy: { version: 2 as const, policy: 'cve-db-updated-at-14d-v2' as const, evaluatedAt: Date.parse(stamp),
    status: 'stale-but-usable' as const, warnings: ['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE'] as const },
  workerCheckedAt: Date.parse(stamp), usableUntil: '2026-10-20T12:00:00.000000001Z',
};
export const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
export const v2page = { ...metadata, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64',
  scannerVersion: '0.69.3', checkedAt: stamp, findingCount: 0, findings: [], nextCursor: null };
export const v2check = { ...metadata, check: 'vuln', coverage: 'image', outcome: 'checked', scannerVersion: '0.69.3', checkedAt: stamp, findingCount: 0 };
export const wireStatus = { scanId: 'test39', state: 'completed', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', imageReference: image,
  checks: ['vuln'], perCheck: { vuln: v2check }, result: v2check };
afterEach(() => vi.useRealTimers());
it('retains exact v2 checked page and redundant status/perCheck metadata on historical reload', () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2027-10-08'));
  expect(parseCurrentVuln(v2page)).toEqual(v2page);
  expect(parseCurrentStatus(wireStatus).perCheck?.vuln).toEqual(v2check);
  expect(parseScanStatus(parseCurrentStatus(wireStatus)).perCheck?.vuln).toEqual(v2check);
});
it('accepts closed unsupported v2 without fabricating a checked count', () => {
  const page = { ...metadata, outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', checkedAt: stamp, findings: [], nextCursor: null };
  expect(parseCurrentVuln(page)).toEqual(page);
  expect(parseCurrentStatus({ ...wireStatus, result: null, perCheck: { vuln: { ...v2check, outcome: 'unsupported', findingCount: undefined, reason: 'OS_UNKNOWN', checksVersion: 'archive1', errorCode: null } } }).perCheck?.vuln?.outcome).toBe('unsupported');
});
it.each(['resultContractVersion', 'dbPolicy', 'db', 'usableUntil', 'workerCheckedAt'])('rejects stripped %s without legacy fallback', key => {
  const page: Record<string, unknown> = { ...v2page }; delete page[key];
  expect(() => parseCurrentVuln(page)).toThrow(CveReportContractError);
  const check: Record<string, unknown> = { ...v2check }; delete check[key];
  expect(() => parseCurrentStatus({ ...wireStatus, perCheck: { vuln: check }, result: check })).toThrow();
});
it.each([
  { resultContractVersion: 3 }, { usableUntil: '2026-10-20T12:00:00.000Z' },
  { checkedAt: '2026-10-08T12:00:00Z' }, { workerCheckedAt: Date.parse(stamp) + 1 },
  { dbPolicy: { ...metadata.dbPolicy, extra: true } }, { dbPolicy: { ...metadata.dbPolicy, version: 1 } },
  { dbPolicy: { ...metadata.dbPolicy, warnings: [...metadata.dbPolicy.warnings].reverse() } },
  { dbPolicy: { ...metadata.dbPolicy, warnings: [] } }, { dbPolicy: { ...metadata.dbPolicy, status: 'usable' } },
  { dbPolicy: { ...metadata.dbPolicy, evaluatedAt: Date.parse('2026-10-21') } },
  { db: { ...metadata.db, policy: 2 } }, { db: { ...metadata.db, updatedAt: '2026-02-30T12:00:00.000Z' } },
  { db: { ...metadata.db, downloadedAt: '2026-10-05T12:00:00.000Z' } },
  { db: { ...metadata.db, nextUpdate: '2026-10-14T12:00:00.000Z' } },
  { db: { ...metadata.db, source: `ghcr.io/aquasecurity/trivy-db@sha256:${'f'.repeat(64)}` } },
])('rejects inconsistent or open v2 evidence %j', patch => expect(() => parseCurrentVuln({ ...v2page, ...patch })).toThrow(CveReportContractError));
it('accepts inclusive 14d, rejects +1ms and exact nanosecond excess', () => {
  const clock = Date.parse('2026-10-20T12:00:00.000Z');
  const page = { ...v2page, workerCheckedAt: clock, checkedAt: new Date(clock).toISOString(), dbPolicy: { ...metadata.dbPolicy, evaluatedAt: clock } };
  expect(parseCurrentVuln(page).outcome).toBe('checked');
  expect(() => parseCurrentVuln({ ...page, dbPolicy: { ...page.dbPolicy, evaluatedAt: clock + 1 } })).toThrow();
  expect(() => parseCurrentVuln({ ...page, db: { ...metadata.db, updatedAt: '2026-10-06T11:59:59.999999999Z' }, usableUntil: '2026-10-20T11:59:59.999999999Z' })).toThrow();
});
it('rejects inconsistent redundant result/perCheck and v2 evidence on failed outcome', () => {
  expect(() => parseCurrentStatus({ ...wireStatus, result: { ...v2check, findingCount: 1 } })).toThrow();
  expect(() => parseCurrentStatus({ ...wireStatus, result: { ...v2check, resultContractVersion: undefined } })).toThrow();
  expect(() => parseCurrentVuln({ ...metadata, outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', findings: [], nextCursor: null })).toThrow();
});
it('keeps all redundant archive metadata consistent, not just the policy receipt', () => {
  const check = { ...v2check, checksVersion: 'archive1', errorCode: null };
  expect(() => parseCurrentStatus({ ...wireStatus, perCheck: { vuln: check }, result: { ...check, checksVersion: 'archive2' } })).toThrow();
});
it('validates exact 24h/publication thresholds and usable receipt', () => {
  const evaluatedAt = Date.parse('2026-10-07T12:00:00.000Z');
  const page = { ...v2page, workerCheckedAt: evaluatedAt, checkedAt: new Date(evaluatedAt).toISOString(),
    db: { ...metadata.db, nextUpdate: '2026-10-07T12:00:00.000000001Z' },
    dbPolicy: { ...metadata.dbPolicy, evaluatedAt, status: 'usable', warnings: [] } };
  expect(parseCurrentVuln(page).outcome).toBe('checked');
  const publicationEqual = { ...page, db: { ...page.db, nextUpdate: '2026-10-07T12:00:00.000Z' }, dbPolicy: { ...page.dbPolicy, status: 'stale-but-usable', warnings: ['DB_PUBLICATION_OVERDUE'] } };
  expect(parseCurrentVuln(publicationEqual).outcome).toBe('checked');
  expect(() => parseCurrentVuln({ ...page, dbPolicy: { ...page.dbPolicy, evaluatedAt: evaluatedAt + 1 } })).toThrow();
});
it('validates future300 seconds inclusively, never rejuvenates old UpdatedAt with a recent download', () => {
  const evaluatedAt = Date.parse(stamp);
  const page = { ...v2page, db: { ...metadata.db, updatedAt: '2026-10-08T12:05:00.000Z', downloadedAt: '2026-10-08T12:05:00.000Z', nextUpdate: '2026-10-09T12:05:00.000Z' },
    usableUntil: '2026-10-22T12:05:00.000000000Z', dbPolicy: { ...metadata.dbPolicy, evaluatedAt, status: 'usable', warnings: [] } };
  expect(parseCurrentVuln(page).outcome).toBe('checked');
  expect(() => parseCurrentVuln({ ...page, db: { ...page.db, downloadedAt: '2026-10-08T12:05:00.000000001Z' } })).toThrow();
  expect(() => parseCurrentVuln({ ...v2page, db: { ...metadata.db, updatedAt: '2026-09-01T12:00:00.000Z', downloadedAt: stamp }, usableUntil: '2026-09-15T12:00:00.000000000Z' })).toThrow();
});
it('does not loosen or tighten legacy checked dates and unsupported shapes', () => {
  const legacy: Record<string, unknown> = { ...v2page };
  for (const key of ['resultContractVersion', 'dbPolicy', 'usableUntil', 'workerCheckedAt']) delete legacy[key];
  expect(parseCurrentVuln({ ...legacy, checkedAt: 'today' }).outcome).toBe('checked');
  const unsupported = { outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', findings: [], nextCursor: null };
  expect(parseCurrentVuln(unsupported)).toEqual(unsupported);
  expect(() => parseCurrentVuln({ ...unsupported, checkedAt: stamp })).toThrow();
});
it.each([
  ['plain-wire accessor', Object.defineProperty({}, 'outcome', { get: () => { throw new Error('rejected-private-payload'); }, enumerable: true })],
  ['unknown shape', { rejectedPayload: 'rejected-private-payload' }],
  ['legacy malformed shape', { outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', checkedAt: stamp, findings: [], nextCursor: null }],
  ['cursor bounds', { ...v2page, nextCursor: 1 }],
  ['finding count bounds', { ...v2page, findingCount: 0, findings: [{ findingId: 'row', cveId: 'CVE-2026-1234', ecosystem: 'apk', packageName: 'fixture', installedVersion: '1', fixedVersion: null, severity: 'HIGH' }] }],
])('P2 decoder rejection is typed and payload-free: %s', (_name, value) => {
  let failure: unknown;
  try { parseCurrentVuln(value); } catch (error) { failure = error; }
  expect(failure).toBeInstanceOf(CveReportContractError);
  expect((failure as Error).message).toBe('Invalid CVE report contract');
  expect(failure).not.toHaveProperty('cause');
  expect(JSON.stringify(failure)).not.toContain('rejected-private-payload');
});
it('P2 classifies aggregate advisory budget rejection without changing valid per-finding wire', () => {
  const advisory = { schemaVersion: 1, state: 'available', assessments: ['alpine', 'nvd', 'ghsa'].map(source => ({ source,
    provenanceRef: `target-${'a'.repeat(64)}`, title: { value: 'Synthetic fixture', state: 'available', redacted: false },
    description: { value: 'x'.repeat(4000), state: 'available', redacted: false }, language: null,
    severity: 'HIGH', fixedVersion: null, cvss: null })), references: [], conflicts: [], conflictState: 'none', limitations: [] };
  const findings = Array.from({ length: 100 }, (_, index) => ({ findingId: `fixture-${index}`, cveId: 'CVE-2026-1234',
    ecosystem: 'apk', packageName: 'fixture', installedVersion: '1', fixedVersion: null, severity: 'HIGH', advisory }));
  expect(parseCurrentVuln({ ...v2page, findingCount: 1, findings: findings.slice(0, 1) }).outcome).toBe('checked');
  expect(() => parseCurrentVuln({ ...v2page, findingCount: 100, findings })).toThrow(CveReportContractError);
});
it('P2 positive controls preserve v2/legacy checked and unsupported wire shapes', () => {
  expect(parseCurrentVuln(v2page)).toEqual(v2page);
  const unsupported = { ...metadata, outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', checkedAt: stamp, findings: [], nextCursor: null };
  expect(parseCurrentVuln(unsupported)).toEqual(unsupported);
  const legacy: Record<string, unknown> = { ...v2page };
  for (const key of ['resultContractVersion', 'dbPolicy', 'usableUntil', 'workerCheckedAt']) delete legacy[key];
  expect(parseCurrentVuln(legacy)).toEqual(legacy);
  const oldUnsupported = { outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN', findings: [], nextCursor: null };
  expect(parseCurrentVuln(oldUnsupported)).toEqual(oldUnsupported);
});
