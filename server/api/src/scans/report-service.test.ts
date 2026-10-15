import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { BadRequestException, ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { ScansService } from './scans.service.js';
import { ScansController } from './scans.controller.js';
import { BrowserScansController } from './browser-scans.controller.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import type { ScanLedger } from '../ledger/ledger.js';
import type { AuthStore } from '../auth/auth.store.js';
import type { BrowserRequest } from '../llm/browser-identity.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';

// SOURCE ONLY under current permission: imports the runtime graph. Do not include
// this file in the approved pure query/page execution command.
const owner = { subject: 'synthetic-owner', scope: ['scan:create'] };
const scanId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const view = { view: 'report-v1', limit: '5' };
const findings = Array.from({ length: 12 }, (_, i) => ({ findingId: `vuln-${i.toString().padStart(3, '0')}`,
  severity: i < 6 ? 'LOW' as const : 'HIGH' as const, cveId: 'CVE-2026-1234', advisory: { preserved: true } }));
function fixture(archive?: ArchiveScanReport) {
  let stored = { outcome: 'checked' as const, findings, findingCount: findings.length,
    scannerVersion: '0.69.3', checkedAt: 'synthetic-stored-time', coverage: 'image' as const, image: 'synthetic', platform: 'linux/amd64' as const };
  let reads = 0;
  const ledger = {
    readReportSnapshot: <T>(read: () => T) => read(),
    snapshot: (id: string, subject: string) => id === scanId && subject === owner.subject ? { state: 'completed' } : undefined,
    archiveResult: (_id: string, subject: string) => { assert.equal(subject, owner.subject); reads++; return archive; },
    vulnDataset: (_id: string, subject: string) => { assert.equal(subject, owner.subject); return stored; },
    sbomDataset: () => ({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null }),
    secretDataset: () => ({ findings: [], coverage: { outcome: 'unsupported', check: 'secret', findingCount: 17, coverage: 'image' } }),
  } as unknown as ScanLedger;
  const api = new ScansService({ ledger } as LedgerStore, {} as OciResolver);
  return { api, ledger, reads: () => reads, changeSnapshot: () => { stored = { ...stored, checkedAt: 'changed-stored-time' }; } };
}
const code = (run: () => unknown, expected: string, Type: typeof BadRequestException | typeof ConflictException) =>
  assert.throws(run, value => value instanceof Type && (value.getResponse() as { errorCode: string }).errorCode === expected);

test('source-only service seam scopes report reads before all cursor diagnostics', () => {
  const { api, reads } = fixture();
  for (const cursor of ['malformed', '', ['duplicate'], undefined]) {
    assert.throws(() => api.report({ ...owner, subject: 'foreign' }, scanId, 'vuln', { ...view, cursor }), NotFoundException);
    assert.throws(() => api.report(owner, 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'vuln', { ...view, cursor }), NotFoundException);
  }
  assert.equal(reads(), 0);
  code(() => api.report(owner, scanId, 'vuln', { ...view, cursor: 'malformed' }), 'INVALID_PAGINATION', BadRequestException);
  const first = api.report(owner, scanId, 'vuln', view);
  assert.ok(first.nextCursor);
  code(() => api.report(owner, scanId, 'sbom', { ...view, cursor: first.nextCursor }), 'REPORT_CURSOR_QUERY_MISMATCH', BadRequestException);
  const missing = fixture();
  missing.ledger.vulnDataset = () => undefined;
  assert.throws(() => missing.api.report(owner, scanId, 'vuln', { ...view, cursor: 'malformed' }), NotFoundException);
  const absent = new ScansService({ ledger: undefined } as unknown as LedgerStore, {} as OciResolver);
  assert.throws(() => absent.report(owner, scanId, 'vuln', view), ServiceUnavailableException);
});

test('source-only service preserves total/evidence and adds global page metadata with stale diagnostics', () => {
  const { api, changeSnapshot } = fixture();
  const first = api.report(owner, scanId, 'vuln', { ...view, severity: 'HIGH' });
  assert.ok('findingCount' in first && first.findingCount === 12);
  assert.ok('page' in first);
  assert.equal(first.page?.matchedCount, 6);
  assert.equal(first.page?.totalCount, 12);
  assert.ok(first.nextCursor);
  const second = api.report(owner, scanId, 'vuln', { ...view, severity: 'HIGH', cursor: first.nextCursor });
  assert.ok('page' in second);
  assert.equal(second.page.returnedCount, 1);
  assert.equal(second.nextCursor, null);
  changeSnapshot();
  code(() => api.report(owner, scanId, 'vuln', { ...view, severity: 'HIGH', cursor: first.nextCursor }), 'REPORT_CURSOR_STALE', ConflictException);
  const sbom = api.report(owner, scanId, 'sbom', view);
  assert.ok('page' in sbom);
  assert.equal(sbom.page.totalCount, null); assert.equal(sbom.page.matchedCount, null);
  const secrets = api.report(owner, scanId, 'secret', view);
  assert.ok('page' in secrets);
  assert.equal(secrets.page.matchedCount, null);
});

test('source-only legacy dispatcher preserves scalar cursor/limit and never opts into new metadata', () => {
  const { api } = fixture();
  const result = { findings: [], nextCursor: 3, coverage: null };
  api.results = (identity, id, cursor, limit) => {
    assert.equal(identity, owner); assert.equal(id, scanId); assert.equal(cursor, '2'); assert.equal(limit, '1');
    return result as ReturnType<ScansService['results']>;
  };
  assert.equal(api.report(owner, scanId, 'secret', { cursor: '2', limit: '1', oldIgnoredKey: 'value' }), result);
  code(() => api.report(owner, scanId, 'secret', { sort: 'ruleId:asc' }), 'INVALID_REPORT_QUERY', BadRequestException);
});

test('source-only archive service pages persisted arrays without scanner or relational fallback', () => {
  const archive = { receipt: { registry: 'synthetic-registry', repository: 'synthetic-repository', digest: 'synthetic-digest', platform: 'linux/amd64' },
    scannerVersion: '0.69.3', checkedAt: 1_700_000_000_000,
    vuln: { outcome: 'checked', findings, db: {}, os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } },
    sbom: { outcome: 'checked', sbom: { image: 'synthetic', platform: 'linux/amd64', os: { name: 'alpine', version: 'synthetic' },
      components: Array.from({ length: 12 }, (_, i) => ({ ecosystem: i < 6 ? 'apk' : 'npm', name: `pkg-${i}`, version: '1' })) } },
    secret: { outcome: 'checked', findings: Array.from({ length: 12 }, (_, i) => ({ findingId: `secret-${i}-0`, ruleId: 'opaque-rule', line: i < 6 ? i : null, evidenceRef: `result-${i}-secret-0` })) },
  } as unknown as ArchiveScanReport;
  const { api, ledger } = fixture(archive);
  ledger.vulnDataset = () => { throw Error('unexpected relational read'); };
  ledger.sbomDataset = () => { throw Error('unexpected relational read'); };
  ledger.secretDataset = () => { throw Error('unexpected relational read'); };
  const vuln = api.report(owner, scanId, 'vuln', { ...view, severity: 'HIGH' });
  assert.ok('page' in vuln);
  assert.equal(vuln.page.matchedCount, 6);
  const sbom = api.report(owner, scanId, 'sbom', { ...view, ecosystem: 'npm', name: 'PKG-' });
  assert.ok('page' in sbom);
  assert.equal(sbom.page.matchedCount, 6);
  const secrets = api.report(owner, scanId, 'secret', { ...view, ruleId: 'opaque-rule', linePresence: 'unknown' });
  assert.ok('page' in secrets);
  assert.equal(secrets.page.matchedCount, 6);
});

test('source-only both controllers forward whole query to same service with verified identity', () => {
  const calls: unknown[][] = [];
  const scans = { report: (...args: unknown[]) => { calls.push(args); return 'synthetic-response'; }, imageSuggestion: () => undefined } as unknown as ScansService;
  const bearer = new ScansController(scans);
  bearer.vuln({ headers: {}, identity: owner }, scanId, view);
  bearer.sbom({ headers: {}, identity: owner }, scanId, view);
  bearer.results({ headers: {}, identity: owner }, scanId, view);
  const browser = new BrowserScansController({} as AuthStore, scans);
  Object.defineProperty(browser, 'identity', { value: () => owner });
  const req = { headers: {} } as BrowserRequest;
  browser.vuln(req, scanId, view); browser.sbom(req, scanId, view); browser.results(req, scanId, view);
  assert.deepEqual(calls.map(call => call.slice(0, 3)), [
    [owner, scanId, 'vuln'], [owner, scanId, 'sbom'], [owner, scanId, 'secret'],
    [owner, scanId, 'vuln'], [owner, scanId, 'sbom'], [owner, scanId, 'secret'],
  ]);
  assert.ok(calls.every(call => call[3] === view));
});
