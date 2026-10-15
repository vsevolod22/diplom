import assert from 'node:assert/strict';
import test from 'node:test';
import { parseReportQuery, ReportViewError, type ReportKind, type Severity } from './report-query.js';
import { pageVuln, pageSbom, pageSecrets } from './report-page.js';

// Pure synthetic entry: no Nest, worker, ledger, filesystem, environment or HTTP imports.
const context = { subject: 'synthetic-owner', scanId: 'synthetic-scan' };
const query = (kind: ReportKind, values: Record<string, unknown> = {}) => parseReportQuery(kind, { view: 'report-v1', ...values })!;
const vulnQuery = (values: Record<string, unknown> = {}) => { const q = query('vuln', values); assert.equal(q.kind, 'vuln'); if (q.kind !== 'vuln') throw Error(); return q; };
const sbomQuery = (values: Record<string, unknown> = {}) => { const q = query('sbom', values); if (q.kind !== 'sbom') throw Error(); return q; };
const secretQuery = (values: Record<string, unknown> = {}) => { const q = query('secret', values); if (q.kind !== 'secret') throw Error(); return q; };
const encode = (token: unknown) => Buffer.from(JSON.stringify(token)).toString('base64url');
const decode = (cursor: string) => JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as { v: number; q: string; r: string; o: number };
const error = (run: () => unknown, code: string) => assert.throws(run, value => value instanceof ReportViewError && value.errorCode === code);
const rows = Object.freeze(Array.from({ length: 31 }, (_, i) => Object.freeze({ findingId: `vuln-${String(i).padStart(3, '0')}`,
  severity: (i < 20 ? 'LOW' : i < 29 ? 'HIGH' : 'UNKNOWN') as Severity, extra: { preserved: i } })));
const snapshot = { outcome: 'checked', findings: rows, checkedAt: 'synthetic-stored-time', db: { version: 1 } };

test('CVE filters and severity ordering apply globally before paging; no input mutation or row rewriting', () => {
  const q = vulnQuery({ limit: '5', severity: 'HIGH', sort: 'severity:desc' });
  const first = pageVuln(rows, q, context, snapshot);
  assert.deepEqual(first.items.map(row => row.findingId), ['vuln-020', 'vuln-021', 'vuln-022', 'vuln-023', 'vuln-024']);
  assert.deepEqual(first.page, { version: 1, limit: 5, offset: 0, returnedCount: 5, totalCount: 31, matchedCount: 9,
    sort: 'severity:desc', filters: { severity: ['HIGH'] } });
  assert.ok(first.nextCursor);
  const second = pageVuln(rows, vulnQuery({ limit: '5', severity: 'HIGH', cursor: first.nextCursor }), context, snapshot);
  assert.deepEqual(second.items.map(row => row.findingId), ['vuln-025', 'vuln-026', 'vuln-027', 'vuln-028']);
  assert.equal(second.nextCursor, null);
  assert.equal(second.page.offset, 5);
  assert.equal(first.items[0], rows[20]);
  assert.equal(rows[0].severity, 'LOW');
  const all = pageVuln(rows, vulnQuery({ limit: '50' }), context, snapshot);
  assert.equal(all.items[0].severity, 'HIGH');
  assert.deepEqual(all.items.slice(-2).map(row => row.severity), ['UNKNOWN', 'UNKNOWN']);
});

test('known severity ordering is explicit, UNKNOWN last in both directions with stable ID ties', () => {
  const values = ['UNKNOWN', 'HIGH', 'MEDIUM', 'CRITICAL', 'LOW', 'HIGH'] as const;
  const findings = values.map((severity, i) => ({ findingId: String(i), severity }));
  assert.deepEqual(pageVuln(findings, vulnQuery(), context, findings).items.map(row => row.findingId), ['3', '1', '5', '2', '4', '0']);
  assert.deepEqual(pageVuln(findings, vulnQuery({ sort: 'severity:asc' }), context, findings).items.map(row => row.findingId), ['4', '2', '1', '5', '3', '0']);
  const empty = pageVuln(findings, vulnQuery({ severity: 'UNKNOWN' }), context, findings);
  assert.equal(empty.page.matchedCount, 1);
});

test('SBOM AND filters are literal/case-insensitive, order ties are ecosystem/version lexical', () => {
  const components = Object.freeze([
    { ecosystem: 'npm' as const, name: '@org/zeta', version: '2' },
    { ecosystem: 'apk' as const, name: 'zlib', version: '1' },
    { ecosystem: 'npm' as const, name: '@org/alpha', version: '2' },
    { ecosystem: 'npm' as const, name: '@org/alpha', version: '10' },
    { ecosystem: 'apk' as const, name: '@org/alpha', version: '1' },
  ]);
  const page = pageSbom(components, sbomQuery({ ecosystem: 'npm', name: '@ORG/', sort: 'name:desc' }), context, components);
  assert.deepEqual(page.items.map(row => [row.name, row.version]), [['@org/zeta', '2'], ['@org/alpha', '10'], ['@org/alpha', '2']]);
  assert.equal(page.page.totalCount, 5); assert.equal(page.page.matchedCount, 3);
  const ecosystems = pageSbom(components, sbomQuery({ sort: 'ecosystem:desc' }), context, components);
  assert.deepEqual(ecosystems.items.map(row => row.ecosystem), ['npm', 'npm', 'npm', 'apk', 'apk']);
  assert.equal(pageSbom(components, sbomQuery({ name: 'absent' }), context, components).page.matchedCount, 0);
});

test('Secrets rule/line presence filters are honest; zero is known, null always last', () => {
  const findings = Object.freeze([
    { findingId: 'secret-0-2', ruleId: 'rule-b', line: null },
    { findingId: 'secret-0-1', ruleId: 'rule-a', line: 10 },
    { findingId: 'secret-0-0', ruleId: 'rule-a', line: 0 },
    { findingId: 'secret-1-0', ruleId: 'rule-a', line: null },
  ]);
  assert.deepEqual(pageSecrets(findings, secretQuery({ linePresence: 'known', sort: 'line:desc' }), context, findings).items.map(row => row.line), [10, 0]);
  assert.deepEqual(pageSecrets(findings, secretQuery({ sort: 'line:asc' }), context, findings).items.map(row => row.line), [0, 10, null, null]);
  assert.deepEqual(pageSecrets(findings, secretQuery({ sort: 'line:desc' }), context, findings).items.map(row => row.line), [10, 0, null, null]);
  assert.deepEqual(pageSecrets(findings, secretQuery({ ruleId: 'rule-a', linePresence: 'unknown' }), context, findings).items.map(row => row.findingId), ['secret-1-0']);
  assert.deepEqual(pageSecrets(findings, secretQuery({ sort: 'ruleId:desc' }), context, findings).items.map(row => row.findingId), ['secret-0-2', 'secret-0-0', 'secret-0-1', 'secret-1-0']);
});

test('all limits walk a 1000-row bounded report exactly once with accurate global counts', () => {
  const findings = Array.from({ length: 1000 }, (_, i) => ({ findingId: String(i).padStart(4, '0'), severity: 'HIGH' as const }));
  for (const limit of ['5', '10', '25', '50']) {
    let cursor: string | undefined;
    const ids: string[] = [];
    do {
      const page = pageVuln(findings, vulnQuery({ limit, ...(cursor ? { cursor } : {}) }), context, findings);
      assert.equal(page.page.offset, ids.length); assert.equal(page.page.totalCount, 1000); assert.equal(page.page.matchedCount, 1000);
      ids.push(...page.items.map(row => row.findingId)); cursor = page.nextCursor ?? undefined;
    } while (cursor);
    assert.deepEqual(ids, findings.map(row => row.findingId));
  }
  assert.throws(() => pageVuln([...findings, findings[0]], vulnQuery(), context, findings), /Invalid report dataset/);
});

test('query identity binds owner/scan/kind/filters/sort/limit, not parameter spelling/order', () => {
  const first = pageVuln(rows, vulnQuery({ limit: '5' }), context, snapshot);
  assert.ok(first.nextCursor);
  const cursor = first.nextCursor;
  const token = decode(cursor);
  assert.deepEqual(Object.keys(token), ['v', 'q', 'r', 'o']);
  assert.ok(cursor.length <= 512);
  assert.ok(!Buffer.from(cursor, 'base64url').toString('utf8').includes(context.subject));
  for (const change of [{ limit: '10' }, { severity: 'HIGH' }, { sort: 'severity:asc' }])
    error(() => pageVuln(rows, vulnQuery({ limit: '5', cursor, ...change }), context, snapshot), 'REPORT_CURSOR_QUERY_MISMATCH');
  for (const change of [{ subject: 'other' }, { scanId: 'other' }])
    error(() => pageVuln(rows, vulnQuery({ limit: '5', cursor }), { ...context, ...change }, snapshot), 'REPORT_CURSOR_QUERY_MISMATCH');
  error(() => pageSbom([], sbomQuery({ limit: '5', cursor }), context, snapshot), 'REPORT_CURSOR_QUERY_MISMATCH');
  assert.equal(pageVuln(rows, vulnQuery({ limit: '5', cursor, severity: 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN', sort: 'severity:desc' }), context, snapshot).page.offset, 5);
  const subset = pageVuln(rows, vulnQuery({ limit: '5', severity: 'HIGH,LOW' }), context, snapshot);
  assert.equal(pageVuln(rows, vulnQuery({ limit: '5', severity: 'LOW,HIGH', cursor: subset.nextCursor }), context, snapshot).page.offset, 5);
});

test('snapshot hashes bind metadata and complete source-order rows, stable under object key reordering', () => {
  const first = pageVuln(rows, vulnQuery({ limit: '5' }), context, snapshot);
  const q = vulnQuery({ limit: '5', cursor: first.nextCursor });
  const reordered = { db: { version: 1 }, checkedAt: snapshot.checkedAt, findings: rows, outcome: 'checked' };
  assert.equal(pageVuln(rows, q, context, reordered).page.offset, 5);
  for (const changed of [{ ...snapshot, checkedAt: 'different' }, { ...snapshot, findings: [...rows].reverse() },
    { ...snapshot, db: { version: 2 } }]) error(() => pageVuln(rows, q, context, changed), 'REPORT_CURSOR_STALE');
});

test('cursor parsing is bounded, canonical and closed; terminal offset allowed, greater rejected', () => {
  const first = pageVuln(rows, vulnQuery({ limit: '5' }), context, snapshot);
  assert.ok(first.nextCursor);
  const token = decode(first.nextCursor);
  const bad = ['', '0', '1', 'x'.repeat(513), first.nextCursor + '=', null, undefined, ['token'], {}, 5,
    encode([]), encode({ ...token, extra: true }), encode({ ...token, v: 2 }), encode({ ...token, o: -1 }),
    encode({ ...token, o: 1.5 }), encode({ ...token, o: 1001 }), encode({ ...token, q: token.q.toUpperCase() }),
    Buffer.from(' ' + JSON.stringify(token)).toString('base64url'),
    encode({ q: token.q, v: token.v, r: token.r, o: token.o })];
  for (const cursor of bad) error(() => pageVuln(rows, vulnQuery({ limit: '5', cursor }), context, snapshot), 'INVALID_PAGINATION');
  const terminal = pageVuln(rows, vulnQuery({ limit: '5', cursor: encode({ ...token, o: rows.length }) }), context, snapshot);
  assert.deepEqual(terminal.items, []); assert.equal(terminal.nextCursor, null); assert.equal(terminal.page.offset, rows.length);
  error(() => pageVuln(rows, vulnQuery({ limit: '5', cursor: encode({ ...token, o: rows.length + 1 }) }), context, snapshot), 'INVALID_PAGINATION');
});

test('checked no-match is zero while nonchecked coverage stays unknown, never checked zero', () => {
  const checked = pageVuln(rows, vulnQuery({ severity: 'CRITICAL' }), context, snapshot);
  assert.equal(checked.page.totalCount, 31); assert.equal(checked.page.matchedCount, 0); assert.equal(checked.nextCursor, null);
  const failed = pageVuln([], vulnQuery(), context, { outcome: 'failed', reason: 'SCAN_TIMEOUT' }, false);
  assert.deepEqual(failed.page, { version: 1, limit: 25, offset: 0, returnedCount: 0, totalCount: null,
    matchedCount: null, sort: 'severity:desc', filters: { severity: null } });
  assert.equal(failed.nextCursor, null);
  assert.equal(pageSbom([], sbomQuery(), context, { outcome: 'failed' }, false).page.totalCount, null);
  assert.equal(pageSecrets([], secretQuery(), context, { outcome: 'unsupported' }, false).page.matchedCount, null);
  assert.throws(() => pageVuln(rows, vulnQuery(), context, snapshot, false), /Invalid report dataset/);
});
