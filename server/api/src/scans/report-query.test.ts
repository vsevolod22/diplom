import assert from 'node:assert/strict';
import test from 'node:test';
import { parseReportQuery, ReportViewError, REPORT_SEVERITIES, type ReportKind } from './report-query.js';

// Pure synthetic entry: only node assert/test and the framework-free query module.
const view = { view: 'report-v1' };
const invalid = (kind: ReportKind, query: unknown) => assert.throws(() => parseReportQuery(kind, query),
  error => error instanceof ReportViewError && error.errorCode === 'INVALID_REPORT_QUERY');

test('report-v1 defaults and exact limit presets; legacy remains a separate contract', () => {
  assert.equal(parseReportQuery('vuln', { cursor: '2', limit: '1', oldIgnoredKey: 'value' }), undefined);
  for (const [kind, sort, filters] of [
    ['vuln', 'severity:desc', { severity: null }],
    ['sbom', 'name:asc', { ecosystem: null, name: null }],
    ['secret', 'ruleId:asc', { ruleId: null, linePresence: null }],
  ] as const) {
    assert.deepEqual(parseReportQuery(kind, view), { kind, limit: 25, cursor: undefined, sort, filters });
    for (const limit of ['5', '10', '25', '50']) assert.equal(parseReportQuery(kind, { ...view, limit })?.limit, Number(limit));
    for (const limit of ['', '0', '1', '100', '05', '25.0', ' 25', '25 ', '1e1', 25, ['25', '25']]) invalid(kind, { ...view, limit });
  }
});

test('new filters require opt-in and reject unknown, cross-report and repeated parameters', () => {
  for (const key of ['sort', 'severity', 'ecosystem', 'name', 'ruleId', 'linePresence']) invalid('vuln', { [key]: 'value' });
  invalid('vuln', { ...view, name: 'package' });
  invalid('sbom', { ...view, severity: 'HIGH' });
  invalid('secret', { ...view, severity: 'UNKNOWN' });
  invalid('secret', { ...view, unknown: 'value' });
  for (const value of ['', 'report-v2', ['report-v1', 'report-v1'], { value: 'report-v1' }]) invalid('vuln', { view: value });
  for (const value of [null, [], 'view=report-v1', undefined]) invalid('vuln', value);
  const query = Object.create(null) as Record<string, unknown>;
  query.view = 'report-v1';
  assert.equal(parseReportQuery('vuln', query)?.limit, 25);
  let accessed = false;
  invalid('vuln', Object.defineProperty({}, 'view', { get() { accessed = true; return 'report-v1'; }, enumerable: true }));
  assert.equal(accessed, false);
});

test('severity subset is exact, duplicate-free and canonical; explicit all equals omitted', () => {
  assert.deepEqual(parseReportQuery('vuln', { ...view, severity: 'CRITICAL,HIGH,UNKNOWN' })?.filters, { severity: ['UNKNOWN', 'HIGH', 'CRITICAL'] });
  assert.deepEqual(parseReportQuery('vuln', { ...view, severity: [...REPORT_SEVERITIES].reverse().join(',') })?.filters, { severity: null });
  for (const severity of ['', 'high', 'HIGH,HIGH', 'HIGH,', ',LOW', 'HIGH, LOW', 'ALL', ['HIGH', 'LOW']]) invalid('vuln', { ...view, severity });
  for (const sort of ['severity:asc', 'severity:desc']) assert.equal(parseReportQuery('vuln', { ...view, sort })?.sort, sort);
  for (const sort of ['severity', 'severity:DESC', 'score:desc', ['severity:asc']]) invalid('vuln', { ...view, sort });
});

test('SBOM literal ASCII name and ecosystem filters normalize without wildcard semantics', () => {
  assert.deepEqual(parseReportQuery('sbom', { ...view, ecosystem: 'npm', name: '@ORG/Module+' })?.filters,
    { ecosystem: 'npm', name: '@org/module+' });
  assert.equal(parseReportQuery('sbom', { ...view, name: 'a'.repeat(128) })?.kind, 'sbom');
  for (const name of ['', 'a'.repeat(129), '*', '%', 'foo bar', 'foo?', '\n', '界', ['foo', 'bar']]) invalid('sbom', { ...view, name });
  for (const ecosystem of ['', 'all', 'NPM', 'npm,apk', ['npm']]) invalid('sbom', { ...view, ecosystem });
  for (const sort of ['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc']) assert.equal(parseReportQuery('sbom', { ...view, sort })?.sort, sort);
});

test('Secrets accepts exact opaque/legacy rule IDs and honest line presence only', () => {
  assert.deepEqual(parseReportQuery('secret', { ...view, ruleId: 'rule-a1b2', linePresence: 'unknown' })?.filters,
    { ruleId: 'rule-a1b2', linePresence: 'unknown' });
  assert.equal(parseReportQuery('secret', { ...view, ruleId: 'Legacy.Rule_1', linePresence: 'known' })?.kind, 'secret');
  for (const ruleId of ['', 'a'.repeat(81), 'rule/id', 'rule*', ['rule-a', 'rule-b']]) invalid('secret', { ...view, ruleId });
  for (const linePresence of ['', 'all', 'true', ['known']]) invalid('secret', { ...view, linePresence });
  for (const sort of ['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc']) assert.equal(parseReportQuery('secret', { ...view, sort })?.sort, sort);
  invalid('secret', { ...view, sort: 'severity:desc' });
});
