import assert from 'node:assert/strict';
import test from 'node:test';
import { REPORT_ECOSYSTEMS, parseReportQuery, type SbomQuery } from './report-query.js';
import { pageSbom } from './report-page.js';
import { PUBLIC_ECOSYSTEMS } from '../worker/public-image-evidence.js';

test('report-v1 accepts only the worker-reviewed public ecosystems and literal Maven name filter', () => {
  assert.deepEqual(REPORT_ECOSYSTEMS, PUBLIC_ECOSYSTEMS);
  for (const ecosystem of REPORT_ECOSYSTEMS) {
    const query = parseReportQuery('sbom', { view: 'report-v1', ecosystem, name: 'ORG.Example:lib', sort: 'ecosystem:desc' });
    assert.deepEqual(query?.filters, { ecosystem, name: 'org.example:lib' });
  }
  for (const ecosystem of ['any', 'DEB', 'rpm,deb', '', ['deb']]) {
    assert.throws(() => parseReportQuery('sbom', { view: 'report-v1', ecosystem }));
  }
  assert.throws(() => parseReportQuery('sbom', { view: 'report-v1', raw: 'PRIVATE_CANARY' }));
  assert.throws(() => parseReportQuery('sbom', { view: 'report-v1', name: 'https://example.test?credential=x' }));
});

test('public ecosystem sorting keeps complete-dataset lexical ties and strict query-bound cursors', () => {
  const rows = REPORT_ECOSYSTEMS.flatMap(ecosystem => [
    { ecosystem, name: 'same', version: '2' }, { ecosystem, name: 'same', version: '1' },
  ]);
  const original = structuredClone(rows);
  const query = parseReportQuery('sbom', { view: 'report-v1', sort: 'ecosystem:asc', limit: '5' }) as SbomQuery;
  const context = { subject: 'alice', scanId: 'public-report' };
  const all: typeof rows = [];
  let cursor: string | undefined;
  do {
    const page = pageSbom(rows, { ...query, cursor }, context, rows);
    assert.equal(page.page.totalCount, 22); assert.equal(page.page.matchedCount, 22);
    all.push(...page.items);
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
  assert.deepEqual(all.map(row => `${row.ecosystem}:${row.version}`), [...REPORT_ECOSYSTEMS].sort().flatMap(ecosystem => [`${ecosystem}:1`, `${ecosystem}:2`]));
  assert.deepEqual(rows, original);
  const first = pageSbom(rows, query, context, rows);
  assert.throws(() => pageSbom(rows, { ...query, cursor: first.nextCursor, filters: { ecosystem: 'maven', name: null } }, context, rows));
});
