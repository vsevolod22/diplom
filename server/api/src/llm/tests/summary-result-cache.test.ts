import assert from 'node:assert/strict';
import test from 'node:test';
import { SUMMARY_CACHE, SummaryResultCache } from '../summary-result-cache.js';
import { fixtureReport, reply } from './fixtures.js';

const body = JSON.stringify({ ...reply(fixtureReport), scannerFacts: fixtureReport.findings });
const report = (index: number) => ({ ...fixtureReport, scanId: String(index) });

test('result cache keys owner, scan, digest, platform, report and policy; returned values cannot mutate retained bytes', () => {
  const cache = new SummaryResultCache();
  cache.put('owner', fixtureReport, 'policy', body);
  assert.equal(cache.get('other', fixtureReport, 'policy'), undefined);
  assert.equal(cache.get('owner', { ...fixtureReport, scanId: 'other' }, 'policy'), undefined);
  const value = cache.get('owner', fixtureReport, 'policy')!;
  value.hypotheses[0].text = 'changed by caller';
  assert.equal(JSON.stringify(cache.get('owner', fixtureReport, 'policy')), body);
  for (const patch of [{ digest: 'different' }, { platform: 'linux/arm64' }, { reportVersion: 'different' }]) {
    cache.put('owner', fixtureReport, 'policy', body);
    assert.equal(cache.get('owner', { ...fixtureReport, ...patch }, 'policy'), undefined);
    assert.equal(cache.get('owner', fixtureReport, 'policy'), undefined, 'a stale binding is discarded, not resurrected');
  }
  cache.put('owner', fixtureReport, 'policy', body);
  assert.equal(cache.get('owner', fixtureReport, 'new-policy'), undefined);
  assert.equal(cache.get('owner', fixtureReport, 'policy'), undefined);
  cache.put('owner', fixtureReport, 'policy', body);
  assert.equal(cache.get('owner', fixtureReport, null), undefined);
  assert.equal(cache.get('owner', fixtureReport, 'policy'), undefined);
});

test('64-entry LRU ceiling evicts least recently read, without cross-instance state', () => {
  const cache = new SummaryResultCache();
  for (let n = 0; n < SUMMARY_CACHE.entries; n++) cache.put('owner', report(n), 'policy', body);
  assert.ok(cache.get('owner', report(0), 'policy'));
  cache.put('owner', report(64), 'policy', body);
  assert.equal(cache.get('owner', report(1), 'policy'), undefined);
  assert.ok(cache.get('owner', report(0), 'policy')); assert.ok(cache.get('owner', report(64), 'policy'));
  assert.equal(new SummaryResultCache().get('owner', report(64), 'policy'), undefined);
  cache.clear(); assert.equal(cache.get('owner', report(0), 'policy'), undefined);
});

test('aggregate bytes and per-result bytes are bounded independently of the entry count', () => {
  const cache = new SummaryResultCache();
  // Controlled storage-size fixture, not validated model/publication evidence.
  const large = JSON.stringify({ ...reply(fixtureReport), scannerFacts: [], padding: 'x'.repeat(60000) });
  assert.ok(Buffer.byteLength(large) < SUMMARY_CACHE.entryBytes);
  for (let n = 0; n < 40; n++) cache.put('owner', report(n), 'policy', large);
  assert.equal(cache.get('owner', report(0), 'policy'), undefined, '2 MiB limit is reached before 64 entries');
  assert.ok(cache.get('owner', report(39), 'policy'));
  cache.put('owner', report(100), 'policy', 'x'.repeat(SUMMARY_CACHE.entryBytes + 1));
  assert.equal(cache.get('owner', report(100), 'policy'), undefined);
});
