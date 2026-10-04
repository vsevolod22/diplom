import assert from 'node:assert/strict';
import test from 'node:test';
import { ImageSearchSessions, normalizeImageSuggestions, parseImageSearch, searchImages } from './image-search.js';
import { hubSearchUrl } from '../oci/gateway-transport.js';

test('opaque cursors bind subject, normalized query and generation; retry is cached', async () => {
  let calls = 0;
  let now = 1000;
  const sessions = new ImageSearchSessions(async (kind, query, page = 1) => {
    calls++;
    return { results: [{ repo_name: `user/image${page}` }], count: 24, next: page < 3 ? hubSearchUrl(kind, query, page + 1).href : null, bytes: 100 };
  }, () => now);
  const first = await sessions.search('alice', 'NGINX', 'generation');
  assert.match(first.nextCursor!, /^[a-f0-9]{48}$/);
  for (const [subject, query, generation, cursor] of [['bob', 'nginx', 'generation', first.nextCursor!], ['alice', 'other', 'generation', first.nextCursor!], ['alice', 'nginx', 'other', first.nextCursor!], ['alice', 'nginx', 'generation', 'a'.repeat(48)]]) {
    await assert.rejects(sessions.search(subject, query, generation, cursor));
  }
  assert.equal(calls, 1);
  const second = await sessions.search('alice', 'nginx', 'generation', first.nextCursor);
  assert.deepEqual(await sessions.search('alice', 'nginx', 'generation', first.nextCursor), second);
  assert.equal(calls, 2);
  now += 300_001;
  await assert.rejects(sessions.search('alice', 'nginx', 'generation', second.nextCursor));
  assert.equal(calls, 2);
});

test('five pages retain 60 unique candidates, reject sixth page and distinguish incomplete', async () => {
  const sessions = new ImageSearchSessions(async (kind, query, page = 1) => ({ results: Array.from({ length: 12 }, (_, i) => ({ repo_name: `user/image${page}-${i}` })), count: 100, next: hubSearchUrl(kind, query, page + 1).href }));
  let result = await sessions.search('alice', 'nginx', 'gen');
  for (let page = 2; page <= 5; page++) result = await sessions.search('alice', 'nginx', 'gen', result.nextCursor);
  assert.equal(result.loaded, 60); assert.equal(result.pages, 5); assert.equal(result.nextCursor, null); assert.equal(result.state, 'quota-exhausted');
});

test('empty and duplicate pages do not falsely become terminal', async () => {
  const sessions = new ImageSearchSessions(async (kind, query, page = 1) => ({ results: page === 2 ? [] : [{ repo_name: 'nginx' }, { repo_name: 'nginx' }], count: 2, next: page < 3 ? hubSearchUrl(kind, query, page + 1).href : null }));
  const first = await sessions.search('alice', 'nginx', 'gen');
  assert.equal(first.items.length, 1); assert.equal(first.items[0].tagConfirmed, false); assert.equal(first.items[0].checks.vuln, 'unsupported');
  const middle = await sessions.search('alice', 'nginx', 'gen', first.nextCursor);
  assert.equal(middle.items.length, 0); assert.equal(middle.state, 'more-available');
  const end = await sessions.search('alice', 'nginx', 'gen', middle.nextCursor);
  assert.equal(end.state, 'terminal'); assert.equal(end.loaded, 1);
});

test('hostile upstream links, malformed pages and byte excess retire the search', async () => {
  for (const next of ['https://evil.example/?page=2', hubSearchUrl('repositories', 'nginx', 1).href, 'garbage', undefined]) {
    const sessions = new ImageSearchSessions(async () => ({ results: [], count: 0, next }));
    await assert.rejects(sessions.search('alice', 'nginx', 'gen'));
  }
  for (const response of [{ results: [], count: -1, next: null }, { results: [], count: 0, next: null, bytes: 128_001 }, { results: Array(13).fill({ repo_name: 'nginx' }), count: 13, next: null }]) {
    await assert.rejects(new ImageSearchSessions(async () => response).search('alice', 'nginx', 'gen'));
  }
});

test('subject/global concurrency and rate budgets release after failure without resetting rates', async () => {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const sessions = new ImageSearchSessions(async () => { await pending; throw Error('upstream'); });
  const active = [sessions.search('alice', 'nginx', 'a'), sessions.search('alice', 'nginx', 'b')];
  await assert.rejects(sessions.search('alice', 'nginx', 'c'));
  for (let i = 0; i < 6; i++) active.push(sessions.search(`user${i}`, 'nginx', 'a'));
  await assert.rejects(sessions.search('other', 'nginx', 'a'));
  release(); await Promise.all(active.map(promise => assert.rejects(promise)));
  let calls = 0;
  const limited = new ImageSearchSessions(async () => { calls++; return { results: [], count: 0, next: null }; });
  for (let i = 0; i < 30; i++) await limited.search('alice', 'nginx', `g${i}`);
  await assert.rejects(limited.search('alice', 'nginx', 'last'));
  assert.equal(calls, 30);
});

test('Alpine 3.16 searches real tags, including its archived release', async () => {
  const result = await searchImages('Alpine 3.16', async (kind, query) => {
    assert.equal(kind, 'tags'); assert.equal(query, '3.16');
    return { results: [{ name: '3.16' }, { name: '3.16.9' }, { name: '../../../invalid' }] };
  });
  assert.deepEqual(result.map(item => item.reference), ['registry-1.docker.io/library/alpine:3.16', 'registry-1.docker.io/library/alpine:3.16.9']);
  assert.ok(result.every(item => item.scannable));
});

test('other repository results are discoverable but not advertised as scannable', async () => {
  const result = await searchImages('nginx', async (kind, query) => {
    assert.equal(kind, 'repositories'); assert.equal(query, 'nginx');
    return { results: [{ repo_name: 'nginx' }, { repo_name: 'someuser/nginx' }, { repo_name: '../../private' }] };
  });
  assert.deepEqual(result.map(item => item.reference), ['registry-1.docker.io/library/nginx:latest', 'registry-1.docker.io/someuser/nginx:latest']);
  assert.ok(result.every(item => !item.scannable));
});

test('search rejects hostile queries and oversized upstream responses', async () => {
  for (const query of ['', ' ', 'a'.repeat(65), 'https://127.0.0.1', 'alpine\nsecrets'])
    assert.throws(() => parseImageSearch(query));
  assert.throws(() => normalizeImageSuggestions({ results: Array(13).fill({ name: '3.16' }) }, true));
  await assert.rejects(searchImages('alpine 3.16', async () => { throw Error('unexpected upstream details'); }),
    error => error instanceof Error && !error.message.includes('unexpected upstream details'));
});
