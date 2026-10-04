import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeImageSuggestions, parseImageSearch, searchImages } from './image-search.js';

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
  assert.throws(() => normalizeImageSuggestions({ results: Array(21).fill({ name: '3.16' }) }, true));
  await assert.rejects(searchImages('alpine 3.16', async () => { throw Error('unexpected upstream details'); }),
    error => error instanceof Error && !error.message.includes('unexpected upstream details'));
});
