// Offline successor evidence checks. This file never imports the discovery runner
// (which would perform network requests) and never launches Docker or old proofs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const proof = new URL('../server/deploy/proof/', import.meta.url);
const text = readFileSync(new URL('task2-small-node-metadata.json', proof), 'utf8');
const evidence = JSON.parse(text);

test('two-candidate metadata allowance is exhausted without accepting an oversized layer', () => {
  assert.deepEqual(evidence.candidates.map(c => c.tag), ['14.0.0-alpine3.11', '16.0.0-alpine3.13']);
  assert.equal(evidence.requests, 5);
  assert.ok(evidence.wireBytes > 0 && evidence.wireBytes <= 16_000_000);
  assert.ok(Date.parse(evidence.finishedAt) - Date.parse(evidence.startedAt) < 60_000);
  assert.equal(evidence.success, false);
  assert.equal(Object.hasOwn(evidence, 'selected'), false);
  assert.equal(Object.hasOwn(evidence, 'failure'), false, 'completed discovery, not transport failure');
});

test('both pinned candidates fit total but not per-layer cap; expansion remains unknown', () => {
  const largest = [35_568_075, 35_767_592];
  const totals = [40_607_353, 40_928_932];
  for (const [i, c] of evidence.candidates.entries()) {
    assert.equal(c.registry, 'registry-1.docker.io');
    assert.equal(c.repository, 'library/node');
    assert.equal(c.platform, 'linux/amd64');
    assert.match(c.digest, /^sha256:[a-f0-9]{64}$/);
    assert.match(c.config.digest, /^sha256:[a-f0-9]{64}$/);
    assert.ok(c.layers.length > 0 && c.layers.length <= 32);
    assert.equal(Math.max(...c.layers.map(l => l.size)), largest[i]);
    assert.equal(c.layers.reduce((sum, l) => sum + l.size, 0), totals[i]);
    assert.equal(c.compressedBytes, totals[i]);
    assert.ok(totals[i] < 96 * 1024 ** 2);
    assert.ok(largest[i] > 32 * 1024 ** 2);
    assert.equal(c.compressedEnvelopeFits, false);
    assert.equal(c.inflatedEnvelope, 'unknown until bounded verified acquisition');
  }
});

test('earlier executed evidence is preserved and successor contains no credentials or report bodies', () => {
  const validation = JSON.parse(readFileSync(new URL('task2-qualification-validation.json', proof), 'utf8'));
  for (const name of ['task2-qualification-results.json', 'task2-npm-remote-candidate.json']) {
    const hash = createHash('sha256').update(readFileSync(new URL(name, proof))).digest('hex');
    assert.equal(hash, validation.hashes['server/deploy/proof/' + name]);
  }
  assert.ok(!/Bearer |ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]+\.|BEGIN .*PRIVATE KEY/.test(text));
  assert.ok(!/"(?:Env|Secrets|Match|Authorization|token)"\s*:/.test(text));
});
