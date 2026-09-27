import assert from 'node:assert/strict';
import test from 'node:test';
import { parseImageReference, requestFingerprint } from './image-reference.js';

const allowed = new Set(['registry.example.com']);
test('explicit canonical reference and immutable request fingerprint', () => {
  const tag = parseImageReference('registry.example.com/org/app:v1', allowed);
  assert.equal(tag.canonical, 'registry.example.com/org/app:v1');
  assert.equal(parseImageReference(`registry.example.com/org/app@sha256:${'a'.repeat(64)}`, allowed).selector,
    `sha256:${'a'.repeat(64)}`);
  assert.equal(requestFingerprint(tag, ['vuln', 'secret'], 'image'), requestFingerprint(tag, ['secret', 'vuln'], 'image'));
  assert.notEqual(requestFingerprint(tag, ['vuln'], 'image'), requestFingerprint(tag, ['vuln'], 'dependencies'));
});
test('rejects URL, credentials, IP, port, traversal, escaped and untrusted hosts', () => {
  for (const input of ['https://registry.example.com/a:b', 'user@registry.example.com/a:b',
    'registry.example.com:443/a:b', '127.0.0.1/a:b', 'registry.example.com/../a:b',
    'registry.example.com/a%2fb:v1', 'registry.example.com/a:b\n', 'evil.example.com/a:b',
    'registry.example.com./a:b', 'registry.example.com/a:b#fragment']) {
    assert.throws(() => parseImageReference(input, allowed), TypeError, input);
  }
});
