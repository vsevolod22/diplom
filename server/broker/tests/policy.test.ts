import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyStore, credentialDigest } from '../src/policy.js';
import { fixtureState, A, B, TOKEN, request } from './support.js';

test('local enrollment: full target, audience, scope, consent, current versions and TTL', () => {
  const store = new PolicyStore();
  store.replace(fixtureState('/private/engine.sock'));
  assert.ok(store.authorize(request(), 100_000));
  for (const mutation of [
    { id: B },
    { id: A.slice(0, 12) },
    { id: A.toUpperCase() },
    { context: 'other' },
    { credential: '' },
    { credential: 'b'.repeat(64) },
    { grant: 'forged' },
  ])
    assert.equal(store.authorize({ ...request(), ...mutation }, 100_000), undefined);
  for (const now of [99_999, 160_000]) assert.equal(store.authorize(request(), now), undefined);
  for (const field of [
    'scope',
    'audience',
    'subject',
    'contextVersion',
    'consentVersion',
    'policyVersion',
    'caller',
  ] as const) {
    const state = fixtureState('/private/engine.sock');
    Object.assign(state.grants[0], { [field]: typeof state.grants[0][field] === 'number' ? 2 : 'wrong' });
    store.replace(state);
    assert.equal(store.authorize(request(), 100_000), undefined, field);
  }
  assert.equal(credentialDigest(TOKEN).length, 64);
});

test('operator replacement is immutable, monotonic and fail closed after invalid refresh', () => {
  const state = fixtureState('/private/engine.sock');
  const store = new PolicyStore();
  store.replace(state);
  const pin = store.authorize(request(), 100_000)!;
  state.grants[0].revoked = true;
  assert.ok(store.authorize(request(), 100_000));
  store.replace(state);
  assert.equal(store.recheck(request(), 100_000, pin), undefined);
  store.replace(fixtureState('/private/engine.sock'));
  assert.equal(store.recheck(request(), 100_000, pin), undefined);
  assert.throws(() => store.replace({ ...state, version: 0 }));
  assert.equal(store.authorize(request(), 100_000), undefined);
});
