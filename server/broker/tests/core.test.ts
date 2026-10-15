import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Broker } from '../src/broker.js';
import { AuditBuffer, correlation, record, type AuditRecord, type AuditTicket } from '../src/audit.js';
import { verifyPrivateBoundary } from '../src/boundary.js';
import { PolicyStore } from '../src/policy.js';
import { harness, barrier } from './harness.js';
import { fixtureState, inspect, request, B } from './support.js';

test('injected fake Engine unit: authorized positive=1, each independent admission deny=0', async () => {
  const h = await harness();
  try {
    for (const mutation of [
      undefined,
      { id: B },
      { credential: '' },
      { grant: 'forged' },
      { context: 'other' },
    ]) {
      let calls = 0;
      const policy = new PolicyStore();
      policy.replace(fixtureState(h.endpoint));
      const broker = new Broker({
        enabled: true,
        policy,
        audit: new AuditBuffer(),
        clock: { wall: () => 100_000, mono: () => 0 },
        boundary: verifyPrivateBoundary(h.root, h.endpoint),
        engine: {
          inspect: async (pin, _signal, _limits, dispatched) => {
            calls++;
            dispatched();
            assert.equal(pin.context.endpoint, h.endpoint);
            assert.equal(pin.context.apiVersion, '1.47');
            return Buffer.from(JSON.stringify(inspect()));
          },
        },
      });
      const result = await broker.handle({ ...request(), ...mutation }, new AbortController().signal);
      assert.equal(calls, mutation ? 0 : 1);
      assert.equal(result.status, mutation ? 'not_authorized' : 'checked');
    }
    assert.equal(h.engine.dispatches, 0);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.cleanup();
  }
});

test('HTTP local grant denial matrix: notBefore/expiry, scope, audience, consent, version, invalid refresh', async () => {
  const h = await harness();
  try {
    const changes: ((s: ReturnType<typeof fixtureState>) => void)[] = [
      (s) => (s.grants[0].notBefore = 100_001),
      (s) => (s.grants[0].expiresAt = 100_000),
      (s) => (s.grants[0].revoked = true),
      (s) => (s.grants[0].scope = 'container:exec'),
      (s) => (s.grants[0].audience = 'scan-api'),
      (s) => (s.grants[0].caller = 'foreign'),
      (s) => (s.grants[0].subject = 'foreign'),
      (s) => (s.grants[0].contextVersion = 2),
      (s) => (s.grants[0].consentVersion = 2),
      (s) => (s.grants[0].policyVersion = 2),
      (s) => (s.consents[0].approved = false),
      (s) => (s.consents[0].revoked = true),
      (s) => (s.consents[0].caller = 'foreign'),
      (s) => (s.consents[0].subject = 'foreign'),
      (s) => (s.callers[0].digest = 'd'.repeat(64)),
      (s) => { Object.assign(s.contexts[0], { apiVersion: '1.48' }); },
    ];
    for (const change of changes) {
      const state = fixtureState(h.endpoint);
      change(state);
      try {
        h.policy.replace(state);
      } catch {
        /* invalid replacement stays unavailable */
      }
      h.refill();
      const before = h.engine.dispatches;
      assert.deepEqual(await h.ask(), { status: 'not_authorized' });
      assert.equal(h.engine.dispatches - before, 0);
    }
    assert.equal(h.calls.length, 0);
  } finally {
    await h.cleanup();
  }
});

test('current versions protect against endpoint replacement and restoration ABA', async () => {
  const gate = barrier();
  const h = await harness({ barriers: { beforeDispatch: gate.wait } });
  try {
    const pending = h.ask();
    await gate.entered;
    const state = fixtureState(h.endpoint);
    state.contexts[0].endpoint = '/private/other.sock';
    h.policy.replace(state);
    h.policy.replace(fixtureState(h.endpoint));
    gate.release();
    assert.deepEqual(await pending, { status: 'not_authorized' });
    assert.equal(h.engine.dispatches, 0);
    assert.equal(h.calls.length, 0);
  } finally {
    gate.release();
    await h.cleanup();
  }
});

test('slow synchronous audit: expiry before transport still zero; expiry before commit suppresses publication', async () => {
  for (const stage of ['admission', 'publication']) {
    let expire = () => {};
    class SlowAudit extends AuditBuffer {
      override reserve(entry: AuditRecord) {
        const ticket = super.reserve(entry);
        if (stage === 'admission') expire();
        return ticket;
      }
      override finish(ticket: AuditTicket, entry: AuditRecord) {
        const accepted = super.finish(ticket, entry);
        if (stage === 'publication') expire();
        return accepted;
      }
    }
    const h = await harness({ audit: new SlowAudit(2) });
    expire = () => h.advanceWall(60_000);
    try {
      assert.deepEqual(await h.ask(), { status: 'not_authorized' });
      assert.equal(h.engine.dispatches, stage === 'admission' ? 0 : 1);
      assert.equal(h.audit.drain().at(-1)?.decision, 'not_authorized');
      assert.equal(h.audit.reservations, 0);
    } finally {
      await h.cleanup();
    }
  }
});

test('concurrency alone denies N+1 with available rate token and no waiting queue', async () => {
  const gate = barrier();
  const h = await harness({ limits: { active: 1 }, barriers: { beforeDispatch: gate.wait } });
  try {
    const pending = h.ask();
    await gate.entered;
    assert.deepEqual(await h.ask(), { status: 'not_authorized' });
    assert.equal(h.broker.active, 1);
    assert.equal(h.engine.dispatches, 0);
    gate.release();
    assert.equal((await pending).status, 'checked');
    assert.equal(h.broker.active, 0);
  } finally {
    gate.release();
    await h.cleanup();
  }
});

test('bounded fixed audit schema, no overwrite, fake raw fields rejected', () => {
  const audit = new AuditBuffer(2);
  const entry = record(
    correlation(),
    100_000,
    undefined,
    'admission',
    'not_authorized',
    'invalid_request',
    false,
  );
  for (const bad of [
    { ...entry, subject: 'evil\nsecret' },
    { ...entry, reason: 'raw-error' },
    { ...entry, url: '/secret' },
    { ...entry, containerId: B, context: 'untrusted\n' },
  ]) {
    assert.equal(audit.deny(bad as AuditRecord), false);
  }
  assert.equal(audit.deny(entry), true);
  assert.equal(audit.deny(entry), true);
  assert.equal(audit.deny(entry), false);
  assert.equal(audit.size, 2);
  assert.equal(audit.drain().length, 2);
  assert.equal(audit.size, 0);
});

test('policy bounds and invalid refresh: no stale-positive grants or caller-controlled fields', () => {
  const p = new PolicyStore();
  for (const change of [
    (s: ReturnType<typeof fixtureState>) => s.callers.push(s.callers[0]),
    (s: ReturnType<typeof fixtureState>) => (s.grants[0].expiresAt = 500_000),
    (s: ReturnType<typeof fixtureState>) => Object.assign(s.grants[0], { extra: true }),
    (s: ReturnType<typeof fixtureState>) => (s.contexts[0].endpoint = '/private/../run/socket'),
    (s: ReturnType<typeof fixtureState>) => (s.contexts[0].endpoint = 'http://localhost'),
    (s: ReturnType<typeof fixtureState>) => (s.callers[0].subject = 'raw\nsecret'),
    (s: ReturnType<typeof fixtureState>) => (s.grants = Array.from({ length: 65 }, (_, i) => ({ ...s.grants[0], id: 'g-' + i }))),
  ]) {
    p.replace(fixtureState('/private/e'));
    const s = fixtureState('/private/e');
    change(s);
    assert.throws(() => p.replace(s));
    assert.equal(p.authorize(request(), 100_000), undefined);
  }
});
