import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuditBuffer } from '../src/audit.js';
import { harness, barrier } from './harness.js';
import { fixtureState } from './support.js';

for (const stage of ['dispatch', 'publication'] as const) {
  for (const change of ['expiry', 'revocation', 'consent', 'policy', 'context', 'unavailable'] as const) {
    test(`${change} race before ${stage}: ${stage === 'dispatch' ? 0 : 1} dispatched, no snapshot`, async () => {
      const gate = barrier();
      const h = await harness({
        barriers: stage === 'dispatch' ? { beforeDispatch: gate.wait } : { beforePublication: gate.wait },
      });
      try {
        const response = h.ask();
        await gate.entered;
        const state = fixtureState(h.endpoint);
        if (change === 'expiry') h.advanceWall(60_000);
        else if (change === 'unavailable') h.policy.unavailable();
        else {
          if (change === 'revocation') state.grants[0].revoked = true;
          if (change === 'consent') state.consents[0].approved = false;
          if (change === 'policy') {
            state.version++;
            state.grants[0].policyVersion++;
          }
          if (change === 'context') {
            state.contexts[0].version++;
            state.grants[0].contextVersion++;
          }
          h.policy.replace(state);
        }
        gate.release();
        const reply = await response;
        assert.equal(reply.status, 'not_authorized');
        assert.equal(reply.snapshot, undefined);
        assert.equal(h.engine.dispatches, stage === 'dispatch' ? 0 : 1);
        assert.equal(h.broker.active, 0);
        assert.equal(h.audit.reservations, 0);
        assert.equal(h.audit.drain().at(-1)?.dispatched, stage !== 'dispatch');
      } finally {
        gate.release();
        await h.cleanup();
      }
    });
  }
}

test('audit full or unavailable denies dispatch; final failure suppresses success', async () => {
  for (const scenario of ['full', 'unavailable', 'final'] as const) {
    const audit = new AuditBuffer(2);
    const gate = barrier();
    const h = await harness({ audit, barriers: { beforePublication: gate.wait } });
    try {
      if (scenario === 'unavailable') audit.available(false);
      if (scenario === 'full') {
        h.broker.deny();
      }
      const pending = h.ask();
      if (scenario === 'final') {
        await gate.entered;
        audit.available(false);
        gate.release();
      }
      const reply = await pending;
      assert.equal(reply.status, scenario === 'final' ? 'failed' : 'not_authorized');
      assert.equal(reply.snapshot, undefined);
      assert.equal(h.engine.dispatches, scenario === 'final' ? 1 : 0);
      assert.equal(audit.reservations, 0);
    } finally {
      gate.release();
      await h.cleanup();
    }
  }
});

test('denied records cannot steal final reservation; drain retains reservation', async () => {
  const gate = barrier();
  const h = await harness({ audit: new AuditBuffer(2), barriers: { beforePublication: gate.wait } });
  try {
    const pending = h.ask();
    await gate.entered;
    assert.equal(h.audit.reservations, 1);
    for (let i = 0; i < 5; i++) h.broker.deny();
    assert.equal(h.audit.size, 1);
    assert.equal(h.audit.drain().length, 1);
    assert.equal(h.audit.reservations, 1);
    gate.release();
    assert.equal((await pending).status, 'checked');
    assert.equal(h.audit.size, 1);
    assert.equal(h.audit.reservations, 0);
  } finally {
    gate.release();
    await h.cleanup();
  }
});

test('N/N+1 no queue, rate burst/refill; slots recover', async () => {
  const gate = barrier();
  const h = await harness({ barriers: { beforeDispatch: gate.wait } });
  try {
    const first = h.ask();
    await gate.entered;
    const second = h.ask();
    // Deterministic barrier entry for both requests, no sleep race.
    while (h.broker.active < 2) await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal((await h.ask()).status, 'not_authorized');
    assert.equal(h.engine.dispatches, 0);
    assert.equal(h.broker.active, 2);
    gate.release();
    assert.equal((await first).status, 'checked');
    assert.equal((await second).status, 'checked');
    assert.equal(h.engine.dispatches, 2);
    assert.equal(h.broker.active, 0);
    assert.equal((await h.ask()).status, 'not_authorized');
    assert.equal(h.engine.dispatches, 2);
    h.refill();
    assert.equal((await h.ask()).status, 'checked');
    assert.equal(h.engine.dispatches, 3);
    assert.equal((await h.ask()).status, 'checked');
    assert.equal(h.engine.dispatches, 4);
  } finally {
    gate.release();
    await h.cleanup();
  }
});
