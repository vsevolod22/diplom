import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { UnixEngine } from '../src/engine.js';
import { LIMITS } from '../src/contracts.js';
import { PolicyStore } from '../src/policy.js';
import { harness, rawRequest } from './harness.js';
import { fixtureState, request, inspect } from './support.js';

test('caller abort after actual dispatch aborts upstream, no publication and slot recovers', async () => {
  let enter!: () => void;
  let upstreamClosed!: () => void;
  const dispatched = new Promise<void>((r) => {
    enter = r;
  });
  const cancelled = new Promise<void>((r) => {
    upstreamClosed = r;
  });
  let stall = true;
  const h = await harness({
    handler: (_req, res) => {
      if (stall) {
        res.once('close', upstreamClosed);
        enter();
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(inspect()));
      }
    },
  });
  try {
    const socket = connect(h.ingressPath);
    socket.on('error', () => {});
    socket.on('connect', () => socket.write(rawRequest()));
    await dispatched;
    assert.equal(h.engine.dispatches, 1);
    socket.destroy();
    await cancelled;
    while (h.broker.active) await new Promise<void>((r) => setImmediate(r));
    assert.equal(h.audit.reservations, 0);
    const final = h.audit.drain().at(-1)!;
    assert.equal(final.decision, 'failed');
    assert.equal(final.reason, 'cancelled');
    assert.equal(final.dispatched, true);
    stall = false;
    h.refill();
    assert.equal((await h.ask()).status, 'checked');
    assert.equal(h.engine.dispatches, 2);
  } finally {
    await h.cleanup();
  }
});

test('direct adapter invalid target/version/transport/limits or pre-abort dispatches zero', async () => {
  const p = new PolicyStore();
  p.replace(fixtureState('/private/e'));
  const pin = p.authorize(request(), 100_000)!;
  for (const modified of [
    { ...pin, id: pin.id.slice(0, 12) },
    { ...pin, context: { ...pin.context, apiVersion: '1.48' } },
    { ...pin, context: { ...pin.context, transport: 'unsupported' } },
    { ...pin, context: { ...pin.context, endpoint: 'http://localhost' } },
    { ...pin, context: { ...pin.context, endpoint: '/private/../e' } },
  ]) {
    const engine = new UnixEngine();
    await assert.rejects(engine.inspect(modified as typeof pin, new AbortController().signal, LIMITS));
    assert.equal(engine.dispatches, 0);
  }
  const engine = new UnixEngine();
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(engine.inspect(pin, aborted.signal, LIMITS));
  await assert.rejects(
    engine.inspect(pin, new AbortController().signal, { ...LIMITS, upstreamBytes: Infinity }),
  );
  assert.equal(engine.dispatches, 0);
});

test('direct adapter connection failure is bounded, safe and never retried', async () => {
  const p = new PolicyStore();
  p.replace(fixtureState('/private/nonexistent-dip-broker.sock'));
  const pin = p.authorize(request(), 100_000)!;
  const engine = new UnixEngine();
  await assert.rejects(engine.inspect(pin, new AbortController().signal, LIMITS), (error: unknown) => {
    assert.equal((error as Error).message, 'upstream');
    assert.ok(!(error as Error).message.includes('nonexistent'));
    return true;
  });
  assert.equal(engine.dispatches, 1);
});

test('fragmented byte-at-a-time raw ingress preserves guard and exact positive', async () => {
  const h = await harness();
  try {
    const response = await new Promise<string>((resolve, reject) => {
      const socket = connect(h.ingressPath);
      const data: Buffer[] = [];
      socket.on('data', (b) => data.push(b));
      socket.on('error', reject);
      socket.on('close', () => resolve(Buffer.concat(data).toString()));
      socket.on('connect', () => {
        const message = rawRequest();
        let i = 0;
        const write = () => {
          if (i < message.length) {
            socket.write(message[i++]);
            setImmediate(write);
          }
        };
        write();
      });
    });
    assert.ok(response.includes('"checked"'));
    assert.equal(h.engine.dispatches, 1);
    assert.equal(h.calls.length, 1);
  } finally {
    await h.cleanup();
  }
});
