import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { performance } from 'node:perf_hooks';
import { harness, barrier, rawRequest } from './harness.js';
import { inspect } from './support.js';
const body = JSON.stringify(inspect());

test('U/U+1 through real streamed Unix adapter, no retries or partial snapshot', async () => {
  for (const oversize of [false, true]) {
    const h = await harness({
      limits: { upstreamBytes: Buffer.byteLength(body) },
      handler: (_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write(body.slice(0, 20));
        setImmediate(() => {
          res.write(body.slice(20));
          res.end(oversize ? ' ' : '');
        });
      },
    });
    try {
      const reply = await h.ask();
      assert.equal(reply.status, oversize ? 'failed' : 'checked');
      assert.equal(h.engine.dispatches, 1);
      assert.equal(h.calls.length, 1);
      assert.equal(h.broker.active, 0);
      assert.equal(h.audit.reservations, 0);
    } finally {
      await h.cleanup();
    }
  }
});

for (const variant of [
  'redirect',
  'error',
  'content-type',
  'duplicate',
  'wrong-id',
  'truncated',
  'compression',
] as const) {
  test(`authorized upstream ${variant}: generic failure with exactly one GET`, async () => {
    const secret = 'UPSTREAM_SECRET_ERROR';
    const h = await harness({
      handler: (_req, res) => {
        if (variant === 'redirect') {
          res.writeHead(302, { Location: 'http://169.254.169.254/' + secret });
          res.end(secret);
        }
        if (variant === 'error') {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(secret);
        }
        if (variant === 'content-type') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(body);
        }
        if (variant === 'duplicate') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(body.slice(0, -1) + ',"Id":"' + secret + '"}');
        }
        if (variant === 'wrong-id') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(body.replace('a'.repeat(64), 'b'.repeat(64)));
        }
        if (variant === 'truncated') {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.length + 100 });
          res.end(body);
        }
        if (variant === 'compression') {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
          res.end(body);
        }
      },
    });
    try {
      const reply = await h.ask();
      assert.deepEqual(reply, { status: 'failed' });
      assert.equal(h.engine.dispatches, 1);
      assert.equal(h.calls.length, 1);
      assert.ok(!JSON.stringify(h.audit.drain()).includes(secret));
      assert.equal(h.broker.active, 0);
    } finally {
      await h.cleanup();
    }
  });
}

for (const phase of ['headers', 'body'] as const) {
  test(`absolute deadline bounds stalled upstream ${phase}; slots recovered`, async () => {
    let stall = true;
    const h = await harness({
      limits: { totalMs: 100, connectMs: 50 },
      handler: (_req, res) => {
        if (stall) {
          if (phase === 'body') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.write('{');
          }
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(body);
        }
      },
    });
    try {
      const start = performance.now();
      const reply = await h.ask();
      const elapsed = performance.now() - start;
      assert.deepEqual(reply, { status: 'failed' });
      assert.ok(elapsed >= 80 && elapsed <= 350, `elapsed ${elapsed}`);
      assert.equal(h.engine.dispatches, 1);
      assert.equal(h.broker.active, 0);
      stall = false;
      h.refill();
      assert.equal((await h.ask()).status, 'checked');
      assert.equal(h.engine.dispatches, 2);
    } finally {
      await h.cleanup();
    }
  });
}

test('header deadline bounds slow ingress without Engine; caller abort releases operation', async () => {
  const gate = barrier();
  const h = await harness({
    limits: { headerMs: 100, totalMs: 500 },
    barriers: { beforeDispatch: gate.wait },
  });
  try {
    const start = performance.now();
    const reply = await h.raw('GET /');
    assert.equal(reply, '');
    assert.ok(performance.now() - start <= 350);
    assert.equal(h.engine.dispatches, 0);
    const socket = connect(h.ingressPath);
    socket.on('error', () => {});
    socket.on('connect', () => socket.write(rawRequest()));
    await gate.entered;
    socket.destroy();
    while (h.broker.active !== 0) await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(h.engine.dispatches, 0);
    assert.equal(h.audit.reservations, 0);
    gate.release();
    h.refill();
    assert.equal((await h.ask()).status, 'checked');
  } finally {
    gate.release();
    await h.cleanup();
  }
});

test('held dispatch barrier is bounded by total deadline', async () => {
  const gate = barrier();
  const h = await harness({ limits: { totalMs: 100 }, barriers: { beforeDispatch: gate.wait } });
  try {
    assert.deepEqual(await h.ask(), { status: 'failed' });
    assert.equal(h.engine.dispatches, 0);
    assert.equal(h.broker.active, 0);
  } finally {
    gate.release();
    await h.cleanup();
  }
});
