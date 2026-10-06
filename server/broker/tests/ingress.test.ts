import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, lstatSync } from 'node:fs';
import { Broker } from '../src/broker.js';
import { PolicyStore } from '../src/policy.js';
import { AuditBuffer } from '../src/audit.js';
import { UnixEngine } from '../src/engine.js';
import { LIMITS, limits } from '../src/contracts.js';
import { harness, rawRequest } from './harness.js';
import { A, B, route, request, fixtureState, inspect } from './support.js';

test('same real HTTP/Unix authorization path: positive exactly one canonical GET', async () => {
  const h = await harness();
  try {
    const result = await h.ask();
    assert.equal(result.status, 'checked');
    assert.equal(result.snapshot.containerId, A);
    assert.equal(result.snapshot.facts.privileged, true);
    assert.equal(h.engine.dispatches, 1);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].method, 'GET');
    assert.equal(h.calls[0].path, `/v1.47/containers/${A}/json`);
    assert.equal(h.calls[0].headers.authorization, undefined);
    assert.equal(h.calls[0].headers['x-broker-grant'], undefined);
    assert.equal(lstatSync(h.ingressPath).mode & 0o777, 0o600);
    assert.equal(h.broker.active, 0);
    const audit = h.audit.drain();
    assert.deepEqual(
      audit.map((r) => [r.stage, r.decision, r.dispatched]),
      [
        ['admission', 'allowed', false],
        ['publication', 'checked', true],
      ],
    );
  } finally {
    await h.cleanup();
  }
});

test('raw parser and exact route matrix: every denied request independently dispatches zero', async () => {
  const h = await harness();
  try {
    const badPaths = [
      route(B),
      route(A, 'other'),
      route(A.slice(0, 12)),
      route(A.toUpperCase()),
      `/v1.47/containers/${A}/json`,
      `/containers/${A}/export`,
      '/containers/create',
      `/containers/${A}/exec`,
      `/containers/${A}/archive`,
      '/containers/json',
      '/events',
      '/logs',
      '/_ping',
      '/version',
      route() + '/',
      route() + '?x=1',
      route() + '#fragment',
      route().replace('/containers/', '//containers/'),
      route().replace('/containers/', '/./containers/'),
      route().replace('/containers/', '/%2fcontainers/'),
      route().replace('/containers/', '/%252fcontainers/'),
      'http://broker' + route(),
      route().replace('/v1/', '/v2/'),
    ];
    const messages = [
      ...badPaths.map((p) => rawRequest(p)),
      ...['POST', 'DELETE', 'PUT', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'].map((m) =>
        rawRequest(route(), m),
      ),
      ...[
        'Authorization: Bearer forged\r\n',
        'X-Broker-Grant: grant-a\r\n',
        'X-Context: fixture\r\n',
        'X-Subject: subject-a\r\n',
        'X-Endpoint: http://169.254.169.254\r\n',
        'X-Scope: container:inspect\r\n',
        'Upgrade: websocket\r\n',
        'Content-Length: 1\r\n',
        'Content-Length: 0\r\nContent-Length: 1\r\n',
        'Transfer-Encoding: chunked\r\n',
        'Expect: 100-continue\r\n',
      ].map((s) => rawRequest(route(), 'GET', s)),
      rawRequest().replace(`Bearer ${'c'.repeat(64)}`, 'Bearer ' + 'd'.repeat(64)),
      rawRequest().replace(/Authorization:.*\r\n/, ''),
      rawRequest().replace('X-Broker-Grant: grant-a', 'X-Broker-Grant: forged'),
      rawRequest().replace('HTTP/1.1', 'HTTP/1.0'),
      rawRequest().replace('HTTP/1.1', 'HTTP/01.01'),
      rawRequest().replace('GET /', 'GET  /'),
      rawRequest() + 'x',
      rawRequest() + rawRequest(),
      rawRequest().replace('Host: broker', 'Host: broker\r\n folded'),
      rawRequest().replace(/\r\n/g, '\n'),
      rawRequest(route(), 'GET', 'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n'),
    ];
    for (const message of messages) {
      h.refill();
      const before = h.engine.dispatches;
      const result = await h.raw(message);
      assert.ok(!result.includes('"checked"'));
      assert.equal(h.engine.dispatches - before, 0, message.split('\r\n')[0]);
      assert.equal(h.calls.length, 0);
    }
    const audit = h.audit.drain();
    assert.ok(audit.every((r) => r.containerId === 'invalid' && r.context === 'invalid'));
    assert.ok(!JSON.stringify(audit).includes('169.254.169.254'));
  } finally {
    await h.cleanup();
  }
});

for (const [operation, method, path] of [
  ['image inspect', 'GET', `/v1.47/images/${A}/json`],
  ['stats', 'GET', `/v1.47/containers/${A}/stats`],
  ['start', 'POST', `/v1.47/containers/${A}/start`],
  ['stop', 'POST', `/v1.47/containers/${A}/stop`],
  ['remove', 'DELETE', `/v1.47/containers/${A}`],
  ['copy', 'POST', `/v1.47/containers/${A}/copy`],
]) {
  test(`explicit ${operation} denial: zero adapter dispatches and fake Engine requests`, async () => {
    const h = await harness();
    try {
      for (const target of [path, route() + '/' + operation.replace(' ', '-')]) {
        const result = await h.raw(rawRequest(target, method));
        assert.ok(!result.includes('"checked"'));
        assert.equal(h.engine.dispatches, 0, target);
        assert.equal(h.calls.length, 0, target);
        assert.equal(h.broker.active, 0);
        assert.equal(h.audit.reservations, 0);
      }
    } finally {
      await h.cleanup();
    }
  });
}

test('empty UsernsMode via authorized HTTP/Unix path is unknown, not private', async () => {
  const h = await harness({
    handler: (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ...inspect(), HostConfig: { ...inspect().HostConfig, UsernsMode: '' } }));
    },
  });
  try {
    const reply = await h.ask();
    assert.equal(reply.status, 'checked');
    assert.equal(reply.snapshot.facts.namespaces.user, 'unknown');
    assert.equal(h.engine.dispatches, 1);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].method, 'GET');
    assert.equal(h.calls[0].path, `/v1.47/containers/${A}/json`);
  } finally {
    await h.cleanup();
  }
});

test('production/default off and forged boundary or socket :ro alone cannot authorize', async () => {
  const h = await harness({ enabled: false });
  try {
    assert.equal((await h.ask()).status, 'not_authorized');
    assert.equal(h.engine.dispatches, 0);
    const engine = new UnixEngine();
    for (const boundary of [undefined, { root: h.root, endpoint: h.endpoint }]) {
      const broker = new Broker({
        policy: h.policy,
        engine,
        audit: new AuditBuffer(),
        enabled: true,
        boundary,
        clock: { wall: () => 100_000, mono: () => 0 },
      });
      assert.equal((await broker.handle(request(), new AbortController().signal)).status, 'not_authorized');
      assert.equal(engine.dispatches, 0);
    }
  } finally {
    await h.cleanup();
  }
});

test('permission change invalidates measured boundary before dispatch', async () => {
  const h = await harness();
  try {
    chmodSync(h.endpoint, 0o644);
    assert.equal((await h.ask()).status, 'not_authorized');
    assert.equal(h.engine.dispatches, 0);
  } finally {
    await h.cleanup();
  }
});

test('registered remote transport is unsupported and never connected', async () => {
  const h = await harness();
  try {
    const state = fixtureState(h.endpoint);
    state.contexts[0].transport = 'unsupported';
    state.contexts[0].endpoint = 'http://169.254.169.254';
    h.policy.replace(state);
    assert.equal((await h.ask()).status, 'unsupported');
    assert.equal(h.engine.dispatches, 0);
  } finally {
    await h.cleanup();
  }
});

test('finite limits reject invalid/infinite/increasing overrides', () => {
  for (const override of [
    { active: 0 },
    { totalMs: Infinity },
    { upstreamBytes: -1 },
    { active: 3 },
    { nope: 1 },
  ]) {
    assert.throws(() => limits(override));
  }
  assert.deepEqual(limits(), LIMITS);
});

test('B/B+1 combined raw admission and parser header overflow', async () => {
  const base = rawRequest().replace('Host: broker', 'Host: broker');
  const h = await harness({ limits: { ingressBytes: Buffer.byteLength(base) } });
  try {
    assert.ok((await h.raw(base)).includes('"checked"'));
    assert.equal(h.engine.dispatches, 1);
    h.refill();
    // Header whitespace is trimmed by Node; parser byte limit still accounts for it.
    const extra = base.replace('Host: broker', 'Host:  broker');
    assert.ok(!(await h.raw(extra)).includes('"checked"'));
    assert.equal(h.engine.dispatches, 1);
    h.refill();
    assert.ok(
      !(await h.raw(rawRequest(route(), 'GET', 'X-Large: ' + 'x'.repeat(8192) + '\r\n'))).includes(
        '"checked"',
      ),
    );
    assert.equal(h.engine.dispatches, 1);
  } finally {
    await h.cleanup();
  }
});
