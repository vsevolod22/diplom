import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import test from 'node:test';
import { makeModuleApiTransport } from '../moduleapi-transport.js';
import { MODULEAPI_ENDPOINT } from '../moduleapi-policy.js';
import { diagnostic } from '../provider-diagnostic.js';
import { makeModuleApiPolicy, syntheticModuleApiKey } from './moduleapi-infra.fixture.js';

class Wire extends EventEmitter {
  destroyed = false;
  authorized = true;
  alpnProtocol = 'http/1.1';
  idle?: () => void;
  destroy() { this.destroyed = true; }
  end() {}
  setTimeout(_ms: number, callback?: () => void) { this.idle = callback; }
  getPeerCertificate() { return {}; }
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const init = (signal = new AbortController().signal): RequestInit => ({ method: 'POST', redirect: 'error',
  body: '{}', signal, headers: { authorization: `Bearer ${syntheticModuleApiKey}`, accept: 'application/json', 'content-type': 'application/json' } });

test('isolated transport: TLS, admission, guard, framing and cancellation', { timeout: 10000 }, async t => {
  let tunnel: Wire, secure: Wire, reply: Wire & { statusCode: number; headers: Record<string, string>; complete: boolean };
  let posts = 0;
  t.mock.method(http, 'request', (options: http.RequestOptions) => {
    assert.deepEqual(options, { hostname: 'moduleapi-egress', port: 8080, method: 'CONNECT', path: 'moduleapi.pro:443',
      headers: { host: 'moduleapi.pro:443' }, agent: false, maxHeaderSize: 8192 });
    return (tunnel = new Wire());
  });
  t.mock.method(tls, 'connect', (options: tls.ConnectionOptions) => {
    assert.equal(options.servername, 'moduleapi.pro'); assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.minVersion, 'TLSv1.2'); assert.deepEqual(options.ALPNProtocols, ['http/1.1']);
    return (secure = new Wire());
  });
  t.mock.method(tls, 'checkServerIdentity', () => undefined);
  t.mock.method(https, 'request', (options: https.RequestOptions, callback: (value: typeof reply) => void) => {
    assert.equal(options.hostname, 'moduleapi.pro'); assert.equal(options.path, '/v1/chat/completions');
    assert.equal(options.method, 'POST'); assert.equal(options.port, 443); assert.equal(options.maxHeaderSize, 8192);
    const agent = options.agent as https.Agent;
    assert.equal(agent.createConnection({}), secure);
    assert.throws(() => agent.createConnection({}));
    posts++;
    reply = Object.assign(new Wire(), { statusCode: 200, headers: { 'content-type': 'application/json' }, complete: true });
    const request = new Wire(); request.end = () => callback(reply); return request;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  assert.equal(MODULEAPI_ENDPOINT, 'https://moduleapi.pro/v1/chat/completions');
  for (const limit of [0, -1, 9, 1.5, NaN]) assert.throws(() => makeModuleApiTransport(makeModuleApiPolicy(), limit));
  const transport = makeModuleApiTransport(makeModuleApiPolicy({ timeoutMs: 40, responseBytes: 4 }), 1);
  const connect = () => tunnel.emit('connect', { statusCode: 200 }, new Wire(), Buffer.alloc(0));
  const finish = () => { reply.emit('data', Buffer.from('{}')); reply.emit('end'); };
  const rejects = async (promise: Promise<Response>, phase: string, reason: string) => {
    await assert.rejects(promise, error => { assert.deepEqual(diagnostic(error), { phase, reason });
      assert.ok(!String(error).includes(syntheticModuleApiKey)); return true; }); await tick();
  };
  await t.test('credentials and guard wait for verified TLS; successful dispatch is once', async () => {
    const before = posts; let guards = 0;
    const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => { guards++; send(); });
    assert.equal(posts, before); connect(); assert.equal(guards, 0); assert.equal(posts, before);
    secure.emit('secureConnect'); assert.equal(guards, 1); assert.equal(posts, before + 1);
    finish(); assert.equal(await (await promise).text(), '{}'); await tick(); assert.ok(secure.destroyed);
  });
  for (const mode of ['unauthorized', 'alpn'] as const) await t.test(`TLS rejects ${mode} before credentials`, async () => {
    const before = posts; const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), () => assert.fail('guard'));
    connect(); if (mode === 'unauthorized') secure.authorized = false; else secure.alpnProtocol = 'h2';
    secure.emit('secureConnect'); await rejects(promise, 'tls', 'rejected'); assert.equal(posts, before);
  });
  await t.test('certificate hostname mismatch is refused before credentials', async () => {
    const mismatch = t.mock.method(tls, 'checkServerIdentity', () => new Error('synthetic certificate mismatch'));
    syncBuiltinESMExports();
    try {
      const before = posts; const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), () => assert.fail('guard'));
      connect(); secure.emit('secureConnect'); await rejects(promise, 'tls', 'rejected'); assert.equal(posts, before);
    } finally { mismatch.mock.restore(); syncBuiltinESMExports(); }
  });
  for (const guard of [() => {}, (send: () => void) => { send(); send(); }, (send: () => void) => { send(); return Promise.resolve(); }]) {
    await t.test('guard must synchronously dispatch exactly once and return undefined', async () => {
      const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), guard); connect(); secure.emit('secureConnect');
      await rejects(promise, 'dispatch_guard', 'rejected');
    });
  }
  await t.test('late guard callback cannot dispatch', async () => {
    let late!: () => void; const before = posts;
    const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => { late = send; });
    connect(); secure.emit('secureConnect'); await rejects(promise, 'dispatch_guard', 'rejected');
    assert.throws(late); assert.equal(posts, before);
  });
  for (const endpoint of [MODULEAPI_ENDPOINT + '?x=1', 'http://moduleapi.pro/v1/chat/completions', 'https://moduleapi.pro.evil/v1/chat/completions']) {
    // @ts-expect-error Intentionally violate the literal endpoint contract to verify runtime rejection.
    await rejects(transport.sendGuarded(endpoint, init(), send => send()), 'request', 'invalid_request');
  }
  for (const patch of [{ headers: { authorization: 'Bearer bad\r\nsecret' } }, { body: 'x'.repeat(65537) },
    { headers: { ...Object.fromEntries(new Headers(init().headers)), cookie: 'forbidden' } }, { redirect: 'follow' }]) {
    await rejects(transport.sendGuarded(MODULEAPI_ENDPOINT, { ...init(), ...patch } as RequestInit, send => send()), 'request', 'invalid_request');
  }
  await t.test('pre-abort and pending abort do not dispatch', async () => {
    const controller = new AbortController(); controller.abort();
    const before = posts; await assert.rejects(transport.sendGuarded(MODULEAPI_ENDPOINT, init(controller.signal), send => send())); await tick();
    const pending = new AbortController(); const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(pending.signal), send => send());
    pending.abort(); await assert.rejects(promise); await tick(); assert.equal(posts, before);
  });
  await t.test('no queue while local slot is held; absolute deadline releases it', async () => {
    const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send());
    await assert.rejects(transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()), error => diagnostic(error)?.reason === 'limit');
    await rejects(promise, 'deadline', 'timeout');
  });
  await t.test('connect and TLS phase deadlines are bounded independently', async () => {
    const timers: Array<{ callback: () => void; ms: number }> = [];
    const timerMock = t.mock.method(globalThis, 'setTimeout', (callback: () => void, ms: number) => {
      timers.push({ callback, ms }); return 0;
    });
    try {
      let promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send());
      assert.ok(timers.every(timer => timer.ms <= 40)); timers[1].callback();
      await rejects(promise, 'connect', 'timeout');
      timers.length = 0;
      promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()); connect();
      timers[2].callback(); await rejects(promise, 'tls', 'timeout');
    } finally { timerMock.mock.restore(); }
  });
  await t.test('process-wide eight-slot cap spans separate transports', async () => {
    const controllers = Array.from({ length: 8 }, () => new AbortController());
    const pending = controllers.map(controller => makeModuleApiTransport(makeModuleApiPolicy(), 8)
      .sendGuarded(MODULEAPI_ENDPOINT, init(controller.signal), send => send()));
    const observed = Promise.all(pending.map(promise => assert.rejects(promise)));
    await assert.rejects(makeModuleApiTransport(makeModuleApiPolicy(), 8).sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()),
      error => diagnostic(error)?.reason === 'limit');
    controllers.forEach(controller => controller.abort()); await observed; await tick();
  });
  await t.test('untrusted CONNECT response and prefetched TLS bytes are rejected', async () => {
    for (const [statusCode, head] of [[403, Buffer.alloc(0)], [200, Buffer.from('extra')]] as const) {
      const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send());
      tunnel.emit('connect', { statusCode }, new Wire(), head); await rejects(promise, 'connect', 'rejected');
    }
  });
  await t.test('response headers, declared lengths and truncation fail closed', async () => {
    for (const [headers, phase, reason] of [
      [{ 'content-type': 'text/html' }, 'headers', 'invalid_type'],
      [{ 'content-type': 'application/json', 'content-encoding': 'gzip' }, 'headers', 'invalid_type'],
      [{ 'content-type': 'application/json', 'content-length': '5' }, 'headers', 'limit'],
      [{ 'content-type': 'application/json', 'content-length': '-1' }, 'headers', 'limit'],
      [{ 'content-type': 'application/json', 'content-length': '3' }, 'body', 'invalid_shape'],
    ] as const) {
      const original = https.request;
      const responseMock = t.mock.method(https, 'request', (options: unknown, callback: (value: typeof reply) => void) =>
        original(options as https.RequestOptions, result => {
          Object.assign(result, { headers }); callback(result as unknown as typeof reply);
        }));
      syncBuiltinESMExports();
      try {
        const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()); connect(); secure.emit('secureConnect');
        if (phase === 'body') finish(); await rejects(promise, phase, reason);
      } finally { responseMock.mock.restore(); syncBuiltinESMExports(); }
    }
  });
  await t.test('all non-200 statuses fail without reading raw body, redirect or retry', async () => {
    for (const statusCode of [201, 301, 302, 307, 400, 401, 429, 500]) {
      const original = https.request;
      const responseMock = t.mock.method(https, 'request', (options: unknown, callback: (value: typeof reply) => void) =>
        original(options as https.RequestOptions, result => {
          Object.assign(result, { statusCode }); callback(result as unknown as typeof reply);
        }));
      syncBuiltinESMExports();
      try {
        const before = posts;
        const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()); connect(); secure.emit('secureConnect');
        assert.equal(reply.listenerCount('data'), 0);
        await rejects(promise, 'headers', 'http_error'); assert.equal(posts, before + 1);
      } finally { responseMock.mock.restore(); syncBuiltinESMExports(); }
    }
  });
  await t.test('CONNECT IO failure never creates TLS or retries, and returns admission', async () => {
    const before = posts;
    const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), () => assert.fail('guard'));
    const failedTunnel = tunnel;
    tunnel.emit('error', new Error(syntheticModuleApiKey)); await rejects(promise, 'connect', 'io_error');
    assert.ok(failedTunnel.destroyed); assert.equal(posts, before);
    const next = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send());
    connect(); secure.emit('secureConnect'); finish(); await next; await tick();
  });
  await t.test('TLS IO failure and abort release resources before another request is admitted', async () => {
    for (const kind of ['error', 'abort'] as const) {
      const controller = new AbortController(); const before = posts;
      const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(controller.signal), () => assert.fail('guard'));
      connect(); const failedSecure = secure; const failedTunnel = tunnel;
      if (kind === 'error') secure.emit('error', new Error(syntheticModuleApiKey)); else controller.abort();
      await assert.rejects(promise, error => !String(error).includes(syntheticModuleApiKey));
      await tick(); assert.ok(failedSecure.destroyed); assert.ok(failedTunnel.destroyed); assert.equal(posts, before);
    }
  });
  await t.test('body IO, premature close, abort and post-dispatch guard throw retain single dispatch', async () => {
    for (const kind of ['error', 'aborted', 'close', 'abort', 'guard'] as const) {
      const controller = new AbortController(); const before = posts;
      const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(controller.signal), send => {
        send(); if (kind === 'guard') throw new Error(syntheticModuleApiKey);
      });
      connect(); secure.emit('secureConnect'); const failedSecure = secure;
      if (kind === 'abort') controller.abort();
      else if (kind === 'close') { reply.complete = false; reply.emit('close'); }
      else if (kind !== 'guard') reply.emit(kind, new Error(syntheticModuleApiKey));
      await assert.rejects(promise, error => !String(error).includes(syntheticModuleApiKey));
      await tick(); assert.ok(reply.destroyed); assert.ok(failedSecure.destroyed); assert.equal(posts, before + 1);
    }
  });
  await t.test('late CONNECT after abort is destroyed and cannot dispatch or consume a second slot', async () => {
    const controller = new AbortController(); const before = posts;
    const promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(controller.signal), () => assert.fail('guard'));
    const lateTunnel = tunnel; controller.abort(); await assert.rejects(promise); await tick();
    const lateSocket = new Wire();
    lateTunnel.emit('connect', { statusCode: 200 }, lateSocket, Buffer.alloc(0));
    assert.ok(lateSocket.destroyed); assert.equal(posts, before);
    const next = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send());
    connect(); secure.emit('secureConnect'); finish(); await next; await tick();
  });
  await t.test('idle timeout and streamed body bound', async () => {
    let promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()); connect(); secure.emit('secureConnect');
    secure.idle!(); await rejects(promise, 'body', 'timeout');
    promise = transport.sendGuarded(MODULEAPI_ENDPOINT, init(), send => send()); connect(); secure.emit('secureConnect');
    reply.emit('data', Buffer.from('12345')); await rejects(promise, 'body', 'limit');
  });
});
