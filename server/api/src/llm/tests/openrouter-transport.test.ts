import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { connect } from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Duplex } from 'node:stream';
import { makeOpenRouterTransport, OpenRouterHttpFailure, providerRetryAfter } from '../openrouter-transport.js';
import { OPENROUTER_ENDPOINT } from '../openrouter-provider.js';
import { fakeKey } from './fixtures.js';

const options = (signal?: AbortSignal): RequestInit => ({ method: 'POST', redirect: 'error', body: '{}', signal,
  headers: { authorization: `Bearer ${fakeKey}`, 'content-type': 'application/json', accept: 'application/json' } });

test('provider HTTP metadata retains only bounded status/kind/retry hints', () => {
  const now = Date.UTC(2026, 9, 25, 12);
  for (const value of [undefined, null, '', '-1', '1.5', 'NaN', 'Infinity', 'CANARY', '1'.repeat(129), '99999999999'])
    assert.equal(providerRetryAfter(value, now), undefined);
  assert.equal(providerRetryAfter('0', now), 0);
  assert.equal(providerRetryAfter('9999999999', now), 86400);
  assert.equal(providerRetryAfter('Sun, 25 Oct 2026 12:01:00 GMT', now), 60);
  assert.equal(providerRetryAfter('Sun, 25 Oct 2026 11:59:00 GMT', now), 0);
  assert.deepEqual(new OpenRouterHttpFailure(429, '60').failure, { kind: 'rate_limited', status: 429, retryAfterSeconds: 60 });
  assert.deepEqual(new OpenRouterHttpFailure(401, '60').failure, { kind: 'auth_failed', status: 401 });
  assert.deepEqual(new OpenRouterHttpFailure(403, '60').failure, { kind: 'unavailable', status: 403 });
  for (const status of [200, 299, 600, NaN, 429.5]) assert.throws(() => new OpenRouterHttpFailure(status));
});

test('destination/path/header fences and pre-abort precede CONNECT; stalled tunnel is cancelled', async () => {
  const sockets = new Set<Duplex>(); let connects = 0;
  const proxy = createServer(); proxy.on('connect', (_req, socket) => {
    connects++; sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  try {
    const transport = makeOpenRouterTransport({ host: '127.0.0.1', port: (proxy.address() as { port: number }).port });
    for (const url of ['https://attacker.invalid', 'http://openrouter.ai/api/v1/chat/completions', `${OPENROUTER_ENDPOINT}?x=1`, `${OPENROUTER_ENDPOINT}/`])
      await assert.rejects(transport(url, options()));
    await assert.rejects(transport(OPENROUTER_ENDPOINT, { ...options(), method: 'GET' }));
    await assert.rejects(transport(OPENROUTER_ENDPOINT, { ...options(), headers: { ...options().headers, 'proxy-authorization': 'CANARY' } }));
    const abort = new AbortController(); abort.abort();
    await assert.rejects(transport(OPENROUTER_ENDPOINT, options(abort.signal)));
    assert.equal(connects, 0);
    await assert.rejects(transport(OPENROUTER_ENDPOINT, options(AbortSignal.timeout(100))));
    assert.equal(connects, 1);
  } finally { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => proxy.close(() => resolve())); }
});

test('real loopback CONNECT and verified TLS POST: no proxy secret, no direct fallback, bounds/redirect/TLS refusal', { timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'llm-transport-'));
  const cert = join(dir, 'cert.pem'), key = join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=synthetic OpenRouter', '-addext', 'subjectAltName=DNS:openrouter.ai'], { timeout: 10000, stdio: 'ignore' });
  let mode = 'ok', requests = 0, connects = 0;
  const sockets = new Set<Duplex>();
  const track = (socket: Duplex) => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); };
  const tls = httpsServer({ cert: readFileSync(cert), key: readFileSync(key) }, (req, res) => {
    requests++; assert.equal(req.method, 'POST'); assert.equal(req.url, '/api/v1/chat/completions');
    assert.equal(req.headers.authorization, `Bearer ${fakeKey}`);
    if (mode === 'headers') return;
        if (['rate', 'busy', 'auth'].includes(mode)) {
          res.writeHead(mode === 'rate' ? 429 : mode === 'busy' ? 503 : 401,
            { 'content-type': 'text/plain', 'content-length': '999999999', 'retry-after': '9999999999', 'x-private': 'CANARY' });
          res.flushHeaders(); res.write('CANARY-private-provider-body'); return;
        }
    if (mode === 'redirect') { res.writeHead(302, { location: 'https://attacker.invalid' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/json', ...(mode === 'hint' ? { 'retry-after': '9999999999', 'x-private': 'CANARY' } : {}) });
    if (mode === 'oversize') { res.end(Buffer.alloc(65537)); return; }
    if (mode === 'body') { res.flushHeaders(); res.write(' '); return; }
    let body = ''; req.on('data', chunk => { body += String(chunk); }); req.on('end', () => { assert.equal(body, '{}'); res.end('{}'); });
  });
  tls.on('connection', track);
  const proxy = createServer(); proxy.on('connection', track);
  proxy.on('connect', (req, downstream) => {
    connects++; assert.equal(req.url, 'openrouter.ai:443');
    assert.deepEqual(Object.keys(req.headers).sort(), ['connection', 'host']);
    assert.equal(req.headers.host, 'openrouter.ai:443');
    if (mode === 'denied') { downstream.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return; }
    const upstream = connect((tls.address() as { port: number }).port, '127.0.0.1'); track(upstream);
    downstream.once('close', () => upstream.destroy()); upstream.once('close', () => downstream.destroy());
    upstream.once('connect', () => {
      downstream.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      downstream.pipe(upstream); upstream.pipe(downstream);
    });
  });
  try {
    await new Promise<void>(resolve => tls.listen(0, '127.0.0.1', resolve));
    await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const run = async (trusted: boolean, success: boolean, guarded?: 'allow' | 'deny') => {
      const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_TLS_REJECT_UNAUTHORIZED; delete env.NODE_EXTRA_CA_CERTS;
      if (trusted) env.NODE_EXTRA_CA_CERTS = cert;
      // Host-only synthetic test CA, never a production TLS disable or secret file.
      const script = `import assert from 'node:assert/strict';
        import {makeOpenRouterTransport,OpenRouterHttpFailure} from ${JSON.stringify(new URL('../openrouter-transport.ts', import.meta.url).href)};
        const t=makeOpenRouterTransport({host:'127.0.0.1',port:${(proxy.address() as { port: number }).port}});
        const init=${JSON.stringify(options())};init.signal=AbortSignal.timeout(400);
        process.stdout.write('synthetic-transport-started\\n');
        let guards=0;
                const call=()=>${guarded ? `t.sendGuarded(${JSON.stringify(OPENROUTER_ENDPOINT)},init,send=>{guards++;${guarded === 'deny' ? 'throw Error("synthetic stale authority");' : 'send();'}})` : `t(${JSON.stringify(OPENROUTER_ENDPOINT)},init)`};
                ${success ? `const response=await call();assert.equal(await response.text(),'{}');assert.equal(response.headers.get('retry-after'),${mode === 'hint' ? `'86400'` : 'null'});assert.equal(response.headers.get('x-private'),null);` : ['rate', 'busy', 'auth'].includes(mode) ? `await assert.rejects(call(),error=>{
                                  assert.ok(error instanceof OpenRouterHttpFailure);
                                  assert.deepEqual(error.failure,${JSON.stringify(mode === 'auth' ? { kind: 'auth_failed', status: 401 } : { kind: 'rate_limited', status: mode === 'rate' ? 429 : 503, retryAfterSeconds: 86400 })});
                                  assert.doesNotMatch(JSON.stringify(error),/CANARY|x-private|retry-after|Bearer/);return true;});` : `await assert.rejects(call(),/OpenRouter transport unavailable/);`}
                assert.equal(guards,${guarded && trusted ? 1 : 0});
        process.stdout.write('synthetic-transport-settled\\n');`;
      await new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { env, stdio: ['ignore', 'pipe', 'pipe'] });
        let output = '', exitCode: number | null | undefined;
        child.once('exit', code => { exitCode = code; });
        child.stdout.on('data', c => { output += String(c); }); child.stderr.on('data', c => { output += String(c); });
        let failure: Error | undefined;
        const deadline = setTimeout(() => {
          const phase = output.includes('synthetic-transport-settled') ? 'settled' : output.includes('synthetic-transport-started') ? 'started' : 'loading';
          failure = Error(`synthetic TLS child timeout (${mode}, trusted=${trusted}, guard=${guarded ?? 'none'}, phase=${phase}, exit=${exitCode})`);
          child.kill('SIGKILL');
        }, 5000);
        child.once('error', error => { failure ??= error; });
        // Reap the owned child and its stdio before tearing down its TLS fixture.
        child.once('close', code => {
          clearTimeout(deadline);
          if (failure) reject(failure);
          else if (code === 0) resolve();
          else reject(Error(output));
        });
      });
      for (let i = 0; sockets.size && i < 100; i++) await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(sockets.size, 0, 'all tunnel/HTTP sockets closed');
    };
    // Reject from secureConnect repeatedly: each fresh child must exit naturally
    // and close every socket, not only settle the rejected transport promise.
    for (let attempt = 0; attempt < 5; attempt++) {
      await run(true, false, 'deny');
      assert.equal(requests, 0, 'fresh TLS guard refusal sends zero credential HTTP/body');
    }
    await run(false, false, 'allow'); assert.equal(requests, 0, 'guard never runs before authenticated TLS');
    await run(true, true, 'allow'); assert.equal(requests, 1, 'fresh guard initiates exactly one credential HTTP/body');
    await run(false, false); assert.equal(requests, 1, 'untrusted TLS sends no credential HTTP');
    mode = 'denied'; await run(true, false); assert.equal(requests, 1, 'CONNECT denied, no fallback');
    for (const value of ['redirect', 'oversize', 'headers', 'body']) { mode = value; await run(true, false); }
    for (const value of ['rate', 'busy', 'auth']) { mode = value; await run(true, false); }
        mode = 'hint'; await run(true, true);
        assert.equal(requests, 9); assert.equal(connects, 17, 'one CONNECT per call, no retry');
  } finally {
    for (const socket of sockets) socket.destroy();
    await Promise.all([new Promise<void>(resolve => proxy.close(() => resolve())), new Promise<void>(resolve => tls.close(() => resolve()))]);
    rmSync(dir, { recursive: true, force: true });
  }
});
