import assert from 'node:assert/strict';
import test from 'node:test';
import { dockerHubManifestFetch, dockerHubSearch, gatewayGet } from './gateway-transport.js';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect } from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ResolutionRejected, type ManifestResponse } from './registry-resolver.js';

test('Hub requests build fixed destinations with discovery-only absolute deadline and size limit', async () => {
  await dockerHubSearch('repositories', 'nginx', 2, async (gateway, url, headers, bytes, deadline) => {
    assert.deepEqual(gateway, { host: 'egress', port: 8080 });
    assert.equal(url.hostname, 'hub.docker.com'); assert.equal(url.searchParams.get('page'), '2');
    assert.deepEqual(headers, { accept: 'application/json' }); assert.equal(bytes, 128_000); assert.equal(deadline, 5000);
    return response(200, { 'content-type': 'application/json' }, '{"results":[],"count":0,"next":null}');
  });
  for (const result of [response(302, { location: 'https://evil.example' }), response(429), response(503), response(200, { 'content-type': 'text/html' }, '{}'), response(200, { 'content-type': 'application/json' }, 'broken'), response(200, { 'content-type': 'application/json' }, 'x'.repeat(128_001))]) {
    await assert.rejects(dockerHubSearch('tags', '3.16', 1, async () => result));
  }
});

test('absolute discovery deadline covers a stalled CONNECT and closes its socket', async () => {
  const sockets = new Set<import('node:stream').Duplex>();
  const server = createServer();
  server.on('connect', (_request, socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const started = performance.now();
    await assert.rejects(gatewayGet({ host: '127.0.0.1', port: (server.address() as { port: number }).port }, new URL('https://hub.docker.com/'), {}, 128_000, 40), /absolute deadline/);
    assert.ok(performance.now() - started < 1000);
  } finally { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('absolute deadline also covers a CONNECT established but stalled TLS handshake', async () => {
  const sockets = new Set<import('node:stream').Duplex>();
  const server = createServer();
  server.on('connect', (_request, socket) => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(gatewayGet({ host: '127.0.0.1', port: (server.address() as { port: number }).port }, new URL('https://hub.docker.com/'), {}, 128_000, 40), /absolute deadline/);
  } finally { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('verified local TLS: stalled headers, drip deadline, streaming overflow and certificate rejection close resources', { timeout: 30_000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'hub-discovery-tls-'));
  const certPath = join(directory, 'cert.pem'); const keyPath = join(directory, 'key.pem');
  const sockets = new Set<import('node:stream').Duplex>();
  const timers = new Set<ReturnType<typeof setInterval>>();
  let mode: 'headers' | 'drip' | 'oversize' = 'headers';
  let requests = 0; let drippedChunks = 0;
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=Hub discovery test', '-addext', 'subjectAltName=DNS:hub.docker.com'], { timeout: 10_000, stdio: 'ignore' });
  const track = (socket: import('node:stream').Duplex) => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); };
  const tls = createHttpsServer({ cert: readFileSync(certPath), key: readFileSync(keyPath) }, (_request, response) => {
    requests++;
    if (mode === 'headers') return;
    response.writeHead(200, { 'content-type': 'application/json' }); response.flushHeaders();
    if (mode === 'oversize') { response.write(Buffer.alloc(128_001)); return; }
    const timer = setInterval(() => { drippedChunks++; response.write(' '); }, 10); timers.add(timer);
    response.once('close', () => { clearInterval(timer); timers.delete(timer); });
  });
  tls.on('connection', track);
  const proxy = createServer(); proxy.on('connection', track);
  proxy.on('connect', (_request, downstream, head) => {
    const upstream = netConnect((tls.address() as { port: number }).port, '127.0.0.1'); track(upstream);
    downstream.once('close', () => upstream.destroy()); upstream.once('close', () => downstream.destroy());
    upstream.once('connect', () => {
      downstream.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      downstream.pipe(upstream); upstream.pipe(downstream);
    });
  });
  try {
    await new Promise<void>(resolve => tls.listen(0, '127.0.0.1', resolve));
    await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const run = async (host: string, trusted: boolean, expected: string) => {
      const env = { ...process.env };
      delete env.NODE_EXTRA_CA_CERTS; delete env.NODE_TLS_REJECT_UNAUTHORIZED; delete env.NODE_OPTIONS;
      if (trusted) env.NODE_EXTRA_CA_CERTS = certPath;
      const script = `import assert from 'node:assert/strict';
        import { gatewayGet } from ${JSON.stringify(new URL('./gateway-transport.ts', import.meta.url).href)};
        await assert.rejects(gatewayGet({host:'127.0.0.1',port:${(proxy.address() as { port: number }).port}}, new URL(${JSON.stringify(`https://${host}/`)}), {},128000,200), new RegExp(${JSON.stringify(expected)}));`;
      await new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { env, stdio: ['ignore', 'pipe', 'pipe'] });
        let output = ''; child.stdout.on('data', chunk => { output += String(chunk); }); child.stderr.on('data', chunk => { output += String(chunk); });
        const deadline = setTimeout(() => { child.kill('SIGKILL'); reject(Error('TLS test child timeout')); }, 5000);
        child.once('error', error => { clearTimeout(deadline); reject(error); });
        child.once('close', code => { clearTimeout(deadline); if (code === 0) resolve(); else reject(Error(output)); });
      });
      for (let attempt = 0; sockets.size && attempt < 100; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(sockets.size, 0, 'deadline/size/TLS failure closed both sides of the tunnel');
      assert.equal(timers.size, 0, 'drip timer released');
    };
    await run('hub.docker.com', true, 'absolute deadline'); assert.equal(requests, 1, 'trusted handshake reached stalled HTTP headers');
    mode = 'drip'; await run('hub.docker.com', true, 'absolute deadline'); assert.equal(requests, 2); assert.ok(drippedChunks > 1, 'ongoing body data cannot extend the absolute deadline');
    mode = 'oversize'; await run('hub.docker.com', true, 'size limit'); assert.equal(requests, 3);
    await run('hub.docker.com', false, 'TLS'); assert.equal(requests, 3, 'untrusted certificate cannot send HTTP');
    await run('wrong.example', true, 'TLS'); assert.equal(requests, 3, 'wrong hostname cannot send HTTP');
  } finally {
    for (const timer of timers) clearInterval(timer);
    for (const socket of sockets) socket.destroy();
    await Promise.all([new Promise<void>(resolve => proxy.close(() => resolve())), new Promise<void>(resolve => tls.close(() => resolve()))]);
    rmSync(directory, { recursive: true, force: true });
  }
});

const gateway = { host: 'egress', port: 8080 };
const path = '/v2/library/alpine/manifests/3.20';
const challenge = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"';
const response = (status: number, headers: ManifestResponse['headers'] = {}, body = ''): ManifestResponse =>
  ({ status, headers, body: Buffer.from(body) });

test('anonymous scoped Bearer challenge never forwards credentials to token or CDN', async () => {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetcher = dockerHubManifestFetch(gateway, 'library/alpine', async (_gateway, url, headers) => {
    calls.push({ url: url.toString(), headers });
    if (calls.length === 1) return response(401, { 'www-authenticate': challenge });
    if (calls.length === 2) return response(200, {}, '{"token":"test-token"}');
    if (calls.length === 3) return response(200);
    return response(302, { location: 'https://production.cloudfront.docker.com/path?signature=private' });
  });
  await fetcher('registry-1.docker.io', path);
  assert.equal(calls[1].url, 'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Falpine%3Apull');
  assert.equal(calls[1].headers.authorization, undefined);
  assert.equal(calls[2].headers.authorization, 'Bearer test-token');
});

test('blob redirect strips authorization and preserves signed URL only in request', async () => {
  const calls: Array<{ host: string; authorization?: string }> = [];
  const fetcher = dockerHubManifestFetch(gateway, 'library/alpine', async (_gateway, url, headers) => {
    calls.push({ host: url.hostname, authorization: headers.authorization });
    if (calls.length === 1) return response(401, { 'www-authenticate': challenge });
    if (calls.length === 2) return response(200, {}, '{"token":"test-token"}');
    if (calls.length === 3) return response(302, { location: 'https://production.cloudfront.docker.com/blob?signature=canary' });
    return response(200);
  });
  await fetcher('registry-1.docker.io', '/v2/library/alpine/blobs/sha256:abc');
  assert.deepEqual(calls, [
    { host: 'registry-1.docker.io', authorization: undefined },
    { host: 'auth.docker.io', authorization: undefined },
    { host: 'registry-1.docker.io', authorization: 'Bearer test-token' },
    { host: 'production.cloudfront.docker.com', authorization: undefined },
  ]);
});

test('hostile auth realms, scopes and redirect URLs fail closed', async () => {
  const hosts = ['https://169.254.169.254/token', 'http://auth.docker.io/token',
    'https://auth.docker.io.evil.org/token', 'https://user@auth.docker.io/token'];
  for (const realm of hosts) {
    await assert.rejects(dockerHubManifestFetch(gateway, 'library/alpine', async () =>
      response(401, { 'www-authenticate': challenge.replace('https://auth.docker.io/token', realm) }))('registry-1.docker.io', path), ResolutionRejected);
  }
  for (const bad of [challenge.replace('repository:library/alpine:pull', 'repository:library/other:pull'),
    challenge.replace('registry.docker.io', 'evil'), 'Basic realm="test"']) {
    await assert.rejects(dockerHubManifestFetch(gateway, 'library/alpine', async () =>
      response(401, { 'www-authenticate': bad }))('registry-1.docker.io', path), ResolutionRejected);
  }
  for (const location of ['http://production.cloudfront.docker.com/path', 'https://169.254.169.254/path',
    'https://production.cloudfront.docker.com.evil.org/path', 'https://user@production.cloudfront.docker.com/path']) {
    await assert.rejects(dockerHubManifestFetch(gateway, 'library/alpine', async () => response(302, { location }))('registry-1.docker.io', '/v2/library/alpine/blobs/sha256:abc'), ResolutionRejected);
  }
});
