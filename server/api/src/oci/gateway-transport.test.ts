import assert from 'node:assert/strict';
import test from 'node:test';
import { dockerHubManifestFetch, dockerHubSearch, gatewayGet } from './gateway-transport.js';
import { createServer } from 'node:http';
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
