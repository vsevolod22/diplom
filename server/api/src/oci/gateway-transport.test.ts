import assert from 'node:assert/strict';
import test from 'node:test';
import { dockerHubManifestFetch } from './gateway-transport.js';
import { ResolutionRejected, type ManifestResponse } from './registry-resolver.js';

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
    await assert.rejects(dockerHubManifestFetch(gateway, 'library/alpine', async () => response(302, { location }))
      ('registry-1.docker.io', '/v2/library/alpine/blobs/sha256:abc'), ResolutionRejected);
  }
});
