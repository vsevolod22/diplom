import test from 'node:test';
import assert from 'node:assert/strict';
import { createPinnedConfigLoader, admittedConfigTarget } from './pinned-image-config.js';
import { configBytes } from '../worker/config-test-fixtures.js';
import type { Job } from '../ledger/ledger.js';
import { NGINX_ARCHIVE_CANDIDATES } from './bounded-image-archive.js';
const bytes = configBytes();
const job: Job = { scanId: 'scan', attempts: 1, registry: 'registry-1.docker.io', repository: 'library/alpine', digest: bytes.digest,
  platform: 'linux/amd64', scope: 'image', checks: '["config"]' };

test('admission remains exact alpine or enumerated archive profiles, never arbitrary repository', () => {
  assert.equal(admittedConfigTarget(job), true);
  for (const candidate of NGINX_ARCHIVE_CANDIDATES) assert.equal(admittedConfigTarget({ ...job, ...candidate }), true);
  for (const change of [{ registry: 'evil.example' }, { repository: 'library/ubuntu' }, { repository: 'library/nginx' },
    { digest: 'latest' }, { platform: 'linux/arm64' }, { scope: 'container' }]) assert.equal(admittedConfigTarget({ ...job, ...change }), false);
});

test('every auth/redirect hop receives cumulative deadline, byte cap and abort; CDN never receives credentials', async () => {
  const seen: string[] = []; let manifestCalls = 0;
  const signal = new AbortController().signal;
  const loader = createPinnedConfigLoader(async (_gateway, url, headers, cap, deadline, _sink, receivedSignal) => {
    assert.equal(receivedSignal, signal); assert.ok(deadline! > 0 && deadline! <= 30_000); seen.push(url.href);
    if (url.hostname === 'auth.docker.io') { assert.equal(cap, 32768); return { status: 200, headers: {}, body: Buffer.from('{"token":"controlled-token"}') }; }
    assert.equal(cap, 1_000_000);
    if (url.pathname.includes('/manifests/')) {
      assert.equal(url.pathname.endsWith(job.digest), true);
      if (++manifestCalls === 1) return { status: 401, headers: { 'www-authenticate': 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"' }, body: Buffer.alloc(0) };
      assert.equal(headers.authorization, 'Bearer controlled-token');
      return { status: 200, headers: { 'content-type': 'application/vnd.oci.image.manifest.v1+json' }, body: bytes.manifest };
    }
    if (url.hostname === 'registry-1.docker.io') return { status: 302, headers: { location: 'https://production.cloudfront.docker.com/config' }, body: Buffer.alloc(0) };
    assert.equal(headers.authorization, undefined); assert.equal(headers.cookie, undefined);
    return { status: 200, headers: { 'content-type': 'application/octet-stream' }, body: bytes.config };
  });
  const input = await loader(job, signal); assert.deepEqual(input.configBytes, bytes.config); assert.equal(seen.length, 5);
});
for (const fault of ['manifest-hash', 'manifest-index', 'config-size', 'config-type', 'manifest-type', 'oversize', 'auth-host', 'redirect-host', 'redirect-loop', 'aborted'] as const) {
  test(`bounded pinned loader rejects ${fault} without fallback`, async () => {
    const controller = new AbortController(); let calls = 0;
    const loader = createPinnedConfigLoader(async (_gateway, url) => {
      calls++;
      if (fault === 'aborted') controller.abort();
      if (fault === 'auth-host') return { status: 401, headers: { 'www-authenticate': 'Bearer realm="https://evil.example/token",service="registry.docker.io",scope="repository:library/alpine:pull"' }, body: Buffer.alloc(0) };
      if (!url.pathname.includes('/manifests/')) {
        if (fault === 'redirect-host' || fault === 'redirect-loop') return { status: 302, headers: { location: fault === 'redirect-host' ? 'https://evil.example/config' : 'https://production.cloudfront.docker.com/config' }, body: Buffer.alloc(0) };
        return { status: 200, headers: { 'content-type': fault === 'config-type' ? 'text/html' : 'application/octet-stream' }, body: fault === 'config-size' ? Buffer.alloc(0) : bytes.config };
      }
      return { status: 200, headers: { 'content-type': fault === 'manifest-type' ? 'text/plain' : 'application/vnd.oci.image.manifest.v1+json' },
        body: fault === 'oversize' ? Buffer.alloc(1_000_001) : fault === 'manifest-hash' ? Buffer.from('CANARY') : fault === 'manifest-index' ? Buffer.from('{"schemaVersion":2,"manifests":[]}') : bytes.manifest };
    });
    await assert.rejects(loader(job, controller.signal)); assert.ok(calls <= 5);
  });
}
