import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import fs, { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger, type Job } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from './oci-resolver.js';
import { PublicImageModule } from './public-image.module.js';
import { ScansService } from '../scans/scans.service.js';
import type { PublicImageInspector, PublicImageScansService } from '../scans/public-image-scans.service.js';
import { configBytes } from '../worker/config-test-fixtures.js';
import { runImageConfig } from '../worker/image-config-runner.js';
import { buildVulnConfig } from '../worker/worker-runtime.js';
import { localDbTrustAnchorFromEnv, PRODUCTION_DB_TRUST_ANCHOR, type DbTrustAnchor } from '../worker/vuln-db-trust.js';
import { admittedConfigTarget, CONFIG_LOAD_MS, CONFIG_LOAD_REQUESTS, createPinnedConfigLoader, type ConfigLoader } from './pinned-image-config.js';
import type { gatewayGet } from './gateway-transport.js';

const bytes = configBytes();
const target = { registry: 'registry-1.docker.io', repository: 'example/public-image', digest: bytes.digest, platform: 'linux/amd64' };
const standalone: Job = { ...target, scanId: 'public-config', attempts: 1, scope: 'image', checks: '["config"]' };
const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const response = (manifest: boolean) => ({ status: 200, headers: { 'content-type': manifest ? manifestType : 'application/octet-stream' },
  body: manifest ? bytes.manifest : bytes.config });
const publicLoader = () => createPinnedConfigLoader(async (_gateway, url) => response(url.pathname.includes('/manifests/')), true);
function fixture(t: TestContext, checks = '["config"]') {
  const directory = mkdtempSync(join(tmpdir(), 'public-config-'));
  const file = join(directory, 'ledger.sqlite');
  const ledger = new ScanLedger(file, () => 1000);
  t.after(() => { ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  const id = ledger.enqueue({ ...target, subject: 'alice', idempotencyKey: 'public-config', checks }).scanId;
  const job = ledger.claim(1000, 100)!;
  assert.ok(job.leaseToken);
  return { ledger, file, job, id };
}

test('generic config admission and transport require explicit public composition, never job fields', async () => {
  for (const repository of ['library/ubuntu', 'library/nginx', 'example/public-image', 'org/nested/image']) {
    const job = { ...standalone, repository };
    assert.equal(admittedConfigTarget(job), false);
    assert.equal(admittedConfigTarget(job, true), true);
  }
  let calls = 0;
  const request: typeof gatewayGet = async (_gateway, url) => { calls++; return response(url.pathname.includes('/manifests/')); };
  const forged = { ...standalone, publicImagePolicy: true, executionProfile: { version: 'public-hub-amd64-v1' } } as unknown as Job;
  await assert.rejects(createPinnedConfigLoader(request)(forged, new AbortController().signal));
  assert.equal(calls, 0);
  const input = await createPinnedConfigLoader(request, true)(standalone, new AbortController().signal);
  assert.deepEqual(input.identity, { registry: target.registry, repository: target.repository, manifestDigest: target.digest,
    platform: { os: 'linux', architecture: 'amd64' } });
  assert.equal(calls, 2);
});

for (const change of [{ registry: 'evil.example' }, { repository: '../image' }, { repository: 'org/Image' },
  { repository: `org/${'a'.repeat(129)}` }, { repository: `a/${'b/'.repeat(127)}c` }, { digest: 'latest' },
  { platform: 'linux/arm64' }, { scope: 'container' }]) {
  test(`public config rejects invalid target before transport: ${JSON.stringify(change)}`, async () => {
    const job = { ...standalone, ...change };
    assert.equal(admittedConfigTarget(job, true), false);
    await assert.rejects(createPinnedConfigLoader(async () => assert.fail('Invalid target reached transport'), true)(job, new AbortController().signal));
  });
}

test('public auth/redirect transport retains pinned paths, credentials isolation and cumulative bounds', async () => {
  const controller = new AbortController(); let calls = 0, manifests = 0;
  const loader = createPinnedConfigLoader(async (gateway, url, headers, cap, deadline, sink, signal) => {
    calls++;
    assert.deepEqual(gateway, { host: 'egress', port: 8080 });
    assert.equal(signal, controller.signal); assert.equal(sink, undefined);
    assert.ok(deadline! > 0 && deadline! <= CONFIG_LOAD_MS);
    if (url.hostname === 'auth.docker.io') {
      assert.equal(cap, 32768); assert.equal(url.searchParams.get('scope'), `repository:${target.repository}:pull`);
      return { status: 200, headers: {}, body: Buffer.from('{"token":"public-fixture-token"}') };
    }
    assert.equal(cap, 1_000_000);
    if (url.pathname.includes('/manifests/')) {
      assert.equal(url.pathname, `/v2/${target.repository}/manifests/${target.digest}`);
      if (++manifests === 1) return { status: 401, headers: { 'www-authenticate':
        `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:${target.repository}:pull"` }, body: Buffer.alloc(0) };
      assert.equal(headers.authorization, 'Bearer public-fixture-token'); return response(true);
    }
    if (url.hostname === target.registry) {
      assert.equal(url.pathname, `/v2/${target.repository}/blobs/${bytes.configDigest}`);
      return { status: 302, headers: { location: 'https://production.cloudfront.docker.com/config' }, body: Buffer.alloc(0) };
    }
    assert.equal(url.hostname, 'production.cloudfront.docker.com');
    assert.equal(headers.authorization, undefined); assert.equal(headers.cookie, undefined); return response(false);
  }, true);
  const input = await loader(standalone, controller.signal);
  assert.deepEqual(input.configBytes, bytes.config); assert.deepEqual(input.manifestBytes, bytes.manifest);
  assert.deepEqual(input.identity, { registry: target.registry, repository: target.repository, manifestDigest: target.digest,
    platform: { os: 'linux', architecture: 'amd64' } });
  assert.equal(calls, 5); assert.ok(calls <= CONFIG_LOAD_REQUESTS);
});

for (const fault of ['manifest-hash', 'config-hash', 'config-size', 'config-type', 'manifest-type', 'oversize', 'deadline', 'aborted', 'auth-host', 'redirect-host', 'redirect-loop'] as const) {
  test(`public transport preserves rejection boundary: ${fault}`, async t => {
    let clock = 1000, calls = 0;
    t.mock.method(Date, 'now', () => clock);
    const controller = new AbortController();
    const loader = createPinnedConfigLoader(async (_gateway, url) => {
      calls++;
      if (fault === 'deadline') clock += CONFIG_LOAD_MS;
      if (fault === 'aborted') controller.abort();
      if (fault === 'auth-host') return { status: 401, headers: { 'www-authenticate':
        `Bearer realm="https://evil.example/token",service="registry.docker.io",scope="repository:${target.repository}:pull"` }, body: Buffer.alloc(0) };
      const manifest = url.pathname.includes('/manifests/');
      if (!manifest && (fault === 'redirect-host' || fault === 'redirect-loop')) return { status: 302,
        headers: { location: fault === 'redirect-host' ? 'https://evil.example/config' : 'https://production.cloudfront.docker.com/config' }, body: Buffer.alloc(0) };
      const result = response(manifest);
      if (manifest && fault === 'manifest-hash') result.body = Buffer.from('wrong manifest');
      if (!manifest && fault === 'config-hash') result.body = Buffer.alloc(bytes.config.length, 32);
      if (!manifest && fault === 'config-size') result.body = Buffer.alloc(0);
      if (manifest && fault === 'oversize') result.body = Buffer.alloc(1_000_001);
      if (manifest && fault === 'manifest-type' || !manifest && fault === 'config-type') result.headers['content-type'] = 'text/plain';
      return result;
    }, true);
    await assert.rejects(loader(standalone, controller.signal));
    assert.ok(calls > 0 && calls <= CONFIG_LOAD_REQUESTS);
  });
}

test('runner public composition checks the original claim without rewriting repository, checks or lease token', async t => {
  const { ledger, job, id } = fixture(t);
  const before = ledger.configAttemptContext(id, job.attempts);
  let calls = 0;
  const loader: ConfigLoader = async (received, signal) => {
    calls++; assert.deepEqual(received, job); assert.equal(received.leaseToken, job.leaseToken);
    assert.equal(Object.isFrozen(received), true); return publicLoader()(received, signal);
  };
  assert.equal((await runImageConfig(ledger, job, new AbortController().signal, loader)).config.outcome, 'failed');
  assert.equal(calls, 0);
  const result = await runImageConfig(ledger, job, new AbortController().signal, loader, true);
  assert.equal(result.config.outcome, 'checked'); assert.equal(calls, 1);
  assert.equal(result.findings[0]?.manifestDigest, job.digest);
  assert.equal(result.findings[0]?.configDigest, bytes.configDigest);
  assert.deepEqual(ledger.configAttemptContext(id, job.attempts), before);
  assert.equal(ledger.configResult(id, 'alice'), undefined); // Runner has no persistence authority.
});

for (const field of ['scanId', 'attempts', 'registry', 'repository', 'digest', 'platform', 'checks', 'scope', 'leaseToken'] as const) {
  test(`explicit public policy cannot authorize a forged claim: ${field}`, async t => {
    const { ledger, job } = fixture(t);
    const forged = { ...job, [field]: field === 'attempts' ? job.attempts + 1 : field === 'repository' ? 'other/public-image' :
          field === 'checks' ? '["secret","config"]' : 'forged' };
    const result = await runImageConfig(ledger, forged, new AbortController().signal,
      async () => assert.fail('Forged claim reached loader'), true);
    assert.equal(result.config.outcome, 'failed');
  });
}

for (const field of ['registry', 'repository', 'manifestDigest', 'platform'] as const) {
  test(`public runner rejects loaded identity mismatch: ${field}`, async t => {
    const { ledger, job } = fixture(t);
    const result = await runImageConfig(ledger, job, new AbortController().signal, async (...args) => {
      const input = await publicLoader()(...args);
      return { ...input, identity: { ...input.identity, [field]: field === 'platform' ? { os: 'linux', architecture: 'arm64' } : 'different' } };
    }, true);
    assert.deepEqual(result.config, { outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' });
  });
}

for (const action of ['retry', 'cancel', 'replacement', 'subject', 'repository', 'digest', 'checks', 'token', 'abort'] as const) {
  test(`public byte-load side effect revokes original authority: ${action}`, { timeout: 3000 }, async t => {
    const { ledger, file, job, id } = fixture(t);
    const controller = new AbortController(); let loadedSignal: AbortSignal | undefined;
    const result = await runImageConfig(ledger, job, controller.signal, async (received, signal) => {
      assert.deepEqual(received, job); assert.equal(received.leaseToken, job.leaseToken); loadedSignal = signal;
      const input = await publicLoader()(received, signal);
      if (action === 'retry') assert.equal(ledger.retry(id, job.attempts, 99_000, job.leaseToken), true);
      else if (action === 'cancel') assert.equal(ledger.cancel(id, 'alice'), 'cancelled');
      else if (action === 'replacement') assert.equal(ledger.claim(32_101, 100)?.attempts, 2);
      else if (action === 'abort') controller.abort();
      else {
        const raw = new Database(file);
        try {
          if (action === 'subject') raw.prepare('UPDATE scans SET subject=? WHERE id=?').run('bob', id);
          if (action === 'repository') raw.prepare('UPDATE scans SET repository=? WHERE id=?').run('other/public-image', id);
          if (action === 'digest') raw.prepare('UPDATE scans SET digest=? WHERE id=?').run(`sha256:${'a'.repeat(64)}`, id);
          if (action === 'checks') raw.prepare('UPDATE scans SET checks=? WHERE id=?').run('["secret","config"]', id);
          if (action === 'token') raw.prepare('UPDATE outbox SET lease_token=? WHERE scan_id=?').run('replacement-token', id);
        } finally { raw.close(); }
      }
      return input;
    }, true);
    assert.deepEqual(result.config, { outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' });
    assert.equal(loadedSignal?.aborted, true);
    assert.equal(ledger.configResult(id, 'alice'), undefined);
    assert.equal(ledger.result(id, 'alice'), undefined);
    assert.equal(ledger.attemptActive(id, job.attempts, job.leaseToken), !['retry', 'cancel', 'replacement', 'token'].includes(action));
  });
}

test('public caller cancellation releases an uncooperative loader and discards late bytes with original token intact', { timeout: 3000 }, async t => {
  const { ledger, job, id } = fixture(t);
  const original = ledger.configAttemptContext(id, job.attempts);
  let started!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const controller = new AbortController(); let loading: Promise<Awaited<ReturnType<ConfigLoader>>> | undefined;
  const work = runImageConfig(ledger, job, controller.signal, (received, signal) => {
    assert.deepEqual(received, job); assert.equal(received.leaseToken, job.leaseToken);
    loading = (async () => {
      const input = await publicLoader()(received, signal);
      started(); await waiting; assert.equal(signal.aborted, true); return input;
    })();
    return loading;
  }, true);
  await ready; controller.abort();
  assert.deepEqual((await work).config, { outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' });
  release(); await loading;
  // Let the discarded analyze path settle before checking for side effects.
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.deepEqual(ledger.configAttemptContext(id, job.attempts), original);
  assert.equal(ledger.attemptActive(id, job.attempts, job.leaseToken), true);
  assert.equal(ledger.configResult(id, 'alice'), undefined); assert.equal(ledger.result(id, 'alice'), undefined);
});

test('disabled and pre-aborted public config never call loader', async t => {
  const { ledger, job } = fixture(t, '["secret"]');
  const noLoad: ConfigLoader = async () => assert.fail('Inactive config loaded bytes');
  assert.deepEqual((await runImageConfig(ledger, job, new AbortController().signal, noLoad, true)).config,
    { outcome: 'skipped', reason: 'CHECK_DISABLED' });
  const controller = new AbortController(); controller.abort();
  assert.equal((await runImageConfig(ledger, { ...job, checks: '["config"]' }, controller.signal, noLoad, true)).config.outcome, 'failed');
});

test('explicit public worker trust accepts selected LOCAL public key; default/proof ignore it and env', t => {
  const directory = mkdtempSync(join(tmpdir(), 'public-config-trust-'));
  // Public SPKI bytes only: no private key generation, reads or signature/readiness claims.
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.alloc(32, 7)]);
  const pem = createPublicKey({ key: der, type: 'spki', format: 'der' }).export({ type: 'spki', format: 'pem' }).toString();
  const hash = createHash('sha256').update(der).digest('hex');
  const selected = localDbTrustAnchorFromEnv({ LOCAL_CVE_TRUST_SHA256: hash });
  assert.deepEqual(selected, { publicKeyPath: '/opt/local-db-trust/public.pem', expectedSpkiSha256: hash });
  assert.equal(localDbTrustAnchorFromEnv({}), PRODUCTION_DB_TRUST_ANCHOR);
  for (const invalid of ['', 'invalid', 'A'.repeat(64)]) assert.throws(() => localDbTrustAnchorFromEnv({ LOCAL_CVE_TRUST_SHA256: invalid }));
  const file = join(directory, 'public.pem'); writeFileSync(file, pem);
  const values = { SCAN_VULN_ENABLED: 'true', SCAN_VULN_RELEASE_DIR: '/synthetic/release', SCAN_VULN_MANIFEST_DIGEST: `sha256:${'a'.repeat(64)}`,
    SCAN_VULN_ARTIFACT_SHA256: 'b'.repeat(64), TRIVY_CACHE_DIR: '/tmp/trivy', LOCAL_CVE_TRUST_SHA256: hash };
  const previous = { ...process.env };
  Object.assign(process.env, values);
  const open = fs.openSync, paths: string[] = [];
  t.mock.method(fs, 'openSync', (path: fs.PathLike, flags: string | number) => {
    paths.push(String(path));
    if (path === selected.publicKeyPath) return open(file, flags);
    assert.equal(path, PRODUCTION_DB_TRUST_ANCHOR.publicKeyPath);
    throw new Error('Test blocks deployed trust-key reads');
  });
  syncBuiltinESMExports();
  try {
    const config = buildVulnConfig(undefined, selected, true);
    assert.ok(config); assert.equal(config.trust.trustedPublicKeyPem, pem);
    assert.equal(config.trust.expectedArtifactSha256, values.SCAN_VULN_ARTIFACT_SHA256);
    assert.equal(buildVulnConfig(undefined, { ...selected, expectedSpkiSha256: '0'.repeat(64) }, true), undefined);
    assert.deepEqual(paths, [selected.publicKeyPath, selected.publicKeyPath]);
    paths.length = 0;
    for (const value of [hash, 'invalid', undefined]) {
      if (value === undefined) delete process.env.LOCAL_CVE_TRUST_SHA256; else process.env.LOCAL_CVE_TRUST_SHA256 = value;
      assert.equal(buildVulnConfig(), undefined);
      assert.equal(buildVulnConfig(undefined, selected), undefined);
      assert.equal(buildVulnConfig('proof', selected), undefined);
      assert.equal(buildVulnConfig(undefined, undefined, true), undefined); // Public mode alone does not read env.
    }
    assert.equal(paths.length, 12); assert.ok(paths.every(path => path === PRODUCTION_DB_TRUST_ANCHOR.publicKeyPath));
  } finally {
    t.mock.restoreAll(); syncBuiltinESMExports();
    for (const key of Object.keys(values)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('public API factory and worker selector agree on LOCAL and production anchors, rejecting invalid configured trust', t => {
  type Provider = { provide: unknown; useFactory: (ledger: LedgerStore, resolver: OciResolver, inspect: PublicImageInspector) => PublicImageScansService };
  const factory = (Reflect.getMetadata('providers', PublicImageModule) as Provider[]).find(provider => provider.provide === ScansService)!.useFactory;
  const previous = process.env.LOCAL_CVE_TRUST_SHA256;
  t.after(() => { if (previous === undefined) delete process.env.LOCAL_CVE_TRUST_SHA256; else process.env.LOCAL_CVE_TRUST_SHA256 = previous; });
  const create = () => factory({ ledger: undefined } as LedgerStore, {} as OciResolver, async () => assert.fail('Trust selection must not inspect images'));
  const anchor = (service: PublicImageScansService) => (service as unknown as { dbTrustAnchor(): DbTrustAnchor }).dbTrustAnchor();
  process.env.LOCAL_CVE_TRUST_SHA256 = 'b'.repeat(64);
  const local = create();
  assert.deepEqual(anchor(local), localDbTrustAnchorFromEnv()); assert.ok(Object.isFrozen(anchor(local)));
  process.env.LOCAL_CVE_TRUST_SHA256 = 'c'.repeat(64);
  assert.equal(anchor(local).expectedSpkiSha256, 'b'.repeat(64)); // Existing instances retain their reviewed selection.
  assert.deepEqual(anchor(create()), localDbTrustAnchorFromEnv());
  process.env.LOCAL_CVE_TRUST_SHA256 = '';
  assert.throws(create, /Invalid LOCAL CVE trust fingerprint/);
  assert.throws(() => localDbTrustAnchorFromEnv(), /Invalid LOCAL CVE trust fingerprint/);
  delete process.env.LOCAL_CVE_TRUST_SHA256;
  assert.deepEqual(anchor(create()), PRODUCTION_DB_TRUST_ANCHOR);
  assert.equal(localDbTrustAnchorFromEnv(), PRODUCTION_DB_TRUST_ANCHOR);
});

test('public entrypoint explicitly selects the API-compatible anchor and passes public composition to DB config', () => {
  const main = readFileSync(new URL('../worker/public-image-worker.main.ts', import.meta.url), 'utf8');
  assert.match(main, /runWorker\(undefined, localDbTrustAnchorFromEnv\(\), true\)/);
  const runtime = readFileSync(new URL('../worker/worker-runtime.ts', import.meta.url), 'utf8');
  assert.match(runtime, /buildVulnConfig\(archivePolicy, anchor, publicImagePolicy\)/);
  assert.doesNotMatch(runtime, /localDbTrustAnchorFromEnv|LOCAL_CVE_TRUST_SHA256/);
});
