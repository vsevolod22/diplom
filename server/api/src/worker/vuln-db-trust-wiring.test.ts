import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { NginxLocalScansService } from '../oci/nginx-local-profile.js';
import { NginxLocalModule } from '../oci/nginx-local.module.js';
import { NGINX_LOCAL_POLICY } from '../oci/nginx-local-policy.js';
import { ScansService } from '../scans/scans.service.js';
import { CURRENT_DB_POLICY } from './cve-db-policy.mjs';
import { preflightVulnDbBundle } from './vuln-db-bundle.js';
import { localDbTrustAnchorFromEnv, PRODUCTION_DB_TRUST_ANCHOR, type DbTrustAnchor } from './vuln-db-trust.js';
import { buildVulnConfig } from './worker-runtime.js';

const store = { ledger: undefined } as LedgerStore, resolver = {} as OciResolver;
class LocalProbe extends NginxLocalScansService {
  db() { return this.vulnDbReady(); }
  anchor() { return this.dbTrustAnchor(); }
}
class ProductionProbe extends ScansService {
  db() { return this.vulnDbReady(); }
  anchor() { return this.dbTrustAnchor(); }
}
function environment(t: TestContext, values: Record<string, string | undefined>) {
  const previous = Object.keys(values).map(key => process.env[key]);
  const apply = (key: string, value: string | undefined) => {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  };
  Object.entries(values).forEach(([key, value]) => apply(key, value));
  t.after(() => Object.keys(values).forEach((key, index) => apply(key, previous[index])));
}
const hash = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

// Disposable signed bytes exercise authentication only, never actual scanner/chain readiness.
// The signing key is generated in memory; no private PEM is read, exported or written.
async function release(t: TestContext) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'local-trust-wiring-')));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const anchor = Object.freeze({ publicKeyPath: join(directory, 'public.pem'),
    expectedSpkiSha256: hash(publicKey.export({ type: 'spki', format: 'der' })) });
  await writeFile(anchor.publicKeyPath, pem);
  const artifact = 'SYNTHETIC ENVELOPE TEST ARTIFACT; NOT A TRIVY DB';
  const db = 'SYNTHETIC ENVELOPE TEST DB; NOT SCANNER COVERAGE';
  const manifest = `sha256:${'a'.repeat(64)}`;
  const now = Date.now();
  const metadata = { Version: 2, UpdatedAt: new Date(now - 3600_000).toISOString(),
    DownloadedAt: new Date(now - 1800_000).toISOString(), NextUpdate: new Date(now + 86400_000).toISOString() };
  const descriptor = { envelopeVersion: 1, signer: 'local-db-operator-v1',
    source: `ghcr.io/aquasecurity/trivy-db@${manifest}`, schemaVersion: 2,
    artifactSha256: hash(artifact), metadataSha256: hash(JSON.stringify(metadata)), dbSha256: hash(db),
    manifestDigest: manifest, updatedAt: metadata.UpdatedAt, downloadedAt: metadata.DownloadedAt, nextUpdate: metadata.NextUpdate };
  const writeDescriptor = async (value = descriptor) => {
    const bytes = Buffer.from(JSON.stringify(value));
    await writeFile(join(directory, 'descriptor.json'), bytes);
    await writeFile(join(directory, 'descriptor.sig'), sign(null, bytes, privateKey));
  };
  const writeMetadata = async (value: typeof metadata) => {
    await writeFile(join(directory, 'db', 'metadata.json'), JSON.stringify(value));
    await writeDescriptor({ ...descriptor, metadataSha256: hash(JSON.stringify(value)),
      updatedAt: value.UpdatedAt, downloadedAt: value.DownloadedAt, nextUpdate: value.NextUpdate });
  };
  await mkdir(join(directory, 'db'));
  await writeFile(join(directory, 'db', 'metadata.json'), JSON.stringify(metadata));
  await writeFile(join(directory, 'db', 'trivy.db'), db);
  await writeFile(join(directory, 'bundle.bin'), artifact);
  await writeDescriptor();
  environment(t, { SCAN_VULN_ENABLED: 'true', SCAN_VULN_RELEASE_DIR: directory, SCAN_VULN_MANIFEST_DIGEST: manifest,
    SCAN_VULN_ARTIFACT_SHA256: hash(artifact), TRIVY_CACHE_DIR: '/tmp/trivy', LOCAL_CVE_TRUST_SHA256: anchor.expectedSpkiSha256 });
  return { directory, anchor, pem, descriptor, metadata, artifact, writeDescriptor, writeMetadata };
}

test('explicit LOCAL API anchor authenticates an actual signed fixture identity, not a synthetic true', async t => {
  const f = await release(t);
  const service = new LocalProbe(store, resolver, f.anchor);
  const identity = await service.db();
  assert.deepEqual(identity, f.descriptor);
  assert.notEqual(identity, true);
  assert.ok(Object.isFrozen(identity));
  // A trusted envelope alone never grants eligibility without a real ledger/ready chain.
  const eligibility = await service.eligibility({ subject: 'owner', scope: ['scan:create'] }, {
    imageReference: `${NGINX_LOCAL_POLICY.registry}/${NGINX_LOCAL_POLICY.repository}@${NGINX_LOCAL_POLICY.digest}`, checks: ['vuln'],
  });
  assert.equal(eligibility.eligible, false);
  assert.equal(eligibility.reason, 'SCANNER_UNAVAILABLE');
  const mutable = { ...f.anchor };
  const snapshot = new LocalProbe(store, resolver, mutable);
  mutable.publicKeyPath = '/not/a/key.pem'; mutable.expectedSpkiSha256 = '0'.repeat(64);
  assert.ok(Object.isFrozen(snapshot.anchor()));
  assert.deepEqual(await snapshot.db(), f.descriptor);
  assert.equal(await new LocalProbe(store, resolver, { ...f.anchor, expectedSpkiSha256: '0'.repeat(64) }).db(), false);
  assert.equal(await new LocalProbe(store, resolver, { ...f.anchor, publicKeyPath: join(f.directory, 'missing.pem') }).db(), false);
});

test('LOCAL worker configuration uses only an explicit anchor and still requires signed bundle preflight', async t => {
  const f = await release(t);
  const config = buildVulnConfig('local', f.anchor);
  assert.ok(config);
  assert.equal(config.trust.trustedPublicKeyPem, f.pem);
  assert.equal(config.trust.expectedSigner, 'local-db-operator-v1');
  assert.equal(config.trust.expectedSource, f.descriptor.source);
  assert.equal(config.trust.expectedSchemaVersion, 2);
  assert.equal(config.trust.expectedArtifactSha256, f.descriptor.artifactSha256);
  assert.equal(config.trust.expectedManifestDigest, f.descriptor.manifestDigest);
  assert.deepEqual((await preflightVulnDbBundle({ ...config.trust, directory: config.releaseDir, policy: CURRENT_DB_POLICY })).identity, f.descriptor);
  assert.equal(buildVulnConfig('local', { ...f.anchor, expectedSpkiSha256: '0'.repeat(64) }), undefined);
  await writeFile(join(f.directory, 'descriptor.sig'), Buffer.alloc(64));
  // Configuration is not verification or readiness; the unchanged preflight rejects invalid signatures.
  await assert.rejects(preflightVulnDbBundle({ ...config.trust, directory: config.releaseDir, policy: CURRENT_DB_POLICY }));
  assert.equal(await new LocalProbe(store, resolver, f.anchor).db(), false);
});

test('explicit LOCAL trust does not bypass signature, artifact, source, schema or the 14-day UpdatedAt policy', async t => {
  const f = await release(t), service = new LocalProbe(store, resolver, f.anchor);
  await writeFile(join(f.directory, 'bundle.bin'), 'tampered');
  assert.equal(await service.db(), false);
  await writeFile(join(f.directory, 'bundle.bin'), f.artifact);
  for (const patch of [{ source: 'ghcr.io/other/db@' + f.descriptor.manifestDigest }, { signer: 'other' }, { schemaVersion: 3 },
    { artifactSha256: '0'.repeat(64) }, { manifestDigest: `sha256:${'b'.repeat(64)}` }]) {
    await f.writeDescriptor({ ...f.descriptor, ...patch });
    assert.equal(await service.db(), false);
  }
  await f.writeDescriptor();
  assert.deepEqual(await service.db(), f.descriptor);
  const daysAgo = (days: number) => new Date(Date.now() - days * 86400_000).toISOString();
  await f.writeMetadata({ ...f.metadata, UpdatedAt: daysAgo(3), DownloadedAt: daysAgo(2), NextUpdate: daysAgo(2) });
  const usable = await service.db();
  assert.ok(usable && typeof usable === 'object'); // Overdue publication remains usable under CURRENT_DB_POLICY.
  await f.writeMetadata({ ...f.metadata, UpdatedAt: daysAgo(15), DownloadedAt: daysAgo(14), NextUpdate: daysAgo(14) });
  assert.equal(await service.db(), false);
});

test('production API, default/proof workers and two-argument LOCAL API ignore LOCAL env and injected worker anchors', async t => {
  const f = await release(t), production = new ProductionProbe(store, resolver), localDefault = new LocalProbe(store, resolver);
  assert.equal(production.anchor(), PRODUCTION_DB_TRUST_ANCHOR);
  assert.deepEqual(localDefault.anchor(), PRODUCTION_DB_TRUST_ANCHOR);
  const attempted: string[] = [];
  // Never read a real deployed key: intercept only the immutable production path.
  t.mock.method(fs, 'openSync', (path: fs.PathLike) => {
    assert.equal(path, PRODUCTION_DB_TRUST_ANCHOR.publicKeyPath);
    attempted.push(String(path));
    throw new Error('Test blocks deployed trust-key reads');
  });
  syncBuiltinESMExports();
  try {
    for (const localHash of [f.anchor.expectedSpkiSha256, '', 'invalid', undefined]) {
      if (localHash === undefined) delete process.env.LOCAL_CVE_TRUST_SHA256; else process.env.LOCAL_CVE_TRUST_SHA256 = localHash;
      assert.equal(await production.db(), false);
      assert.equal(await localDefault.db(), false);
      assert.equal(buildVulnConfig(), undefined);
      assert.equal(buildVulnConfig(undefined, f.anchor), undefined);
      assert.equal(buildVulnConfig('proof', f.anchor), undefined);
      assert.equal(buildVulnConfig('local'), undefined); // Env alone cannot select LOCAL trust.
    }
    assert.equal(attempted.length, 24);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('LOCAL Nest factory selects the compiled env anchor explicitly and rejects invalid present env', t => {
  type Provider = { provide: unknown; useFactory: (ledger: LedgerStore, resolver: OciResolver) => NginxLocalScansService };
  const providers = Reflect.getMetadata('providers', NginxLocalModule) as Provider[];
  const factory = providers.find(provider => provider.provide === ScansService)!.useFactory;
  const selected = (service: NginxLocalScansService) =>
    (service as unknown as { dbTrustAnchor(): DbTrustAnchor }).dbTrustAnchor();
  environment(t, { LOCAL_CVE_TRUST_SHA256: 'b'.repeat(64) });
  const service = factory(store, resolver);
  assert.ok(service instanceof NginxLocalScansService);
  assert.deepEqual(selected(service), localDbTrustAnchorFromEnv());
  process.env.LOCAL_CVE_TRUST_SHA256 = 'c'.repeat(64);
  assert.equal(selected(service).expectedSpkiSha256, 'b'.repeat(64));
  process.env.LOCAL_CVE_TRUST_SHA256 = '';
  assert.throws(() => factory(store, resolver), /Invalid LOCAL CVE trust fingerprint/);
  delete process.env.LOCAL_CVE_TRUST_SHA256;
  assert.deepEqual(selected(factory(store, resolver)), PRODUCTION_DB_TRUST_ANCHOR);
});

test('only explicit LOCAL/public worker entrypoints select LOCAL trust; runtime receives its explicit anchor', async () => {
  const main = await readFile(new URL('./nginx-local-worker.main.ts', import.meta.url), 'utf8');
  assert.match(main, /runWorker\('local', localDbTrustAnchorFromEnv\(\)\)/);
  const worker = await readFile(new URL('./worker.main.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(worker, /localDbTrustAnchorFromEnv|LOCAL_CVE_TRUST/);
  const runtime = await readFile(new URL('./worker-runtime.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(runtime, /localDbTrustAnchorFromEnv|LOCAL_CVE_TRUST/);
  assert.match(runtime, /buildVulnConfig\(archivePolicy, anchor, publicImagePolicy\)/);
    const publicWorker = await readFile(new URL('./public-image-worker.main.ts', import.meta.url), 'utf8');
    assert.match(publicWorker, /runWorker\(undefined, localDbTrustAnchorFromEnv\(\), true\)/);
});
