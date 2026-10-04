import assert from 'node:assert/strict';
import type { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { link, mkdir, mkdtemp, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import test, { type TestContext } from 'node:test';
import type { Job } from '../ledger/ledger.js';
import { preflightVulnDbBundle } from './vuln-db-bundle.js';
import { scanVulnPinned, type VulnScanOptions } from './vuln-worker.js';

const job: Job = { scanId: 'scan', attempts: 1, registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["vuln"]', scope: 'image' };
const image = `${job.registry}/${job.repository}@${job.digest}`;
const failure = { ok: false, errorCode: 'SCAN_FAILED' };
const report = () => JSON.stringify({ SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: image,
  Metadata: { RepoDigests: [image], ImageConfig: { os: 'linux', architecture: 'amd64' },
    OS: { Family: 'alpine', Name: '3.21.3' } },
  Results: [{ Target: 'alpine:3.21.3', Class: 'os-pkgs', Type: 'alpine', Vulnerabilities: [
    { VulnerabilityID: 'CVE-2025-12345', PkgName: 'busybox', InstalledVersion: '1.36.1-r2',
      Severity: 'HIGH', SeveritySource: 'alpine', Description: 'CANARY_SECRET' } ] }] });

async function fixture(t: TestContext, stale = false) {
  const releaseDir = await realpath(await mkdtemp('/tmp/vuln-release-'));
  const cacheDir = await mkdtemp('/tmp/vuln-cache-');
  t.after(async () => { await rm(releaseDir, { recursive: true, force: true });
    await rm(cacheDir, { recursive: true, force: true }); });
  await mkdir(join(releaseDir, 'db'));
  await mkdir(join(cacheDir, 'db'));
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const manifestDigest = `sha256:${'b'.repeat(64)}`;
  const artifact = Buffer.from('TEST ARTIFACT (NOT A REAL TRIVY DB)');
  const db = Buffer.from('TEST DB (NOT A REAL TRIVY DB)');
  const now = Date.now() - (stale ? 3 * 86_400_000 : 0);
  const metadata = { Version: 2, UpdatedAt: new Date(now - 60_000).toISOString(),
    DownloadedAt: new Date(now - 30_000).toISOString(), NextUpdate: new Date(now + 86_400_000).toISOString() };
  const metadataBytes = Buffer.from(JSON.stringify(metadata));
  await writeFile(join(releaseDir, 'db', 'metadata.json'), metadataBytes);
  await writeFile(join(releaseDir, 'db', 'trivy.db'), db);
  // Hard links emulate the file identity of a read-only bind mount without requiring root in tests.
  for (const file of ['metadata.json', 'trivy.db'])
    await link(join(releaseDir, 'db', file), join(cacheDir, 'db', file));
  await writeFile(join(releaseDir, 'bundle.bin'), artifact);
  const hash = (value: Buffer) => createHash('sha256').update(value).digest('hex');
  const descriptor = { envelopeVersion: 1, signer: 'independent-vuln-db-operator',
    source: `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`, schemaVersion: 2,
    artifactSha256: hash(artifact), metadataSha256: hash(metadataBytes), dbSha256: hash(db),
    manifestDigest, updatedAt: metadata.UpdatedAt, downloadedAt: metadata.DownloadedAt,
    nextUpdate: metadata.NextUpdate };
  const descriptorBytes = Buffer.from(JSON.stringify(descriptor));
  await writeFile(join(releaseDir, 'descriptor.json'), descriptorBytes);
  await writeFile(join(releaseDir, 'descriptor.sig'), sign(null, descriptorBytes, privateKey));
  const options: VulnScanOptions = { timeoutMs: 1000, releaseDir, cacheDir,
    trust: { trustedPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      expectedSigner: descriptor.signer, expectedSource: descriptor.source, expectedSchemaVersion: 2,
      expectedArtifactSha256: descriptor.artifactSha256, expectedManifestDigest: manifestDigest } };
  return { options, releaseDir, cacheDir };
}
function scanner() {
  const child = new EventEmitter() as EventEmitter & { stdout: PassThrough; kill: (signal: string) => boolean };
  child.stdout = new PassThrough();
  const signals: string[] = [];
  child.kill = signal => { signals.push(signal); return true; };
  const calls: { binary: string; args: string[]; options: Parameters<typeof spawn>[2] }[] = [];
  let stops = 0;
  const lifecycle = { spawn: ((binary: string, args: string[], options: Parameters<typeof spawn>[2]) => {
    calls.push({ binary, args, options }); return child;
  }) as unknown as typeof spawn, stopWorker: () => { stops++; }, preflight: preflightVulnDbBundle };
  return { child, calls, signals, lifecycle, get stops() { return stops; } };
}

test('signed fresh DB preflight precedes fixed vuln-only argv; result contains sanitized findings', async t => {
  const { options } = await fixture(t);
  const fake = scanner();
  process.env.SENSITIVE_TRIVY_TOKEN = 'CANARY_SECRET';
  try {
    const pending = scanVulnPinned(job, options, fake.lifecycle);
    // preflight is asynchronous: allow both file checks to finish.
    for (let i = 0; i < 100 && !fake.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(fake.calls.length, 1);
    assert.equal(fake.calls[0].binary, '/usr/local/bin/trivy');
    assert.deepEqual(fake.calls[0].args, ['image', '--image-src', 'remote', '--scanners', 'vuln',
      '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--cache-dir', options.cacheDir,
      '--platform', 'linux/amd64', '--format', 'json', image]);
    assert.equal(fake.calls[0].options?.shell, false);
    assert.deepEqual(fake.calls[0].options?.stdio, ['ignore', 'pipe', 'ignore']);
    assert.equal(fake.calls[0].options?.env?.SENSITIVE_TRIVY_TOKEN, undefined);
    fake.child.stdout.write(report()); fake.child.emit('close', 0);
    const result = await pending;
    assert.equal(result.ok, true);
    assert.ok(!JSON.stringify(result).includes('CANARY_SECRET'));
    if (result.ok) {
      assert.equal(result.scannerVersion, '0.69.3');
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].cveId, 'CVE-2025-12345');
    }
  } finally { delete process.env.SENSITIVE_TRIVY_TOKEN; }
});

test('wrong image, platform, scope, checks, path or timeout never spawn', async t => {
  const { options } = await fixture(t);
  const fake = scanner();
  for (const invalid of [{ ...job, repository: 'other' }, { ...job, registry: 'evil.test' },
    { ...job, digest: 'sha256:bad' }, { ...job, platform: 'linux/arm64' },
    { ...job, checks: '["secret"]' }, { ...job, scope: 'repository' }])
    assert.deepEqual(await scanVulnPinned(invalid, options, fake.lifecycle), failure);
  for (const bad of [{ ...options, cacheDir: '/tmp/../other' }, { ...options, timeoutMs: 0 },
    { ...options, releaseDir: 'relative' }])
    assert.deepEqual(await scanVulnPinned(job, bad, fake.lifecycle), failure);
  assert.equal(fake.calls.length, 0);
});

test('missing, tampered, stale or mismatched DB prevents scanner launch', async t => {
  const { options, releaseDir, cacheDir } = await fixture(t);
  const fake = scanner();

  await writeFile(join(releaseDir, 'db', 'trivy.db'), 'tampered');
  assert.deepEqual(await scanVulnPinned(job, options, fake.lifecycle), failure);
  await unlink(join(releaseDir, 'db', 'trivy.db'));
  assert.deepEqual(await scanVulnPinned(job, options, fake.lifecycle), failure);
  assert.equal(fake.calls.length, 0);
});

test('signed but stale DB cannot start the scanner', async t => {
  const { options } = await fixture(t, true);
  const fake = scanner();
  assert.deepEqual(await scanVulnPinned(job, options, fake.lifecycle), failure);
  assert.equal(fake.calls.length, 0);
});

test('valid release with an independently replaced cache DB fails before spawn', async t => {
  const { options, cacheDir } = await fixture(t);
  await unlink(join(cacheDir, 'db', 'trivy.db'));
  await writeFile(join(cacheDir, 'db', 'trivy.db'), 'other DB');
  const fake = scanner();
  assert.deepEqual(await scanVulnPinned(job, options, fake.lifecycle), failure);
  assert.equal(fake.calls.length, 0);
});

test('preflight must finish before spawn; abort during preflight prevents launch', async t => {
  const { options } = await fixture(t);
  const fake = scanner();
  const controller = new AbortController();
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  fake.lifecycle.preflight = (async trust => { await gate; return preflightVulnDbBundle(trust); }) as typeof preflightVulnDbBundle;
  const pending = scanVulnPinned(job, { ...options, signal: controller.signal }, fake.lifecycle);
  controller.abort(); release();
  assert.deepEqual(await pending, failure);
  assert.equal(fake.calls.length, 0);
});

test('incomplete, malformed or invalid UTF-8 JSON never means zero findings', async t => {
  const { options } = await fixture(t);
  for (const output of [Buffer.from('{'), Buffer.from([0xff]), Buffer.from('{}'),
    Buffer.from(report().replace('"Results":', '"MissingResults":')), Buffer.alloc(0)]) {
    const fake = scanner();
    const pending = scanVulnPinned(job, options, fake.lifecycle);
    for (let i = 0; i < 100 && !fake.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(fake.calls.length, 1);
    fake.child.stdout.write(output); fake.child.emit('close', 0);
    assert.deepEqual(await pending, failure);
  }
});

test('stdout byte cap and subprocess errors fail without raw logs or early resolution', async t => {
  const { options } = await fixture(t);
  const fake = scanner();
  let resolved = false;
  const pending = scanVulnPinned(job, options, fake.lifecycle).then(value => { resolved = true; return value; });
  for (let i = 0; i < 100 && !fake.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
  fake.child.stdout.write(Buffer.alloc(8_000_001));
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(resolved, false);
  fake.child.emit('close', 0);
  assert.deepEqual(await pending, failure);
  const second = scanner();
  const failed = scanVulnPinned(job, options, second.lifecycle);
  for (let i = 0; i < 100 && !second.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
  second.child.emit('error', new Error('CANARY_SECRET'));
  second.child.emit('close', 1);
  assert.deepEqual(await failed, failure);
});

test('abort and timeout kill process and refuse late successful output', async t => {
  const { options } = await fixture(t);
  const fake = scanner(); const controller = new AbortController();
  const pending = scanVulnPinned(job, { ...options, signal: controller.signal }, fake.lifecycle);
  for (let i = 0; i < 100 && !fake.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
  controller.abort();
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(fake.stops, 1);
  fake.child.stdout.write(report()); fake.child.emit('close', 0);
  assert.deepEqual(await pending, failure);
  const slow = scanner();
  const timeout = scanVulnPinned(job, options, slow.lifecycle);
  for (let i = 0; i < 100 && !slow.calls.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
  await new Promise(resolve => setTimeout(resolve, 1100));
  assert.deepEqual(slow.signals, ['SIGKILL']);
  slow.child.emit('close', 0);
  assert.deepEqual(await timeout, { ok: false, errorCode: 'SCAN_TIMEOUT' });
});
