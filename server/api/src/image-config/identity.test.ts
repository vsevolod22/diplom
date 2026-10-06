import assert from 'node:assert/strict';
import test from 'node:test';
import { createImageConfigModule } from './index.js';
import { createVerifier } from './verified-input.js';
import { ConfigFailure } from './policy.js';
import { baseConfig, digest, encode, fixturePort, setup } from './test-fixtures.js';

for (const change of ['manifest bytes', 'manifest digest', 'schemaVersion', 'manifest mediaType', 'index', 'descriptor hash', 'descriptor size', 'descriptor mediaType', 'config byte', 'os', 'architecture', 'variant'] as const) {
  test(`public entry rejects ${change} mismatch`, async () => {
    const f = setup();
    switch (change) {
      case 'manifest bytes': f.input.manifestBytes[0] ^= 1; break;
      case 'manifest digest': f.input.identity.manifestDigest = `sha256:${'0'.repeat(64)}`; break;
      case 'schemaVersion': f.manifest.schemaVersion = 1; f.repinManifest(); break;
      case 'manifest mediaType': f.manifest.mediaType = 'secret/canary'; f.repinManifest(); break;
      case 'index': f.repinManifest(encode({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [] })); break;
      case 'descriptor hash': f.manifest.config.digest = `sha256:${'0'.repeat(64)}`; f.repinManifest(); break;
      case 'descriptor size': f.manifest.config.size++; f.repinManifest(); break;
      case 'descriptor mediaType': f.manifest.config.mediaType = 'secret/canary'; f.repinManifest(); break;
      case 'config byte': f.input.configBytes[f.input.configBytes.length - 1] ^= 1; break;
      case 'os': f.input.identity.platform.os = 'windows'; break;
      case 'architecture': f.input.identity.platform.architecture = 'arm64'; break;
      case 'variant': f.input.identity.platform.variant = 'v8'; break;
    }
    const result = await f.analyze();
    assert.equal(result.config.reason, 'OCI_IDENTITY_REJECTED');
    assert.deepEqual(result.findings, []);
    assert.deepEqual(result.completedRuleIds, []);
  });
}

test('Docker v2 media types are supported, but absent or malformed descriptor fields are not', async () => {
  const f = setup();
  f.manifest.mediaType = 'application/vnd.docker.distribution.manifest.v2+json';
  f.manifest.config.mediaType = 'application/vnd.docker.container.image.v1+json';
  f.repinManifest();
  assert.equal((await f.analyze()).config.outcome, 'checked');
  for (const descriptor of [null, [], {}, { ...f.manifest.config, size: -1 }, { ...f.manifest.config, size: '1' },
    { ...f.manifest.config, size: 1.5 }, { ...f.manifest.config, digest: f.manifest.config.digest.toUpperCase() }]) {
    f.repinManifest(encode({ ...f.manifest, config: descriptor }));
    assert.equal((await f.analyze()).config.reason, 'OCI_IDENTITY_REJECTED');
  }
});

test('variant matches exactly and platform canaries never become output', async () => {
  const f = setup({ ...baseConfig(), architecture: 'arm64', variant: 'v8' });
  f.input.identity.platform = { os: 'linux', architecture: 'arm64', variant: 'v8' };
  assert.equal((await f.analyze()).findings[0]?.platform.variant, 'v8');
  for (const platform of [{ os: 'CANARY_OS', architecture: 'amd64' }, { os: 'linux', architecture: 'CANARY_ARCH' },
    { os: 'linux', architecture: 'arm64', variant: 'CANARY_VARIANT' }]) {
    f.input.identity.platform = platform;
    const result = await f.analyze();
    assert.equal(result.config.reason, 'OCI_IDENTITY_REJECTED');
    assert.equal(JSON.stringify(result).includes('CANARY'), false);
  }
});

test('private runtime receipts reject serialized, cloned, structural, cast and cross-instance proof', () => {
  const f = setup();
  const verifier = createVerifier();
  const receipt = verifier.verify(f.input);
  assert.equal(verifier.read(receipt).user, '0');
  for (const fake of [JSON.parse(JSON.stringify(receipt)), structuredClone(receipt), { ...receipt },
    { verified: true, manifestDigest: f.input.identity.manifestDigest }, true, undefined, null]) {
    assert.throws(() => verifier.read(fake), (error: unknown) => error instanceof ConfigFailure && error.reason === 'OCI_IDENTITY_REJECTED');
  }
  assert.throws(() => createVerifier().read(receipt), ConfigFailure);
  assert.deepEqual(Object.keys(receipt), []);
});

test('verified snapshot owns bytes and identity; caller mutation cannot rebind evidence', async () => {
  const f = setup();
  const verifier = createVerifier();
  const receipt = verifier.verify(f.input);
  const before = verifier.read(receipt);
  f.input.configBytes.fill(0);
  f.input.manifestBytes.fill(0);
  f.input.identity.manifestDigest = `sha256:${'f'.repeat(64)}`;
  f.input.identity.platform.os = 'windows';
  f.manifest.config.digest = `sha256:${'a'.repeat(64)}`;
  assert.deepEqual(verifier.read(receipt), before);
  assert.equal(before.user, '0');
  assert.equal(before.platform.os, 'linux');
  assert.equal(Object.isFrozen(before), true);
  assert.equal(Object.isFrozen(before.platform), true);
  assert.throws(() => { (before.platform as { os: string }).os = 'windows'; }, TypeError);
  assert.equal((await f.analyze()).config.reason, 'OCI_IDENTITY_REJECTED');
});

test('public result and request mutations cannot alter later runs or install a capability', async () => {
  const f = setup();
  const first = await f.analyze();
  const expected = await f.analyze();
  (first.findings[0].platform as { os: string }).os = 'CANARY';
  first.config.outcome = 'failed';
  first.supportedRuleIds.length = 0;
  assert.deepEqual(await f.analyze(), expected);
  const result = await f.module.analyze({ enabled: true, target: {}, verified: true, receipt: {},
    descriptor: f.manifest.config, trustedCallerPort: { resolveAuthorizedTarget: () => f.input } });
  assert.equal(result.config.reason, 'OCI_IDENTITY_REJECTED');
});

test('bootstrap port is captured and absent targets never fall back to raw request bytes', async () => {
  const f = setup();
  const { target, port } = fixturePort(f.input);
  const module = createImageConfigModule(port);
  port.resolveAuthorizedTarget = () => undefined;
  assert.equal((await module.analyze({ enabled: true, target })).config.outcome, 'checked');
  assert.equal((await module.analyze({ enabled: true, manifestBytes: f.input.manifestBytes, configBytes: f.input.configBytes,
    identity: f.input.identity })).config.reason, 'OCI_IDENTITY_REJECTED');
});

test('target change yields a different stable finding ID', async () => {
  const a = setup();
  const b = setup({ ...baseConfig(), unknown: 'different-target' });
  const first = (await a.analyze()).findings[0].findingId;
  assert.notEqual(first, (await b.analyze()).findings[0].findingId);
  assert.equal(first, (await a.analyze({ scanId: 'ignored', time: 999 })).findings[0].findingId);
  assert.equal(a.input.identity.manifestDigest, digest(a.input.manifestBytes));
});
