import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, symlink, truncate, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { preflightVulnDbBundle, type BundlePreflightOptions } from './vuln-db-bundle.js';

const NOW = new Date('2026-10-03T12:00:00.000Z');
const artifact = Buffer.from('SYNTHETIC TEST BYTES; NOT A TRIVY VULNERABILITY DB');
const hash = createHash('sha256').update(artifact).digest('hex');
const fail = /Vulnerability DB bundle preflight failed/;

async function fixture(t: TestContext) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'vuln-db-preflight-')));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const trustedPublicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const manifestDigest = `sha256:${'a'.repeat(64)}`;
  const options: BundlePreflightOptions = {
    directory, trustedPublicKeyPem, expectedSigner: 'offline-operator',
    expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`, expectedSchemaVersion: 2,
    expectedArtifactSha256: hash, expectedManifestDigest: manifestDigest, now: NOW,
  };
  const metadata = {
    Version: 2, NextUpdate: '2026-10-04T10:00:00.123456789Z',
    UpdatedAt: '2026-10-03T10:00:00.123456789Z',
    DownloadedAt: '2026-10-03T11:00:00.123456789Z',
  };
  const metadataBytes = Buffer.from(JSON.stringify(metadata));
  await mkdir(join(directory, 'db'));
  await writeFile(join(directory, 'db', 'metadata.json'), metadataBytes);
  const dbBytes = Buffer.from('SYNTHETIC DB BYTES; NOT A TRIVY DATABASE');
  await writeFile(join(directory, 'db', 'trivy.db'), dbBytes);
  const descriptor = {
    envelopeVersion: 1, signer: options.expectedSigner, source: options.expectedSource,
    schemaVersion: options.expectedSchemaVersion, artifactSha256: hash,
    metadataSha256: createHash('sha256').update(metadataBytes).digest('hex'),
    dbSha256: createHash('sha256').update(dbBytes).digest('hex'), manifestDigest,
    updatedAt: metadata.UpdatedAt, downloadedAt: metadata.DownloadedAt,
    nextUpdate: metadata.NextUpdate,
  };
  const writeDescriptor = async (data = descriptor) => {
    const bytes = Buffer.from(JSON.stringify(data));
    await writeFile(join(directory, 'descriptor.json'), bytes);
    await writeFile(join(directory, 'descriptor.sig'), sign(null, bytes, privateKey));
  };
  await writeDescriptor();
  await writeFile(join(directory, 'bundle.bin'), artifact);
  return { directory, options, descriptor, metadata, writeDescriptor };
}

test('valid signed envelope and pinned synthetic bytes: preflight only', async (t) => {
  const { options, descriptor } = await fixture(t);
  assert.deepEqual(await preflightVulnDbBundle(options), {
    kind: 'envelope-preflight-only', artifactSha256: hash, schemaVersion: 2, identity: descriptor,
  });
});

test('streaming hash buffer covers multiple blocks and the final partial block without hiding tamper', async (t) => {
  const { directory, options, descriptor, writeDescriptor } = await fixture(t);
  const bytes = Buffer.alloc(3 * 64 * 1024 + 17);
  for (let index = 0; index < bytes.length; index++) bytes[index] = index % 251;
  const digest = createHash('sha256').update(bytes).digest('hex');
  await writeFile(join(directory, 'bundle.bin'), bytes);
  await writeFile(join(directory, 'db', 'trivy.db'), bytes);
  await writeDescriptor({ ...descriptor, artifactSha256: digest, dbSha256: digest });
  const pinned = { ...options, expectedArtifactSha256: digest };
  assert.equal((await preflightVulnDbBundle(pinned)).identity.dbSha256, digest);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(join(directory, 'db', 'trivy.db'), bytes);
  await assert.rejects(preflightVulnDbBundle(pinned), fail);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(join(directory, 'db', 'trivy.db'), bytes);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(join(directory, 'bundle.bin'), bytes);
  await assert.rejects(preflightVulnDbBundle(pinned), fail);
});

test('rejects tamper, invalid signature, wrong independent key and hash, without leaking input', async (t) => {
  const { directory, options, writeDescriptor } = await fixture(t);
  await writeFile(join(directory, 'bundle.bin'), Buffer.from('SECRET RAW ARTIFACT'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeFile(join(directory, 'bundle.bin'), artifact);
  await writeFile(join(directory, 'descriptor.json'), 'SECRET RAW DESCRIPTOR');
  await assert.rejects(preflightVulnDbBundle(options), (error: Error) => error.message === fail.source && !error.cause);
  await writeDescriptor();
  await writeFile(join(directory, 'descriptor.sig'), Buffer.alloc(64));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeDescriptor();
  const { publicKey } = generateKeyPairSync('ed25519');
  await assert.rejects(preflightVulnDbBundle({ ...options, trustedPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() }), fail);
  await assert.rejects(preflightVulnDbBundle({ ...options, expectedArtifactSha256: '0'.repeat(64) }), fail);
  await assert.rejects(preflightVulnDbBundle({ ...options, expectedManifestDigest: `sha256:${'b'.repeat(64)}` }), fail);
});

test('rejects metadata tampering, forged DB timestamps and mismatched OCI digest', async (t) => {
  const { directory, options, descriptor, metadata, writeDescriptor } = await fixture(t);
  await writeFile(join(directory, 'db', 'metadata.json'), JSON.stringify({ ...metadata, Version: 3 }));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeFile(join(directory, 'db', 'metadata.json'), JSON.stringify(metadata));
  await writeFile(join(directory, 'db', 'trivy.db'), 'tampered');
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeFile(join(directory, 'db', 'trivy.db'), 'SYNTHETIC DB BYTES; NOT A TRIVY DATABASE');
  await writeDescriptor({ ...descriptor, updatedAt: '2026-10-03T10:00:00.000Z' });
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeDescriptor({ ...descriptor, manifestDigest: `sha256:${'b'.repeat(64)}` });
  await assert.rejects(preflightVulnDbBundle(options), fail);
});

test('rejects missing files and symlinked files or directory', async (t) => {
  const { directory, options, writeDescriptor } = await fixture(t);
  await unlink(join(directory, 'bundle.bin'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await symlink(join(directory, 'descriptor.json'), join(directory, 'bundle.bin'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await unlink(join(directory, 'bundle.bin'));
  await writeFile(join(directory, 'bundle.bin'), artifact);
  await unlink(join(directory, 'descriptor.sig'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeDescriptor();
  await unlink(join(directory, 'descriptor.json'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeDescriptor();
  await unlink(join(directory, 'descriptor.sig'));
  await symlink(join(directory, 'descriptor.json'), join(directory, 'descriptor.sig'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await unlink(join(directory, 'descriptor.sig'));
  await writeDescriptor();
  await rm(join(directory, 'db'), { recursive: true });
  const external = await mkdtemp(join(tmpdir(), 'vuln-db-external-'));
  t.after(async () => { await rm(external, { recursive: true, force: true }); });
  await symlink(external, join(directory, 'db'));
  await assert.rejects(preflightVulnDbBundle(options), fail);
  const link = `${directory}-link`;
  await symlink(directory, link);
  t.after(async () => { await rm(link, { force: true }); });
  await assert.rejects(preflightVulnDbBundle({ ...options, directory: link }), fail);
});

test('rejects oversize descriptor and artifact before accepting bytes', async (t) => {
  const { directory, options, writeDescriptor } = await fixture(t);
  await truncate(join(directory, 'descriptor.json'), 4097);
  await assert.rejects(preflightVulnDbBundle(options), fail);
  await writeDescriptor();
  await truncate(join(directory, 'bundle.bin'), 512 * 1024 * 1024 + 1);
  await assert.rejects(preflightVulnDbBundle(options), fail);
});

test('rejects unknown signer/source/schema and noncanonical descriptor', async (t) => {
  const { directory, options, descriptor, writeDescriptor } = await fixture(t);
  for (const change of [{ signer: 'other' }, { source: 'other' }, { schemaVersion: 3 }]) {
    await writeDescriptor({ ...descriptor, ...change });
    await assert.rejects(preflightVulnDbBundle(options), fail);
  }
  await writeDescriptor();
  await writeFile(join(directory, 'descriptor.json'), JSON.stringify(descriptor) + '\n');
  await assert.rejects(preflightVulnDbBundle(options), fail);
});

test('rejects stale, expired NextUpdate, invalid timestamps and excessive clock skew', async (t) => {
  const { options, descriptor, writeDescriptor } = await fixture(t);
  for (const change of [
    { downloadedAt: '2026-10-02T11:59:59.000Z' },
    { updatedAt: '2026-10-01T11:59:59.000Z', downloadedAt: '2026-10-02T12:00:00.000Z' },
    { nextUpdate: '2026-10-03T12:00:00.000Z' },
    { updatedAt: '2026-10-03T12:05:01.000Z', downloadedAt: '2026-10-03T12:05:01.000Z' },
    { downloadedAt: 'not a time' },
    { nextUpdate: '2026-10-11T10:00:00.000Z' },
  ]) {
    await writeDescriptor({ ...descriptor, ...change });
    await assert.rejects(preflightVulnDbBundle(options), fail);
  }
});
