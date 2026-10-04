import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, realpath, rm, symlink, truncate, unlink, writeFile } from 'node:fs/promises';
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
  const options: BundlePreflightOptions = {
    directory, trustedPublicKeyPem, expectedSigner: 'offline-operator',
    expectedSource: 'pinned-local-source', expectedSchemaVersion: 2,
    expectedArtifactSha256: hash, now: NOW,
  };
  const descriptor = {
    envelopeVersion: 1, signer: options.expectedSigner, source: options.expectedSource,
    schemaVersion: options.expectedSchemaVersion, artifactSha256: hash,
    updatedAt: '2026-10-03T10:00:00.000Z', downloadedAt: '2026-10-03T11:00:00.000Z',
    nextUpdate: '2026-10-04T10:00:00.000Z',
  };
  const writeDescriptor = async (data = descriptor) => {
    const bytes = Buffer.from(JSON.stringify(data));
    await writeFile(join(directory, 'descriptor.json'), bytes);
    await writeFile(join(directory, 'descriptor.sig'), sign(null, bytes, privateKey));
  };
  await writeDescriptor();
  await writeFile(join(directory, 'bundle.bin'), artifact);
  return { directory, options, descriptor, writeDescriptor };
}

test('valid signed envelope and pinned synthetic bytes: preflight only', async (t) => {
  const { options } = await fixture(t);
  assert.deepEqual(await preflightVulnDbBundle(options), {
    kind: 'envelope-preflight-only', artifactSha256: hash, schemaVersion: 2,
  });
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
