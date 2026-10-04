import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const manifest = `sha256:${'a'.repeat(64)}`;
const sha = data => createHash('sha256').update(data).digest('hex');
const script = new URL('./sign-offline-db.mjs', import.meta.url).pathname;

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'dip-db-sign-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, 'db'));
  const db = Buffer.from('NOT A REAL DB: signing workflow test');
  const bundle = gzipSync(db);
  const metadata = {
    Version: 2, NextUpdate: new Date(Date.now() + 3600000).toISOString(),
    UpdatedAt: new Date(Date.now() - 3600000).toISOString(),
    DownloadedAt: new Date(Date.now() - 1800000).toISOString(),
  };
  await writeFile(join(dir, 'db', 'trivy.db'), db);
  await writeFile(join(dir, 'db', 'metadata.json'), JSON.stringify(metadata));
  await writeFile(join(dir, 'bundle.bin'), bundle);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = join(dir, 'operator.pem');
  const pub = join(dir, 'operator.pub.pem');
  // Keys must live outside the bundle directory.
  const release = join(dir, 'release');
  await mkdir(join(release, 'db'), { recursive: true });
  for (const [source, destination] of [['bundle.bin', 'bundle.bin'], ['db/trivy.db', 'db/trivy.db'], ['db/metadata.json', 'db/metadata.json']]) {
    await writeFile(join(release, destination), await readFile(join(dir, source)));
  }
  await writeFile(key, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  await writeFile(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  const args = [script, release, key, pub, manifest, sha(bundle), sha(db)];
  const run = (override = args) => spawnSync(process.execPath, override, { encoding: 'utf8', timeout: 10000 });
  return { release, pub, publicKey, run, args };
}

test('manual signer binds fixed fields; second signing refuses overwrite', async t => {
  const { release, publicKey, run } = await fixture(t);
  assert.equal(run().status, 0);
  const descriptor = await readFile(join(release, 'descriptor.json'));
  const signature = await readFile(join(release, 'descriptor.sig'));
  assert.equal(verify(null, descriptor, publicKey, signature), true);
  const data = JSON.parse(descriptor);
  assert.equal(data.manifestDigest, manifest);
  assert.equal(data.source, `ghcr.io/aquasecurity/trivy-db@${manifest}`);
  assert.equal(data.signer, 'local-db-operator-v1');
  assert.equal(run().status, 1);
});

test('refuses wrong pins, stale DB, untrusted public key and permissive private key', async t => {
  const { release, pub, publicKey, run, args } = await fixture(t);
  assert.equal(run([...args.slice(0, -2), '0'.repeat(64), args.at(-1)]).status, 1);
  assert.equal(run([...args.slice(0, -1), '0'.repeat(64)]).status, 1);
  const other = generateKeyPairSync('ed25519').publicKey;
  await writeFile(pub, other.export({ type: 'spki', format: 'pem' }));
  assert.equal(run().status, 1);
  await writeFile(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  await chmod(args[2], 0o644);
  assert.equal(run().status, 1);
  await chmod(args[2], 0o600);
  const metadataPath = join(release, 'db', 'metadata.json');
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  metadata.NextUpdate = '2020-01-01T00:00:00.000Z';
  await writeFile(metadataPath, JSON.stringify(metadata));
  assert.equal(run().status, 1);
});
