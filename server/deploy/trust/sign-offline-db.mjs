#!/usr/bin/env node
// Operator-only, manual attestation of a pinned Trivy DB release. Never invoke from a downloader or worker.
import { createHash, createPrivateKey, createPublicKey, sign, timingSafeEqual } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { lstat, mkdir, open, readFile, rename, rm, rmdir } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';

const MAX_DB = 2 * 1024 ** 3;
const MAX_BUNDLE = 512 * 1024 ** 2;
const DIGEST = /^[a-f0-9]{64}$/;
const MANIFEST = /^sha256:[a-f0-9]{64}$/;
const SOURCE = 'ghcr.io/aquasecurity/trivy-db';
const fail = () => new Error('DB release attestation failed');

function timestamp(raw) {
  if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/.test(raw)) throw fail();
  const ms = raw.replace(/\.(\d{1,9})Z$/, (_, n) => `.${n.padEnd(3, '0').slice(0, 3)}Z`);
  const time = Date.parse(ms);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== ms) throw fail();
  return time;
}

async function regular(path, max) {
  const st = await lstat(path);
  if (!st.isFile() || st.isSymbolicLink() || st.size < 1 || st.size > max) throw fail();
  return st;
}

async function hashFile(path, max) {
  const before = await regular(path, max);
  const hash = createHash('sha256');
  let size = 0;
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    for await (const bytes of fd.createReadStream({ autoClose: false })) {
      size += bytes.length;
      if (size > max) throw fail();
      hash.update(bytes);
    }
    const after = await fd.stat();
    if (size !== before.size || size !== after.size || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw fail();
    return hash.digest('hex');
  } finally { await fd.close(); }
}

async function decompressedHash(path) {
  const hash = createHash('sha256');
  let total = 0;
  await pipeline(createReadStream(path, { flags: 'r' }), createGunzip(), new Writable({
    write(chunk, _encoding, done) {
      total += chunk.length;
      if (total > MAX_DB) { done(fail()); return; }
      hash.update(chunk);
      done();
    },
  }));
  return hash.digest('hex');
}

async function main() {
  const [dir, keyPath, publicPath, manifest, expectedBundle, expectedDb] = process.argv.slice(2);
  if (!dir || !keyPath || !publicPath || !MANIFEST.test(manifest ?? '') ||
      !DIGEST.test(expectedBundle ?? '') || !DIGEST.test(expectedDb ?? '')) throw fail();
  const directory = resolve(dir);
  if (!isAbsolute(directory) || directory === resolve(keyPath) ||
      [keyPath, publicPath].some(p => resolve(p).startsWith(directory + '/'))) throw fail();
  const keyStat = await regular(keyPath, 8192);
  if ((keyStat.mode & 0o077) !== 0) throw fail();
  const privateKey = createPrivateKey(await readFile(keyPath));
  const trusted = createPublicKey(await readFile(publicPath));
  if (privateKey.asymmetricKeyType !== 'ed25519' || trusted.asymmetricKeyType !== 'ed25519' ||
      !timingSafeEqual(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }),
                       trusted.export({ type: 'spki', format: 'der' }))) throw fail();
  const rootStat = await lstat(directory);
  const dbStat = await lstat(join(directory, 'db'));
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || !dbStat.isDirectory() || dbStat.isSymbolicLink()) throw fail();
  const metadataPath = join(directory, 'db', 'metadata.json');
  await regular(metadataPath, 4096);
  const metadataBytes = await readFile(metadataPath);
  const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metadataBytes));
  if (!metadata || Array.isArray(metadata) || metadata.Version !== 2) throw fail();
  const updated = timestamp(metadata.UpdatedAt);
  const downloaded = timestamp(metadata.DownloadedAt);
  const next = timestamp(metadata.NextUpdate);
  const now = Date.now();
  if (updated > now + 300000 || downloaded > now + 300000 || downloaded < updated ||
      now - updated > 48 * 3600000 || now - downloaded > 24 * 3600000 ||
      next <= updated || next - updated > 7 * 86400000 || now >= next) throw fail();
  const bundlePath = join(directory, 'bundle.bin');
  const dbPath = join(directory, 'db', 'trivy.db');
  const artifactSha256 = await hashFile(bundlePath, MAX_BUNDLE);
  const dbSha256 = await hashFile(dbPath, MAX_DB);
  if (artifactSha256 !== expectedBundle || dbSha256 !== expectedDb ||
      await decompressedHash(bundlePath) !== dbSha256) throw fail();
  // Preserve exact key order: verifier refuses alternate/extra JSON fields.
  const descriptor = Buffer.from(JSON.stringify({
    envelopeVersion: 1, signer: 'local-db-operator-v1', source: `${SOURCE}@${manifest}`,
    schemaVersion: 2, artifactSha256,
    metadataSha256: createHash('sha256').update(metadataBytes).digest('hex'),
    dbSha256, manifestDigest: manifest,
    updatedAt: metadata.UpdatedAt, downloadedAt: metadata.DownloadedAt, nextUpdate: metadata.NextUpdate,
  }));
  if (descriptor.length > 4096 || await hashFile(metadataPath, 4096) !== createHash('sha256').update(metadataBytes).digest('hex')) throw fail();
  // Exclusive operator lock prevents our signer from racing another signing invocation.
  // A crash leaves the lock for manual investigation; this is not atomic DB publication.
  const lock = join(directory, '.signing.lock');
  await mkdir(lock, { mode: 0o700 });
  const temporary = [];
  try {
    for (const name of ['descriptor.json', 'descriptor.sig']) {
      try { await lstat(join(directory, name)); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
      throw fail();
    }
    const signature = sign(null, descriptor, privateKey);
    if (signature.length !== 64) throw fail();
    for (const [name, bytes] of [['descriptor.json', descriptor], ['descriptor.sig', signature]]) {
      const target = join(directory, `.${basename(name)}.${process.pid}.tmp`);
      const fd = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      temporary.push(target);
      try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    }
    await rename(temporary[0], join(directory, 'descriptor.json'));
    await rename(temporary[1], join(directory, 'descriptor.sig'));
    console.log('Signed local operator release; this is not a publisher signature.');
  } finally {
    for (const path of temporary) await rm(path, { force: true });
    await rmdir(lock);
  }
}

main().catch(() => { console.error('DB release attestation failed'); process.exitCode = 1; });
