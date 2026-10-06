// Host-only fixture builder. Never mounts its ephemeral private key in containers.
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { chmod, copyFile, link, mkdir, open, readFile, unlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';
import { preflightVulnDbBundle } from '../../api/src/worker/vuln-db-bundle.ts';

let stage = 'input';
const root = resolve(process.argv[3]);
const productionKey = resolve('..', 'deploy/trust/db-signing-key.pub.pem');
const fingerprint = pem => createHash('sha256').update(createPublicKey(pem).export({ type: 'spki', format: 'der' })).digest('hex');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function hashFile(path, cap) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await fd.stat();
    if (!before.isFile() || before.size < 1 || before.size > cap) throw Error();
    const h = createHash('sha256'); let total = 0;
    for await (const bytes of fd.createReadStream({ autoClose: false })) { total += bytes.length; if (total > cap) throw Error(); h.update(bytes); }
    const after = await fd.stat();
    if (total !== before.size || before.size !== after.size || before.ino !== after.ino || before.ctimeMs !== after.ctimeMs) throw Error();
    return h.digest('hex');
  } finally { await fd.close(); }
}
const options = (directory, pem, d) => ({ directory, trustedPublicKeyPem: pem, expectedSigner: 'local-db-operator-v1',
  expectedSource: d.source, expectedSchemaVersion: 2, expectedManifestDigest: d.manifestDigest, expectedArtifactSha256: d.artifactSha256 });
async function put(path, value) {
  try { await chmod(path, 0o600); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await writeFile(path, value, { mode: 0o600 }); await chmod(path, 0o444);
}
async function init() {
  const env = await readFile(resolve('../../.local-auth/stand.env'), 'utf8');
  const pins = Object.fromEntries(env.split('\n').filter(l => /^SCAN_VULN_(RELEASE_HOST_DIR|MANIFEST_DIGEST|ARTIFACT_SHA256)=/.test(l)).map(l => {
    const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1).replace(/^['"]|['"]$/g, '')];
  }));
  stage = 'source-preflight';
  const source = pins.SCAN_VULN_RELEASE_HOST_DIR;
  const pem = await readFile(productionKey, 'utf8');
  if (fingerprint(pem) !== 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078') throw Error();
  const expected = { source: `ghcr.io/aquasecurity/trivy-db@${pins.SCAN_VULN_MANIFEST_DIGEST}`,
    manifestDigest: pins.SCAN_VULN_MANIFEST_DIGEST, artifactSha256: pins.SCAN_VULN_ARTIFACT_SHA256 };
  const verified = await preflightVulnDbBundle(options(source, pem, expected));
  stage = 'snapshot-copy';
  const snapshot = join(root, 'snapshot'); await mkdir(join(snapshot, 'db'), { recursive: true, mode: 0o755 });
  for (const file of ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db']) {
    await copyFile(join(source, file), join(snapshot, file), constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE); await chmod(join(snapshot, file), 0o444);
  }
  await preflightVulnDbBundle(options(snapshot, pem, expected));
  // Verify the usable copied gzip actually expands to the exact copied DB bytes.
  let expanded = 0; const gzipHash = createHash('sha256');
  await pipeline(createReadStream(join(snapshot, 'bundle.bin')), createGunzip(), new Writable({ write(bytes, _enc, done) {
    expanded += bytes.length; if (expanded > 2 * 1024 ** 3) { done(Error()); return; } gzipHash.update(bytes); done();
  } }));
  if (gzipHash.digest('hex') !== verified.identity.dbSha256) throw Error();
  const pair = generateKeyPairSync('ed25519');
  const pub = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  await writeFile(join(root, 'test-private.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  await put(join(root, 'test-public.pem'), pub);
  const info = { sourceManifest: expected.manifestDigest, dbSha256: verified.identity.dbSha256,
    artifactSha256: verified.identity.artifactSha256, keyFingerprint: fingerprint(pub), fixtureTimesFabricated: true,
    productionAnchorUnchanged: true, localTestSignatureNotAqua: true };
  await writeFile(join(root, 'source.json'), JSON.stringify(info), { mode: 0o600 });
  console.log(JSON.stringify(info));
}
async function mint() {
  const [name, kind, phase, ttlText] = process.argv.slice(4);
  if (!/^[a-z0-9-]+$/.test(name) || !['normal', 'queued', 'during', 'precommit'].includes(phase)) throw Error();
  const ttl = Number(ttlText); if (!Number.isSafeInteger(ttl) || ttl < 20 || ttl > 3600) throw Error();
  const info = JSON.parse(await readFile(join(root, 'source.json'), 'utf8'));
  const directory = join(root, name), release = join(directory, 'release'), proof = join(directory, 'proof');
  await mkdir(join(release, 'db'), { recursive: true, mode: 0o755 }); await mkdir(proof, { mode: 0o755 });
  stage = 'case-copy';
  for (const file of ['bundle.bin', 'db/trivy.db']) {
    // Share immutable bytes ONLY within our own copied snapshot. A case that
    // mutates either file gets a distinct inode; never link to the live release.
    const mutates = kind === 'malformed-content' || (file === 'bundle.bin' ? kind === 'bundle-tamper' : kind === 'db-tamper');
    if (mutates) {
      await copyFile(join(root, 'snapshot', file), join(release, file), constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
      await chmod(join(release, file), 0o444);
    } else await link(join(root, 'snapshot', file), join(release, file));
  }
  stage = 'case-hash';
  if (await hashFile(join(release, 'bundle.bin'), 512 * 1024 ** 2) !== info.artifactSha256 ||
      await hashFile(join(release, 'db/trivy.db'), 2 * 1024 ** 3) !== info.dbSha256) throw Error();
  const t = Date.now();
  let metadata = { Version: 2, UpdatedAt: new Date(t - 60_000).toISOString(), DownloadedAt: new Date(t).toISOString(),
    NextUpdate: new Date(t + ttl * 1000).toISOString() };
  await put(join(release, 'db/metadata.json'), JSON.stringify(metadata));
  stage = 'case-sign';
  const signed = spawnSync(process.execPath, [resolve('../deploy/trust/sign-offline-db.mjs'), release,
    join(root, 'test-private.pem'), join(root, 'test-public.pem'), info.sourceManifest, info.artifactSha256, info.dbSha256],
    { timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'] });
  if (signed.status !== 0) throw Error();
  for (const file of ['descriptor.json', 'descriptor.sig']) await chmod(join(release, file), 0o444);
  const pub = await readFile(join(root, 'test-public.pem'), 'utf8');
  const descriptor = JSON.parse(await readFile(join(release, 'descriptor.json'), 'utf8'));
  stage = 'case-preflight';
  await preflightVulnDbBundle(options(release, pub, descriptor));
  const baselineVerifiedAt = Date.now();
  stage = 'case-mutation';
  const privateKey = await readFile(join(root, 'test-private.pem'));
  const resign = async bytes => { await put(join(release, 'descriptor.json'), bytes); await put(join(release, 'descriptor.sig'), sign(null, bytes, privateKey)); };
  const flip = async path => {
    await chmod(path, 0o600); const fd = await open(path, constants.O_RDWR | constants.O_NOFOLLOW);
    try { const b = Buffer.alloc(1); await fd.read(b, 0, 1, 0); b[0] ^= 1; await fd.write(b, 0, 1, 0); } finally { await fd.close(); }
    await chmod(path, 0o444);
  };
  if (kind === 'db-tamper') await flip(join(release, 'db/trivy.db'));
  else if (kind === 'bundle-tamper') await flip(join(release, 'bundle.bin'));
  else if (kind === 'metadata-tamper') await flip(join(release, 'db/metadata.json'));
  else if (kind === 'bad-signature') await flip(join(release, 'descriptor.sig'));
  else if (kind === 'missing-db') await unlink(join(release, 'db/trivy.db'));
  else if (kind === 'schema') {
    metadata = { ...metadata, Version: 3 };
    const bytes = Buffer.from(JSON.stringify(metadata)); await put(join(release, 'db/metadata.json'), bytes);
    await resign(Buffer.from(JSON.stringify({ ...descriptor, schemaVersion: 3, metadataSha256: hash(bytes) })));
  } else if (kind === 'malformed-metadata') {
    const bytes = Buffer.from('{MALFORMED_DB_SECRET_CANARY'); await put(join(release, 'db/metadata.json'), bytes);
    await resign(Buffer.from(JSON.stringify({ ...descriptor, metadataSha256: hash(bytes) })));
  } else if (kind === 'noncanonical-descriptor') await resign(Buffer.from(' ' + JSON.stringify(descriptor)));
  else if (kind === 'malformed-content') {
    const bytes = Buffer.from('NOT_A_BOLT_DB_SECRET_CANARY');
    const { gzipSync } = await import('node:zlib'); const bundle = gzipSync(bytes);
    await put(join(release, 'db/trivy.db'), bytes); await put(join(release, 'bundle.bin'), bundle);
    descriptor.artifactSha256 = hash(bundle); descriptor.dbSha256 = hash(bytes);
    await resign(Buffer.from(JSON.stringify(descriptor)));
  } else if (!['valid', 'stale'].includes(kind)) throw Error();
  const config = { keyFingerprint: info.keyFingerprint, manifestDigest: info.sourceManifest,
    artifactSha256: descriptor.artifactSha256, phase };
  await put(join(proof, 'db-proof.json'), JSON.stringify(config)); await put(join(proof, 'test-key.pub.pem'), pub);
  let envelopeValid = false;
  try { await preflightVulnDbBundle(options(release, pub, descriptor)); envelopeValid = true; } catch { /* safe intentional fixture */ }
  if (envelopeValid !== ['valid', 'stale', 'malformed-content'].includes(kind)) throw Error();
  console.log(JSON.stringify({ name, kind, phase, keyFingerprint: info.keyFingerprint, baselineVerifiedAt,
    nextUpdate: metadata.NextUpdate, mintedAt: t, envelopeValidBeforeExpiry: envelopeValid,
    fixtureTimesFabricated: true, dbSha256: descriptor.dbSha256 }));
}
try { if (process.argv[2] === 'init') await init(); else if (process.argv[2] === 'mint') await mint(); else throw Error(); }
catch (error) {
  const ioCode = ['ENOSPC', 'EDQUOT', 'ENOENT', 'EACCES', 'EIO', 'ETIMEDOUT'].includes(error.code) ? error.code : 'UNCLASSIFIED';
  console.log(JSON.stringify({ fixtureFailure: true, stage, ioCode })); process.exitCode = 1;
}
