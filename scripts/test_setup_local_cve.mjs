import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { childEnvironment, loadCveActivation, parseSetupArguments, setupLocalCve } from './setup-local-cve.mjs';
import { parseVerifyArguments, verifyLocalCve } from './verify-local-cve.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const manifest = `sha256:${'a'.repeat(64)}`;
const refused = /LOCAL CVE setup refused;/;

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'local-cve-setup-test-')));
  const stand = join(root, '.local-stand'), trust = join(stand, 'trust');
  const release = join(stand, 'db-releases', 'synthetic');
  fs.mkdirSync(join(release, 'db'), { recursive: true, mode: 0o700 });
  // recursive mkdir's intermediate modes are platform-dependent; establish the contract explicitly.
  for (const path of [stand, join(stand, 'db-releases'), release, join(release, 'db')]) fs.chmodSync(path, 0o700);
  const db = Buffer.from('SYNTHETIC DB: cryptographic workflow test, not scanner compatible');
  const bundle = gzipSync(db), at = Date.now();
  const metadata = { Version: 2, UpdatedAt: new Date(at - 3600_000).toISOString(),
    DownloadedAt: new Date(at - 1800_000).toISOString(), NextUpdate: new Date(at + 3600_000).toISOString() };
  for (const [name, bytes] of [['db/trivy.db', db], ['bundle.bin', bundle], ['db/metadata.json', JSON.stringify(metadata)]]) {
    fs.writeFileSync(join(release, name), bytes, { mode: 0o600 });
  }
  const argv = ['--release', 'synthetic', '--manifest', manifest, '--bundle', sha(bundle), '--db', sha(db)];
  const calls = [], logs = [];
  const run = async (executable, args, options) => {
    calls.push({ executable, args, options });
    if (args[0].endsWith('/sign-offline-db.mjs')) {
      // Synthetic signer seam only: no real signer process, host key, Docker or network.
      const [, dir, keyPath, pubPath, manifestDigest, artifactSha256, dbSha256] = args;
      assert.equal(sha(fs.readFileSync(join(dir, 'bundle.bin'))), artifactSha256);
      assert.equal(sha(fs.readFileSync(join(dir, 'db/trivy.db'))), dbSha256);
      const key = createPrivateKey(fs.readFileSync(keyPath));
      assert.equal(createPublicKey(key).export({ type: 'spki', format: 'pem' }), fs.readFileSync(pubPath, 'utf8'));
      const m = JSON.parse(fs.readFileSync(join(dir, 'db/metadata.json'), 'utf8'));
      const descriptor = Buffer.from(JSON.stringify({ envelopeVersion: 1, signer: 'local-db-operator-v1',
        source: `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`, schemaVersion: 2, artifactSha256,
        metadataSha256: sha(fs.readFileSync(join(dir, 'db/metadata.json'))), dbSha256, manifestDigest,
        updatedAt: m.UpdatedAt, downloadedAt: m.DownloadedAt, nextUpdate: m.NextUpdate }));
      fs.writeFileSync(join(dir, 'descriptor.json'), descriptor, { mode: 0o600, flag: 'wx' });
      fs.writeFileSync(join(dir, 'descriptor.sig'), sign(null, descriptor, key), { mode: 0o600, flag: 'wx' });
      return 'synthetic signer completed';
    }
    assert.equal(args[0], '--import');
    return JSON.stringify(await verifyLocalCve(args.slice(3)));
  };
  t.after(() => {
    for (const path of [release, join(release, 'db')]) if (fs.existsSync(path)) fs.chmodSync(path, 0o700);
    if (fs.existsSync(join(root, '.local-auth'))) fs.chmodSync(join(root, '.local-auth'), 0o700);
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, stand, trust, release, argv, calls, logs, run,
    setup: (options = {}) => setupLocalCve(argv, { root, run, log: line => logs.push(line), ...options }) };
}

function installPair(f, pair = generateKeyPairSync('ed25519')) {
  fs.mkdirSync(f.trust, { mode: 0o700 });
  fs.writeFileSync(join(f.trust, 'db-signing-key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(join(f.trust, 'db-signing-key.pub.pem'), pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o444 });
}
const mode = path => fs.statSync(path).mode & 0o777;

// These tests require the repository's tsx loader, solely for real backend verification of temporary fixtures.
test('first publication signs then verifies, freezes public release, and publishes exact canonical activation', async t => {
  const f = fixture(t);
  fs.writeFileSync(join(f.stand, 'scan-jwt'), 'DO NOT READ OR ROTATE', { mode: 0o000 });
  fs.mkdirSync(join(f.root, '.local-auth'), { mode: 0o000 });

  const activation = await f.setup();
  assert.deepEqual(Object.keys(activation), ['version', 'release', 'manifestDigest', 'artifactSha256', 'publicKeySha256']);
  assert.equal(fs.readFileSync(join(f.stand, 'cve.json'), 'utf8'), JSON.stringify(activation));
  assert.equal(mode(join(f.stand, 'cve.json')), 0o600);
  assert.equal(mode(f.trust), 0o700);
  assert.equal(mode(join(f.trust, 'db-signing-key.pem')), 0o600);
  assert.equal(mode(join(f.trust, 'db-signing-key.pub.pem')), 0o444);
  assert.equal(mode(f.release), 0o555);
  assert.equal(mode(join(f.release, 'db')), 0o555);
  for (const name of ['bundle.bin', 'descriptor.json', 'descriptor.sig', 'db/trivy.db', 'db/metadata.json']) {
    assert.equal(mode(join(f.release, name)), 0o444);
  }
  assert.deepEqual(loadCveActivation(f.root), activation);
  assert.equal(f.calls.length, 2);
  for (const call of f.calls) {
    assert.equal(call.executable, process.execPath);
    assert(call.options.timeout > 0 && call.options.timeout <= 120_000);
    assert.deepEqual(call.options.env, childEnvironment());
    assert(!JSON.stringify(call).includes('BEGIN PRIVATE KEY'));
    assert(!JSON.stringify(call).includes('.local-auth'));
  }
  assert(!JSON.stringify(f.logs).includes('PRIVATE KEY'));
  assert.equal(mode(join(f.stand, 'scan-jwt')), 0o000);
  assert(!fs.existsSync(join(f.stand, '.cve-setup.lock')));
  assert(!fs.existsSync(join(f.stand, '.cve.json.pending')));
});

test('an existing matching pair is validated and reused, never regenerated', async t => {
  const f = fixture(t); installPair(f);
  const before = fs.readFileSync(join(f.trust, 'db-signing-key.pem'));
  await f.setup({ generatePair: () => { throw Error('must not generate'); } });
  assert.deepEqual(fs.readFileSync(join(f.trust, 'db-signing-key.pem')), before);
});

test('existing activation is never overwritten, even if same release; no children or key generation', async t => {
  const f = fixture(t); await f.setup();
  const before = fs.readFileSync(join(f.stand, 'cve.json'));
  f.calls.length = 0;
  await assert.rejects(f.setup({ generatePair: () => { throw Error('must not generate'); } }), refused);
  assert.equal(f.calls.length, 0);
  assert.deepEqual(fs.readFileSync(join(f.stand, 'cve.json')), before);
});

test('partial, mismatched, unsafe, oversized, symlink and hardlink keys refuse without child invocation', async t => {
  for (const scenario of ['partial-private', 'partial-public', 'mismatch', 'private-mode', 'public-mode', 'oversized', 'symlink', 'hardlink', 'trust-link']) {
    await t.test(scenario, async t => {
      const f = fixture(t); installPair(f);
      const priv = join(f.trust, 'db-signing-key.pem'), pub = join(f.trust, 'db-signing-key.pub.pem');
      if (scenario === 'partial-private') fs.unlinkSync(pub);
      if (scenario === 'partial-public') fs.unlinkSync(priv);
      if (scenario === 'mismatch') {
        fs.chmodSync(pub, 0o600);
        fs.writeFileSync(pub, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
        fs.chmodSync(pub, 0o444);
      }
      if (scenario === 'private-mode') fs.chmodSync(priv, 0o644);
      if (scenario === 'public-mode') fs.chmodSync(pub, 0o644);
      if (scenario === 'oversized') fs.writeFileSync(priv, 'x'.repeat(8193));
      if (scenario === 'symlink') { fs.renameSync(priv, join(f.stand, 'outside')); fs.symlinkSync(join(f.stand, 'outside'), priv); }
      if (scenario === 'hardlink') fs.linkSync(priv, join(f.stand, 'outside'));
      if (scenario === 'trust-link') { fs.renameSync(f.trust, join(f.stand, 'outside')); fs.symlinkSync(join(f.stand, 'outside'), f.trust); }
      await assert.rejects(f.setup(), refused);
      assert.equal(f.calls.length, 0);
      assert(!fs.existsSync(join(f.stand, 'cve.json')));
    });
  }
});

test('strict public arguments reject traversal, duplicates and ambient-only pins before children or keys', async t => {
  const f = fixture(t);
  for (const argv of [[], [...f.argv, '--db', 'b'.repeat(64)], ['--release', '../escape', ...f.argv.slice(2)],
    ['--release', 'a/b', ...f.argv.slice(2)], ['--release', 'synthetic\n', ...f.argv.slice(2)],
    [...f.argv.slice(0, -1), f.argv.at(-1) + '\n'],
    [...f.argv.slice(0, 2), '--bundle', manifest, ...f.argv.slice(4)]]) {
    assert.throws(() => parseSetupArguments(argv), refused);
    await assert.rejects(setupLocalCve(argv, { root: f.root, run: f.run }), refused);
  }
  assert.equal(f.calls.length, 0);
  assert(!fs.existsSync(f.trust));
  assert.deepEqual(Object.keys(childEnvironment()).sort(), ['LANG', 'PATH', 'TZ']);
});

test('foreign release files, symlinks, preexisting signatures and stale setup locks refuse', async t => {
  for (const scenario of ['extra', 'release-link', 'db-link', 'signature', 'lock', 'pending']) {
    await t.test(scenario, async t => {
      const f = fixture(t);
      if (scenario === 'extra') fs.writeFileSync(join(f.release, 'unexpected.pem'), 'not allowed');
      if (scenario === 'signature') fs.writeFileSync(join(f.release, 'descriptor.sig'), Buffer.alloc(64));
      if (scenario === 'lock') fs.mkdirSync(join(f.stand, '.cve-setup.lock'));
      if (scenario === 'pending') fs.writeFileSync(join(f.stand, '.cve.json.pending'), '{}');
      if (scenario === 'release-link') {
        fs.renameSync(f.release, join(f.stand, 'outside')); fs.symlinkSync(join(f.stand, 'outside'), f.release);
      }
      if (scenario === 'db-link') {
        fs.renameSync(join(f.release, 'db'), join(f.stand, 'outside')); fs.symlinkSync(join(f.stand, 'outside'), join(f.release, 'db'));
      }
      await assert.rejects(f.setup(), refused);
      assert.equal(f.calls.length, 0);
    });
  }
});

test('child failure is sanitized, preserves new keys and never publishes activation', async t => {
  for (const stage of [1, 2]) {
    const f = fixture(t); let calls = 0;
    await assert.rejects(f.setup({ run: async (...args) => {
      if (++calls === stage) throw Error('PRIVATE RAW ERROR /protected/path');
      return f.run(...args);
    } }), error => {
      assert.match(error.message, refused);
      assert(!error.message.includes('PRIVATE RAW'));
      assert.equal(error.cause, undefined);
      return true;
    });
    assert(fs.existsSync(join(f.trust, 'db-signing-key.pem')));
    assert(!fs.existsSync(join(f.stand, 'cve.json')));
    assert(!fs.existsSync(join(f.stand, '.cve-setup.lock')));
  }
});

test('public activation loader rejects alternate serialization, extra fields, wrong hash and writable release', async t => {
  const f = fixture(t), activation = await f.setup(), config = join(f.stand, 'cve.json');
  for (const bytes of [JSON.stringify(activation) + '\n', JSON.stringify({ ...activation, extra: true }),
    JSON.stringify({ ...activation, publicKeySha256: '0'.repeat(64) }), JSON.stringify({ ...activation, release: 'db-releases/../trust' })]) {
    fs.writeFileSync(config, bytes);
    assert.throws(() => loadCveActivation(f.root), refused);
  }
  fs.writeFileSync(config, JSON.stringify(activation));
  fs.chmodSync(f.release, 0o755);
  assert.throws(() => loadCveActivation(f.root), refused);
});

test('real backend verifier rejects substituted anchor, DB pins, signature and metadata with fixed errors', async t => {
  const f = fixture(t); await f.setup();
  const args = f.calls[1].args.slice(3);
  const result = await verifyLocalCve(args);
  assert.equal(result.scannerChecked, false);
  assert.equal(result.dbPolicy.policy, 'cve-db-updated-at-14d-v2');
  for (const flag of ['--public-key-sha256', '--db', '--bundle', '--manifest']) {
    const changed = [...args]; changed[changed.indexOf(flag) + 1] = flag === '--manifest' ? `sha256:${'0'.repeat(64)}` : '0'.repeat(64);
    await assert.rejects(verifyLocalCve(changed), { message: 'LOCAL CVE release verification failed' });
  }
  for (const name of ['descriptor.sig', 'db/metadata.json', 'db/trivy.db', 'bundle.bin']) {
    const path = join(f.release, name), original = fs.readFileSync(path);
    fs.chmodSync(path, 0o600); fs.writeFileSync(path, Buffer.alloc(original.length, 1));
    await assert.rejects(verifyLocalCve(args), { message: 'LOCAL CVE release verification failed' });
    fs.writeFileSync(path, original); fs.chmodSync(path, 0o444);
  }
  assert.throws(() => parseVerifyArguments([...args, '--db', '0'.repeat(64)]));
});
