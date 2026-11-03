import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { bridgeFixture } from './public-cve-bridge-fixtures.mjs';
import { publicImageCveConfig } from './public-image-stand-profile.mjs';
import { cveOverlay, readProfile, publicImageStand } from './public-image-stand.mjs';
import { preparePublicCve, publicCveProvision, loadMigrationPlan, stream } from './public-cve-provision.mjs';
const hash = (b) => createHash('sha256').update(b).digest('hex');
const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
function cloneFixture(t) {
  const f = bridgeFixture(t), source = join(f.stand, f.current.release, 'bundle.bin'), destination = join(f.root, 'clone.bin');
  const copies = [];
  // Simulate the clone syscall with tiny fixture bytes; this is not native APFS qualification.
  const io = { ...fs, copyFileSync: (s, d, flags) => {
    copies.push(flags);
    assert.equal(flags, fs.constants.COPYFILE_EXCL | fs.constants.COPYFILE_FICLONE_FORCE);
    fs.copyFileSync(s, d, fs.constants.COPYFILE_EXCL);
  } };
  return { source, destination, copies, io };
}
function legacy(t) {
  const f = bridgeFixture(t),
    old = join(f.root, '.local-stand');
  fs.unlinkSync(old);
  fs.mkdirSync(old, { mode: 0o700 });
  fs.mkdirSync(join(old, 'db-releases'), { mode: 0o700 });
  fs.mkdirSync(join(old, 'trust'), { mode: 0o700 });
  fs.cpSync(join(f.stand, f.current.release), join(old, f.current.release), { recursive: true });
  fs.copyFileSync(
    join(f.stand, 'trust', `${f.current.publicKeySha256}.pub.pem`),
    join(old, 'trust/db-signing-key.pub.pem'),
  );
  fs.chmodSync(join(old, 'trust/db-signing-key.pub.pem'), 0o444);
  fs.symlinkSync('/forbidden-old-private-key', join(old, 'trust/db-signing-key.pem'));
  fs.writeFileSync(
    join(f.stand, 'profile.json'),
    JSON.stringify({ version: 1, project: 'dip-public-images', cve: f.current }),
    { mode: 0o600 },
  );
  const cve = publicImageCveConfig(f.root, f.current, 1);
  fs.writeFileSync(join(f.stand, 'compose.cve.json'), JSON.stringify(cveOverlay(cve)), { mode: 0o600 });
  for (const c of f.containers)
    for (const m of [...c.HostConfig.Mounts, ...c.Mounts]) {
      if (m.Type !== 'bind') continue;
      if (m.Source.includes('/trust/')) m.Source = cve.publicKeyPath;
      else m.Source = m.Source.replace(f.stand, old);
    }
  for (const name of ['refresh-signing-key.pem', 'refresh-signing-key.pub.pem', 'refresh-signer.json'])
    fs.unlinkSync(join(f.stand, 'trust', name));
  return f;
}

test('prepare copies exact signed bytes and creates dedicated signer without old private-key/activation/JWT access or lifecycle', async (t) => {
  const f = legacy(t),
    profile = f.read('profile.json'),
    jwt = f.read('scan-jwt');
  const oldDescriptor = fs.readFileSync(join(f.root, '.local-stand', f.current.release, 'descriptor.json'));
  const result = await preparePublicCve({ root: f.root, run: f.run, log: () => {} });
  assert.equal(result.outcome, 'prepared');
  assert.equal(f.read('profile.json'), profile);
  assert.equal(f.read('scan-jwt'), jwt);
  assert.equal(
    f.calls.some((c) => c.kind === 'docker'),
    false,
  );
  assert.equal(
    f.calls.some((c) => c.args[0]?.endsWith('sign-offline-db.mjs')),
    false,
  );
  assert.deepEqual(fs.readFileSync(join(f.stand, f.current.release, 'descriptor.json')), oldDescriptor);
  const signer = JSON.parse(f.read('trust/refresh-signer.json'));
  assert.notEqual(signer.publicKeySha256, f.current.publicKeySha256);
  assert.equal(fs.statSync(join(f.stand, 'trust/refresh-signing-key.pem')).mode & 0o777, 0o600);
  assert.equal(loadMigrationPlan(f.root, result.id).candidate.manifestDigest, f.current.manifestDigest);
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
});

test('explicit prepared migration uses DEFAULT bridge and same signed bytes, then fresh refresh rotates only future trust', async (t) => {
  const f = legacy(t),
    source = join(f.root, '.local-stand', f.current.release);
  const digest = hash(fs.readFileSync(join(source, 'descriptor.sig')));
  const prepared = await preparePublicCve({ root: f.root, run: f.run, log: () => {} });
  const options = { ...f.options, integration: undefined, docker: f.bridgeDocker };
  const result = await publicCveProvision(['migrate', '--prepared', prepared.id], options);
  assert.equal(result.outcome, 'activated');
  assert.equal(readProfile(f.root).version, 2);
  assert.equal(readProfile(f.root).cve.publicKeySha256, f.current.publicKeySha256);
  assert.equal(hash(fs.readFileSync(join(source, 'descriptor.sig'))), digest);
  assert.equal(
    f.calls.some((c) => c.args[0]?.endsWith('fetch-db-layer.mjs')),
    false,
  );
  assert.equal(
    f.calls.some((c) => c.args[0]?.endsWith('sign-offline-db.mjs')),
    false,
  );
  assert.equal(
    (await f.refresh([], { integration: undefined, docker: f.bridgeDocker })).outcome,
    'activated',
  );
  assert.equal(
    readProfile(f.root).cve.publicKeySha256,
    JSON.parse(f.read('trust/refresh-signer.json')).publicKeySha256,
  );
  assert.notEqual(readProfile(f.root).cve.publicKeySha256, f.current.publicKeySha256);
  assert.equal(hash(fs.readFileSync(join(source, 'descriptor.sig'))), digest);
  // Existing launcher status uses v2 public paths; no fallback to legacy assets.
  await publicImageStand(['status'], {
    root: f.root,
    run: (args, options) => f.bridgeDocker(args, { ...options, timeout: options.timeout ?? 30000 }),
    log: () => {},
  });
});

test('clone guard macOS uses force-clone/exclusive, exact bytes, separate single-link inode, immutable source and fsync', t => {
  const f = cloneFixture(t), before = stamp(fs.lstatSync(f.source));
  let synced = 0;
  const result = stream(f.source, 1024 ** 2, f.destination, { platform: 'darwin', io: { ...f.io,
    fsyncSync: fd => { synced++; fs.fsyncSync(fd); }, writeSync: () => { throw Error('no streaming fallback'); },
  } });
  assert.equal(result.sha256, hash(fs.readFileSync(f.destination)));
  assert.deepEqual(fs.readFileSync(f.source), fs.readFileSync(f.destination));
  assert.deepEqual(stamp(fs.lstatSync(f.source)), before);
  assert.notEqual(fs.lstatSync(f.source).ino, fs.lstatSync(f.destination).ino);
  assert.equal(fs.lstatSync(f.destination).nlink, 1);
  assert.equal(fs.lstatSync(f.destination).mode & 0o777, 0o444);
  assert.equal(f.copies.length, 1); assert.equal(synced, 1);
});

test('clone guard macOS clone refusal never falls back, overwrites or cleans retained evidence', async t => {
  for (const code of ['ENOTSUP', 'EXDEV', 'ENOSPC']) await t.test(code, t => {
    const f = cloneFixture(t), before = stamp(fs.lstatSync(f.source));
    let copies = 0;
    assert.throws(() => stream(f.source, 1024 ** 2, f.destination, { platform: 'darwin', io: { ...f.io,
      copyFileSync: () => { copies++; throw Object.assign(Error('synthetic clone refusal'), { code }); },
      writeSync: () => { throw Error('no fallback'); },
    } }), { code });
    assert.equal(copies, 1); assert(!fs.existsSync(f.destination));
    assert.deepEqual(stamp(fs.lstatSync(f.source)), before);
  });
});

test('clone guard rejects destination races and existing symlinks without touching their bytes', async t => {
  for (const kind of ['race', 'symlink']) await t.test(kind, t => {
    const f = cloneFixture(t), other = join(f.destination + '-other');
    fs.writeFileSync(other, 'unrelated');
    if (kind === 'symlink') fs.symlinkSync(other, f.destination);
    assert.throws(() => stream(f.source, 1024 ** 2, f.destination, { platform: 'darwin', io: { ...f.io,
      copyFileSync: (s, d, flags) => {
        if (kind === 'race') fs.writeFileSync(d, 'racing owner', { flag: 'wx' });
        f.io.copyFileSync(s, d, flags);
      },
    } }), { code: 'EEXIST' });
    assert.equal(fs.readFileSync(other, 'utf8'), 'unrelated');
    if (kind === 'race') assert.equal(fs.readFileSync(f.destination, 'utf8'), 'racing owner');
    else assert(fs.lstatSync(f.destination).isSymbolicLink());
  });
});

test('clone guard rejects corrupt clones, hardlinks, symlinks, source drift and late destination replacement', async t => {
  for (const fault of ['corrupt', 'hardlink', 'symlink', 'source-drift', 'destination-replaced', 'wrong-mode']) await t.test(fault, t => {
    const f = cloneFixture(t);
    const io = { ...f.io, copyFileSync: (s, d, flags) => {
      if (fault === 'hardlink') return fs.linkSync(s, d);
      if (fault === 'symlink') return fs.symlinkSync(s, d);
      f.io.copyFileSync(s, d, flags);
      if (fault === 'corrupt') { fs.chmodSync(d, 0o600); fs.writeFileSync(d, Buffer.alloc(fs.statSync(d).size)); fs.chmodSync(d, 0o444); }
      if (fault === 'wrong-mode') fs.chmodSync(d, 0o600);
      if (fault === 'source-drift') { fs.chmodSync(s, 0o600); fs.chmodSync(s, 0o444); }
    }, fsyncSync: fd => {
      fs.fsyncSync(fd);
      if (fault === 'destination-replaced') { fs.unlinkSync(f.destination); fs.writeFileSync(f.destination, 'replacement', { mode: 0o444 }); }
    } };
    assert.throws(() => stream(f.source, 1024 ** 2, f.destination, { platform: 'darwin', io }), /refused\/HOLD/);
    assert(fs.lstatSync(f.destination)); // Never unlink an uncertain clone/foreign replacement.
  });
});

test('clone guard rejects linked sources and preserves Linux exclusive streaming copy behavior', t => {
  const f = cloneFixture(t);
  const options = { platform: 'linux', io: { ...fs, copyFileSync: () => { throw Error('Linux must retain streaming copy'); } } };
  stream(f.source, 1024 ** 2, f.destination, options);
  assert.deepEqual(fs.readFileSync(f.source), fs.readFileSync(f.destination));
  assert.equal(fs.statSync(f.destination).nlink, 1);
  assert.equal(fs.statSync(f.destination).mode & 0o777, 0o444);
  assert.throws(() => stream(f.source, 1024 ** 2, f.destination, options), { code: 'EEXIST' });
  const link = f.destination + '-link'; fs.linkSync(f.source, link);
  assert.throws(() => stream(f.source, 1024 ** 2, undefined, { platform: 'darwin' }), /refused\/HOLD/);
  fs.unlinkSync(link);
  fs.symlinkSync(f.source, link);
  assert.throws(() => stream(link, 1024 ** 2, undefined, { platform: 'darwin' }), /refused\/HOLD/);
});

test('provision growth guard allows exact existing target at three releases but refuses a fourth allocation', async t => {
  for (const existing of [true, false]) await t.test(String(existing), async t => {
    const f = legacy(t), releases = join(f.stand, 'db-releases'), target = join(f.stand, f.current.release);
    if (!existing) fs.renameSync(target, join(releases, 'retained'));
    fs.mkdirSync(join(releases, 'previous')); fs.mkdirSync(join(releases, 'incoming'));
    const original = f.read('profile.json');
    if (existing) assert.equal((await preparePublicCve({ root: f.root, run: f.run, log: () => {} })).outcome, 'prepared');
    else {
      await assert.rejects(preparePublicCve({ root: f.root, run: f.run, log: () => {} }), /refused\/HOLD/);
      assert(!fs.existsSync(target)); assert(fs.existsSync(join(f.stand, '.operation.lock', 'provision.json')));
    }
    assert.equal(fs.readdirSync(releases).length, 3); assert.equal(f.read('profile.json'), original);
    assert(!f.calls.some(c => c.kind === 'docker'));
  });
});

test('unprepared or altered copy cannot authorize migration or submit lifecycle', async (t) => {
  const f = legacy(t);
  await assert.rejects(
    publicCveProvision(['migrate', '--prepared', 'a'.repeat(32)], {
      ...f.options,
      integration: undefined,
      docker: f.bridgeDocker,
    }),
  );
  assert.equal(
    f.calls.some((c) => c.kind === 'docker'),
    false,
  );
  const p = await preparePublicCve({ root: f.root, run: f.run, log: () => {} });
  const file = join(f.stand, f.current.release, 'descriptor.sig');
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, Buffer.alloc(64));
  fs.chmodSync(file, 0o444);
  await assert.rejects(
    publicCveProvision(['migrate', '--prepared', p.id], {
      ...f.options,
      integration: undefined,
      docker: f.bridgeDocker,
    }),
  );
  assert.equal(
    f.calls.some((c) => c.kind === 'docker'),
    false,
  );
});
