import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { bridgeFixture } from './public-cve-bridge-fixtures.mjs';
import { publicImageCveConfig } from './public-image-stand-profile.mjs';
import { cveOverlay, readProfile, publicImageStand } from './public-image-stand.mjs';
import { preparePublicCve, publicCveProvision, loadMigrationPlan } from './public-cve-provision.mjs';
const hash = (b) => createHash('sha256').update(b).digest('hex');
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
