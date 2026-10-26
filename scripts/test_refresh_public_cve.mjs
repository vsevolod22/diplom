import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fixture, ROOT, oldManifest } from './public-refresh-cve-fixtures.mjs';
import {
  publicCveFailure,
  refreshPublicCve,
  disposeEmptyPublicCveStaging,
  loadPublicBinding,
  PUBLIC_DRAIN_PROBE,
  PUBLIC_READY_PROBE,
  PUBLIC_WEB_PROBE,
} from './refresh-public-cve.mjs';
import { PROJECT } from './public-image-stand.mjs';
import { checkDisk } from './refresh-local-cve.mjs';
import { runChild } from './setup-local-cve.mjs';
test('Engine materialized mount ordering is not authority drift or a false HOLD', async (t) => {
  const f = fixture(t);
  let reordered = false;
  f.beforeDocker = (args) => {
    if (!reordered && args[0] === 'container' && args[1] === 'stop') {
      f.containers.find((c) => c.Name === '/dip-public-images-api-1').Mounts.reverse();
      reordered = true;
    }
  };
  assert.equal((await f.refresh()).outcome, 'activated');
  assert(reordered);
});

const mutations = (f) =>
  f.calls.filter(
    (c) => c.kind === 'docker' && (['stop', 'start'].includes(c.args[1]) || c.args.includes('up')),
  );
const lock = (f) => join(f.stand, '.operation.lock');
const noLock = (f) => assert.equal(fs.existsSync(lock(f)), false);
const refusal = (phase, hold) => (error) => {
  assert.equal(publicCveFailure(error).phase, phase);
  assert.equal(publicCveFailure(error).hold, hold);
  for (const key of ['cause', 'args', 'stdout', 'stderr', 'env'])
    assert.equal(Object.hasOwn(error, key), false);
  assert.doesNotMatch(error.message, /PRIVATE-SYNTHETIC|private snapshot|ab{10}/);
  return true;
};

test('invalid CLI/unprovisioned root refuse before network/process execution', async () => {
  await assert.rejects(
    refreshPublicCve([], { root: '/nonexistent', run: () => assert.fail(), docker: () => assert.fail() }),
    refusal('preflight', false),
  );
  const r = spawnSync(process.execPath, ['scripts/refresh-public-cve.mjs', '--invalid'], {
    cwd: ROOT,
    env: {},
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(r.status, 1);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /PUBLIC CVE refresh refused/);
});

test('unchanged uses real signature/hash/freshness verifier, no Docker/private key read or signing', async (t) => {
  const f = fixture(t);
  f.discover = oldManifest;
  fs.unlinkSync(join(f.stand, 'trust/refresh-signing-key.pem'));
  const result = await f.refresh();
  assert.equal(result.outcome, 'unchanged');
  noLock(f);
  assert.equal(
    f.calls.some((c) => c.kind === 'docker' || c.args[0]?.endsWith('sign-offline-db.mjs')),
    false,
  );
});

test('authenticated candidate stages/freeze without Docker; staged release reused and reauthenticated', async (t) => {
  const f = fixture(t),
    before = f.read('profile.json'),
    trust = f.read('trust/refresh-signing-key.pub.pem');
  assert.equal((await f.refresh(['--stage-only'])).outcome, 'staged');
  noLock(f);
  assert.equal(f.read('profile.json'), before);
  assert.equal(f.read('trust/refresh-signing-key.pub.pem'), trust);
  const dir = join(f.stand, 'db-releases', f.manifest.slice(7));
  assert.equal(fs.statSync(dir).mode & 0o777, 0o555);
  assert.equal(fs.statSync(join(dir, 'db/trivy.db')).mode & 0o777, 0o444);
  assert.equal(
    f.calls.some((c) => c.kind === 'docker'),
    false,
  );
  const signs = f.calls.filter((c) => c.args[0]?.endsWith('sign-offline-db.mjs')).length;
  await f.refresh(['--stage-only']);
  assert.equal(f.calls.filter((c) => c.args[0]?.endsWith('sign-offline-db.mjs')).length, signs);
});

test('full public workflow fences/drains/stops, preserves data contract, recreates worker then API with same pins only', async (t) => {
  const f = fixture(t),
    old = f.read('profile.json'),
    pins = f.read('compose.images.json'),
    jwt = f.read('scan-jwt');
  const result = await f.refresh();
  assert.deepEqual(result, { outcome: 'activated', manifest: f.manifest });
  noLock(f);
  assert.notEqual(f.read('profile.json'), old);
  assert.equal(f.read('compose.images.json'), pins);
  assert.equal(f.read('scan-jwt'), jwt);
  assert.equal(loadPublicBinding(f.root).current.manifestDigest, f.manifest);
  assert.equal(fs.existsSync(join(f.stand, 'db-releases/prior/bundle.bin')), true);
  assert.equal(f.captures, 1);
  assert.deepEqual(f.comparisons, ['before-api', 'after-api']);
  assert.deepEqual(
    mutations(f).map((c) => (c.args.includes('up') ? `up-${c.args.at(-1)}` : c.args[1])),
    ['stop', 'stop', 'stop', 'up-worker', 'up-api', 'start'],
  );
  assert(f.calls.some((c) => c.args.at(-1) === PUBLIC_WEB_PROBE));
  assert.doesNotMatch(f.logs.join('\n'), /ab{10}|PRIVATE|\.local-stand/);
});

for (const condition of ['absent', 'stopped', 'paused'])
  test(`new release ${condition} stand stays deferred and stopped`, async (t) => {
    const f = fixture(t),
      prior = f.read('profile.json');
    if (condition === 'absent') {
      f.containers = [];
      f.volumes = [];
      f.networks = [];
    } else {
      const w = f.containers.find((c) => c.Name.includes('-worker-'));
      w.State[condition === 'paused' ? 'Paused' : 'Running'] = condition === 'paused';
      if (condition === 'stopped') w.State.Status = 'exited';
    }
    assert.equal((await f.refresh()).outcome, 'deferred-stopped');
    assert.equal(f.read('profile.json'), prior);
    assert.equal(mutations(f).length, 0);
    noLock(f);
  });

for (const counts of [
  { jobs: 1, outbox: 0, leases: 0 },
  { jobs: 0, outbox: 1, leases: 0 },
  { jobs: 0, outbox: 0, leases: 1 },
]) {
  test(`busy drain ${Object.keys(counts).find((k) => counts[k])}: resumes only same API/web without changing activation`, async (t) => {
    const f = fixture(t),
      prior = f.read('profile.json');
    f.pending.push(counts);
    assert.equal((await f.refresh([], { drainMs: 0 })).outcome, 'deferred-busy');
    noLock(f);
    assert.equal(f.read('profile.json'), prior);
    assert.deepEqual(
      mutations(f).map((c) => c.args[1]),
      ['stop', 'stop', 'start', 'start'],
    );
  });
}
for (const bad of [{ pending: 0 }, { jobs: 0, outbox: -1, leases: 0 }, { jobs: 0, outbox: 0, leases: '0' }]) {
  test('malformed drain receipt leaves sticky HOLD and does not resume/recreate', async (t) => {
    const f = fixture(t);
    f.pending.push(bad);
    await assert.rejects(f.refresh(), refusal('drain', true));
    assert(fs.existsSync(join(lock(f), 'mutation.json')));
    assert.equal(mutations(f).length, 2);
    assert.equal(f.containers.find((c) => c.Name === `/${PROJECT}-web-1`).State.Running, false);
    await assert.rejects(f.refresh(), refusal('preflight', false));
    assert.equal(mutations(f).length, 2);
  });
}
for (const fail of ['stop', 'up-worker', 'up-api', 'capture', 'preservation', 'web'])
  test(`ambiguous ${fail} retains journal, no rollback or retry`, async (t) => {
    const f = fixture(t);
    f.fail = fail;
    await assert.rejects(f.refresh(), (error) => {
      assert.equal(publicCveFailure(error).hold, true);
      return true;
    });
    const journal = fs.readFileSync(join(lock(f), 'refresh.json'), 'utf8');
    assert.doesNotMatch(journal, /SCAN_JWT|ab{10}|PRIVATE|Env|HostConfig/);
    const n = mutations(f).length;
    await assert.rejects(f.refresh());
    assert.equal(mutations(f).length, n);
  });

for (const fail of ['download', 'prepare', 'sign', 'verify', 'config'])
  test(`pre-mutation ${fail} fails closed and retains prior release/binding`, async (t) => {
    const f = fixture(t),
      prior = f.read('profile.json');
    f.fail = fail;
    await assert.rejects(f.refresh());
    assert.equal(mutations(f).length, 0);
    assert.equal(f.read('profile.json'), prior);
    noLock(f);
    assert(fs.existsSync(join(f.stand, 'db-releases/prior/descriptor.sig')));
  });
for (const age of [15 * 86400_000, 3 * 3600_000])
  test(`candidate stale/rollback age ${age} rejected before Docker`, async (t) => {
    const f = fixture(t);
    f.age = age;
    await assert.rejects(f.refresh(['--stage-only']));
    assert.equal(
      f.calls.some((c) => c.kind === 'docker'),
      false,
    );
    noLock(f);
  });
for (const name of ['descriptor.sig', 'bundle.bin', 'db/trivy.db', 'db/metadata.json'])
  test(`tampered ${name} in unchanged release is rejected by real backend`, async (t) => {
    const f = fixture(t);
    f.discover = oldManifest;
    const p = join(f.stand, 'db-releases/prior', name);
    fs.chmodSync(p, 0o600);
    fs.writeFileSync(p, 'tampered');
    fs.chmodSync(p, 0o444);
    await assert.rejects(f.refresh());
    assert.equal(
      f.calls.some((c) => c.kind === 'docker'),
      false,
    );
    noLock(f);
  });

test('v1 LOCAL-backed public profile refuses before opening any LOCAL binding', async (t) => {
  const f = fixture(t),
    p = join(f.stand, 'profile.json'),
    v = JSON.parse(f.read('profile.json'));
  v.version = 1;
  fs.writeFileSync(p, JSON.stringify(v), { mode: 0o600 });
  await assert.rejects(f.refresh(), refusal('preflight', false));
  assert.equal(f.calls.length, 0);
  noLock(f);
});
for (const mode of ['missing', 'wrong'])
  test(`existing-only public signing key ${mode} never generated/rotated`, async (t) => {
    const f = fixture(t),
      p = join(f.stand, 'trust/refresh-signing-key.pem');
    if (mode === 'missing') fs.unlinkSync(p);
    else fs.writeFileSync(p, 'not a key');
    await assert.rejects(f.refresh(), refusal('sign', false));
    noLock(f);
    assert.equal(
      f.calls.some((c) => c.args[0]?.endsWith('sign-offline-db.mjs')),
      false,
    );
  });

test('remote endpoint rejected with no lifecycle calls', async (t) => {
  const f = fixture(t);
  f.endpoint = 'tcp://untrusted.invalid:2375';
  await assert.rejects(f.refresh(), refusal('namespace', false));
  assert.equal(mutations(f).length, 0);
  noLock(f);
});
for (const drift of ['command', 'memory', 'swap', 'tmpfs', 'mount', 'jwt', 'pin'])
  test(`runtime ${drift} drift is rejected before admission fence`, async (t) => {
    const f = fixture(t),
      w = f.containers.find((c) => c.Name.includes('-worker-')),
      a = f.containers.find((c) => c.Name.includes('-api-'));
    if (drift === 'command')
      w.Config.Cmd = ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'];
    if (drift === 'memory') w.HostConfig.Memory = 1073741824;
    if (drift === 'swap') w.HostConfig.MemorySwap *= 2;
    if (drift === 'tmpfs') w.HostConfig.Tmpfs['/tmp/trivy'] = 'rw,size=512m';
    if (drift === 'mount') w.Mounts.find((m) => m.Destination === '/tmp/trivy/db').RW = true;
    if (drift === 'jwt')
      a.Config.Env = a.Config.Env.map((e) =>
        e.startsWith('SCAN_JWT_SECRET=') ? `SCAN_JWT_SECRET=${'cd'.repeat(48)}` : e,
      );
    if (drift === 'pin') w.Config.Image = `${PROJECT}-worker:local`;
    await assert.rejects(f.refresh(), refusal('namespace', false));
    assert.equal(mutations(f).length, 0);
    noLock(f);
  });

test('off-allowlist project census never follows foreign name to inspect', async (t) => {
  const f = fixture(t);
  f.extraCensus = { container: [`dip-local-full-api-1\t${PROJECT}`] };
  await assert.rejects(f.refresh());
  assert.equal(mutations(f).length, 0);
  assert(
    !f.calls.some(
      (c) => c.kind === 'docker' && c.args[1] === 'inspect' && c.args[2] === 'dip-local-full-api-1',
    ),
  );
});

test('candidate writable/wrong cache binding refuses BEFORE readiness exec/API recreate', async (t) => {
  const f = fixture(t);
  let changed = false;
  f.beforeDocker = (args) => {
    if (
      !changed &&
      args[0] === 'container' &&
      args[1] === 'inspect' &&
      args[2] === `${PROJECT}-worker-1` &&
      mutations(f).some((c) => c.args.includes('up'))
    ) {
      f.containers
        .find((c) => c.Name.includes('-worker-'))
        .Mounts.find((m) => m.Destination === '/tmp/trivy/db').RW = true;
      changed = true;
    }
  };
  await assert.rejects(f.refresh());
  assert.equal(publicCveFailure(await f.refresh().catch((e) => e)).hold, false);
  assert(!f.calls.some((c) => c.args.at(-1) === PUBLIC_READY_PROBE));
  assert(!mutations(f).some((c) => c.args.includes('up') && c.args.at(-1) === 'api'));
});

test('profile replacement after first mutation keeps HOLD and no second submission', async (t) => {
  const f = fixture(t);
  let changed = false;
  f.beforeDocker = (args) => {
    if (!changed && args[1] === 'stop') {
      const p = join(f.stand, 'profile.json'),
        bytes = f.read('profile.json');
      fs.renameSync(p, p + '.original');
      fs.writeFileSync(p, bytes, { mode: 0o600 });
      changed = true;
    }
  };
  await assert.rejects(f.refresh());
  assert(fs.existsSync(join(lock(f), 'mutation.json')));
  assert.equal(mutations(f).length, 1);
});

test('public disk budget stops before download; no active or retained release is pruned', async (t) => {
  const f = fixture(t),
    prior = f.read('profile.json');
  for (let i = 0; i < 7; i++) fs.mkdirSync(join(f.stand, 'db-releases', `retained-${i}`), { mode: 0o700 });
  await assert.rejects(f.refresh([], { diskCheck: checkDisk }), refusal('staging', false));
  assert.equal(fs.readdirSync(join(f.stand, 'db-releases')).length, 8);
  assert.equal(f.read('profile.json'), prior);
  assert(!f.calls.some((c) => c.args[0]?.endsWith('fetch-db-layer.mjs') && c.args[1] !== 'discover'));
  noLock(f);
});
test('interrupted workspace is neither adopted nor deleted by next attempt', async (t) => {
  const f = fixture(t),
    work = join(f.stand, '.cve-refresh-work');
  fs.mkdirSync(work, { mode: 0o700 });
  fs.writeFileSync(join(work, 'retained'), 'retained', { mode: 0o600 });
  await assert.rejects(f.refresh(), refusal('preflight', false));
  assert.equal(f.calls.length, 0);
  assert.equal(fs.readFileSync(join(work, 'retained'), 'utf8'), 'retained');
  noLock(f);
});
test('signed old baseline cannot be forged to bypass monotonic updatedAt', async (t) => {
  const f = fixture(t),
    p = join(f.stand, 'db-releases/prior/descriptor.json');
  const d = JSON.parse(fs.readFileSync(p));
  d.updatedAt = '1970-01-01T00:00:00.000Z';
  fs.chmodSync(p, 0o600);
  fs.writeFileSync(p, JSON.stringify(d));
  fs.chmodSync(p, 0o444);
  await assert.rejects(f.refresh(), refusal('preflight', false));
  assert.equal(f.calls.length, 0);
  noLock(f);
});
test("public shared lock replacement never deletes another owner's directory or intent", async (t) => {
  const f = fixture(t);
  let changed = false;
  f.beforeDocker = (args) => {
    if (!changed && args[1] === 'stop') {
      const path = lock(f);
      fs.renameSync(path, path + '.original');
      fs.mkdirSync(path, { mode: 0o700 });
      fs.writeFileSync(join(path, 'foreign'), 'untouched', { mode: 0o600 });
      changed = true;
    }
  };
  await assert.rejects(f.refresh());
  assert.equal(fs.readFileSync(join(lock(f), 'foreign'), 'utf8'), 'untouched');
  assert(fs.existsSync(join(f.stand, '.operation.lock.original/mutation.json')));
  assert.equal(mutations(f).length, 1);
});
test('public drain SQL executes readonly schema15; accounts/report data and DB schema are unchanged', () => {
  const require = createRequire(join(ROOT, 'server/api/package.json')),
    DB = require('better-sqlite3');
  // Serialized runtime program is executed against an isolated memory DB via an
  // injected constructor, so no /data or live ledger path can be opened.
  const db = new DB(':memory:');
  db.exec(
    'CREATE TABLE scans(state TEXT); CREATE TABLE outbox(delivered_at TEXT,lease_until INTEGER,lease_token TEXT); PRAGMA user_version=15;',
  );
  db.exec("INSERT INTO scans VALUES ('cancelled');INSERT INTO outbox VALUES ('delivered',123,'leased');");
  const original = db.serialize(),
    output = [];
  const FakeDB = function (path, options) {
    assert.equal(path, '/data/ledger.sqlite');
    assert.equal(options.readonly, true);
    return new Proxy(db, {
      get(target, key) {
        if (key === 'close') return () => {};
        const value = target[key];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  };
  new Function('require', 'console', PUBLIC_DRAIN_PROBE)(() => FakeDB, {
    log: (raw) => output.push(JSON.parse(raw)),
  });
  assert.deepEqual(output, [{ jobs: 0, outbox: 0, leases: 1 }]);
  assert.deepEqual(db.serialize(), original);
  db.close();
  assert.doesNotMatch(PUBLIC_READY_PROBE, /localWorkerReady|nginx-local-profile/);
  assert.match(PUBLIC_READY_PROBE, /chainReady/);
  assert.match(PUBLIC_WEB_PROBE, /127\.0\.0\.1:8081/);
  assert.doesNotMatch(PUBLIC_WEB_PROBE, /:8080/);
});

const dispositionFiles = ['scripts/refresh-public-cve.mjs', 'scripts/refresh-local-cve.mjs', 'scripts/setup-local-cve.mjs', 'server/deploy/trust/fetch-db-layer.mjs'];
function emptyDispositionFixture(t) {
  const f = fixture(t);
  for (const name of dispositionFiles) {
    fs.mkdirSync(join(f.root, name.slice(0, name.lastIndexOf('/'))), { recursive: true });
    fs.copyFileSync(join(ROOT, name), join(f.root, name));
  }
  const work = join(f.stand, '.cve-refresh-work'); fs.mkdirSync(work, { mode: 0o700 });
  return { f, work, options: { root: f.root, integration: f.integration } };
}
test('empty staging disposition is a separate source/identity-bound review, then exclusive archive, never refresh', async t => {
  const { f, work, options } = emptyDispositionFixture(t), before = fs.lstatSync(work), profile = f.read('profile.json');
  const checked = await disposeEmptyPublicCveStaging(['--check-empty-staging'], options);
  assert.match(checked.review, /^[a-f0-9]{64}$/); assert.equal(checked.archived, false); assert.equal(checked.refreshAuthorized, false);
  noLock(f); assert(fs.existsSync(work)); assert(!fs.existsSync(join(f.stand, '.cve-refresh-archives')));
  const result = await disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', checked.review], options);
  assert.equal(result.outcome, 'empty-staging-archived-only'); assert.equal(result.priorFailureCause, 'UNKNOWN'); assert.equal(result.refreshSubmitted, false);
  const catalog = join(f.stand, '.cve-refresh-archives'), names = fs.readdirSync(catalog);
  assert.equal(names.length, 1); const archive = join(catalog, names[0]);
  assert.deepEqual(fs.readdirSync(archive).sort(), ['complete.json', 'intent.json', 'work']);
  assert.equal(fs.lstatSync(join(archive, 'work')).ino, before.ino); assert.deepEqual(fs.readdirSync(join(archive, 'work')), []);
  const receipt = JSON.parse(fs.readFileSync(join(archive, 'complete.json')));
  assert.equal(receipt.priorAttemptCertified, false); assert.equal(receipt.refreshSubmitted, false);
  assert.equal(receipt.priorFailureCause, 'UNKNOWN'); assert(!fs.existsSync(work)); noLock(f);
  assert.equal(f.read('profile.json'), profile); assert.equal(f.calls.length, 0);
  await assert.rejects(disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', checked.review], options));
  assert.deepEqual(fs.readdirSync(catalog), names); noLock(f);
});
for (const corruption of ['nonempty', 'symlink', 'unsafe-mode', 'pending', 'foreign-lock', 'llm-pending', 'overlap']) test('empty staging disposition refuses ' + corruption + ' without removal/adoption', async t => {
  const { f, work, options } = emptyDispositionFixture(t);
  if (corruption === 'nonempty') fs.writeFileSync(join(work, 'retained'), 'evidence');
  if (corruption === 'symlink') { fs.renameSync(work, work + '.original'); fs.symlinkSync(work + '.original', work); }
  if (corruption === 'unsafe-mode') fs.chmodSync(work, 0o755);
  if (corruption === 'pending') fs.writeFileSync(join(f.stand, '.profile.pending'), 'retained');
  if (corruption === 'foreign-lock') fs.mkdirSync(join(f.stand, '.unknown.lock'), { mode: 0o700 });
  if (corruption === 'llm-pending') fs.writeFileSync(join(f.stand, '.llm-pending-profile'), 'retained');
  if (corruption === 'overlap') { fs.mkdirSync(lock(f), { mode: 0o700 }); fs.writeFileSync(join(lock(f), 'foreign'), 'retained'); }
  await assert.rejects(disposeEmptyPublicCveStaging(['--check-empty-staging'], options));
  assert(fs.lstatSync(work)); assert(!fs.existsSync(join(f.stand, '.cve-refresh-archives'))); assert.equal(f.calls.length, 0);
  if (corruption === 'overlap') assert.equal(fs.readFileSync(join(lock(f), 'foreign'), 'utf8'), 'retained'); else noLock(f);
});
for (const drift of ['source', 'workspace-inode', 'stale-token']) test('archive review refuses ' + drift + ' before disposition intent', async t => {
  const { f, work, options } = emptyDispositionFixture(t);
  const checked = await disposeEmptyPublicCveStaging(['--check-empty-staging'], options);
  if (drift === 'source') fs.appendFileSync(join(f.root, dispositionFiles[0]), '\n// changed after review\n');
  if (drift === 'workspace-inode') { fs.renameSync(work, work + '.retained'); fs.mkdirSync(work, { mode: 0o700 }); }
  const review = drift === 'stale-token' ? '0'.repeat(64) : checked.review;
  await assert.rejects(disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', review], options));
  assert(fs.existsSync(work)); assert(!fs.existsSync(join(f.stand, '.cve-refresh-archives'))); noLock(f); assert.equal(f.calls.length, 0);
});
for (const drift of ['nonempty', 'lock-replacement', 'intent-change', 'source']) test('archive boundary ' + drift + ' preserves evidence and sticky owned intent on uncertainty', async t => {
  const { f, work, options } = emptyDispositionFixture(t);
  const checked = await disposeEmptyPublicCveStaging(['--check-empty-staging'], options);
  await assert.rejects(disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', checked.review], { ...options, onBeforeMove() {
    if (drift === 'nonempty') fs.writeFileSync(join(work, 'new-evidence'), 'retained');
    if (drift === 'source') fs.appendFileSync(join(f.root, dispositionFiles[1]), '\n// source drift\n');
    if (drift === 'intent-change') fs.writeFileSync(join(lock(f), 'empty-staging-intent.json'), 'foreign-evidence');
    if (drift === 'lock-replacement') { fs.renameSync(lock(f), lock(f) + '.original'); fs.mkdirSync(lock(f), { mode: 0o700 }); fs.writeFileSync(join(lock(f), 'foreign'), 'retained'); }
  } }), refusal('staging', true));
  assert(fs.existsSync(work)); assert(fs.existsSync(lock(f))); assert.equal(f.calls.length, 0);
  const intentRoot = drift === 'lock-replacement' ? lock(f) + '.original' : lock(f);
  assert(fs.existsSync(join(intentRoot, 'empty-staging-intent.json')));
  if (drift === 'lock-replacement') assert.equal(fs.readFileSync(join(lock(f), 'foreign'), 'utf8'), 'retained');
});
test('archive never overwrites an unexpected intent target, even after moving the original empty directory', async t => {
  const { f, work, options } = emptyDispositionFixture(t), original = fs.lstatSync(work);
  const checked = await disposeEmptyPublicCveStaging(['--check-empty-staging'], options);
  let archive;
  await assert.rejects(disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', checked.review], { ...options, onBeforeMove() {
    const catalog = join(f.stand, '.cve-refresh-archives'); archive = join(catalog, fs.readdirSync(catalog)[0]);
    fs.writeFileSync(join(archive, 'intent.json'), 'foreign-evidence', { flag: 'wx', mode: 0o600 });
  } }), refusal('staging', true));
  assert.equal(fs.readFileSync(join(archive, 'intent.json'), 'utf8'), 'foreign-evidence');
  assert.equal(fs.lstatSync(join(archive, 'work')).ino, original.ino);
  assert(fs.existsSync(join(lock(f), 'empty-staging-intent.json'))); assert.equal(f.calls.length, 0);
});
test('archive budget exhaustion preserves all earlier archives, without prune or new intent', async t => {
  const { f, work, options } = emptyDispositionFixture(t), catalog = join(f.stand, '.cve-refresh-archives');
  fs.mkdirSync(catalog, { mode: 0o700 });
  for (let i = 0; i < 16; i++) fs.mkdirSync(join(catalog, 'empty-' + i.toString(16).padStart(32, '0')), { mode: 0o700 });
  const checked = await disposeEmptyPublicCveStaging(['--check-empty-staging'], options);
  await assert.rejects(disposeEmptyPublicCveStaging(['--archive-empty-staging', '--review', checked.review], options));
  assert.equal(fs.readdirSync(catalog).length, 16); assert(fs.existsSync(work)); noLock(f); assert.equal(f.calls.length, 0);
});
test('ordinary refresh never auto-archives empty retained staging, and disposition CLI delegates no child or Docker work', async t => {
  const { f, work } = emptyDispositionFixture(t);
  await assert.rejects(f.refresh(), refusal('preflight', false)); assert(fs.existsSync(work));
  const result = await f.refresh(['--check-empty-staging']); assert.equal(result.archived, false);
  assert.equal(f.calls.length, 0); noLock(f);
});
test('public transport diagnostic survives the real child-adapter boundary, with no raw failure or evidence loss', async t => {
  const f = fixture(t), prior = f.read('profile.json');
  const receipt = 'CVE_TRANSPORT_FAILURE ' + JSON.stringify({ version: 1, boundary: 'blob-request', cause: 'HTTP_STATUS', status: 429 }) + '\n';
  const run = async (exe, args, options) => {
    if (args[0]?.endsWith('/fetch-db-layer.mjs') && args[1] !== 'discover') {
      return runChild(exe, args, options, (_exe, _args, _options, done) => done(Object.assign(Error('PRIVATE-SIGNED-URL'), { code: 1 }), '', receipt));
    }
    return f.run(exe, args, options);
  };
  await assert.rejects(f.refresh([], { run }), error => {
    const d = publicCveFailure(error); assert.equal(d.phase, 'download'); assert.equal(d.checkpoint, 'fetch');
    assert.equal(d.diagnostic.transport.boundary, 'blob-request'); assert.equal(d.diagnostic.transport.status, 429);
    assert.match(d.message, /HTTP_STATUS/); assert(!JSON.stringify(d).includes('PRIVATE')); assert(!Object.hasOwn(error, 'cause')); return true;
  });
  assert.equal(f.read('profile.json'), prior); assert.equal(mutations(f).length, 0); noLock(f);
  assert.deepEqual(fs.readdirSync(join(f.stand, '.cve-refresh-work')), []);
});
