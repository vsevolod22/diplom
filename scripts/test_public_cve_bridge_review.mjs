import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { bridgeFixture } from './public-cve-bridge-fixtures.mjs';
import { PROJECT, acquireLock } from './public-image-stand.mjs';
import { llmBridgeFixture } from './public-cve-bridge-llm-fixtures.mjs';
import { createPublicCveBridge } from './public-cve-bridge.mjs';
import { archiveCveBackup, preflightCveCapacity } from './public-cve-bridge-capacity.mjs';
const changed = (f) =>
  f.calls.filter(
    (c) =>
      c.kind === 'docker' &&
      (['stop', 'start'].includes(c.args[1]) || c.args.includes('up') || c.args[0] === 'create'),
  );

test('R1 real Docker default truncated projection must be requested --no-trunc', async (t) => {
  const f = bridgeFixture(t);
  assert.equal(
    (await f.refresh([], { integration: undefined, docker: f.bridgeDocker })).outcome,
    'activated',
  );
});
test('R2 four completed generations refuse BEFORE stopping admission', async (t) => {
  const f = bridgeFixture(t),
    parent = join(f.stand, 'cve-backups');
  fs.mkdirSync(parent, { mode: 0o700 });
  for (let i = 0; i < 4; i++) {
    const p = join(parent, 'refresh-' + String(i).repeat(32));
    fs.mkdirSync(p, { mode: 0o700 });
    fs.writeFileSync(
      join(p, 'complete.json'),
      JSON.stringify({ version: 1, project: PROJECT, preserved: true }),
      { mode: 0o600 },
    );
  }
  await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
  assert.deepEqual(changed(f), []);
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
});
test('R3 untrusted source indirection is refused before Compose can open it', async (t) => {
  const f = bridgeFixture(t),
    path = join(f.root, 'server/deploy/compose.public-images.yaml');
  const source = JSON.parse(fs.readFileSync(path));
  source.services.api.env_file = ['/forbidden/private.env'];
  fs.writeFileSync(path, JSON.stringify(source));
  await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
  assert(!f.calls.some((c) => c.kind === 'docker' && c.args[0] === 'compose'));
  assert.deepEqual(changed(f), []);
});
test('R4 web stays stopped through final preservation; same original ID resumes LAST', async (t) => {
  const f = bridgeFixture(t),
    id = f.containers.find((c) => c.Name === `/${PROJECT}-web-1`).Id;
  f.beforeDocker = () => {
    if (f.helperEvents.length && f.helperEvents.filter((e) => e === 'rm').length < 3)
      assert.equal(f.containers.find((c) => c.Id === id).State.Running, false);
  };
  assert.equal(
    (await f.refresh([], { integration: undefined, docker: f.bridgeDocker })).outcome,
    'activated',
  );
  const ops = changed(f);
  assert.equal(ops[0].args.at(-1), id);
  assert.equal(ops.at(-1).args[1], 'start');
  assert.equal(ops.at(-1).args.at(-1), id);
});

test('R4 final web health drift after same-ID resume cannot report activated', async (t) => {
  const f = bridgeFixture(t),
    web = f.containers.find((c) => c.Name === `/${PROJECT}-web-1`);
  let resumed = false,
    changedHealth = false;
  f.beforeDocker = (args) => {
    if (args[0] === 'container' && args[1] === 'start' && args.at(-1) === web.Id) resumed = true;
    if (resumed && args[0] === 'container' && args[1] === 'ls' && !changedHealth) {
      changedHealth = true;
      web.State.Health = { Status: 'unhealthy' };
    }
  };
  await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
  assert(changedHealth);
  assert(fs.existsSync(join(f.stand, '.operation.lock/mutation.json')));
});
test('R2 headroom fails before web/API stop, leaving binding and admission unchanged', async (t) => {
  const f = bridgeFixture(t),
    prior = f.read('profile.json');
  await assert.rejects(
    f.refresh([], {
      integration: createPublicCveBridge({ statfs: () => ({ bavail: 1, bsize: 4096 }) }),
      docker: f.bridgeDocker,
    }),
  );
  assert.deepEqual(changed(f), []);
  assert.equal(f.read('profile.json'), prior);
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
});
for (const at of ['config', 'stop-worker'])
  for (const replace of [false, true])
    test(`R3 source ${replace ? 'same-byte inode replacement' : 'byte drift'} at ${at} is fenced`, async (t) => {
      const f = bridgeFixture(t),
        path = join(f.root, 'server/deploy/compose.public-images.yaml');
      let injected = false;
      f.beforeDocker = (args) => {
        if (
          injected ||
          !(at === 'config'
            ? args[0] === 'compose' && args.includes('config')
            : args[0] === 'container' &&
              args[1] === 'stop' &&
              args.at(-1) === f.containers.find((c) => c.Name === `/${PROJECT}-worker-1`).Id)
        )
          return;
        injected = true;
        const bytes = fs.readFileSync(path);
        if (replace) {
          fs.writeFileSync(path + '.next', bytes);
          fs.renameSync(path + '.next', path);
        } else fs.appendFileSync(path, '\n');
      };
      await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
      assert(injected);
      assert(!f.calls.some((c) => c.kind === 'docker' && c.args.includes('up')));
      assert.equal(fs.existsSync(join(f.stand, '.operation.lock')), at === 'stop-worker');
      if (at === 'config') assert.deepEqual(changed(f), []);
      else assert.equal(f.containers.find((c) => c.Name === `/${PROJECT}-web-1`).State.Running, false);
    });
for (const llm of [false, true])
  test(`R2 explicit completed ${llm ? 'four' : 'two'}-store archive retains payloads and frees one bounded slot`, async (t) => {
    const f = llm ? llmBridgeFixture(t) : bridgeFixture(t),
      docker = llm ? f.llmDocker : f.bridgeDocker;
    assert.equal(
      (await f.refresh([], { integration: undefined, docker, ...(llm ? { run: f.llmRun } : {}) })).outcome,
      'activated',
    );
    const parent = join(f.stand, 'cve-backups'),
      name = fs.readdirSync(parent)[0],
      id = name.slice(8),
      source = join(parent, name);
    const backup = llm
        ? join(f.stand, 'llm-deployments', 'deploy-' + id, 'fenced/core/auth.sqlite')
        : join(source, 'fenced/auth.sqlite'),
      bytes = fs.readFileSync(backup),
      ino = fs.statSync(backup).ino;
    assert.deepEqual(archiveCveBackup(f.root, id), { outcome: 'archived' });
    assert(!fs.existsSync(source));
    const retained = join(
      f.stand,
      'cve-backups-archive',
      name,
      ...(llm ? ['llm-snapshots', 'fenced', 'core'] : ['fenced']),
      'auth.sqlite',
    );
    assert.deepEqual(fs.readFileSync(retained), bytes);
    assert.equal(fs.statSync(retained).ino, ino);
    if (llm) assert(!fs.existsSync(join(f.stand, 'llm-deployments', 'deploy-' + id)));
    for (let i = 0; i < 3; i++) {
      const p = join(parent, 'refresh-' + String(i).repeat(32));
      fs.mkdirSync(p, { mode: 0o700 });
      fs.writeFileSync(
        join(p, 'complete.json'),
        JSON.stringify({ version: 1, project: PROJECT, preserved: true }),
        { mode: 0o600 },
      );
    }
    const lock = acquireLock(f.root);
    try {
      preflightCveCapacity(f.root, lock, {
        llm,
        statfs: () => ({ bavail: 16 * 1024 ** 3, bsize: 1 }),
      }).verify();
    } finally {
      lock.release();
    }
  });
for (const fault of ['partial', 'symlink', 'hardlink', 'corrupt', 'archive-cap', 'shared-lock'])
  test(`R2 archive ${fault} refuses without moving/removing completed payload`, async (t) => {
    const f = bridgeFixture(t);
    assert.equal(
      (await f.refresh([], { integration: undefined, docker: f.bridgeDocker })).outcome,
      'activated',
    );
    const parent = join(f.stand, 'cve-backups'),
      name = fs.readdirSync(parent)[0],
      source = join(parent, name),
      id = name.slice(8),
      payload = join(source, 'fenced/auth.sqlite');
    let lock;
    if (fault === 'partial') fs.unlinkSync(join(source, 'complete.json'));
    if (fault === 'symlink') {
      fs.renameSync(payload, payload + '.original');
      fs.symlinkSync(payload + '.original', payload);
    }
    if (fault === 'hardlink') fs.linkSync(payload, payload + '.link');
    if (fault === 'corrupt') {
      const fd = fs.openSync(payload, 'r+');
      try {
        fs.writeSync(fd, Buffer.from('BAD'), 0, 3, 0);
      } finally {
        fs.closeSync(fd);
      }
    }
    if (fault === 'archive-cap') {
      const dir = join(f.stand, 'cve-backups-archive');
      fs.mkdirSync(dir, { mode: 0o700 });
      for (let i = 0; i < 8; i++) fs.mkdirSync(join(dir, 'refresh-' + String(i).repeat(32)), { mode: 0o700 });
    }
    if (fault === 'shared-lock') lock = acquireLock(f.root);
    try {
      assert.throws(() => archiveCveBackup(f.root, id));
      assert(fs.existsSync(source));
      assert(fs.lstatSync(payload));
    } finally {
      lock?.release();
    }
    assert(!fs.existsSync(join(f.stand, '.operation.lock')));
  });
test('R2 archive rejects foreign LLM audit linkage without moving either generation', async (t) => {
  const f = llmBridgeFixture(t);
  assert.equal(
    (await f.refresh([], { integration: undefined, docker: f.llmDocker, run: f.llmRun })).outcome,
    'activated',
  );
  const parent = join(f.stand, 'cve-backups'),
    name = fs.readdirSync(parent)[0],
    id = name.slice(8),
    source = join(parent, name);
  fs.writeFileSync(
    join(source, 'llm-audit.json'),
    JSON.stringify({ version: 1, name: 'deploy-' + 'f'.repeat(32) }),
  );
  assert.throws(() => archiveCveBackup(f.root, id));
  assert(fs.existsSync(source));
  assert(fs.existsSync(join(f.stand, 'llm-deployments', 'deploy-' + id)));
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
});
