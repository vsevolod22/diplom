import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { bridgeFixture, Database } from './public-cve-bridge-fixtures.mjs';
import { readProfile, acquireLock } from './public-image-stand.mjs';
import { publicCveFailure } from './refresh-public-cve.mjs';

test('DEFAULT bridge activates through real stable-copy/SQLite backup/restore and bounded export/comparison', async (t) => {
  const f = bridgeFixture(t),
    before = Object.values(f.sourcePaths).map((p) => fs.readFileSync(p));
  const result = await f.refresh([], { integration: undefined, docker: f.bridgeDocker });
  assert.equal(result.outcome, 'activated');
  assert.equal(readProfile(f.root).version, 2);
  assert.deepEqual(f.helperEvents, Array(3).fill(['create', 'start', 'stop', 'rm']).flat());
  assert.deepEqual(
    Object.values(f.sourcePaths).map((p) => fs.readFileSync(p)),
    before,
  );
  const parent = join(f.stand, 'cve-backups'),
    audit = join(parent, fs.readdirSync(parent)[0]);
  assert.equal(JSON.parse(fs.readFileSync(join(audit, 'complete.json'))).preserved, true);
  for (const phase of ['fenced', 'before-api', 'after-api'])
    for (const role of ['auth', 'ledger'])
      assert.equal(fs.statSync(join(audit, phase, `${role}.sqlite`)).mode & 0o777, 0o600);
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
  assert(!f.logs.some((line) => /not-real|base64|credential|Env/.test(line)));
});
for (const fault of [
  'writable-mount',
  'copy-up',
  'volume-source',
  'helper-env',
  'epoch',
  'frame',
  'after-api-data',
])
  test(`concrete bridge ${fault} retains shared HOLD/private partials without retry`, async (t) => {
    const f = bridgeFixture(t);
    f.fault = fault;
    await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }), (error) => {
      assert.equal(publicCveFailure(error).hold, true);
      return true;
    });
    assert(fs.existsSync(join(f.stand, '.operation.lock/mutation.json')));
    const n = f.helperEvents.length;
    await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
    assert.equal(f.helperEvents.length, n);
    if (['writable-mount', 'copy-up', 'volume-source', 'helper-env'].includes(fault))
      assert(!f.helperEvents.includes('start'));
  });

test('real stable WAL/main copies preserve source bytes and committed WAL rows', async (t) => {
  const f = bridgeFixture(t),
    db = new Database(f.sourcePaths.auth);
  db.pragma('journal_mode=WAL');
  db.exec("INSERT INTO users VALUES('wal-user','synthetic-value')");
  const main = fs.readFileSync(f.sourcePaths.auth),
    wal = fs.readFileSync(f.sourcePaths.auth + '-wal');
  try {
    assert.equal(
      (await f.refresh([], { integration: undefined, docker: f.bridgeDocker })).outcome,
      'activated',
    );
    assert.deepEqual(fs.readFileSync(f.sourcePaths.auth), main);
    assert.deepEqual(fs.readFileSync(f.sourcePaths.auth + '-wal'), wal);
    const parent = join(f.stand, 'cve-backups'),
      audit = join(parent, fs.readdirSync(parent)[0]);
    const copy = new Database(join(audit, 'fenced/auth.sqlite'), { readonly: true });
    try {
      assert.equal(copy.prepare("SELECT count(*) n FROM users WHERE id='wal-user'").get().n, 1);
    } finally {
      copy.close();
    }
  } finally {
    db.close();
  }
});

for (const drift of ['worker-epoch', 'api-epoch', 'api-health'])
  test(`post-snapshot ${drift} cannot pass final activation acceptance`, async (t) => {
    const f = bridgeFixture(t);
    let changed = false;
    f.beforeDocker = (args) => {
      if (
        !changed &&
        args[0] === 'container' &&
        args[1] === 'ls' &&
        f.helperEvents.filter((e) => e === 'rm').length === 3
      ) {
        changed = true;
        const c = f.containers.find(
          (c) => c.Name === `/dip-public-images-${drift.startsWith('worker') ? 'worker' : 'api'}-1`,
        );
        if (drift.endsWith('health')) c.State.Health.Status = 'unhealthy';
        else c.RestartCount++;
      }
    };
    await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }), (error) => {
      assert.equal(publicCveFailure(error).hold, true);
      return true;
    });
    assert(changed);
    assert(fs.existsSync(join(f.stand, '.operation.lock/mutation.json')));
  });

test('shared exported launcher lock excludes refresh and all existing recovery guards', async (t) => {
  const f = bridgeFixture(t),
    path = join(f.stand, '.operation.lock');
  const l = acquireLock(f.root);
  assert.equal(l.path, path);
  await assert.rejects(f.refresh([], { integration: undefined, docker: f.bridgeDocker }));
  l.release();
  for (const name of [
    '.reconcile-build-only.lock',
    '.reconcile-network-only.lock',
    '.reconcile-running-build-only.lock',
    '.recover-build-and-redeploy.lock',
  ]) {
    fs.mkdirSync(join(f.stand, name), { mode: 0o700 });
    assert.throws(() => acquireLock(f.root));
    fs.rmdirSync(join(f.stand, name));
  }
});
