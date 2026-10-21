import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fixture, ROOT } from './public-refresh-cve-fixtures.mjs';
import {
  publicCveScheduler,
  agentPlist,
  validateLoadedAgent,
  publicStatus,
  LABEL,
  INTERVAL_SECONDS,
  schedulePublicCve,
} from './schedule-public-cve.mjs';
const timestamp = '2026-10-20T12:00:00.000Z';
const manifest = `sha256:${'a'.repeat(64)}`;
function loaded({ root, home, node }) {
  return `gui/501/${LABEL} = {\npath = ${join(home, 'Library/LaunchAgents', `${LABEL}.plist`)}\nprogram = ${node}\nworking directory = ${root}\narguments = {\n${node}\n${join(root, 'scripts/schedule-public-cve.mjs')}\nrun\n}\nenvironment = {\nHOME => ${home}\nPATH => /opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\nLANG => C\nTZ => UTC\n}\nrun interval = 21600 seconds\n}`;
}
test('distinct six-hour public agent plist has no LOCAL path, credential, daemon startup or immediate run', () => {
  const plist = agentPlist({ root: '/repo/a&b', node: '/node/bin/node', home: '/Users/synthetic' });
  assert.equal(INTERVAL_SECONDS, 21600);
  assert.match(plist, /io.diplom.public-images.cve-refresh/);
  assert.match(plist, /schedule-public-cve.mjs/);
  assert.match(plist, /a&amp;b/);
  assert.match(plist, /<key>RunAtLoad<\/key><false\/>/);
  assert.match(plist, /<key>KeepAlive<\/key><false\/>/);
  assert.doesNotMatch(
    plist,
    /schedule-local|local-full|\.local-stand|JWT|PRIVATE|NODE_OPTIONS|StandardOutPath|StandardErrorPath|DOCKER_HOST/,
  );
});
test('unprovisioned install/run and invalid CLI refuse without a LaunchAgent or refresh operation', async () => {
  for (const command of ['install', 'run'])
    await assert.rejects(
      schedulePublicCve([command], { root: '/missing', platform: 'darwin', run: () => assert.fail() }),
    );
  const result = spawnSync(process.execPath, ['scripts/schedule-public-cve.mjs', 'invalid'], {
    cwd: ROOT,
    env: {},
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /PUBLIC CVE schedule/);
});
for (const outcome of ['unchanged', 'activated', 'deferred-busy', 'deferred-stopped'])
  test(`scheduler retains bounded public ${outcome} only after shared lock grant`, async (t) => {
    const f = fixture(t),
      scheduler = publicCveScheduler({ integration: f.integration });
    await scheduler.scheduledRun({
      root: f.root,
      clock: () => timestamp,
      refresh: async (_args, options) => {
        options.onLocked();
        options.log('PRIVATE-SYNTHETIC-ERROR');
        return { outcome, manifest };
      },
    });
    const raw = f.read('cve-refresh-status.json'),
      status = JSON.parse(raw);
    assert.equal(status.outcome, outcome);
    assert.equal(status.state, 'completed');
    assert.equal(status.manifest, manifest);
    assert(Buffer.byteLength(raw) <= 4096);
    assert.equal(fs.statSync(join(f.stand, 'cve-refresh-status.json')).mode & 0o777, 0o600);
    assert.doesNotMatch(raw, /PRIVATE|scan-jwt|\.local-stand/);
    assert.equal(fs.existsSync(join(f.stand, '.cve-schedule.lock')), false);
  });
test('schedule + actual injected updater exercise public workflow end-to-end offline', async (t) => {
  const f = fixture(t),
    scheduler = publicCveScheduler({ integration: f.integration });
  await scheduler.scheduledRun({
    root: f.root,
    clock: () => timestamp,
    refresh: (args, options) => f.refresh(args, { onLocked: options.onLocked }),
  });
  assert.equal(JSON.parse(f.read('cve-refresh-status.json')).outcome, 'activated');
});
test('overlap/HOLD refusal preserves prior failure bytes AND inode, with no child execution', async (t) => {
  const f = fixture(t),
    scheduler = publicCveScheduler({ integration: f.integration });
  fs.mkdirSync(join(f.stand, '.operation.lock'), { mode: 0o700 });
  fs.writeFileSync(join(f.stand, '.operation.lock/mutation.json'), 'retained', { mode: 0o600 });
  const path = join(f.stand, 'cve-refresh-status.json'),
    prior = '{"retained":"HOLD"}';
  fs.writeFileSync(path, prior, { mode: 0o600 });
  const ino = fs.lstatSync(path).ino;
  await assert.rejects(
    scheduler.scheduledRun({
      root: f.root,
      refresh: (args, options) => f.refresh(args, { onLocked: options.onLocked }),
    }),
  );
  assert.equal(f.read('cve-refresh-status.json'), prior);
  assert.equal(fs.lstatSync(path).ino, ino);
  assert.equal(f.calls.length, 0);
  assert.equal(f.read('.operation.lock/mutation.json'), 'retained');
});
test('arbitrary exception output/getters do not cross public failed-status boundary', async (t) => {
  const f = fixture(t),
    scheduler = publicCveScheduler({ integration: f.integration });
  const hostile = Object.create(null);
  Object.defineProperty(hostile, 'message', { get: () => assert.fail('must not inspect attacker error') });
  await assert.rejects(
    scheduler.scheduledRun({
      root: f.root,
      clock: () => timestamp,
      refresh: async (_args, options) => {
        options.onLocked();
        throw hostile;
      },
    }),
  );
  assert.deepEqual(JSON.parse(f.read('cve-refresh-status.json')), {
    version: 1,
    state: 'failed',
    startedAt: timestamp,
    finishedAt: timestamp,
    phase: 'preflight',
    hold: false,
  });
});
for (const kind of ['dangling', 'foreign'])
  test(`${kind} status symlink is refused without replacement`, async (t) => {
    const f = fixture(t),
      scheduler = publicCveScheduler({ integration: f.integration }),
      target = join(f.root, 'foreign');
    if (kind === 'foreign') fs.writeFileSync(target, 'untouched');
    fs.symlinkSync(target, join(f.stand, 'cve-refresh-status.json'));
    let advanced = false;
    await assert.rejects(
      scheduler.scheduledRun({
        root: f.root,
        refresh: async (_args, options) => {
          options.onLocked();
          advanced = true;
        },
      }),
    );
    assert.equal(advanced, false);
    assert(fs.lstatSync(join(f.stand, 'cve-refresh-status.json')).isSymbolicLink());
    if (kind === 'foreign') assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
  });
test('substituted scheduler lock is not deleted and no result replaces running status', async (t) => {
  const f = fixture(t),
    scheduler = publicCveScheduler({ integration: f.integration }),
    path = join(f.stand, '.cve-schedule.lock');
  await assert.rejects(
    scheduler.scheduledRun({
      root: f.root,
      clock: () => timestamp,
      refresh: async (_args, options) => {
        options.onLocked();
        fs.renameSync(path, path + '.original');
        fs.mkdirSync(path, { mode: 0o700 });
        return { outcome: 'unchanged', manifest };
      },
    }),
  );
  assert(fs.existsSync(path));
  assert.equal(JSON.parse(f.read('cve-refresh-status.json')).state, 'running');
});
test('public status renderer never echoes arbitrary retained fields or error messages', () => {
  const raw = JSON.stringify({
    version: 1,
    state: 'failed',
    startedAt: timestamp,
    finishedAt: timestamp,
    phase: 'fence',
    hold: true,
    message: 'sensitive text',
    Env: ['private'],
    JWT: 'synthetic',
  });
  assert.doesNotMatch(publicStatus(raw), /sensitive|private|JWT|Env|message/);
  assert.throws(() =>
    publicStatus(
      JSON.stringify({
        version: 1,
        state: 'completed',
        startedAt: timestamp,
        finishedAt: timestamp,
        outcome: 'unchanged',
        manifest: manifest + '\n',
      }),
    ),
  );
});
test('loaded public job requires exact public argv, interval, paths and clean environment', () => {
  const options = { root: '/fixture/repo', home: '/fixture/home', node: '/fixture/node' };
  const expected = { ...options, path: join(options.home, 'Library/LaunchAgents', `${LABEL}.plist`) };
  validateLoadedAgent(loaded(options), expected);
  for (const text of [
    loaded(options).replace('schedule-public', 'schedule-local'),
    loaded(options).replace('21600 seconds', '60 seconds'),
    loaded(options).replace('TZ => UTC', 'TZ => UTC\nOPENROUTER_API_KEY => synthetic'),
    loaded(options).replace('TZ => UTC', 'TZ => UTC\nNODE_OPTIONS => synthetic'),
  ]) {
    assert.throws(() => validateLoadedAgent(text, expected));
  }
});
test('installer is fixture-only, no overwrite or restart/adoption of foreign plist', async (t) => {
  const f = fixture(t),
    scheduler = publicCveScheduler({ integration: f.integration }),
    home = join(f.root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(join(home, 'Library'), { mode: 0o700 });
  fs.mkdirSync(join(home, 'Library/LaunchAgents'), { mode: 0o700 });
  const node = fs.realpathSync(process.execPath),
    calls = [];
  const options = {
    root: f.root,
    home,
    node,
    platform: 'darwin',
    uid: 501,
    log: () => {},
    run: async (exe, args, opts) => {
      assert.equal(exe, '/bin/launchctl');
      assert.equal(opts.env.HOME, home);
      calls.push(args);
      if (args[0] === 'print') return loaded({ root: f.root, home, node });
      return '';
    },
  };
  await scheduler.scheduleCve(['install'], options);
  await scheduler.scheduleCve(['install'], options);
  assert.equal(calls.filter((args) => args[0] === 'bootstrap').length, 1);
  const path = join(home, 'Library/LaunchAgents', `${LABEL}.plist`);
  fs.writeFileSync(path, 'foreign', { mode: 0o600 });
  await assert.rejects(scheduler.scheduleCve(['install'], options));
  assert.equal(fs.readFileSync(path, 'utf8'), 'foreign');
});
