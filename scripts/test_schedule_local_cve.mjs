import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentPlist, INTERVAL_SECONDS, LABEL, scheduledRun, scheduleLocalCve, validateLoadedAgent } from './schedule-local-cve.mjs';
import { refreshLocalCve } from './refresh-local-cve.mjs';
import { acquireStandLock } from './setup-local-cve.mjs';

const manifest = `sha256:${'a'.repeat(64)}`;
const loaded = ({ root, home, node }) => `gui/501/${LABEL} = {\npath = ${join(home, 'Library/LaunchAgents', `${LABEL}.plist`)}\nprogram = ${node}\nworking directory = ${root}\narguments = {\n${node}\n${join(root, 'scripts/schedule-local-cve.mjs')}\nrun\n}\nenvironment = {\nHOME => ${home}\nPATH => /opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\nLANG => C\nTZ => UTC\n}\nrun interval = 21600 seconds\n}`;
function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'cve-schedule-')));
  fs.mkdirSync(join(root, '.local-stand'), { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('plist uses exact program paths, 6h interval, no KeepAlive/start-on-load or inherited secrets', () => {
  const plist = agentPlist({ root: '/repo/a&b', node: '/node/bin/node', home: '/Users/local' });
  assert.equal(INTERVAL_SECONDS, 21600);
  assert.ok(plist.includes('<integer>21600</integer>'));
  assert.ok(plist.includes('/repo/a&amp;b/scripts/schedule-local-cve.mjs'));
  assert.ok(plist.includes('<key>KeepAlive</key><false/>'));
  assert.ok(plist.includes('<key>RunAtLoad</key><false/>'));
  assert.ok(plist.includes(`<string>${LABEL}</string>`));
  assert.doesNotMatch(plist, /JWT|PRIVATE|TOKEN|DOCKER_HOST|NODE_OPTIONS|StandardOutPath|StandardErrorPath/);
  assert.throws(() => agentPlist({ root: '/repo/../elsewhere' }));
  assert.throws(() => agentPlist({ root: '/repo\nelsewhere' }));
});

for (const outcome of ['unchanged', 'activated', 'deferred-busy', 'deferred-stopped']) {
  test(`run records bounded public ${outcome} outcome without exposing refresh output`, async t => {
    const root = fixture(t);
    await scheduledRun({ root, refresh: async (args, options) => {
      assert.deepEqual(args, []); assert.equal(options.root, root);
      options.onLocked();
      options.log('do not persist raw output');
      return { outcome, manifest };
    } });
    const path = join(root, '.local-stand/cve-refresh-status.json');
    const raw = fs.readFileSync(path, 'utf8');
    const result = JSON.parse(raw);
    assert.equal(result.state, 'completed'); assert.equal(result.outcome, outcome);
    assert.equal(result.manifest, manifest); assert.equal(fs.statSync(path).mode & 0o777, 0o600);
    assert.doesNotMatch(raw, /raw output/);
    assert.equal(fs.existsSync(join(root, '.local-stand/.cve-schedule.lock')), false);
  });
}

test('failure records only sanitized status, not child exception', async t => {
  const root = fixture(t);
  await assert.rejects(scheduledRun({ root, refresh: async (_args, options) => { options.onLocked(); throw Error('secret value'); } }), /refused/);
  const raw = fs.readFileSync(join(root, '.local-stand/cve-refresh-status.json'), 'utf8');
  assert.equal(JSON.parse(raw).state, 'failed'); assert.doesNotMatch(raw, /secret value/);
});

test('concurrent/stale schedule lock refuses without overwriting active status', async t => {
  const root = fixture(t), stand = join(root, '.local-stand');
  fs.mkdirSync(join(stand, '.cve-schedule.lock'), { mode: 0o700 });
  await assert.rejects(scheduledRun({ root, refresh: () => assert.fail('must not run') }));
  assert.equal(fs.existsSync(join(stand, 'cve-refresh-status.json')), false);
});

test('symlinked status is refused without following or replacing it', async t => {
  const root = fixture(t), target = join(root, 'foreign');
  fs.writeFileSync(target, 'untouched');
  fs.symlinkSync(target, join(root, '.local-stand/cve-refresh-status.json'));
  await assert.rejects(scheduledRun({ root, refresh: async (_args, options) => {
    options.onLocked(); assert.fail('must not reach updater work');
  } }));
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
});

test('scheduler preserves existing HOLD status and journal when shared lock is held', async t => {
  const root = fixture(t), stand = join(root, '.local-stand');
  acquireStandLock(root);
  const journal = join(stand, '.stand-operation.lock/refresh.json');
  fs.writeFileSync(journal, 'synthetic retained journal', { mode: 0o600 });
  const path = join(stand, 'cve-refresh-status.json');
  const prior = JSON.stringify({ version: 1, state: 'failed', phase: 'readiness', checkpoint: 'storage' });
  fs.writeFileSync(path, prior, { mode: 0o600 });
  const identity = fs.lstatSync(path);
  await assert.rejects(scheduledRun({ root, refresh: (args, options) => refreshLocalCve(args, {
    ...options, run: () => assert.fail('must not launch child'), docker: () => assert.fail('must not contact Docker'),
  }) }));
  assert.equal(fs.readFileSync(path, 'utf8'), prior);
  assert.equal(fs.lstatSync(path).ino, identity.ino);
  assert.equal(fs.readFileSync(journal, 'utf8'), 'synthetic retained journal');
});

test('dangling status symlink is refused without replacement or updater work', async t => {
  const root = fixture(t), path = join(root, '.local-stand/cve-refresh-status.json');
  const target = join(root, 'missing');
  fs.symlinkSync(target, path);
  let called = false;
  await assert.rejects(scheduledRun({ root, refresh: async (_args, options) => {
    options.onLocked(); called = true; return { outcome: 'unchanged', manifest };
  } }));
  assert.equal(called, false);
  assert.equal(fs.lstatSync(path).isSymbolicLink(), true);
  assert.equal(fs.readlinkSync(path), target);
  assert.equal(fs.existsSync(target), false);
});

test('scheduler never releases a substituted schedule lock', async t => {
  const root = fixture(t), lock = join(root, '.local-stand/.cve-schedule.lock');
  const moved = join(root, '.local-stand/original-schedule-lock');
  let replacement;
  await assert.rejects(scheduledRun({ root, refresh: async (_args, options) => {
    options.onLocked();
    fs.renameSync(lock, moved);
    fs.mkdirSync(lock, { mode: 0o700 });
    replacement = fs.lstatSync(lock);
    return { outcome: 'unchanged', manifest };
  } }));
  assert.equal(fs.lstatSync(lock).ino, replacement.ino);
  assert.equal(fs.lstatSync(moved).isDirectory(), true);
});

test('installer creates exactly its new plist, bootstrap once, idempotent when loaded', async t => {
  const root = fixture(t), home = join(root, 'home'), node = join(root, 'node');
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(join(home, 'Library'), { mode: 0o700 });
  fs.mkdirSync(join(home, 'Library/LaunchAgents'), { mode: 0o700 }); fs.writeFileSync(node, 'fixture');
  const calls = [], log = [];
  const options = { root, home, node, platform: 'darwin', uid: 501,
    run: async (exe, args, opts) => { assert.equal(exe, '/bin/launchctl');
      assert.equal(opts.timeout, 15000); assert.equal(opts.env.HOME, home); calls.push(args); return args[0] === 'print' ? loaded({ root, home, node }) : ''; },
    log: text => log.push(text) };
  await scheduleLocalCve(['install'], options);
  assert.equal(calls[0][0], 'bootstrap'); assert.equal(calls[1][0], 'print');
  await scheduleLocalCve(['install'], options);
  assert.equal(calls.length, 3); assert.equal(calls[2][0], 'print');
  const plist = join(home, 'Library/LaunchAgents', `${LABEL}.plist`);
  assert.equal(fs.statSync(plist).mode & 0o777, 0o600);
  fs.writeFileSync(plist, 'foreign');
  await assert.rejects(scheduleLocalCve(['install'], options));
  assert.equal(fs.readFileSync(plist, 'utf8'), 'foreign'); assert.equal(calls.length, 3);
});

test('loaded job rejects same-label different config, missing args and dangerous injected environment', () => {
  const options = { root: '/repo', home: '/Users/local', node: '/node/bin/node' };
  const identity = { ...options, path: join(options.home, 'Library/LaunchAgents', `${LABEL}.plist`) };
  const valid = loaded(options);
  validateLoadedAgent(valid, identity);
  for (const bad of ['', valid.replace('program = /node/bin/node', 'program = /foreign'),
    valid.replace('/repo/scripts/schedule-local-cve.mjs', '/repo/scripts/foreign.mjs'),
    valid.replace('run interval = 21600 seconds', 'run interval = 10 seconds'),
    valid.replace('LANG => C', 'LANG => C\nDYLD_INSERT_LIBRARIES => /foreign'),
        valid.replace('HOME => /Users/local', 'HOME => /foreign'),
        valid.replace('PATH => /opt/homebrew/bin', 'PATH => /foreign'),
        valid.replace('LANG => C', 'LANG => C\nNODE_OPTIONS => --require /foreign'),
        valid.replace('program = /node/bin/node', 'program = /foreign').replace('LANG => C', 'LANG => C\nprogram = /node/bin/node'),
        valid.replace('program = /node/bin/node', 'program = /node/bin/node\nprogram = /foreign')]) {
    assert.throws(() => validateLoadedAgent(bad, identity));
  }
});

test('LOCAL keeps its non-strict benign metadata policy without the PUBLIC opt-in', () => {
  const options = { root: '/repo', home: '/Users/local', node: '/node/bin/node' };
  const identity = { ...options, path: join(options.home, 'Library/LaunchAgents', `${LABEL}.plist`) };
  for (const extra of ['', `\nXPC_SERVICE_NAME => ${LABEL}\nOSLogRateLimit => 64`,
    '\nXPC_SERVICE_NAME => synthetic-local-value\nOSLogRateLimit => 32\nBENIGN_METADATA => synthetic']) {
    validateLoadedAgent(loaded(options).replace('TZ => UTC', 'TZ => UTC' + extra), identity);
  }
});

for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'DYLD_INSERT_LIBRARIES', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
  for (const block of ['environment', 'inherited environment', 'default environment']) test('LOCAL still rejects dangerous ' + name + ' in ' + block, () => {
    const options = { root: '/repo', home: '/Users/local', node: '/node/bin/node' };
    const identity = { ...options, path: join(options.home, 'Library/LaunchAgents', `${LABEL}.plist`) };
    const line = name + ' => PRIVATE-SYNTHETIC';
    const text = block === 'environment' ? loaded(options).replace('TZ => UTC', 'TZ => UTC\n' + line) :
      loaded(options).replace('environment = {', block + ' = {\n' + line + '\n}\nenvironment = {');
    assert.throws(() => validateLoadedAgent(text, identity), error => !error.message.includes('PRIVATE-SYNTHETIC'));
  });
}

test('installer refuses other platform and unsupported operations', async () => {
  await assert.rejects(scheduleLocalCve(['install'], { platform: 'linux' }));
  await assert.rejects(scheduleLocalCve(['uninstall']));
});
