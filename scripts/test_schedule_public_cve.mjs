import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fixture, ROOT } from './public-refresh-cve-fixtures.mjs';
import { createCveScheduler } from './schedule-local-cve.mjs';
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

test('status accepts exact launchd metadata with no receipt and only prints the existing fixture job', async (t) => {
  const f = fixture(t), scheduler = publicCveScheduler({ integration: f.integration });
  const home = join(f.root, 'home'), node = fs.realpathSync(process.execPath);
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(join(home, 'Library'), { mode: 0o700 });
  fs.mkdirSync(join(home, 'Library/LaunchAgents'), { mode: 0o700 });
  const path = join(home, 'Library/LaunchAgents', `${LABEL}.plist`);
  const plist = scheduler.agentPlist({ root: f.root, home, node });
  fs.writeFileSync(path, plist, { mode: 0o600 });
  const identity = fs.lstatSync(path), calls = [], logs = [];
  await scheduler.scheduleCve(['status'], {
    root: f.root, home, node, platform: 'darwin', uid: 501, log: text => logs.push(text),
    run: async (exe, args) => {
      assert.equal(exe, '/bin/launchctl');
      assert.deepEqual(args, ['print', `gui/501/${LABEL}`]);
      calls.push(args);
      return loaded({ root: f.root, home, node }).replace('TZ => UTC', `TZ => UTC\nXPC_SERVICE_NAME => ${LABEL}\nOSLogRateLimit => 64`);
    },
  });
  assert.equal(calls.length, 1);
  assert.deepEqual(logs, [`PUBLIC CVE schedule loaded: ${LABEL}, every 6 hours.`]);
  assert.equal(fs.readFileSync(path, 'utf8'), plist);
  assert.equal(fs.lstatSync(path).ino, identity.ino);
  assert.equal(fs.existsSync(join(f.stand, 'cve-refresh-status.json')), false);
  assert.equal(fs.existsSync(join(f.stand, '.cve-schedule.lock')), false);
  assert.equal(f.calls.length, 0);
});

const metadataOptions = { root: '/fixture/repo', home: '/fixture/home', node: '/fixture/node' };
const metadataIdentity = { ...metadataOptions, path: join(metadataOptions.home, 'Library/LaunchAgents', `${LABEL}.plist`) };
const withMetadata = lines => loaded(metadataOptions).replace('TZ => UTC', 'TZ => UTC\n' + lines.join('\n'));
for (const lines of [[], [`XPC_SERVICE_NAME => ${LABEL}`], ['OSLogRateLimit => 64'], [`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64']]) {
  test('public accepts only present exact optional launchd metadata: ' + lines.length + ' fields', () => {
    validateLoadedAgent(withMetadata(lines), metadataIdentity);
  });
}
for (const lines of [
  ['UNREVIEWED_METADATA => 64'], ['OPENROUTER_API_KEY => PRIVATE-SYNTHETIC'],
  ['XPC_SERVICE_NAME => io.diplom.local-full.cve-refresh'], ['XPC_SERVICE_NAME =>'],
  ['OSLogRateLimit => 0'], ['OSLogRateLimit => 63'], ['OSLogRateLimit => 64.0'], ['OSLogRateLimit => +64'],
  [`XPC_SERVICE_NAME => ${LABEL}`, `XPC_SERVICE_NAME => ${LABEL}`], ['OSLogRateLimit => 64', 'OSLogRateLimit => 64'],
  [`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64', 'EXTRA => PRIVATE-SYNTHETIC'],
]) test('public rejects unknown/mismatched/duplicate metadata without weakening the exact count', () => {
  assert.throws(() => validateLoadedAgent(withMetadata(lines), metadataIdentity), error => !error.message.includes('PRIVATE-SYNTHETIC'));
});
for (const key of ['HOME', 'PATH', 'LANG', 'TZ']) test('optional launchd metadata never substitutes required ' + key, () => {
  const valid = withMetadata([`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64']);
  const line = valid.split('\n').find(s => s.startsWith(key + ' => '));
  assert.throws(() => validateLoadedAgent(valid.replace(line + '\n', ''), metadataIdentity));
  assert.throws(() => validateLoadedAgent(valid.replace(line, key + ' => PRIVATE-SYNTHETIC'), metadataIdentity));
});
for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'DYLD_INSERT_LIBRARIES', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
  for (const block of ['environment', 'inherited environment', 'default environment']) test('public still rejects dangerous ' + name + ' in ' + block, () => {
    const line = name + ' => PRIVATE-SYNTHETIC';
    const text = block === 'environment' ? withMetadata([`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64', line]) :
      loaded(metadataOptions).replace('environment = {', block + ' = {\n' + line + '\n}\nenvironment = {');
    assert.throws(() => validateLoadedAgent(text, metadataIdentity), error => !error.message.includes('PRIVATE-SYNTHETIC'));
  });
}
for (const control of ['\0', '\x07', '\x0b', '\x0c', '\x1b', '\x7f']) test('public rejects control characters rather than trimming hidden metadata into authority', () => {
  assert.throws(() => validateLoadedAgent(withMetadata(['OSLogRateLimit => 64' + control]), metadataIdentity));
});
test('legitimate launchctl indentation and CRLF remain accepted', () => {
  const text = withMetadata([`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64']).split('\n').map(line => '\t' + line).join('\r\n');
  validateLoadedAgent(text, metadataIdentity);
});
for (const text of [
  withMetadata(['OSLogRateLimit=64']), withMetadata(['nested = {', 'OSLogRateLimit => 64', '}']),
  withMetadata(['OSLogRateLimit => 64']).slice(0, -1), withMetadata(['OSLogRateLimit => 64']) + '\n}',
  withMetadata(['OSLogRateLimit => 64']).replace('arguments = {', 'environment = {'),
]) test('public rejects malformed loaded metadata/structure', () => {
  assert.throws(() => validateLoadedAgent(text, metadataIdentity));
});
test('optional metadata is explicit opt-in; strict shared default does not admit it', () => {
  const shared = createCveScheduler({ label: LABEL, script: 'schedule-public-cve.mjs', strictLoadedEnvironment: true });
  shared.validateLoadedAgent(loaded(metadataOptions), metadataIdentity);
  assert.throws(() => shared.validateLoadedAgent(withMetadata([`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64']), metadataIdentity));
});
test('metadata hook rejects getters, unknown keys, required overrides and malformed values without evaluating them', () => {
  let getterCalls = 0;
  const getter = Object.defineProperty({}, 'OSLogRateLimit', { enumerable: true, get() { getterCalls++; throw Error('PRIVATE'); } });
  const stringifier = { toString() { assert.fail('must not coerce metadata values'); } };
  for (const metadata of [getter, null, [], 'PRIVATE', new Map(), { HOME: '/foreign' }, { NODE_OPTIONS: 'PRIVATE' },
    { XPC_SERVICE_NAME: 'foreign' }, { OSLogRateLimit: '0' }, { OSLogRateLimit: stringifier }, { [Symbol('foreign')]: '64' }]) {
    assert.throws(() => createCveScheduler({ label: LABEL, strictLoadedEnvironment: true, loadedEnvironmentMetadata: metadata }));
  }
  assert.equal(getterCalls, 0);
  assert.throws(() => createCveScheduler({ label: LABEL, loadedEnvironmentMetadata: { OSLogRateLimit: '64' } }));
});
test('hook is captured, not a later-mutable environment permission; raw output objects are never coerced', () => {
  const metadata = { XPC_SERVICE_NAME: LABEL, OSLogRateLimit: '64' };
  const shared = createCveScheduler({ label: LABEL, script: 'schedule-public-cve.mjs', strictLoadedEnvironment: true, loadedEnvironmentMetadata: metadata });
  metadata.OSLogRateLimit = '0'; metadata.EXTRA = 'PRIVATE';
  shared.validateLoadedAgent(withMetadata([`XPC_SERVICE_NAME => ${LABEL}`, 'OSLogRateLimit => 64']), metadataIdentity);
  assert.throws(() => shared.validateLoadedAgent(withMetadata(['OSLogRateLimit => 0']), metadataIdentity));
  assert.throws(() => shared.validateLoadedAgent({ toString() { assert.fail('raw output coercion'); } }, metadataIdentity));
});
