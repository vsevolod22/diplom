// Focused offline lane. Run explicitly: node --test scripts/test_deploy.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEPLOY_ERRORS, normalizeOptions, runDeployment } from './deploy-core.mjs';
import { main, parseArgs } from './deploy.mjs';
import { deployAdapterDiagnostic } from './deploy-adapter.mjs';
import { adapterFixture } from './deploy-adapter.test.mjs';
import { runIsolatedDocker, isolatedDockerDiagnostic } from './public-image-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const RAW = 'synthetic-private-stderr-DO-NOT-PRINT';
const web = { mode: 'web', apply: true };
const app = { mode: 'app', apply: true, services: ['api'] };
const allServices = ['web', 'api', 'worker', 'egress', 'llm-egress', 'openai-egress'];
function fake({ migration = false, safe = true, fault, mutate } = {}) {
  const calls = [], lease = Object.freeze({ owner: 'test-only' });
  const values = {
    status: { ready: true, locked: false }, acquireLock: lease,
    releaseLock: { released: true }, build: { image: 'candidate' },
    validateCandidate: { valid: true, requiredCapabilities: ['auth-a3'], availableCapabilities: ['auth-a3'] },
    verify: { valid: true }, waitForIdle: { idle: true }, prepareRecovery: { durable: true },
    fenceAdmissions: { fenced: true }, snapshot: { durable: true },
    qualifyState: { qualified: true, migration }, switchServices: { switched: true },
    health: { healthy: true }, publishReceipt: { published: true }, restoreOld: { restored: true },
  };
  const adapter = Object.fromEntries(['preflight', ...Object.keys(values)].map(name => [name, async ctx => {
    calls.push({ name, ctx });
    if (name !== 'acquireLock' && name !== 'status' && ctx.options.apply) assert.equal(ctx.lease, lease);
    mutate?.(name, ctx);
    if (name === fault) throw Object.assign(new Error(RAW), { stderr: RAW });
    if (name === 'preflight') return { services: [...ctx.services], interruptedServices: ctx.mode === 'web' ? ['web'] : ['api', 'web', 'worker'],
      migration, rollbackSafe: safe, old: { image: 'immutable-old', recipe: 'exact' }, availableCapabilities: ['auth-a3'] };
    return values[name];
  }]));
  return { adapter, calls, names: () => calls.map(c => c.name) };
}
function failure(result, code, phase) {
  assert.equal(result.ok, false); assert.equal(result.code, code); assert.equal(result.phase, phase);
  assert.ok(Object.hasOwn(DEPLOY_ERRORS, result.code)); assert.ok(result.nextAction.length > 10);
  assert.ok(!JSON.stringify(result).includes(RAW));
}

test('upgrade-operations CLI: valid all-six app parsing; invalid scopes never instantiate an adapter or execute an engine', async () => {
  const valid = parseArgs(['app', '--services', allServices.join(','), '--upgrade-operations', '--plan']);
  assert.equal(valid.upgradeOperations, true); assert.equal(valid.apply, false); assert.deepEqual(valid.services, allServices);
  const invalidUpgrade = [['web', '--upgrade-operations'], ['status', '--upgrade-operations'], ['app', '--services', 'api', '--upgrade-operations']];
  for (const args of [['--help'], [], ['app'], ['web', '--services', 'api'], ['web', '--apply', '--plan'], ['status', '--apply'], ['web', '--bogus'], ...invalidUpgrade]) {
    const child = spawnSync(process.execPath, [join(ROOT, 'scripts/deploy.mjs'), ...args], {
      cwd: ROOT, env: { PATH: '/nonexistent-test-engine' }, encoding: 'utf8', timeout: 3000,
    });
    assert.equal(child.error, undefined); assert.equal(child.stderr, '');
    assert.equal(child.status, args[0] === '--help' ? 0 : 1);
    if (args[0] === '--help') assert.match(child.stdout, /Usage:/);
    else failure(JSON.parse(child.stdout), args.includes('--upgrade-operations') ? 'DEPLOY_OPERATIONS_SCOPE' : 'DEPLOY_USAGE', 'arguments');
  }
  const original = console.log; const output = []; let loaded = 0;
  try {
    console.log = value => output.push(value);
    const factory = async () => { loaded++; throw Error(RAW); };
    assert.equal(await main(['--help'], factory), 0);
    assert.equal(await main(['invalid'], factory), 1);
    for (const args of invalidUpgrade) assert.equal(await main(args, factory), 1);
    assert.equal(loaded, 0);
    assert.equal(await main(['web'], factory), 1);
  } finally { console.log = original; }
  assert.ok(!output.join('').includes(RAW));
});

test('upgrade-operations core defaults false and rejects invalid scopes before lease; plan/status stay read-only', async () => {
  for (const options of [{ mode: 'web' }, { mode: 'status' }, { mode: 'app', services: allServices }]) {
    assert.equal(normalizeOptions(options).upgradeOperations, false);
    assert.equal(normalizeOptions({ ...options, upgradeOperations: false }).upgradeOperations, false);
  }
  for (const options of [{ mode: 'web' }, { mode: 'status' }, { mode: 'app', services: ['api'] }]) {
    const f = fake(); const result = await runDeployment(f.adapter, { ...options, upgradeOperations: true });
    failure(result, 'DEPLOY_OPERATIONS_SCOPE', 'arguments'); assert.deepEqual(f.names(), []);
  }
  for (const options of [{ mode: 'web' }, { mode: 'status' }]) {
    const f = fake(); assert.equal((await runDeployment(f.adapter, options)).ok, true);
    assert.deepEqual(f.names(), [options.mode === 'status' ? 'status' : 'preflight']);
  }
});

test('web single lease builds before switch and never fences, snapshots, migrates or verifies by default', async () => {
  const f = fake(); const result = await runDeployment(f.adapter, web);
  assert.equal(result.ok, true);
  assert.deepEqual(f.names(), ['acquireLock', 'preflight', 'build', 'validateCandidate', 'prepareRecovery', 'switchServices', 'health', 'publishReceipt', 'releaseLock']);
  for (const { ctx } of f.calls) assert.deepEqual(ctx.services, ['web']);
});

test('every non-migrating app snapshots and qualifies copies after durable recovery/fencing', async () => {
  const f = fake(); assert.equal((await runDeployment(f.adapter, app)).ok, true);
  assert.deepEqual(f.names(), ['acquireLock', 'preflight', 'build', 'validateCandidate', 'waitForIdle', 'prepareRecovery', 'fenceAdmissions', 'snapshot', 'qualifyState', 'switchServices', 'health', 'publishReceipt', 'releaseLock']);
  const qualify = f.calls.find(c => c.name === 'qualifyState').ctx;
  assert.equal(qualify.expectedMigration, false); assert.equal(qualify.snapshot.durable, true);
  assert.equal(f.calls.find(c => c.name === 'fenceAdmissions').ctx.fenceAttempted, true);
});

test('migration consent precedes build; actual startup boundary is flagged BEFORE switch dispatch', async () => {
  const denied = fake({ migration: true });
  failure(await runDeployment(denied.adapter, app), 'DEPLOY_MIGRATION_REQUIRED', 'preflight');
  assert.deepEqual(denied.names(), ['acquireLock', 'preflight', 'releaseLock']);
  const f = fake({ migration: true, fault: 'switchServices', mutate(name, ctx) {
    if (name === 'switchServices') { assert.equal(ctx.migrationAttempted, true); assert.equal(ctx.switchAttempted, true); }
  } });
  const result = await runDeployment(f.adapter, { ...app, migrate: true });
  failure(result, 'DEPLOY_SWITCH', 'switchServices'); assert.equal(result.lock, 'retained');
  assert.ok(!f.names().includes('restoreOld')); assert.ok(!f.names().includes('releaseLock'));
});

test('build failure leaves OLD serving and releases exactly the owned lease', async () => {
  const f = fake({ fault: 'build' }); const result = await runDeployment(f.adapter, web);
  failure(result, 'DEPLOY_BUILD', 'build'); assert.equal(result.keptOldServing, true);
  assert.equal(result.lock, 'released'); assert.deepEqual(f.names(), ['acquireLock', 'preflight', 'build', 'releaseLock']);
});

test('shared lock refusal has no preflight, build or release side effects', async () => {
  const f = fake(); f.adapter.acquireLock = async () => { throw Object.assign(Error(RAW), { code: 'DEPLOY_LOCKED' }); };
  const result = await runDeployment(f.adapter, web); failure(result, 'DEPLOY_LOCKED', 'acquireLock');
  assert.deepEqual(f.names(), []); assert.equal(result.lock, 'not-acquired');
});

test('fencing/snapshot/copy-qualification failures HOLD without app or DB rollback', async () => {
  for (const [fault, code] of [['fenceAdmissions', 'DEPLOY_FENCE'], ['snapshot', 'DEPLOY_SNAPSHOT'], ['qualifyState', 'DEPLOY_QUALIFY']]) {
    const f = fake({ fault }); const result = await runDeployment(f.adapter, app);
    failure(result, code, fault); assert.equal(result.lock, 'retained'); assert.equal(result.needsRecovery, true);
    assert.ok(!f.names().includes('releaseLock')); assert.ok(!f.names().includes('restoreOld')); assert.ok(!f.names().includes('switchServices'));
  }
});

test('publication uncertainty always HOLDs, even for known-safe web', async () => {
  const f = fake({ fault: 'publishReceipt' }); const result = await runDeployment(f.adapter, web);
  failure(result, 'DEPLOY_RECEIPT', 'publishReceipt'); assert.equal(result.state, 'publication-uncertain');
  assert.equal(result.lock, 'retained'); assert.equal(result.publishAttempted, true);
  assert.ok(!f.names().includes('restoreOld')); assert.ok(!f.names().includes('releaseLock'));
});

test('web health failure restores only proven OLD then verifies OLD health before unlock', async () => {
  const f = fake(); f.adapter.health = async ctx => {
    f.calls.push({ name: 'health', ctx }); if (ctx.target === 'candidate') throw Error(RAW); return { healthy: true };
  };
  const result = await runDeployment(f.adapter, web); failure(result, 'DEPLOY_HEALTH', 'health');
  assert.equal(result.rollback, 'restored'); assert.equal(result.lock, 'released');
  assert.deepEqual(f.names().slice(-3), ['restoreOld', 'health', 'releaseLock']);
  assert.equal(f.calls.at(-2).ctx.target, 'old');
});

test('unknown OLD identity or uncertain restore retains recovery and never unlocks', async () => {
  for (const options of [{ safe: false, fault: 'health' }, { fault: 'restoreOld' }]) {
    const f = fake(options);
    if (options.fault === 'restoreOld') f.adapter.health = async () => { throw Error(RAW); };
    const result = await runDeployment(f.adapter, web); assert.equal(result.ok, false); assert.equal(result.lock, 'retained');
    assert.equal(result.state, 'recovery-required'); assert.ok(!f.names().includes('releaseLock'));
  }
});

test('finite errors ignore code getters; drain settles before owned lease release without a competing timer', async () => {
  const f = fake(); f.adapter.build = async () => { const e = Error(RAW); Object.defineProperty(e, 'code', { get() { assert.fail('unsafe getter'); } }); throw e; };
  failure(await runDeployment(f.adapter, web), 'DEPLOY_BUILD', 'build');
  const d = fake(); let rejectDrain, entered;
  const started = new Promise(resolve => { entered = resolve; });
  d.adapter.waitForIdle = async ctx => {
    assert.equal(ctx.options.drainTimeoutMs, 1); assert.equal(ctx.signal, undefined);
    entered(); return new Promise((_, reject) => { rejectDrain = reject; });
  };
  const pending = runDeployment(d.adapter, { ...app, drainTimeoutMs: 1 });
  await started;
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.ok(!d.names().includes('releaseLock'), 'core must await adapter settlement even past the drain budget');
  rejectDrain(Object.assign(Error(RAW), { code: 'DEPLOY_DRAIN' }));
  const result = await pending; failure(result, 'DEPLOY_DRAIN', 'waitForIdle');
  assert.equal(result.lock, 'released'); assert.ok(!d.names().includes('fenceAdmissions'));
});

test('actual adapter web: publish happy path and restore identified exited candidate with backend isolation', { timeout: 20000 }, async t => {
  for (const failedStart of [null, 'web']) {
    const f = await adapterFixture(t, { failedStart }); const before = structuredClone(f.containers());
    const oldWeb = before.find(c => f.role(c) === 'web');
    const result = await runDeployment(f.adapter, web);
    if (failedStart) {
      failure(result, 'DEPLOY_SWITCH', 'switchServices');
      assert.equal(result.rollback, 'restored', JSON.stringify(f.diagnostics));
      assert.equal(result.state, 'old-restored');
      assert.equal(f.containers().find(c => f.role(c) === 'web').Image, oldWeb.Image);
      assert.notEqual(f.containers().find(c => f.role(c) === 'web').Id, oldWeb.Id);
      assert.equal(f.events.filter(e => e === 'up:web').length, 2);
    } else assert.equal(result.ok, true, JSON.stringify({ result, diagnostics: f.diagnostics }));
    assert.equal(result.lock, 'released'); assert.equal(f.locked(), false);
    assert.deepEqual(f.containers().filter(c => f.role(c) !== 'web'), before.filter(c => f.role(c) !== 'web'));
    assert.ok(f.events.includes('build:web')); assert.ok(f.events.includes('up:web'));
    assert.ok(f.events.indexOf('build:web') < f.events.indexOf('up:web'));
    assert.ok(!f.events.some(e => /^(stop|start|up):(api|worker|.*egress)|helper/.test(e)));
    assert.equal(f.pins().services.web.image, f.containers().find(c => f.role(c) === 'web').Image);
    f.verifyStores();
  }
});

test('actual adapter app: full copy-qualified happy path and failed API startup HOLD', { timeout: 30000 }, async t => {
  for (const failedStart of [null, 'api']) {
    const f = await adapterFixture(t, { failedStart }); const pinsBefore = f.pins();
    const result = await runDeployment(f.adapter, app);
    if (failedStart) {
      failure(result, 'DEPLOY_SWITCH', 'switchServices');
      assert.equal(result.lock, 'retained'); assert.equal(f.locked(), true);
      assert.equal(result.rollback, 'unsafe'); assert.equal(result.publishAttempted, false);
      assert.equal(f.containers().find(c => f.role(c) === 'web').State.Running, false);
      assert.deepEqual(f.pins(), pinsBefore);
      assert.ok(!f.events.includes('snapshot:after-api'));
    } else {
      assert.equal(result.ok, true, JSON.stringify({ result, diagnostics: f.diagnostics, events: f.events }));
      assert.equal(f.locked(), false);
      assert.ok(f.events.indexOf('snapshot:after-api') > f.events.indexOf('up:api'));
      for (const c of f.containers()) assert.equal(f.pins().services[f.role(c)].image, c.Image);
    }
    assert.ok(f.events.indexOf('build:api') < f.events.indexOf('stop:web'));
    assert.deepEqual(f.events.filter(e => e.startsWith('stop:') && !e.includes('helper')), ['stop:web', 'stop:api', 'stop:worker']);
    assert.ok(f.events.includes('up:api'), JSON.stringify({ result, diagnostics: f.diagnostics }));
    assert.ok(f.events.indexOf('snapshot:fenced') < f.events.indexOf('up:api'));
    assert.ok(f.events.indexOf('snapshot:before-api') < f.events.indexOf('up:api'));
    assert.ok(!f.events.some(e => /^(stop|start|up):.*egress/.test(e)));
    f.verifyStores();
  }
});

test('upgrade-operations actual adapter: default preserves prior preset, explicit all-six plans v2, invalid scope is inert; shared lease ownership', { timeout: 20000 }, async t => {
  const f = await adapterFixture(t); const lease = await f.adapter.acquireLock({ options: web });
  assert.equal(f.locked(), true);
  await assert.rejects(f.adapter.acquireLock({ options: web }), e => e.code === 'DEPLOY_LOCKED');
  await assert.rejects(f.adapter.releaseLock({ lease: {}, options: web }), e => e.code === 'DEPLOY_UNLOCK');
  assert.equal(f.locked(), true);
  assert.deepEqual(await f.adapter.releaseLock({ lease, options: web }), { released: true });
  assert.equal(f.locked(), false);
  const readOnly = fixture => {
    assert.deepEqual(fixture.events, [], 'planning must not build, stop, snapshot or switch');
    assert.equal(fixture.locked(), false);
    assert.ok(!fixture.calls.some(args => ['build', 'create'].includes(args[0]) ||
      args[0] === 'container' && ['stop', 'start', 'rm'].includes(args[1]) || args[0] === 'compose' && args.includes('up')));
  };
  assert.equal(f.publishedSelection.operations, undefined); assert.equal(f.configuredSelection.operations, undefined);
  const options = { mode: 'app', services: allServices };
  const unchanged = await runDeployment(f.adapter, options);
  assert.equal(unchanged.ok, true, JSON.stringify({ unchanged, diagnostics: f.diagnostics }));
  assert.equal(unchanged.upgradeOperations, false); assert.equal(unchanged.operations, null); readOnly(f);
  // Both descriptor and OLD lack operations: only the real adapter's explicit
  // selectOpenAiOperations(..., true) path can select the v2 preset here.
  const upgraded = await runDeployment(f.adapter, { ...options, upgradeOperations: true });
  assert.equal(upgraded.ok, true, JSON.stringify({ upgraded, diagnostics: f.diagnostics }));
  assert.equal(upgraded.phase, 'plan'); assert.equal(upgraded.operations, 'public-images-v2');
  assert.equal(upgraded.upgradeOperations, true); assert.deepEqual([...upgraded.services].sort(), [...allServices].sort()); readOnly(f);
  for (const [mode, services] of [['web', ['web']], ['status', []], ['app', ['api']]]) {
    const callsBefore = f.calls.length;
    await assert.rejects(f.rawAdapter.prepare({ mode, services, upgradeOperations: true }), error =>
      ['OPERATIONS_UPGRADE_REQUIRES_ALL_APP_TARGETS', 'TARGETS_INVALID'].includes(deployAdapterDiagnostic(error).code));
    assert.equal(f.calls.length, callsBefore, 'invalid scope must fail before any engine command'); readOnly(f);
  }
  const prior = await adapterFixture(t, { publishedOperations: true });
  assert.equal(prior.publishedSelection.operations, 'public-images-v2');
  assert.equal(prior.configuredSelection.operations, undefined, 'operator descriptor need not repeat the published preset');
  const preserved = await runDeployment(prior.adapter, options);
  assert.equal(preserved.ok, true, JSON.stringify({ preserved, diagnostics: prior.diagnostics }));
  assert.equal(preserved.upgradeOperations, false); assert.equal(preserved.operations, 'public-images-v2'); readOnly(prior);
});

async function preparedStopFixture(t, options) {
  const f = await adapterFixture(t, options);
  const ctx = { options: { ...app }, mode: 'app', services: ['api'] };
  ctx.lease = await f.rawAdapter.acquireLock(ctx);
  ctx.plan = await f.rawAdapter.preflight(ctx); ctx.interruptedServices = ctx.plan.interruptedServices;
  ctx.candidate = await f.rawAdapter.build(ctx);
  assert.equal((await f.rawAdapter.validateCandidate(ctx)).valid, true);
  assert.equal((await f.rawAdapter.waitForIdle(ctx)).idle, true);
  ctx.recovery = await f.rawAdapter.prepareRecovery(ctx); ctx.fenceAttempted = true;
  return { f, ctx, pinsBefore: f.pins(), before: structuredClone(f.containers()) };
}

function assertStopCommandAndHold(f, before, pinsBefore) {
  const stops = f.calls.filter(args => args[0] === 'container' && args[1] === 'stop');
  assert.ok(stops.length > 0);
  for (const command of stops) {
    assert.deepEqual(command.slice(0, 4), ['container', 'stop', '--timeout', '30']);
    assert.equal(command.length, 5); assert.match(command[4], /^[a-f0-9]{64}$/);
    assert.ok(before.some(c => c.Id === command[4]), 'stop must address the exact recorded ID');
  }
  f.verifyStores(); assert.deepEqual(f.pins(), pinsBefore); assert.equal(f.locked(), true);
  assert.ok(!f.events.some(e => /^(start|up|snapshot):/.test(e)));
}

test('stop-stdout real wrapper empty acknowledgement plus independent clean-stop proof succeeds', { timeout: 15000 }, async t => {
  const id = 'a'.repeat(64), args = ['container', 'stop', '--timeout', '30', id];
  for (const stdout of [id + '\n', '']) {
    let invocations = 0;
    const result = await runIsolatedDocker(args, { root: ROOT, env: {}, timeout: 1234 }, (executable, argv, options, callback) => {
      invocations++; assert.equal(executable, 'docker'); assert.deepEqual(argv, args);
      assert.equal(options.encoding, 'utf8'); assert.equal(options.timeout, 1234);
      callback(null, stdout, RAW);
    });
    assert.equal(invocations, 1); assert.equal(typeof result, 'string'); assert.equal(result, stdout);
    assert.ok(!result.includes(RAW));
  }
  await assert.rejects(runIsolatedDocker(args, { root: ROOT, env: {} }, (_exe, _args, _options, callback) => {
    callback(Object.assign(Error(RAW), { code: 1 }), id + '\n', RAW);
  }), error => {
    assert.equal(isolatedDockerDiagnostic(error).exitCode, 1);
    assert.ok(!error.message.includes(RAW)); return true;
  });
  const { f, ctx, pinsBefore, before } = await preparedStopFixture(t, { stopStdout: 'empty' });
  try {
    assert.deepEqual(await f.rawAdapter.fenceAdmissions(ctx), { fenced: true });
  } catch (error) {
    assert.fail(JSON.stringify({ diagnostic: deployAdapterDiagnostic(error), events: f.events,
      stopped: f.containers().filter(c => !c.State.Running).map(c => f.role(c)), lockRetained: f.locked() }));
  } finally {
    assertStopCommandAndHold(f, before, pinsBefore);
  }
  assert.deepEqual(f.events.filter(e => e.startsWith('stop:')), ['stop:web', 'stop:api', 'stop:worker']);
  assert.ok(f.events.indexOf('build:api') < f.events.indexOf('stop:web'));
  for (const name of ['web', 'api', 'worker']) {
    const c = f.containers().find(c => f.role(c) === name);
    assert.equal(c.State.Running, false); assert.equal(c.State.Status, 'exited');
    assert.equal(c.State.Pid, 0); assert.equal(c.State.ExitCode, 0);
    const original = before.find(previous => f.role(previous) === name);
    assert.equal(c.Id, original.Id); assert.equal(c.State.StartedAt, original.State.StartedAt);
    assert.deepEqual(c.Config, original.Config); assert.deepEqual(c.HostConfig, original.HostConfig);
  }
  // No release/resume: the regression ends at fenced state in disposable temp files.
});

test('stop-stdout echoed ID cannot authorize bad identity/control/epoch/nonclean exit or uncertain dispatch', { timeout: 30000 }, async t => {
  for (const fault of ['identity', 'control', 'started-at', 'nonclean', 'dispatch']) {
    const { f, ctx, pinsBefore, before } = await preparedStopFixture(t, { stopStdout: 'id', stopFault: fault });
    const callsBeforeFence = f.calls.length;
    const code = fault === 'nonclean' ? 'WRITER_NOT_CLEANLY_STOPPED' : fault === 'dispatch' ? 'STOP_DISPATCH_FAILED' : 'STOP_CONTROL_CHANGED';
    await assert.rejects(f.rawAdapter.fenceAdmissions(ctx), error => {
      const diagnostic = deployAdapterDiagnostic(error);
      assert.equal(diagnostic.code, code, fault);
      if (fault === 'dispatch') {
        assert.equal(diagnostic.cause, 'EXIT_NONZERO'); assert.equal(diagnostic.exitCode, 1);
        assert.equal(diagnostic.stdoutBytes, 65, 'nonzero executor supplied a full ID echo but still grants no stop authority');
      }
      return true;
    }, fault + ' must fail even when the executor supplied the matching ID on stdout');
    assert.deepEqual(f.events.filter(e => e.startsWith('stop:')), ['stop:web'], fault + ': no further writers may be stopped');
    const webId = before.find(c => f.role(c) === 'web').Id;
    const afterCalls = f.calls.slice(callsBeforeFence);
    const stopIndex = afterCalls.findIndex(args => args[0] === 'container' && args[1] === 'stop');
    if (fault !== 'dispatch') {
      assert.deepEqual(afterCalls[stopIndex + 1], ['container', 'inspect', webId], 'successful dispatch must independently inspect the exact ID');
    }
    assertStopCommandAndHold(f, before, pinsBefore);
  }
});

test('helper-authority actual adapter accepts only proven false-to-null OOM default and completes fenced four-store snapshot', { timeout: 35000 }, async t => {
  const control = c => Object.fromEntries(['Id', 'Image', 'Name', 'Path', 'Args', 'Config', 'HostConfig', 'Mounts'].map(key => [key, c[key]]));
  for (const transition of ['oom-null', 'oom-true', 'readonly-drift', 'mount-drift']) {
    const { f, ctx, pinsBefore, before } = await preparedStopFixture(t, { helperTransition: transition });
    assert.deepEqual(await f.rawAdapter.fenceAdmissions(ctx), { fenced: true });
    assertStopCommandAndHold(f, before, pinsBefore);
    const callsBeforeSnapshot = f.calls.length;
    if (transition === 'oom-null') {
      ctx.snapshot = await f.rawAdapter.snapshot(ctx);
      assert.equal(ctx.snapshot.durable, true); assert.equal(ctx.snapshot.stores.historyVersion, 4);
      assert.deepEqual(Object.keys(ctx.snapshot.stores.core).sort(), ['auth', 'ledger']);
      assert.deepEqual(Object.keys(ctx.snapshot.stores.llm).sort(), ['history', 'quota']);
      for (const value of Object.values(ctx.snapshot.stores.core)) assert.match(value.logicalSha256, /^[a-f0-9]{64}$/);
      for (const value of Object.values(ctx.snapshot.stores.llm)) assert.match(value, /^[a-f0-9]{64}$/);
      assert.equal(f.containers().filter(c => f.role(c) === undefined).length, 0, 'validated helper must finish and be removed');
    } else {
      await assert.rejects(f.rawAdapter.snapshot(ctx), error => {
        const diagnostic = deployAdapterDiagnostic(error);
        assert.match(diagnostic.code, /^(?:HELPER_[A-Z_]+|ADAPTER_SNAPSHOT_FAILED)$/);
        return true;
      }, transition + ' must not gain authority from normalizing OomKillDisable');
      assert.ok(!f.calls.slice(callsBeforeSnapshot).some(args => args[0] === 'container' && ['exec', 'rm'].includes(args[1])),
        'invalid helper must be rejected before readiness/export or successful removal');
    }
    assert.equal(f.helperTransitions.length, 1);
    const observed = f.helperTransitions[0];
    assert.equal(observed.created.HostConfig.OomKillDisable, false);
    if (transition === 'oom-null') {
      const expected = structuredClone(control(observed.created)); expected.HostConfig.OomKillDisable = null;
      assert.deepEqual(control(observed.running), expected, 'only the evidenced OOM default may change; mounts/security/commands stay exact');
    } else if (transition === 'oom-true') assert.equal(observed.running.HostConfig.OomKillDisable, true);
    else if (transition === 'readonly-drift') assert.equal(observed.running.HostConfig.ReadonlyRootfs, false);
    else assert.equal(observed.running.Mounts[0].RW, true);
    assert.ok(f.events.indexOf('stop:worker') < f.events.indexOf('start:helper'), 'writers must be stopped before helper startup');
    for (const name of ['web', 'api', 'worker']) {
      const current = f.containers().find(c => f.role(c) === name);
      const old = before.find(c => f.role(c) === name);
      assert.equal(current.State.Running, false); assert.equal(current.State.ExitCode, 0);
      assert.equal(current.Id, old.Id); assert.equal(current.State.StartedAt, old.State.StartedAt);
      assert.deepEqual(control(current), control(old), 'helper equivalence must not weaken peer control checks');
    }
    assert.ok(!f.diagnostics.some(diagnostic => diagnostic.fakeEngineFailure), 'failures must come from adapter validation, not a broken fake');
    assert.ok(!f.events.some(event => event.startsWith('up:') || event.startsWith('start:') && event !== 'start:helper'));
    f.verifyStores(); assert.deepEqual(f.pins(), pinsBefore); assert.equal(f.locked(), true);
  }
});

test('lifecycle-empty actual adapter complete app verifies state through helper start-stop-rm and retained starts, never stdout authority', { timeout: 45000 }, async t => {
  for (const fault of [null, 'stop-error', 'stop-control', 'stop-137', 'rm-present']) {
    const f = await adapterFixture(t, { lifecycleStdout: 'empty', helperTransition: 'oom-null', helperLifecycleFault: fault });
    const pinsBefore = f.pins(); const before = structuredClone(f.containers());
    const result = await runDeployment(f.adapter, app);
    if (fault === null) {
      assert.equal(result.ok, true, JSON.stringify({ result, diagnostics: f.diagnostics, events: f.events }));
      assert.equal(result.phase, 'complete'); assert.equal(result.lock, 'released'); assert.equal(f.locked(), false);
      assert.deepEqual(f.events.filter(event => event.startsWith('snapshot:')), ['snapshot:fenced', 'snapshot:before-api', 'snapshot:after-api']);
      assert.equal(f.helperTransitions.length, 3); assert.equal(f.events.filter(event => event === 'rm:helper').length, 3);
      assert.equal(f.containers().filter(c => f.role(c) === undefined).length, 0);
      for (const name of ['worker', 'web']) {
        const old = before.find(c => f.role(c) === name), current = f.containers().find(c => f.role(c) === name);
        assert.equal(current.Id, old.Id, name + ' must resume unchanged, not be upgraded');
        assert.notEqual(current.State.StartedAt, old.State.StartedAt); assert.equal(current.State.Running, true);
        assert.ok(f.lifecycleReplies.some(reply => reply.args[0] === 'container' && reply.args[1] === 'start' && reply.args[2] === old.Id && reply.stdout === ''));
      }
      assert.ok(f.events.indexOf('build:api') < f.events.indexOf('stop:web'));
      assert.ok(f.events.indexOf('stop:worker') < f.events.indexOf('start:helper'));
      assert.ok(f.events.indexOf('snapshot:before-api') < f.events.indexOf('up:api'));
      assert.ok(f.events.indexOf('snapshot:after-api') > f.events.indexOf('up:api'));
      for (const c of f.containers()) assert.equal(f.pins().services[f.role(c)].image, c.Image);
    } else {
      failure(result, 'DEPLOY_SNAPSHOT', 'snapshot');
      assert.equal(result.lock, 'retained'); assert.equal(result.needsRecovery, true); assert.equal(f.locked(), true);
      assert.equal(result.publishAttempted, false); assert.equal(result.rollback, 'unsafe');
      assert.deepEqual(f.pins(), pinsBefore); assert.ok(!f.events.includes('up:api'));
      assert.ok(!f.events.includes('start:worker')); assert.ok(!f.events.includes('start:web'));
      if (fault === 'stop-error') {
        assert.ok(f.lifecycleReplies.some(reply => reply.exitCode === 1 && reply.stdout.trim().length === 64), 'subprocess failure must reject despite a matching ID echo');
      } else assert.ok(f.lifecycleReplies.every(reply => reply.exitCode === 0), 'bad inspection/removal state must reject even with all commands exiting zero');
      if (fault === 'rm-present') {
        assert.ok(f.events.includes('rm:helper')); assert.equal(f.containers().filter(c => f.role(c) === undefined).length, 1,
          'rm exit zero plus empty output cannot prove disappearance');
      }
    }
    const creates = f.lifecycleReplies.filter(reply => reply.args[0] === 'create');
    assert.equal(creates.length, fault === null ? 3 : 1);
    for (const reply of creates) assert.match(reply.stdout.trim(), /^[a-f0-9]{64}$/, 'create must still supply an exact nonempty helper ID');
    for (const reply of f.lifecycleReplies.filter(reply => reply.args[0] === 'container')) {
      if (reply.exitCode === 0) assert.equal(reply.stdout, '', 'every successful start/stop/rm uses real-wrapper empty stdout');
      if (reply.args[1] === 'stop') {
        assert.equal(reply.args[2], '--timeout'); assert.ok(['10', '30'].includes(reply.args[3]));
        assert.match(reply.args[4], /^[a-f0-9]{64}$/); assert.equal(reply.args.length, 5);
      }
    }
    assert.ok(!f.events.some(event => /^(?:stop|start|up):.*egress/.test(event)));
    f.verifyStores();
  }
});
