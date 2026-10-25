// Offline policy/source regressions only: no Docker client, child processes,
// provider requests, source qualification/builds, or native/live SQLite access.
// Synthetic fingerprints below exercise ordering/equality, not SQLite recovery.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import {
  executePublicLlmMaintenance, publicLlmStand, expectedPublicLlmConfig, inspectPublicLlmNamespace, PUBLIC_LLM_ENV, publicLlmEnvironmentOverlay,
  validatePublicLlmContainer, validatePublicLlmImage, publicLlmHelperArguments, PUBLIC_LLM_BACKUP_PROGRAM,
  PUBLIC_LLM_CHECK_PROGRAM, PUBLIC_LLM_INITIALIZE_PROGRAM, capturePublicLlmSource,
} from './public-llm-stand.mjs';
import { PROJECT, LABEL, readProfile } from './public-image-stand.mjs';
import {
  byteFile, privateFile, capturePublicLlmExecutionClosure, PUBLIC_LLM_EXECUTION_MODULES,
} from './public-llm-build-continuation.mjs';
import { fixture } from './public-refresh-cve-fixtures.mjs';
import * as existingBuildModule from './public-llm-existing-build-continuation.mjs';
import {
  EXISTING_BUILD_HOLD, preparePublicLlmExistingBuildContinuation, captureExistingBuildExecution,
  publicLlmExistingBuildStand, classifyExistingBuildCause, runExistingBuildDocker,
  inspectExistingBuildPriorImage, existingBuildMetadataDiagnostic,
  EXISTING_BUILD_GATEWAY_RESTART, validateExistingBuildPeerEpoch,
  classifyExistingWorkerOutputFailure, EXISTING_BUILD_WORKER_OUTPUT_RETIREMENT,
  validateExistingWorkerOutputRetirement, inspectExistingBuildOwnTags,
} from './public-llm-existing-build-continuation.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const AUDIT = 'deploy-2c9ed08b8269264b09bf14eb6189a649';
const KEY = 'diplom-public-8081-llm-key-' + 'a'.repeat(32);
const SELECTION = Object.freeze({ version: 1, keyVolume: KEY });
const sha = text => createHash('sha256').update(text).digest('hex');
const clone = value => structuredClone(value);
const role = c => c.Config.Labels['com.docker.compose.service'];
const ORIGINAL = Object.freeze({
  core: { auth: { logicalSha256: sha('nonempty-auth') }, ledger: { logicalSha256: sha('nonempty-reports') } },
  llm: { history: sha('nonempty-history'), quota: sha('nonempty-quota') },
  empty: false,
});

function temporary(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'existing-llm-policy-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

// Same seven-service/six-network extension as test_public_llm_stand.mjs,
// using only disposable metadata from the shared offline fixture.
function existingNamespace(t) {
  const f = fixture(t);
  const profile = JSON.parse(fs.readFileSync(join(f.stand, 'profile.json')));
  const api = f.containers.find(c => role(c) === 'api');
  const bound = {
    ...profile.cve,
    releaseHostDir: api.Mounts.find(m => m.Destination === '/opt/release').Source,
    publicKeyPath: api.Mounts.find(m => m.Destination === '/opt/local-db-trust/public.pem').Source,
  };
  const model = expectedPublicLlmConfig(f.root, bound, SELECTION);
  f.images['llm-egress'] = clone(f.images.egress);
  Object.assign(f.images['llm-egress'], { Id: 'sha256:' + 'e'.repeat(64), RepoTags: [`${PROJECT}-llm-egress:local`] });
  f.images['llm-egress'].Config.Cmd = ['python', '-I', 'openrouter.py'];
  f.containers = Object.entries(model.services).map(([name, spec], index) => {
    const c = f.makeContainer(name, spec, index);
    if (name === 'llm-egress') c.Config.Env = clone(f.images[name].Config.Env);
    for (const m of c.Mounts.filter(m => m.Type === 'volume')) {
      m.Driver = 'local'; m.Source = `/fixture/volumes/${m.Name}`;
    }
    if (name === 'api') {
      const desired = c.HostConfig.Mounts.find(m => m.Target === '/run/secrets');
      const actual = c.Mounts.find(m => m.Destination === '/run/secrets');
      Object.assign(desired, { Source: KEY, VolumeOptions: { NoCopy: true } });
      Object.assign(actual, { Name: KEY, Source: `/fixture/volumes/${KEY}` });
    }
    return c;
  });
  f.networks = Object.values(model.networks).map(n => ({
    Name: n.name, Id: sha(n.name), Driver: 'bridge', Labels: { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT },
    Internal: Boolean(n.internal), Options: null,
    Containers: Object.fromEntries(f.containers.filter(c => c.State.Running && c.NetworkSettings.Networks[n.name]).map(c => [c.Id, {}])),
  }));
  f.volumes.push({ Name: KEY, Driver: 'local', Scope: 'local', Mountpoint: `/fixture/volumes/${KEY}`, Options: null, Labels: { 'diplom.public-llm': 'key-v1' } });
  const metadata = async (args, options) => {
    assert(['ls', 'inspect'].includes(args[1]), 'offline metadata seam refuses lifecycle');
    // The base fixture predates external key volumes and prints PROJECT for
    // every census row. Preserve actual ownership so a foreign consumer is
    // caught by the all-consumer query, not a false own-name collision.
    if (args[1] === 'ls' && ['container', 'volume', 'network'].includes(args[0]) && !args.includes('--filter')) {
      f.calls.push({ kind: 'docker', args });
      return f[`${args[0]}s`].map(item => {
        const labels = args[0] === 'container' ? item.Config.Labels : item.Labels;
        return `${item.Name.startsWith('/') ? item.Name.slice(1) : item.Name}\t${labels['com.docker.compose.project'] ?? ''}`;
      }).join('\n');
    }
    return f.docker(args, options);
  };
  const inspect = () => inspectPublicLlmNamespace(metadata, { root: f.root, env: { DOCKER_HOST: f.endpoint }, timeout: 15000 }, f.root, bound, SELECTION, { images: f.images });
  return { f, model, bound, inspect, metadata };
}

function operations({ fault, mutate } = {}) {
  const calls = [], ops = {};
  for (const name of ['preflight', 'intent', 'stop', 'drain', 'candidate', 'initialize', 'startRetained', 'up', 'ready', 'publish', 'complete']) {
    ops[name] = async value => {
      calls.push([name, value]);
      if (fault === name) throw Error('synthetic boundary refusal');
    };
  }
  ops.snapshot = async phase => {
    calls.push(['snapshot', phase]);
    const result = clone(ORIGINAL);
    mutate?.(result, phase);
    return result;
  };
  return { ops, calls };
}

function sourceFixture(t, root = temporary(t)) {
  // Read only explicitly named source inputs, never a repository state directory.
  const inputs = [
    ...PUBLIC_LLM_EXECUTION_MODULES, 'scripts/public-llm-existing-build-continuation.mjs', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
    'index.html', 'admin.html', 'vite.config.ts', 'tsconfig.json', '.gitignore', '.dockerignore',
    'server/api/package.json', 'server/api/tsconfig.json', 'server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/compose.public-images.yaml', 'server/deploy/compose.public-llm.yaml',
    'server/deploy/public-stand.Dockerfile', 'server/deploy/public-stand.nginx.conf',
    'server/deploy/api.Dockerfile', 'server/deploy/worker.Dockerfile',
    'server/deploy/gateway/Dockerfile', 'server/deploy/gateway/proxy.py',
    'server/deploy/gateway/openrouter.Dockerfile', 'server/deploy/gateway/openrouter.py',
  ];
  for (const path of new Set(inputs)) {
    fs.mkdirSync(dirname(join(root, path)), { recursive: true });
    fs.copyFileSync(join(ROOT, path), join(root, path));
  }
  for (const path of ['src', 'public', 'server/api/src', 'server/runtime/src']) fs.mkdirSync(join(root, path), { recursive: true });
  fs.writeFileSync(join(root, 'src/placeholder.ts'), 'export {};\n');
  return root;
}

test('POLICY existing nonempty four-store continuation compares original baseline before candidate; checks, never initializes', async () => {
  const x = operations();
  assert.equal((await executePublicLlmMaintenance(x.ops, clone(ORIGINAL))).outcome, 'ready');
  assert.deepEqual(x.calls.slice(0, 4), [['preflight', undefined], ['intent', undefined], ['snapshot', 'fenced'], ['candidate', undefined]]);
  assert.deepEqual(x.calls.filter(([name]) => name === 'initialize'), [['initialize', false]]);
  assert(!x.calls.some(([name]) => ['stop', 'drain'].includes(name)), 'the held stopped peers must not be restarted/drained again');
  assert.deepEqual(x.calls.slice(-4), [['publish', undefined], ['up', 'web'], ['ready', 'web'], ['complete', undefined]]);
});

for (const store of ['auth', 'ledger', 'history', 'quota']) {
  test(`POLICY fresh fenced ${store} drift refuses before candidate/build, check or application start`, async () => {
    const x = operations({ mutate(value, phase) {
      if (phase !== 'fenced') return;
      if (store === 'auth' || store === 'ledger') value.core[store].logicalSha256 = sha('changed');
      else value.llm[store] = sha('changed');
    } });
    await assert.rejects(executePublicLlmMaintenance(x.ops, clone(ORIGINAL)));
    assert.deepEqual(x.calls, [['preflight', undefined], ['intent', undefined], ['snapshot', 'fenced']]);
  });
}

for (const missing of [null, {}, { history: ORIGINAL.llm.history }]) {
  test(`POLICY missing/mixed LLM snapshot ${JSON.stringify(missing)} never becomes an initializer fallback`, async () => {
    const x = operations({ mutate(value, phase) { if (phase === 'fenced') value.llm = missing; } });
    await assert.rejects(executePublicLlmMaintenance(x.ops, clone(ORIGINAL)));
    assert(!x.calls.some(([name]) => ['candidate', 'initialize', 'up', 'publish'].includes(name)));
  });
}

for (const phase of ['before-api', 'after-api']) for (const store of ['auth', 'ledger', 'history', 'quota']) {
  test(`POLICY ${phase} ${store} drift keeps admission closed`, async () => {
    const x = operations({ mutate(value, at) {
      if (at !== phase) return;
      if (store === 'auth' || store === 'ledger') value.core[store].logicalSha256 = sha('changed');
      else value.llm[store] = sha('changed');
    } });
    await assert.rejects(executePublicLlmMaintenance(x.ops, clone(ORIGINAL)));
    assert(!x.calls.some(([name, role]) => name === 'publish' || name === 'up' && (phase === 'before-api' ? ['api', 'web'] : ['web']).includes(role)));
  });
}

for (const fault of ['preflight', 'intent', 'candidate', 'initialize', 'startRetained', 'up', 'ready', 'publish']) {
  test(`POLICY ${fault} refusal dispatches that boundary once, with no automatic retry/complete`, async () => {
    const x = operations({ fault });
    await assert.rejects(executePublicLlmMaintenance(x.ops, clone(ORIGINAL)));
    assert.equal(x.calls.filter(([name]) => name === fault).length, 1);
    assert.equal(x.calls.filter(([name]) => name === 'intent').length, fault === 'preflight' ? 0 : 1);
    assert(!x.calls.some(([name]) => name === 'complete'));
  });
}

test('METADATA fixture qualifies exactly seven services/six networks and selected key only on readonly API', async t => {
  const x = existingNamespace(t), seen = await x.inspect();
  assert.equal(seen.containers.length, 7); assert.equal(seen.networks.length, 6); assert.equal(seen.volumes.length, 3);
  assert.deepEqual(seen.containers.filter(c => c.Mounts.some(m => m.Name === KEY)).map(role), ['api']);
  const m = seen.containers.find(c => role(c) === 'api').Mounts.find(m => m.Name === KEY);
  assert.equal(m.RW, false);
  assert(x.f.calls.every(c => ['ls', 'inspect'].includes(c.args[1])), 'metadata-only runner must not execute lifecycle');
});

for (const mutation of ['writable-key', 'copy-up-key', 'foreign-key', 'inline-provider-key']) {
  test(`METADATA API ${mutation} refuses without lifecycle`, t => {
    const x = existingNamespace(t), api = clone(x.f.containers.find(c => role(c) === 'api'));
    const desired = api.HostConfig.Mounts.find(m => m.Target === '/run/secrets');
    if (mutation === 'writable-key') { desired.ReadOnly = false; api.Mounts.find(m => m.Name === KEY).RW = true; }
    if (mutation === 'copy-up-key') desired.VolumeOptions.NoCopy = false;
    if (mutation === 'foreign-key') desired.Source = 'foreign-key-volume';
    if (mutation === 'inline-provider-key') api.Config.Env.push('OPENROUTER_API_KEY=synthetic-not-a-key');
    assert.throws(() => validatePublicLlmContainer(api, 'api', x.model.services.api, x.f.images.api, x.model, { images: x.f.images }, SELECTION));
    assert.equal(x.f.calls.length, 0);
  });
}

for (const volume of [KEY, `${PROJECT}_auth_accounts`, `${PROJECT}_scan_ledger`]) {
  test(`METADATA foreign stopped consumer of ${volume} refuses (all-consumer census)`, async t => {
    const x = existingNamespace(t), foreign = clone(x.f.containers.find(c => role(c) === 'api'));
    foreign.Id = 'f'.repeat(64); foreign.Name = '/unrelated-consumer';
    foreign.Config.Labels['com.docker.compose.project'] = 'unrelated';
    foreign.State.Running = false; foreign.State.Status = 'exited';
    foreign.Mounts = [{ Type: 'volume', Name: volume }];
    x.f.containers.push(foreign);
    await assert.rejects(x.inspect());
    assert(x.f.calls.some(c => c.args.includes(`volume=${volume}`)), 'must reach the all-consumer census for this volume');
    assert(x.f.calls.every(c => ['ls', 'inspect'].includes(c.args[1])));
  });
}

test('HELPER snapshot consumes explicit candidate image ID, readonly stores, no key/JWT/network; no initializer program', () => {
  const prior = 'sha256:' + 'b'.repeat(64), candidate = 'sha256:' + 'c'.repeat(64);
  const args = publicLlmHelperArguments(`${PROJECT}-llm-${AUDIT.slice(7)}-fenced`, candidate, 'backup');
  assert(args.includes(candidate)); assert(!args.includes(prior));
  assert.equal(args.at(-1), PUBLIC_LLM_BACKUP_PROGRAM);
  assert.notEqual(args.at(-1), PUBLIC_LLM_INITIALIZE_PROGRAM); assert.notEqual(args.at(-1), PUBLIC_LLM_CHECK_PROGRAM);
  assert.equal(args[args.indexOf('--network') + 1], 'none'); assert(args.includes('--read-only'));
  for (const [name, target] of [['auth_accounts', '/auth'], ['scan_ledger', '/data']]) {
    assert(args.includes(`type=volume,src=${PROJECT}_${name},dst=${target},readonly,volume-nocopy`));
  }
  assert(!JSON.stringify(args).includes(KEY)); assert(!JSON.stringify(args).includes('SCAN_JWT_SECRET'));
});

for (const drift of ['source-bytes', 'source-inode', 'execution-bytes', 'execution-inode']) {
  test(`SOURCE ${drift} invalidates captured proof even if replacement bytes match`, t => {
    const root = sourceFixture(t), source = capturePublicLlmSource(root), execution = capturePublicLlmExecutionClosure(root);
    const path = join(root, drift.startsWith('execution') ? 'scripts/local-stand.mjs' : 'src/placeholder.ts');
    source.verify(); execution.verify();
    if (drift.endsWith('inode')) { const bytes = fs.readFileSync(path); fs.renameSync(path, path + '.retained'); fs.writeFileSync(path, bytes); }
    else fs.appendFileSync(path, '\n// synthetic source drift\n');
    assert.throws(drift.startsWith('execution') ? execution.verify : source.verify);
  });
}

test('EVIDENCE fixture preserves the normal five-entry failed-build prefix, including durable failure/checkpoint', t => {
  const root = temporary(t), lock = join(root, '.operation.lock'); fs.mkdirSync(lock, { mode: 0o700 });
  const entries = {
    'mutation.json': { version: 1, project: PROJECT, command: 'public-llm-up', phase: 'fence-web', endpoint: 'unix:///fixture/docker.sock' },
    'helper-fenced.json': { id: 'd'.repeat(64), image: 'sha256:' + 'b'.repeat(64), purpose: 'backup' },
    'build-failure.json': { version: 1, phase: 'build-submit-worker', role: 'worker', category: 'resources' },
    'build-checkpoint.json': { version: 1, phase: 'validated-before-build', sourceBasis: 'validated-before-build', baseline: clone(ORIGINAL), retirementPolicy: null },
  };
  fs.mkdirSync(join(lock, 'llm-candidate'), { mode: 0o700 });
  for (const [name, value] of Object.entries(entries)) fs.writeFileSync(join(lock, name), JSON.stringify(value), { mode: 0o600 });
  const proofs = Object.keys(entries).map(name => privateFile(join(lock, name)));
  assert.deepEqual(fs.readdirSync(lock).sort(), ['build-checkpoint.json', 'build-failure.json', 'helper-fenced.json', 'llm-candidate', 'mutation.json']);
  for (const proof of proofs) proof.verify();
  const checkpoint = byteFile(join(lock, 'build-checkpoint.json'));
  fs.appendFileSync(checkpoint.path, '\n'); assert.throws(checkpoint.verify);
  assert(fs.existsSync(join(lock, 'build-failure.json')), 'never delete durable failure/checkpoint to force the legacy checker');
});

// This fixture intentionally stops at an incomplete exported backup listing. It
// tests the real preparer's early authority guards, NOT native four-store
// restore or a successful review token. No SQLite constructor may be called.
function prefixFixture(t) {
  const x = existingNamespace(t), root = sourceFixture(t, x.f.root), home = temporary(t);
  const settings = join(home, '.local/state/diplom-public-images/llm');
  fs.mkdirSync(settings, { recursive: true, mode: 0o700 });
  const json = (path, value) => fs.writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  fs.writeFileSync(join(settings, 'llm.env'), Object.entries(PUBLIC_LLM_ENV).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
  fs.symlinkSync('/nonexistent-forbidden-test-key', join(settings, 'openrouter.key'));
  json(join(settings, 'key-volume.json'), { version: 1, volume: KEY, uid: 65532, gid: 65532, fileMode: '0400', directoryMode: '0500', target: PUBLIC_LLM_ENV.OPENROUTER_API_KEY_FILE, initializerImage: x.f.images.api.Id });
  json(join(x.f.stand, 'llm-profile.json'), SELECTION);
  json(join(x.f.stand, 'compose.llm-env.json'), publicLlmEnvironmentOverlay(SELECTION));
  const pins = { services: Object.fromEntries(Object.entries(x.model.services).map(([name]) => [name, { image: x.f.images[name].Id }])) };
  json(join(x.f.stand, 'compose.images.json'), pins);
  const lock = join(x.f.stand, '.operation.lock'), stage = join(lock, 'llm-candidate');
  const audit = join(x.f.stand, 'llm-deployments', AUDIT);
  for (const path of [lock, stage, join(x.f.stand, 'llm-deployments'), audit, join(audit, 'fenced'), join(audit, 'fenced/core'), join(audit, 'fenced/llm')]) fs.mkdirSync(path, { mode: 0o700 });
  fs.copyFileSync(join(x.f.stand, 'compose.cve.json'), join(stage, 'compose.cve.json'));
  json(join(stage, 'compose.llm-env.json'), publicLlmEnvironmentOverlay(SELECTION));
  json(join(lock, 'mutation.json'), { version: 1, project: PROJECT, command: 'public-llm-up', phase: 'fence-web', endpoint: x.f.endpoint });
  json(join(lock, 'helper-fenced.json'), { id: 'd'.repeat(64), image: pins.services.api.image, purpose: 'backup' });
  json(join(lock, 'build-failure.json'), { version: 1, phase: 'build-submit-worker', role: 'worker', category: 'unclassified' });
  const jwt = privateFile(join(x.f.stand, 'scan-jwt'));
  const build = {
    version: 1, phase: 'validated-before-build', source: capturePublicLlmSource(root).manifest,
    sourceBasis: 'validated-before-build', baseline: clone(ORIGINAL), retirementPolicy: null,
    pins, publicProfile: readProfile(root),
    imageMetadata: Object.fromEntries(Object.entries(x.f.images).filter(([name]) => Object.hasOwn(pins.services, name)).map(([name, image]) => [name, { Id: image.Id, Os: image.Os, Config: image.Config }])),
    peers: x.f.containers.map(c => ({ name: role(c), id: c.Id, image: c.Image })),
    jwtIdentity: Object.fromEntries(Object.entries(jwt.identity).filter(([key]) => ['dev', 'ino', 'mode', 'uid', 'size', 'mtime', 'ctime'].includes(key))),
  };
  json(join(lock, 'build-checkpoint.json'), build);
  let dispatches = 0, databases = 0;
  const options = {
    root, home, audit: AUDIT, ambient: {},
    run: async () => { dispatches++; throw Error('forbidden engine dispatch'); },
    Database: class { constructor() { databases++; throw Error('forbidden SQLite access'); } },
  };
  return { ...x, root, home, lock, stage, audit, build, json, options, counts: () => ({ dispatches, databases }) };
}

test('EXACT prefix: normal five-entry worker HOLD reaches fenced backup verification without deleting checkpoint/failure or dispatching engine/SQLite', async t => {
  const x = prefixFixture(t), before = fs.readdirSync(x.lock).sort();
  assert.deepEqual(EXISTING_BUILD_HOLD, { audit: AUDIT, phase: 'build-submit-worker' });
  await assert.rejects(preparePublicLlmExistingBuildContinuation(x.options), error => /at storedBaseline /.test(error.stack));
  assert.deepEqual(fs.readdirSync(x.lock).sort(), before);
  assert.deepEqual(x.counts(), { dispatches: 0, databases: 0 });
});

for (const corruption of [
  'missing-checkpoint', 'missing-failure', 'wrong-phase', 'wrong-category', 'missing-image-role',
  'pins', 'profile', 'jwt-identity', 'empty-baseline', 'absent-llm-baseline', 'foreign-key-selection',
  'candidate-overlay', 'later-intent', 'later-candidate-pins',
]) {
  test(`EXACT early authority rejects ${corruption} before backup access/engine; durable evidence is not cleaned up`, async t => {
    const x = prefixFixture(t), buildPath = join(x.lock, 'build-checkpoint.json');
    if (corruption === 'missing-checkpoint') fs.renameSync(buildPath, join(x.root, 'retained-checkpoint'));
    else if (corruption === 'missing-failure') fs.renameSync(join(x.lock, 'build-failure.json'), join(x.root, 'retained-failure'));
    else if (corruption === 'wrong-phase' || corruption === 'wrong-category') {
      x.json(join(x.lock, 'build-failure.json'), { version: 1, phase: corruption === 'wrong-phase' ? 'build-submit-web' : 'build-submit-worker', role: 'worker', category: corruption === 'wrong-category' ? 'resources' : 'unclassified' });
    } else if (corruption === 'foreign-key-selection') x.json(join(x.f.stand, 'llm-profile.json'), { version: 1, keyVolume: null });
    else if (corruption === 'candidate-overlay') x.json(join(x.stage, 'compose.llm-env.json'), publicLlmEnvironmentOverlay({ version: 1, keyVolume: null }));
    else if (corruption === 'later-intent') x.json(join(x.lock, 'existing-build-current-continue.json'), { version: 1 });
    else if (corruption === 'later-candidate-pins') x.json(join(x.stage, 'compose.images.json'), {});
    else {
      if (corruption === 'missing-image-role') delete x.build.imageMetadata.worker;
      if (corruption === 'pins') x.build.pins.services.api.image = 'sha256:' + 'f'.repeat(64);
      if (corruption === 'profile') x.build.publicProfile.version = 1;
      if (corruption === 'jwt-identity') x.build.jwtIdentity.ino = '0';
      if (corruption === 'empty-baseline') x.build.baseline.empty = true;
      if (corruption === 'absent-llm-baseline') x.build.baseline.llm = null;
      x.json(buildPath, x.build);
    }
    const listing = fs.readdirSync(x.lock).sort(), evidence = Object.fromEntries(listing.filter(name => name.endsWith('.json')).map(name => [name, fs.readFileSync(join(x.lock, name))]));
    await assert.rejects(preparePublicLlmExistingBuildContinuation(x.options), error => error.code !== 'ENOENT' && !/at storedBaseline /.test(error.stack) && /refused|rejected|invalid/i.test(error.message));
    assert.deepEqual(x.counts(), { dispatches: 0, databases: 0 });
    assert.deepEqual(fs.readdirSync(x.lock).sort(), listing);
    for (const [name, bytes] of Object.entries(evidence)) assert.deepEqual(fs.readFileSync(join(x.lock, name)), bytes);
  });
}

for (const drift of ['bytes', 'inode']) test(`EXACT new entry ${drift} drift invalidates execution closure`, t => {
  const root = sourceFixture(t), path = join(root, 'scripts/public-llm-existing-build-continuation.mjs');
  const proof = captureExistingBuildExecution(root); proof.verify();
  assert(proof.manifest.modules.includes('scripts/public-llm-existing-build-continuation.mjs'));
  assert.equal(proof.manifest.modules.length, PUBLIC_LLM_EXECUTION_MODULES.length + 1);
  if (drift === 'inode') { const bytes = fs.readFileSync(path); fs.renameSync(path, path + '.retained'); fs.writeFileSync(path, bytes); }
  else fs.appendFileSync(path, '\n// drift after review\n');
  assert.throws(proof.verify);
});

for (const argv of [
  ['continue-existing-build', '--audit', AUDIT],
  ['check-existing-build', '--audit', 'deploy-' + '0'.repeat(32)],
  ['continue-current-build', '--audit', AUDIT],
  ['continue-existing-build', '--audit', AUDIT, '--review', 'f'.repeat(64), '--ack-reviewed-current-source'],
  ['continue-existing-build', '--audit', AUDIT, '--review', 'f'.repeat(64), '--ack-reviewed-current-source', '--ack-retire-only-unavailable-worker'],
  ['continue-existing-build', '--audit', AUDIT, '--review', 'not-a-token', '--ack-reviewed-current-source', '--ack-retire-only-unavailable-peers'],
]) test(`EXACT malformed CLI refuses before any lookup/dispatch: ${argv.join(' ')}`, async () => {
  let dispatches = 0;
  await assert.rejects(publicLlmExistingBuildStand(argv, { root: '/nonexistent-forbidden-repository', run: async () => { dispatches++; throw Error('must not dispatch'); }, Database: class {}, ambient: {}, log: () => assert.fail('refusal must not print unchecked evidence') }));
  assert.equal(dispatches, 0);
});

for (const [error, stderr, expected] of [
  [{ killed: true }, 'PRIVATE LOG', 'timeout'],
  [{ code: 'ENOENT' }, '', 'docker_unavailable'],
  [{}, 'Cannot connect to the Docker daemon', 'docker_unavailable'],
  [{}, 'no space left on device', 'resources'],
  [{}, 'ERR_PNPM_OUTDATED_LOCKFILE frozen-lockfile', 'dependency_install'],
  [{}, 'error TS2345: private argument', 'typescript'],
  [{}, 'failed to resolve: manifest unknown', 'base_image_resolution'],
  [{}, 'failed to compute cache key', 'build_context'],
  [{}, 'TLS handshake timeout', 'build_network'],
  [{}, 'PRIVATE UNCLASSIFIED LOG', 'unclassified'],
]) test(`BUILD adapter ${expected} records bounded category only; one dispatch, no retry or leaked log`, async () => {
  const secret = 'PRIVATE_TEST_LOG_SENTINEL', cause = classifyExistingBuildCause(error, '', stderr);
  assert.equal(cause, expected);
  const args = ['compose', '-p', PROJECT, 'build', 'worker']; let calls = 0;
  await assert.rejects(runExistingBuildDocker(args, { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, received, options, callback) => {
    calls++; assert.equal(program, 'docker'); assert.deepEqual(received, args); assert.equal(options.timeout, 1000);
    callback(error, secret, stderr + '\n' + secret);
  }), failure => failure.buildCause === expected && !failure.message.includes(secret) && !JSON.stringify(failure).includes(secret));
  assert.equal(calls, 1);
});

// These source-level probes execute only the selected expression/method, not
// the launcher or a Docker command. They cover otherwise-private selection
// boundaries without adding production exports or claiming runtime recovery.
function sourceNode(path, predicate) {
  const text = fs.readFileSync(join(ROOT, path), 'utf8');
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  assert.equal(source.parseDiagnostics.length, 0);
  const matches = [];
  const visit = node => { if (predicate(node)) matches.push(node); ts.forEachChild(node, visit); };
  visit(source); assert.equal(matches.length, 1, `expected one source contract in ${path}`);
  return matches[0].getText(source);
}

for (const suffix of ['before-api', 'after-api']) test(`SOURCE helper ${suffix} uses candidate API, never vanished prior API`, () => {
  const expression = sourceNode('scripts/public-llm-stand.mjs', node => ts.isVariableDeclaration(node) && node.name.getText() === 'image' && node.initializer && ts.isConditionalExpression(node.initializer) && node.initializer.getText().includes("suffix === 'fenced'"));
  const initializer = expression.slice(expression.indexOf('=') + 1);
  const candidate = { Id: 'sha256:' + 'c'.repeat(64) };
  const selected = runInNewContext(initializer, { purpose: 'backup', suffix, continuation: { backupImage: { Id: 'sha256:' + 'b'.repeat(64) } }, priorImages: { api: undefined }, candidateImages: { api: candidate } });
  assert.equal(selected, candidate);
});

test('SOURCE missing original API metadata selects validated tagged API for initial fenced snapshot', () => {
  const declaration = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isVariableDeclaration(node) && node.name.getText() === 'backupImage');
  const initializer = declaration.slice(declaration.indexOf('=') + 1), candidate = { Id: 'sha256:' + 'c'.repeat(64) };
  const selected = runInNewContext(initializer, { images: {}, taggedImages: { api: candidate } });
  assert.equal(selected, candidate);
});

for (const scenario of ['existing', 'fresh', 'drift']) test(`SOURCE existing-build initialization boundary ${scenario}: no writable initializer/check helper`, async () => {
  const method = sourceNode('scripts/public-llm-stand.mjs', node => ts.isMethodDeclaration(node) && node.name.getText() === 'initialize');
  let helpers = 0; const checks = [];
  const context = {
    phase: '', priorSelection: SELECTION, continuation: { existingBuildOnly: true, baseline: clone(ORIGINAL) },
    fencedBaseline: clone(ORIGINAL),
    safe: value => { if (!value) throw Error('source contract refused'); },
    equal: (a, b) => JSON.stringify(a) === JSON.stringify(b),
    helper: async () => { helpers++; throw Error('must never dispatch a helper'); },
    verifyPeers: async () => { checks.push('peers'); },
    users: async () => { checks.push('users'); },
    census: async () => { checks.push('census'); },
  };
  if (scenario === 'drift') context.fencedBaseline.llm.history = sha('changed');
  const ops = runInNewContext(`({${method}})`, context);
  if (scenario === 'existing') await ops.initialize(false);
  else await assert.rejects(ops.initialize(scenario === 'fresh'));
  assert.equal(helpers, 0);
  assert.deepEqual(checks, scenario === 'existing' ? ['peers', 'users', 'census'] : []);
});

for (const stale of [false, true]) test(`SOURCE CLI ${stale ? 'stale' : 'matching'} review token is compared with freshly prepared authority before lifecycle delegation`, async () => {
  const declaration = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isFunctionDeclaration(node) && node.name?.text === 'publicLlmExistingBuildStand');
  // getText includes the export modifier, which is not part of an expression.
  const functionText = declaration.replace(/^export\s+/, '').replaceAll('import.meta.url', JSON.stringify(new URL('./public-llm-existing-build-continuation.mjs', import.meta.url).href));
  const current = 'c'.repeat(64), calls = [];
  const main = runInNewContext(`(${functionText})`, {
    EXISTING_BUILD_HOLD,
    need: value => { if (!value) throw Error('source contract refused'); },
    preparePublicLlmExistingBuildContinuation: async options => { calls.push('prepare'); assert.equal(options.audit, AUDIT); return { review: current }; },
    publicLlmStand: async () => { calls.push('delegate'); return { outcome: 'offline-delegated' }; },
  });
  const action = main(['continue-existing-build', '--audit', AUDIT, '--review', stale ? 'b'.repeat(64) : current, '--ack-reviewed-current-source', '--ack-retire-only-unavailable-peers'], { root: '/offline-fixture', run: async () => assert.fail('must not execute engine'), log: () => {} });
  if (stale) await assert.rejects(action);
  else assert.equal((await action).outcome, 'offline-delegated');
  assert.deepEqual(calls, stale ? ['prepare'] : ['prepare', 'delegate']);
});

for (const [code, stderr] of [
  ['EIO', 'synthetic blob input/output error'],
  ['EIO', ''],
  [1, 'blob read: I/O error'],
  [1, 'failed to read blob sha256:synthetic: input/output error'],
  [1, 'image not found: failed to read blob: input/output error'],
]) test(`STORAGE real metadata adapter classifies ${code === 'EIO' ? 'EIO' : stderr.startsWith('image') ? 'I/O before missing-image hint' : 'blob I/O'} as storage_io, with one dispatch and no raw-output retention`, async () => {
  const sentinel = 'PRIVATE_SYNTHETIC_STORAGE_OUTPUT', args = ['image', 'inspect', 'sha256:' + 'b'.repeat(64)];
  let dispatches = 0;
  await assert.rejects(runExistingBuildDocker(args, { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, received, options, callback) => {
    dispatches++; assert.equal(program, 'docker'); assert.deepEqual(received, args);
    assert.equal(options.timeout, 1000);
    callback(Object.assign(Error(sentinel), { code, cmd: sentinel }), sentinel, stderr + '\n' + sentinel);
  }), failure => {
    assert.equal(failure.category, 'storage_io'); assert.notEqual(failure.category, 'image');
    assert(!failure.message.includes(sentinel)); assert(!JSON.stringify(failure).includes(sentinel));
    for (const key of ['stdout', 'stderr', 'cmd', 'cause']) assert(!Object.hasOwn(failure, key));
    return true;
  });
  assert.equal(dispatches, 1, 'classification must never cause a retry or second submission');
});

// Snapshot only disposable synthetic evidence. Include identities and bytes;
// omit atime because merely reading a file can update it on some filesystems.
function evidenceTree(root) {
  const result = [];
  const visit = path => {
    const stat = fs.lstatSync(path);
    result.push({ path: path.slice(root.length), dev: String(stat.dev), ino: String(stat.ino), mode: stat.mode, uid: stat.uid, nlink: stat.nlink, size: stat.size, mtime: stat.mtimeMs, ctime: stat.ctimeMs,
      ...(stat.isFile() ? { bytes: fs.readFileSync(path).toString('hex') } : stat.isSymbolicLink() ? { target: fs.readlinkSync(path) } : {}) });
    if (stat.isDirectory()) for (const name of fs.readdirSync(path).sort()) visit(join(path, name));
  };
  visit(root); return result;
}

for (const name of ['auth-volume-init', 'api']) test(`STORAGE production prior-image loop ${name} propagates finite DockerIO refusal; no missing/retire exception, retry, initializer or evidence mutation`, async t => {
  const x = prefixFixture(t), before = evidenceTree(x.f.stand), missing = [], images = {}, submissions = [];
  const sentinel = 'PRIVATE_SYNTHETIC_BLOB_IO_SENTINEL', image = x.build.pins.services[name].image;
  const query = args => runExistingBuildDocker(args, { root: x.root, env: {}, timeout: 1000 }, (program, received, options, callback) => {
    submissions.push(received.slice()); assert.equal(program, 'docker');
    assert.deepEqual(received, ['image', 'inspect', image]);
    callback(Object.assign(Error(sentinel), { code: 1 }), sentinel, 'image not found: failed to read blob: input/output error\n' + sentinel);
  });
  // Execute the actual private loop, not a reimplementation of its catch.
  // Native fenced-store restore and the rest of the preparer are deliberately
  // outside this isolated metadata-boundary test.
  const loop = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isForOfStatement(node) && node.expression.getText() === 'roles' && node.statement.getText().includes('const saved = build.imageMetadata[name]'));
  const replaceableDeclaration = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isVariableDeclaration(node) && node.name.getText() === 'replaceable');
  const replaceable = runInNewContext(replaceableDeclaration.slice(replaceableDeclaration.indexOf('=') + 1));
  const action = runInNewContext(`(async () => {${loop}})()`, {
    roles: [name], replaceable, build: x.build, pins: x.build.pins, images, missing, query,
    inspectExistingBuildPriorImage, validatePublicLlmImage,
    need: value => { if (!value) throw Error('source contract refused'); },
    equal: (a, b) => JSON.stringify(a) === JSON.stringify(b),
  });
  await assert.rejects(action, failure => {
    assert.equal(failure.category, 'storage_io'); assert.notEqual(failure.category, 'image');
    assert.equal(failure.boundary, 'prior-image-inspect-' + name);
    const diagnostic = existingBuildMetadataDiagnostic(failure);
    assert.deepEqual(diagnostic, { boundary: 'prior-image-inspect-' + name, category: 'DockerIO' });
    assert(Object.isFrozen(diagnostic));
    assert.deepEqual(Object.keys(failure).sort(), ['boundary', 'category']);
    assert(!failure.message.includes(sentinel)); assert(!JSON.stringify(failure).includes(sentinel));
    assert(!JSON.stringify(diagnostic).includes(image));
    for (const key of ['stdout', 'stderr', 'cmd', 'cause', 'image', 'reference']) assert(!Object.hasOwn(failure, key));
    return true;
  });
  assert.deepEqual(submissions, [['image', 'inspect', image]], 'no retry, tag lookup, build, helper or initializer submission');
  assert.deepEqual(missing, [], 'storage I/O must not authorize a retirement exception');
  assert.deepEqual(images, {});
  assert.deepEqual(evidenceTree(x.f.stand), before);
  assert.deepEqual(x.counts(), { dispatches: 0, databases: 0 });
});

test('STORAGE finite metadata diagnostic ignores unknown labels and never reads error getters', () => {
  assert.equal(existingBuildMetadataDiagnostic({ boundary: 'prior-image-inspect-foreign', category: 'storage_io' }), null);
  assert.equal(existingBuildMetadataDiagnostic({ boundary: 'prior-image-inspect-auth-volume-init', category: 'raw-provider-output' }), null);
  const getters = Object.defineProperties({}, {
    boundary: { get() { assert.fail('must not evaluate an error boundary getter'); } },
    category: { get() { assert.fail('must not evaluate an error category getter'); } },
  });
  assert.equal(existingBuildMetadataDiagnostic(getters), null);
});

function sourceVariable(name, context = {}) {
  const declaration = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isVariableDeclaration(node) && node.name.getText() === name);
  return runInNewContext(`(${declaration.slice(declaration.indexOf('=') + 1)})`, context);
}

// Source-level peer-policy fixture: actual private validation closure and its
// pure hash/epoch helpers, backed only by disposable synthetic container data.
// No full preparer, engine runner or native restore is executed here.
function peerPolicyFixture(t, name) {
  const x = existingNamespace(t), peer = clone(x.f.containers.find(c => role(c) === name));
  const command = [...(peer.Config.Entrypoint ?? []), ...peer.Config.Cmd];
  peer.Path = command[0]; peer.Args = command.slice(1);
  Object.assign(peer.State, { Running: false, Status: 'exited', Pid: 0, ExitCode: 0, StartedAt: '2026-10-01T00:00:00Z', FinishedAt: '2026-10-01T00:05:00Z', Error: '', OOMKilled: false, Paused: false, Restarting: false, Dead: false });
  const context = {
    ...existingBuildModule, PROJECT, LABEL, structuredClone, crypto: { createHash }, audit: AUDIT,
    need: value => { if (!value) throw Error('synthetic peer policy refusal'); },
  };
  for (const helper of ['canonical', 'equal', 'hash', 'role', 'owned', 'control', 'epoch', 'stopped']) context[helper] = sourceVariable(helper, context);
  const saved = { name, id: peer.Id, image: peer.Image, control: context.control(peer), epoch: Array.from(context.epoch(peer)) };
  context.build = { peers: [saved], imageMetadata: clone(x.f.images) };
  context.pins = { services: Object.fromEntries(Object.entries(x.f.images).map(([role, image]) => [role, { image: image.Id }])) };
  Object.assign(context, { model: x.model, images: x.f.images, priorSelection: SELECTION, validatePublicLlmContainer,
    jwtFile: { bytes: peer.Config.Env.find(v => v.startsWith('SCAN_JWT_SECRET='))?.slice('SCAN_JWT_SECRET='.length) } });
  const validate = sourceVariable('validateOriginalPeer', context);
  return { ...x, peer, saved, context, validate };
}

for (const name of ['api', 'worker', 'web', 'auth-volume-init', 'scan-volume-init']) test(`RESTART stopped ${name} stays exact: timestamp/PID/counter/state/exit/OOM drifts refuse without changing original evidence`, t => {
  const x = peerPolicyFixture(t, name), before = evidenceTree(x.f.stand), original = clone(x.saved);
  x.validate(x.peer, name);
  for (const [label, mutate] of [
    ['container identity', c => { c.Id = 'f'.repeat(64); }],
    ['runtime image', c => { c.Image = 'sha256:' + 'f'.repeat(64); }],
    ['configured image', c => { c.Config.Image = 'sha256:' + 'f'.repeat(64); }],
    ['control/command', c => { c.Config.Cmd = [...c.Config.Cmd, 'unreviewed']; }],
    ['host control', c => { c.HostConfig.ReadonlyRootfs = false; }],
    ['start timestamp', c => { c.State.StartedAt = '2026-10-25T17:57:47Z'; }],
    ['finish timestamp', c => { c.State.FinishedAt = '2026-10-25T17:57:47Z'; }],
    ['PID', c => { c.State.Pid = 999; }],
    ['restart counter', c => { c.RestartCount++; }],
    ['running', c => { c.State.Running = true; }],
    ['status', c => { c.State.Status = 'running'; }],
    ['exit', c => { c.State.ExitCode = 137; }],
    ['OOM', c => { c.State.OOMKilled = true; }],
    ['paused', c => { c.State.Paused = true; }],
    ['restarting', c => { c.State.Restarting = true; }],
    ['dead', c => { c.State.Dead = true; }],
    ['error', c => { c.State.Error = 'synthetic-state-error'; }],
  ]) {
    const changed = clone(x.peer); mutate(changed);
    assert.throws(() => x.validate(changed, name), `${name}: ${label} must not inherit the gateway restart exception`);
  }
  assert.deepEqual(x.saved, original);
  assert.deepEqual(evidenceTree(x.f.stand), before);
  assert.equal(x.f.calls.length, 0);
});

for (const refusal of ['stale-token', 'current-source-drift']) test(`RESTART shared continuation entry still rejects ${refusal} before engine access or original-evidence mutation`, async t => {
  const x = prefixFixture(t), proof = captureExistingBuildExecution(x.root), current = 'c'.repeat(64), checks = [];
  const continuation = {
    existingBuildOnly: true, root: x.root, auditName: AUDIT, review: current,
    verify() { checks.push('source'); proof.verify(); },
    checkPrefix() { assert.fail('must refuse before proceeding to prefix/preflight'); },
  };
  if (refusal === 'current-source-drift') fs.appendFileSync(join(x.root, 'scripts/public-llm-existing-build-continuation.mjs'), '\n// synthetic change after gateway epoch review\n');
  const before = evidenceTree(x.f.stand);
  await assert.rejects(publicLlmStand(['continue-existing-build', '--audit', AUDIT, '--review', refusal === 'stale-token' ? 'b'.repeat(64) : current, '--ack-reviewed-current-source', '--ack-retire-only-unavailable-peers'], {
    root: x.root, home: x.home, ambient: {}, existingBuildContinuation: continuation,
    run: async () => assert.fail('must not dispatch Docker'),
    Database: class { constructor() { assert.fail('must not access SQLite'); } }, log: () => {},
  }));
  assert.deepEqual(checks, refusal === 'stale-token' ? [] : ['source']);
  assert.deepEqual(evidenceTree(x.f.stand), before);
});

function fixedGatewayPair(name) {
  const fixed = EXISTING_BUILD_GATEWAY_RESTART.gateways[name];
  return { original: clone(fixed.original), current: { ...clone(fixed.original), epoch: clone(fixed.currentEpoch) } };
}

test('RESTART authorization is frozen to the exact audit, recorded instant and two gateway roles', () => {
  const policy = EXISTING_BUILD_GATEWAY_RESTART;
  assert.equal(policy.audit, AUDIT);
  assert.equal(policy.authorizationAt, '2026-10-25T17:57:47Z');
  assert.deepEqual(Object.keys(policy.gateways).sort(), ['egress', 'llm-egress']);
  assert(Object.isFrozen(policy)); assert(Object.isFrozen(policy.gateways));
  for (const fixed of Object.values(policy.gateways)) {
    assert(Object.isFrozen(fixed)); assert(Object.isFrozen(fixed.original));
    assert(Object.isFrozen(fixed.original.epoch)); assert(Object.isFrozen(fixed.currentEpoch));
  }
});

for (const name of ['egress', 'llm-egress']) {
  test(`RESTART ${name} accepts only its fixed original-record/new-epoch pair with unchanged ID/image/control and evidence`, t => {
    const x = prefixFixture(t), before = evidenceTree(x.f.stand), pair = fixedGatewayPair(name), retained = clone(pair);
    assert.equal(validateExistingBuildPeerEpoch(AUDIT, pair.original, pair.current), true);
    for (const field of ['name', 'id', 'image', 'control']) assert.equal(pair.current[field], pair.original[field]);
    assert.notDeepEqual(pair.current.epoch, pair.original.epoch);
    assert.deepEqual(pair, retained, 'validation must never rewrite the original peer record');
    assert.deepEqual(evidenceTree(x.f.stand), before);
    assert.deepEqual(x.counts(), { dispatches: 0, databases: 0 });
  });

  for (const [label, mutate] of [
    ['container ID', p => { p.current.id = 'f'.repeat(64); p.current.epoch[0] = p.current.id; }],
    ['epoch container ID', p => { p.current.epoch[0] = 'f'.repeat(64); }],
    ['image ID', p => { p.current.image = 'sha256:' + 'f'.repeat(64); }],
    ['control hash', p => { p.current.control = 'f'.repeat(64); }],
    ['start timestamp', p => { p.current.epoch[1] = '2026-10-25T17:57:48Z'; }],
    ['finish timestamp', p => { p.current.epoch[2] = '2026-10-25T17:57:48Z'; }],
    ['PID', p => { p.current.epoch[3]++; }],
    ['restart counter', p => { p.current.epoch[4]++; }],
    ['running state', p => { p.current.epoch[5] = false; }],
    ['status', p => { p.current.epoch[6] = 'restarting'; }],
    ['exit code', p => { p.current.epoch[7] = 137; }],
    ['error', p => { p.current.epoch[8] = 'synthetic-runtime-error'; }],
    ['extra epoch field', p => { p.current.epoch.push(false); }],
    ['incomplete epoch', p => { p.current.epoch.pop(); }],
    ['extra record authority', p => { p.current.allowRestart = true; }],
    ['role substitution', p => { p.current.name = 'worker'; }],
    ['rewritten old epoch', p => { p.original.epoch[3]++; }],
    ['rewritten matching controls', p => { p.original.control = p.current.control = 'f'.repeat(64); }],
    ['rewritten matching images', p => { p.original.image = p.current.image = 'sha256:' + 'f'.repeat(64); }],
    ['rewritten matching IDs', p => { p.original.id = p.current.id = 'f'.repeat(64); p.original.epoch[0] = p.current.epoch[0] = 'f'.repeat(64); }],
  ]) test(`RESTART ${name} rejects ${label}, not an arbitrary epoch relaxation`, () => {
    const pair = fixedGatewayPair(name); mutate(pair);
    assert.throws(() => validateExistingBuildPeerEpoch(AUDIT, pair.original, pair.current));
  });

  test(`RESTART ${name} refuses another audit, stale old live epoch, subsequent restart and cross-gateway epochs`, () => {
    const pair = fixedGatewayPair(name);
    assert.throws(() => validateExistingBuildPeerEpoch('deploy-' + '0'.repeat(32), pair.original, pair.current));
    assert.throws(() => validateExistingBuildPeerEpoch(AUDIT, pair.original, clone(pair.original)), 'post-restart checking must not accept stale pre-restart live metadata');
    const third = clone(pair.current); third.epoch[1] = '2026-10-25T18:00:00Z'; third.epoch[3]++;
    assert.throws(() => validateExistingBuildPeerEpoch(AUDIT, pair.original, third));
    assert.throws(() => validateExistingBuildPeerEpoch(AUDIT, pair.current, third), 'the approved new epoch cannot become a new historical authority');
    const other = fixedGatewayPair(name === 'egress' ? 'llm-egress' : 'egress');
    assert.throws(() => validateExistingBuildPeerEpoch(AUDIT, pair.original, other.current));
  });

  test(`RESTART ${name} retains production running-state guard: OOM/paused/restarting/dead drift cannot hide outside the epoch tuple`, () => {
    const statement = sourceNode('scripts/public-llm-existing-build-continuation.mjs', node => ts.isIfStatement(node) && node.expression.getText().includes("['api', 'worker', 'web'].includes(name)") && node.elseStatement?.getText().includes('c.State.OOMKilled'));
    const stateGuard = runInNewContext(`(c, name) => {${statement}}`, {
      need: value => { if (!value) throw Error('synthetic running-state refusal'); },
      stopped: () => assert.fail('healthy fixed gateway must not enter the stopped-peer branch'),
    });
    const pair = fixedGatewayPair(name), e = pair.current.epoch;
    const peer = { Id: e[0], RestartCount: e[4], State: { StartedAt: e[1], FinishedAt: e[2], Pid: e[3], Running: e[5], Status: e[6], ExitCode: e[7], Error: e[8], OOMKilled: false, Paused: false, Restarting: false, Dead: false } };
    assert.equal(validateExistingBuildPeerEpoch(AUDIT, pair.original, pair.current), true);
    stateGuard(peer, name);
    for (const field of ['OOMKilled', 'Paused', 'Restarting', 'Dead']) {
      const changed = clone(peer); changed.State[field] = true;
      assert.throws(() => stateGuard(changed, name), `${field} must fail independently of the allowed epoch pair`);
    }
  });
}

test('RESTART caller rejects synthetic gateway epochs even if ID/image/control and old/live epoch match each other', t => {
  for (const name of ['egress', 'llm-egress']) {
    const x = peerPolicyFixture(t, name), before = evidenceTree(x.f.stand);
    assert.throws(() => x.validate(x.peer, name), 'matching arbitrary gateway records are not fixed restart authority');
    assert.deepEqual(evidenceTree(x.f.stand), before);
    assert.equal(x.f.calls.length, 0);
  }
});

test('TAG normal namespace image census still refuses a blob error, with no fixed-tag fallback, retry or evidence change', async t => {
  const x = existingNamespace(t), before = evidenceTree(x.f.stand), submissions = [];
  const query = async (args, options) => {
    if (args[0] !== 'image' || args[1] !== 'ls') return x.metadata(args, options);
    return runExistingBuildDocker(args, options, (program, received, settings, callback) => {
      submissions.push(received.slice()); assert.equal(program, 'docker');
      callback(Object.assign(Error('synthetic image census failure'), { code: 1 }), '', 'rpc error: code = NotFound desc = content digest sha256:' + 'a'.repeat(64) + ': blob not found');
    });
  };
  await assert.rejects(inspectPublicLlmNamespace(query, { root: x.f.root, env: { DOCKER_HOST: x.f.endpoint }, timeout: 15000 }, x.f.root, x.bound, SELECTION, { images: x.f.images }));
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].slice(0, 2), ['image', 'ls']);
  assert.deepEqual(evidenceTree(x.f.stand), before);
});

test('TAG normal namespace image census refuses an unknown own output tag instead of inspecting/executing it', async t => {
  const x = existingNamespace(t), unknown = `${PROJECT}-unreviewed:local`, before = evidenceTree(x.f.stand);
  const query = async (args, options) => {
    const result = await x.metadata(args, options);
    return args[0] === 'image' && args[1] === 'ls' ? result + '\n' + unknown : result;
  };
  await assert.rejects(inspectPublicLlmNamespace(query, { root: x.f.root, env: { DOCKER_HOST: x.f.endpoint }, timeout: 15000 }, x.f.root, x.bound, SELECTION, { images: x.f.images }));
  assert(!x.f.calls.some(({ args }) => args[0] === 'image' && args[1] === 'inspect' && args[2] === unknown));
  assert(x.f.calls.every(({ args }) => ['ls', 'inspect'].includes(args[1])));
  assert.deepEqual(evidenceTree(x.f.stand), before);
});

test('TAG SOURCE fresh-build boundary keeps all four builds before candidate image inspection, immutable pins and pinned-model validation', () => {
  const method = sourceNode('scripts/public-llm-stand.mjs', node => ts.isMethodDeclaration(node) && node.name.getText() === 'candidate');
  const source = ts.createSourceFile('offline-candidate.mjs', `const ops = {${method}};`, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  assert.equal(source.parseDiagnostics.length, 0);
  const nodes = [];
  const visit = node => { nodes.push(node); ts.forEachChild(node, visit); }; visit(source);
  const builds = nodes.filter(node => ts.isForOfStatement(node) && ts.isArrayLiteralExpression(node.expression) && node.expression.elements.every(ts.isStringLiteralLike) && node.expression.elements.map(e => e.text).join(',') === 'api,worker,web,llm-egress');
  assert.equal(builds.length, 1);
  const selections = nodes.filter(node => ts.isForOfStatement(node) && node.expression.getText(source) === 'Object.entries(nextModel().services)');
  assert.equal(selections.length, 1);
  assert(selections[0].pos > builds[0].end, 'a failed fresh build must not reach candidate tag inspection');
  const immutablePin = nodes.find(node => ts.isCallExpression(node) && node.expression.getText(source) === 'writeExclusive' && node.getText(source).includes("'compose.images.json'") && node.getText(source).includes('Object.entries(candidateImages)'));
  assert(immutablePin && immutablePin.pos > selections[0].end);
  const pinnedValidation = nodes.find(node => ts.isCallExpression(node) && node.expression.getText(source) === 'validatePublicLlmConfig' && node.arguments[0]?.getText(source) === 'pinned' && node.arguments.at(-1)?.getText(source) === 'candidateImages');
  assert(pinnedValidation && pinnedValidation.pos > immutablePin.end, 'runtime execution remains behind validated immutable candidate pins');
});

for (const corruption of ['missing-container', 'unknown-own-container']) test(`TAG SOURCE runtime container census remains mandatory despite output-tag exception: ${corruption} refuses before image authority`, async t => {
  const x = existingNamespace(t), calls = [], roles = Array.from(sourceVariable('roles'));
  const equalityContext = {}; equalityContext.canonical = sourceVariable('canonical', equalityContext);
  const equal = sourceVariable('equal', equalityContext);
  const inspectRuntime = sourceVariable('inspectRuntime', {
    ...existingBuildModule, PROJECT, model: x.model, roles, equal,
    need: value => { if (!value) throw Error('synthetic census refusal'); },
    validateOriginalPeer: () => assert.fail('invalid census must refuse before peer inspection'),
  });
  const rows = roles.map(name => [`${PROJECT}-${name}-1`, PROJECT]);
  if (corruption === 'missing-container') rows.pop();
  else rows.push([`${PROJECT}-unreviewed-1`, PROJECT]);
  const before = evidenceTree(x.f.stand);
  await assert.rejects(inspectRuntime(async args => {
    calls.push(Array.from(args));
    assert.equal(args[0], 'container'); assert.equal(args[1], 'ls'); assert(args.includes('--all'));
    return rows.map(row => row.join('\t')).join('\n');
  }), error => error.message === 'synthetic census refusal');
  assert.equal(calls.length, 1, 'no image lookup, fallback, execution or retry before a valid runtime census');
  assert.deepEqual(calls[0].slice(0, 2), ['container', 'ls']);
  assert.deepEqual(evidenceTree(x.f.stand), before);
  assert.equal(x.f.calls.length, 0);
});

function syntheticBlobFailureText(digest = 'sha256:' + 'a'.repeat(64)) {
  return `rpc error: code = NotFound desc = blob ${digest} expected at /offline-synthetic/content/${digest}: blob not found`;
}

test('TAG classifier emits bounded hashed blob evidence only, never missing-image or execution authority', () => {
  const digest = 'sha256:' + 'a'.repeat(64), stderr = syntheticBlobFailureText(digest);
  const proof = classifyExistingWorkerOutputFailure({ code: 1 }, '[]', stderr);
  assert.deepEqual(proof, { version: 1, kind: 'rpc-blob-not-found', exitCode: 1, blobDigest: digest, stdoutSha256: sha('[]'), stderrSha256: sha(stderr) });
  assert(Object.isFrozen(proof));
  assert(!JSON.stringify(proof).includes('/offline-synthetic'));
  for (const key of ['Config', 'Id', 'image', 'category', 'execute', 'stdout', 'stderr', 'cmd', 'cause']) assert(!Object.hasOwn(proof, key));
});

for (const [label, mutate] of [
  ['wrong exit', v => { v.error.code = 2; }],
  ['string exit', v => { v.error.code = '1'; }],
  ['killed process', v => { v.error.killed = true; }],
  ['signal', v => { v.error.signal = 'SIGKILL'; }],
  ['nonempty stdout', v => { v.stdout = 'unreviewed output'; }],
  ['oversized stdout', v => { v.stdout = ' '.repeat(65537); }],
  ['oversized stderr', v => { v.stderr += ' '.repeat(65537); }],
  ['non-ASCII stderr', v => { v.stderr += '\u0080'; }],
  ['storage input/output', v => { v.stderr += ': input/output error'; }],
  ['storage I/O', v => { v.stderr += ': I/O error'; }],
  ['missing RPC code', v => { v.stderr = v.stderr.replace('rpc error: code = NotFound', 'unknown error'); }],
  ['missing expected-at bound', v => { v.stderr = v.stderr.replace('expected at', 'elsewhere'); }],
  ['different failure text', v => { v.stderr = v.stderr.replace('blob not found', 'permission denied'); }],
  ['ambiguous blob digests', v => { v.stderr += ' blob sha256:' + 'b'.repeat(64); }],
]) test(`TAG classifier rejects ${label}, without a generic unclassified fallback`, () => {
  const value = { error: { code: 1 }, stdout: '[]', stderr: syntheticBlobFailureText() }; mutate(value);
  assert.equal(classifyExistingWorkerOutputFailure(value.error, value.stdout, value.stderr), null);
});

test('TAG classifier does not evaluate raw error getters', () => {
  const error = Object.defineProperty({}, 'code', { get() { assert.fail('must not invoke an error getter'); } });
  assert.equal(classifyExistingWorkerOutputFailure(error, '', syntheticBlobFailureText()), null);
});

// Sanitized recorded proofs come from the public production constant. These
// policy fixtures do not claim to reproduce the private daemon stderr whose
// hashes were recorded; raw parsing/adapter behavior is tested separately.
function outputTagFixture(t, normal = false) {
  const x = existingNamespace(t), fixed = EXISTING_BUILD_WORKER_OUTPUT_RETIREMENT, calls = [], counts = new Map();
  const failure = proof => Object.assign(Error('synthetic sanitized metadata refusal'), { category: 'unclassified', workerOutputFailure: clone(proof) });
  const state = {
    audit: AUDIT, missingPriorMetadata: ['api', 'worker'],
    censusError: normal ? null : failure(fixed.censusFailure),
    workerError: normal ? null : failure(fixed.workerFailure),
    tags: [...fixed.knownTags], overrides: {},
  };
  const query = async args => {
    calls.push(Array.from(args));
    assert.equal(args[0], 'image', 'output-tag qualification must never execute a container/build/lifecycle operation');
    if (args[1] === 'ls') { if (state.censusError) throw state.censusError; return state.tags.join('\n'); }
    assert.equal(args[1], 'inspect');
    const name = ['api', 'worker', 'web', 'egress', 'llm-egress'].find(name => args[2] === `${PROJECT}-${name}:local`);
    assert(name, 'no arbitrary tag or prior pinned image ID may be inspected by the output-only exception');
    const count = (counts.get(name) ?? 0) + 1; counts.set(name, count);
    if (name === 'worker' && state.workerError) throw state.workerError;
    if (Object.hasOwn(state.overrides, name)) return state.overrides[name](clone(x.f.images[name]), count);
    return JSON.stringify([clone(x.f.images[name])]);
  };
  const inspect = () => inspectExistingBuildOwnTags(query, state.audit, state.missingPriorMetadata);
  return { ...x, fixed, state, calls, counts, failure, query, inspect };
}

test('TAG exact worker-output policy is frozen, fixed to five tags and explicitly grants no execution/full-census authority', () => {
  const fixed = EXISTING_BUILD_WORKER_OUTPUT_RETIREMENT;
  assert.equal(fixed.audit, AUDIT); assert.equal(fixed.tag, `${PROJECT}-worker:local`);
  assert.deepEqual(fixed.knownTags, ['api', 'egress', 'llm-egress', 'web', 'worker'].map(name => `${PROJECT}-${name}:local`));
  assert.deepEqual(fixed.validatedOtherRoles, ['api', 'egress', 'llm-egress', 'web']);
  assert.equal(fixed.workerFailure.blobDigest, fixed.blobDigest); assert.equal(fixed.censusFailure.blobDigest, fixed.blobDigest);
  assert.equal(fixed.executionAuthority, false); assert.equal(fixed.requiresWorkerBuild, true); assert.equal(fixed.ownPrefixCensusProven, false);
  for (const value of [fixed, fixed.workerFailure, fixed.censusFailure, fixed.knownTags, fixed.validatedOtherRoles]) assert(Object.isFrozen(value));
});

test('TAG exact matching worker+census failures plus four actual metadata observations admit rebuild-only evidence, never fabricated worker metadata', async t => {
  const x = outputTagFixture(t), before = evidenceTree(x.f.stand), result = await x.inspect(), retirement = result.workerOutputRetirement;
  assert(retirement); assert.equal(retirement.audit, AUDIT);
  assert.deepEqual(retirement.workerFailure, x.fixed.workerFailure); assert.deepEqual(retirement.censusFailure, x.fixed.censusFailure);
  assert.deepEqual(retirement.knownTagAuthority, x.fixed.knownTags);
  assert.equal(retirement.executionAuthority, false); assert.equal(retirement.requiresWorkerBuildBeforeUse, true);
  assert.equal(retirement.ownPrefixCensusProven, false); assert.equal(retirement.additionalOwnPrefixTagsAbsentProven, false);
  assert.equal(retirement.originalImageMetadataCertified, false);
  assert.deepEqual(Object.keys(result.taggedImages).sort(), x.fixed.validatedOtherRoles);
  assert.deepEqual(result.images.map(image => image.name).sort(), x.fixed.validatedOtherRoles);
  assert(!Object.hasOwn(result.taggedImages, 'worker')); assert(!Object.hasOwn(retirement, 'Config')); assert(!Object.hasOwn(retirement, 'Id'));
  for (const name of x.fixed.validatedOtherRoles) {
    validatePublicLlmImage(x.f.images[name], name);
    assert.deepEqual(result.taggedImages[name], x.f.images[name]);
    assert.deepEqual(retirement.validatedOtherTags[name], { Id: x.f.images[name].Id, Os: x.f.images[name].Os, Config: x.f.images[name].Config });
    assert.equal(x.counts.get(name), 2, 'successful metadata is fenced twice, not retried after failure');
  }
  assert.equal(x.counts.get('worker'), 1); assert.equal(x.calls.filter(args => args[1] === 'ls').length, 1);
  assert.equal(x.calls.length, 10); assert.deepEqual(evidenceTree(x.f.stand), before);
});

test('TAG successful scoped census keeps all five real tag observations and never invokes the damaged-output exception', async t => {
  const x = outputTagFixture(t, true), result = await x.inspect();
  assert.deepEqual(Object.keys(result.taggedImages).sort(), ['api', 'egress', 'llm-egress', 'web', 'worker']);
  assert.equal(result.images.length, 5); assert(!Object.hasOwn(result, 'workerOutputRetirement'));
  assert.equal(x.calls.length, 6);
  for (const count of x.counts.values()) assert.equal(count, 1);
});

for (const corruption of [
  'wrong-audit', 'wrong-missing-prior-roles', 'wrong-worker-blob', 'wrong-census-blob', 'matching-but-unapproved-blob',
  'wrong-worker-output-hash', 'wrong-census-output-hash', 'plain-census-unclassified', 'plain-worker-unclassified',
  'census-storage-io', 'worker-storage-io', 'worker-unexpected-failure', 'worker-success', 'extra-worker-proof-authority',
]) test(`TAG exceptional admission rejects ${corruption}; no execution, cleanup or failed-query retry`, async t => {
  const x = outputTagFixture(t), before = evidenceTree(x.f.stand);
  if (corruption === 'wrong-audit') x.state.audit = 'deploy-' + '0'.repeat(32);
  if (corruption === 'wrong-missing-prior-roles') x.state.missingPriorMetadata = ['api'];
  if (corruption === 'wrong-worker-blob') x.state.workerError.workerOutputFailure.blobDigest = 'sha256:' + 'b'.repeat(64);
  if (corruption === 'wrong-census-blob') x.state.censusError.workerOutputFailure.blobDigest = 'sha256:' + 'b'.repeat(64);
  if (corruption === 'matching-but-unapproved-blob') x.state.workerError.workerOutputFailure.blobDigest = x.state.censusError.workerOutputFailure.blobDigest = 'sha256:' + 'b'.repeat(64);
  if (corruption === 'wrong-worker-output-hash') x.state.workerError.workerOutputFailure.stderrSha256 = 'b'.repeat(64);
  if (corruption === 'wrong-census-output-hash') x.state.censusError.workerOutputFailure.stdoutSha256 = 'b'.repeat(64);
  if (corruption === 'plain-census-unclassified') x.state.censusError = Object.assign(Error('synthetic unrelated error'), { category: 'unclassified' });
  if (corruption === 'plain-worker-unclassified') x.state.workerError = Object.assign(Error('synthetic unrelated error'), { category: 'unclassified' });
  if (corruption === 'census-storage-io') x.state.censusError = Object.assign(Error('synthetic I/O error'), { category: 'storage_io' });
  if (corruption === 'worker-storage-io') x.state.workerError = Object.assign(Error('synthetic I/O error'), { category: 'storage_io' });
  if (corruption === 'worker-unexpected-failure') x.state.workerError = Object.assign(Error('synthetic daemon unavailable'), { category: 'docker_unavailable' });
  if (corruption === 'worker-success') x.state.workerError = null;
  if (corruption === 'extra-worker-proof-authority') x.state.workerError.workerOutputFailure.execute = true;
  await assert.rejects(x.inspect());
  assert(x.calls.every(args => args[0] === 'image' && ['ls', 'inspect'].includes(args[1])));
  assert.equal(x.calls.filter(args => args[1] === 'ls').length, 1);
  assert((x.counts.get('worker') ?? 0) <= 1);
  assert.deepEqual(evidenceTree(x.f.stand), before);
});

for (const name of ['api', 'egress', 'llm-egress', 'web']) for (const corruption of ['missing-metadata', 'invalid-policy', 'wrong-tag', 'extra-unknown-failure', 'second-observation-drift']) {
  test(`TAG exceptional admission requires actual stable ${name} metadata: ${corruption} refuses`, async t => {
    const x = outputTagFixture(t), before = evidenceTree(x.f.stand);
    x.state.overrides[name] = (image, count) => {
      if (corruption === 'missing-metadata') return '[]';
      if (corruption === 'invalid-policy') image.Config.User = 'synthetic-unapproved-user';
      if (corruption === 'wrong-tag') image.RepoTags = [`${PROJECT}-unreviewed:local`];
      if (corruption === 'extra-unknown-failure') throw Object.assign(Error('synthetic additional metadata failure'), { category: 'unclassified' });
      if (corruption === 'second-observation-drift' && count === 2) image.Id = 'sha256:' + 'b'.repeat(64);
      return JSON.stringify([image]);
    };
    await assert.rejects(x.inspect());
    assert.equal(x.counts.get('worker'), 1); assert((x.counts.get(name) ?? 0) <= 2);
    assert(x.calls.every(args => args[0] === 'image' && ['ls', 'inspect'].includes(args[1])));
    assert.deepEqual(evidenceTree(x.f.stand), before);
  });
}

for (const unknown of [`${PROJECT}-unreviewed:local`, `${PROJECT}-worker:latest`, 'foreign-worker:local']) test(`TAG own-tags API refuses arbitrary successful-census tag ${unknown}`, async t => {
  const x = outputTagFixture(t, true), before = evidenceTree(x.f.stand); x.state.tags.push(unknown);
  await assert.rejects(x.inspect());
  assert(!x.calls.some(args => args[1] === 'inspect' && args[2] === unknown));
  assert.deepEqual(evidenceTree(x.f.stand), before);
});

test('TAG pure retirement validation refuses missing/extra positive metadata authorities', t => {
  const x = outputTagFixture(t), positive = Object.fromEntries(x.fixed.validatedOtherRoles.map(name => [name, clone(x.f.images[name])]));
  for (const name of x.fixed.validatedOtherRoles) {
    const changed = clone(positive); delete changed[name];
    assert.throws(() => validateExistingWorkerOutputRetirement(AUDIT, x.fixed.workerFailure, x.fixed.censusFailure, changed));
  }
  positive.worker = clone(x.f.images.worker);
  assert.throws(() => validateExistingWorkerOutputRetirement(AUDIT, x.fixed.workerFailure, x.fixed.censusFailure, positive));
});

for (const [label, args, scoped] of [
  ['exact worker output', ['image', 'inspect', `${PROJECT}-worker:local`], true],
  ['exact filtered own census', ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}', '--filter', `reference=${PROJECT}-*`], true],
  ['unfiltered census', ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], false],
  ['foreign-filter census', ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}', '--filter', 'reference=foreign-*'], false],
  ['other own tag', ['image', 'inspect', `${PROJECT}-api:local`], false],
  ['arbitrary worker tag', ['image', 'inspect', `${PROJECT}-worker:latest`], false],
  ['immutable original ID', ['image', 'inspect', 'sha256:' + 'b'.repeat(64)], false],
]) test(`TAG real adapter scopes sanitized RPC blob proof to ${label}: ${scoped ? 'bounded proof' : 'no exception authority'}`, async () => {
  const stderr = syntheticBlobFailureText(), stdout = '', expected = classifyExistingWorkerOutputFailure({ code: 1 }, stdout, stderr);
  let dispatches = 0;
  await assert.rejects(runExistingBuildDocker(args, { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, received, options, callback) => {
    dispatches++; assert.equal(program, 'docker'); assert.deepEqual(received, args);
    callback(Object.assign(Error('PRIVATE_SYNTHETIC_RPC_BLOB_OUTPUT'), { code: 1 }), stdout, stderr);
  }), failure => {
    if (scoped) {
      assert.equal(failure.category, 'worker_output_blob_not_found'); assert.deepEqual(failure.workerOutputFailure, expected);
    } else assert(!Object.hasOwn(failure, 'workerOutputFailure'));
    assert.notEqual(failure.category, 'image'); assert(!failure.message.includes('/offline-synthetic'));
    for (const key of ['stdout', 'stderr', 'cmd', 'cause']) assert(!Object.hasOwn(failure, key));
    return true;
  });
  assert.equal(dispatches, 1);
});

for (const args of [
  ['image', 'inspect', `${PROJECT}-worker:local`],
  ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}', '--filter', `reference=${PROJECT}-*`],
]) test(`TAG real adapter rejects mixed RPC blob + I/O as storage_io, never worker retirement: ${args[1]}`, async () => {
  let dispatches = 0;
  await assert.rejects(runExistingBuildDocker(args, { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, received, options, callback) => {
    dispatches++; callback(Object.assign(Error('synthetic storage failure'), { code: 1 }), '', syntheticBlobFailureText() + ': input/output error');
  }), failure => failure.category === 'storage_io' && !Object.hasOwn(failure, 'workerOutputFailure'));
  assert.equal(dispatches, 1);
});

test('TAG SOURCE review token binds the worker-output exception and positive metadata rather than reusing the pre-exception token', async t => {
  const x = outputTagFixture(t), result = await x.inspect(), hashingContext = { crypto: { createHash } };
  hashingContext.canonical = sourceVariable('canonical', hashingContext);
  const hash = sourceVariable('hash', hashingContext);
  const base = {
    ...existingBuildModule, audit: AUDIT, endpoint: 'unix:///offline-fixture/docker.sock',
    source: { manifest: { files: [{ path: 'src/offline.ts', sha256: sha('offline-source') }] } },
    execution: { manifest: { modules: ['scripts/public-llm-existing-build-continuation.mjs'] } },
    settings: { selection: SELECTION }, priorSelection: SELECTION, stored: { baseline: clone(ORIGINAL) },
    proofs: [], stateFiles: [], candidateFiles: [], proofEvidence: value => value,
    runtime: { containers: [], images: result.images },
    images: {}, backupImage: x.f.images.api,
    pins: { services: { api: { image: x.f.images.api.Id }, worker: { image: x.f.images.worker.Id } } },
  };
  const tokenFor = workerOutputRetirement => {
    const reviewEvidence = sourceVariable('reviewEvidence', { ...base, missing: ['api', 'worker'], inventory: { workerOutputRetirement } });
    assert.deepEqual(reviewEvidence.workerOutputRetirement, workerOutputRetirement ?? null);
    return sourceVariable('review', { hash, reviewEvidence });
  };
  const accepted = tokenFor(result.workerOutputRetirement), beforeException = tokenFor(undefined);
  assert.match(accepted, /^[a-f0-9]{64}$/); assert.notEqual(accepted, beforeException);
  for (const mutation of ['failure-hash', 'positive-image', 'census-proven']) {
    const changed = clone(result.workerOutputRetirement);
    if (mutation === 'failure-hash') changed.workerFailure.stderrSha256 = 'b'.repeat(64);
    if (mutation === 'positive-image') changed.validatedOtherTags.api.Id = 'sha256:' + 'b'.repeat(64);
    if (mutation === 'census-proven') changed.ownPrefixCensusProven = true;
    assert.notEqual(tokenFor(changed), accepted, 'evidence hashing must bind each reviewed exception fact');
  }
});

test('BUILD adapter success discards raw output and does not dispatch an extra operation', async () => {
  let calls = 0;
  const result = await runExistingBuildDocker(['compose', 'build', 'api'], { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, args, options, done) => { calls++; done(null, 'PRIVATE SUCCESS STDOUT', 'PRIVATE SUCCESS STDERR'); });
  assert.equal(result, ''); assert.equal(calls, 1);
});
