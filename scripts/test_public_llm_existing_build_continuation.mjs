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
  executePublicLlmMaintenance, expectedPublicLlmConfig, inspectPublicLlmNamespace, PUBLIC_LLM_ENV, publicLlmEnvironmentOverlay,
  validatePublicLlmContainer, validatePublicLlmImage, publicLlmHelperArguments, PUBLIC_LLM_BACKUP_PROGRAM,
  PUBLIC_LLM_CHECK_PROGRAM, PUBLIC_LLM_INITIALIZE_PROGRAM, capturePublicLlmSource,
} from './public-llm-stand.mjs';
import { PROJECT, LABEL, readProfile } from './public-image-stand.mjs';
import {
  byteFile, privateFile, capturePublicLlmExecutionClosure, PUBLIC_LLM_EXECUTION_MODULES,
} from './public-llm-build-continuation.mjs';
import { fixture } from './public-refresh-cve-fixtures.mjs';
import {
  EXISTING_BUILD_HOLD, preparePublicLlmExistingBuildContinuation, captureExistingBuildExecution,
  publicLlmExistingBuildStand, classifyExistingBuildCause, runExistingBuildDocker,
  inspectExistingBuildPriorImage, existingBuildMetadataDiagnostic,
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
  return { f, model, bound, inspect };
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

test('BUILD adapter success discards raw output and does not dispatch an extra operation', async () => {
  let calls = 0;
  const result = await runExistingBuildDocker(['compose', 'build', 'api'], { root: '/offline-fixture', env: {}, timeout: 1000 }, (program, args, options, done) => { calls++; done(null, 'PRIVATE SUCCESS STDOUT', 'PRIVATE SUCCESS STDERR'); });
  assert.equal(result, ''); assert.equal(calls, 1);
});
