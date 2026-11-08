// Focused offline qualification: real preserving adapter; fake engine/HTTP only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import { adapterFixture, openAiSelection, moduleApiSelection } from './moduleapi-slot-transition-fixture.mjs';
import { runDeployment } from './deploy-core.mjs';
import { deployAdapterDiagnostic } from './deploy-adapter.mjs';
import * as deployment from './public-llm-source-build.mjs';
import * as stand from './public-llm-stand.mjs';
import { loadCveRuntime, publicLlmMainOperation } from './public-cve-bridge-runtime.mjs';

const services = ['web', 'api', 'openai-egress'];
const options = { mode: 'app', services, apply: true };
const read = path => JSON.parse(fs.readFileSync(path, 'utf8'));
const current = f => Object.fromEntries(f.containers().map(c => [f.role(c), structuredClone(c)]));
const detail = (f, result) => JSON.stringify({ result, diagnostics: f.diagnostics, events:f.events, lastCalls:f.calls.slice(-3).map(c=>c.slice(0,3)) });
const attempts = f => fs.existsSync(join(f.stand, 'deploy-adapter-v1'))
  ? fs.readdirSync(join(f.stand, 'deploy-adapter-v1')).map(n => join(f.stand, 'deploy-adapter-v1', n)) : [];
const mutations = f => f.calls.filter(c => c[0] === 'build' || c[0] === 'create' || c[0] === 'compose' && c.includes('up') ||
  c[0] === 'image' && c[1] !== 'inspect' && c[1] !== 'ls' || c[0] === 'container' && ['start', 'stop', 'rm'].includes(c[1]));

// This baseline is deliberately an actual apply, not a mock result or descriptor-only assertion.
test('unchanged v6 follows existing preserving adapter path without selecting ModuleAPI', { timeout: 120000 }, async t => {
  const f = await adapterFixture(t, { installModuleApi: false });
  const prior = current(f), jwt = fs.readFileSync(join(f.stand, 'scan-jwt'));
  const result = await runDeployment(f.adapter, { ...options, services: ['web', 'api'] });
  assert.equal(result.ok, true, detail(f, result));
  assert.equal(f.locked(), false);
  assert.equal(stand.readPublicLlmBinding(f.root).version, 6);
  assert.deepEqual(current(f)['openai-egress'], prior['openai-egress']);
  assert.ok(!f.events.includes('build:openai-egress'));
  assert.deepEqual(fs.readFileSync(join(f.stand, 'scan-jwt')), jwt);
  f.verifyStores();
});

function assertPreserved(f, prior, jwt) {
  const after = current(f);
  assert.equal(Object.keys(after).length, 8, 'same eight peers, no new gateway role');
  assert.equal(f.networks.length, 8);
  for (const name of ['worker', 'egress', 'llm-egress', 'auth-volume-init', 'scan-volume-init']) {
    assert.equal(after[name].Id, prior[name].Id, name + ' retained container');
    assert.equal(after[name].Image, prior[name].Image, name + ' retained image');
    assert.deepEqual(after[name].Config, prior[name].Config, name + ' retained configuration');
  }
  assert.deepEqual(fs.readFileSync(join(f.stand, 'scan-jwt')), jwt);
  f.verifyStores();
  assert.ok(!f.events.some(e => e.startsWith('migration:')));
  assert.ok(!f.calls.some(c => c[0] === 'image' && ['rm', 'prune'].includes(c[1])));
  assert.ok(!f.calls.some(c => ['network', 'volume'].includes(c[0]) && !['inspect', 'ls'].includes(c[1])));
}
function assertV7(f) {
  const after = current(f), api = after.api, gateway = after['openai-egress'];
  assert.deepEqual(stand.readPublicLlmBinding(f.root), deployment.validateModuleApiDeployment(f.desired));
  assert.deepEqual(gateway.Config.Cmd, ['python', '-I', 'moduleapi.py', '--serve']);
  assert.deepEqual(Object.keys(gateway.NetworkSettings.Networks).sort(), ['dip-public-images_openai_internal', 'dip-public-images_openai_uplink']);
  assert.ok(gateway.NetworkSettings.Networks['dip-public-images_openai_internal'].Aliases.includes('moduleapi-egress'));
  assert.ok(!(gateway.NetworkSettings.Networks['dip-public-images_openai_uplink'].Aliases ?? []).includes('moduleapi-egress'));
  assert.deepEqual(api.Mounts.filter(m => m.Name === 'moduleapi-secrets').map(m => [m.Destination, m.RW]), [['/run/moduleapi-secrets', false]]);
  assert.ok(!f.containers().some(c => c.Mounts.some(m => m.Name === 'openai-secrets')), 'old OpenAI volume retained but unused');
  assert.ok(f.volumes.some(v => v.Name === 'openai-secrets'));
  for (const name of ['web', 'worker', 'egress', 'llm-egress']) {
    assert.ok(!Object.keys(after[name].NetworkSettings.Networks).some(n => n.includes('openai_')));
    assert.ok(!after[name].Mounts.some(m => m.Name === 'moduleapi-secrets'));
  }
  assert.ok(!api.Config.Env.some(v => /^(?:OPENAI_|MODULE_API_KEY=)/.test(v)));
  assert.ok(api.Config.Env.includes('LLM_PROVIDER=moduleapi'));
  assert.ok(api.Config.Env.includes('LLM_QUOTA_LIFETIME_USER_COST_MICROS=5000000'));
}
function assertCompletion(f, prior, nonce) {
  assert.match(nonce, /^[a-f0-9]{32}$/);
  const directory = join(f.stand, 'deploy-adapter-v1', nonce);
  const completion = read(join(directory, 'complete.json'));
  assert.equal(completion.nonce, nonce, 'completion belongs to exact acquired operation');
  assert.equal(read(join(directory, 'lease.json')).nonce, nonce);
  assert.equal(read(join(directory, 'intent.json')).nonce, nonce);
  assert.deepEqual(completion.referenceCustody, read(join(directory, 'reference-custody.json')));
  assert.deepEqual(completion.referenceCustody.old.map(r => r.name).sort(), [...services].sort());
  assert.deepEqual(completion.referenceCustody.candidates.map(r => r.name).sort(), [...services].sort());
  for (const row of completion.referenceCustody.old) {
    assert.equal(row.image, prior[row.name].Image, 'genuine old slot image authority');
    assert.ok(f.images.get(row.image).RepoTags.includes(row.tag), 'old image remains pinned');
  }
  assert.ok(!JSON.stringify(completion.referenceCustody).includes('moduleapi-egress'), 'alias is not custody identity');
  return directory;
}

test('real adapter replaces v6 gateway slot with v7, then repeats v7; four stores/JWT/custody/web-last preserved', { timeout: 180000 }, async t => {
  const f = await adapterFixture(t), prior = current(f), jwt = fs.readFileSync(join(f.stand, 'scan-jwt'));
  const protectedBytes = fs.readFileSync(join(f.settings, 'moduleapi-deployment.json'));
  assert.equal(f.quotaRows.length, 3, 'retained settled/reserved/UNKNOWN rows are nonempty');
  assert.ok(f.quotaRows.every(row => JSON.parse(row.quota_policy).paidAccounting.provider === 'OpenAI'));
  const plan = await f.rawAdapter.prepare(options);
  assert.equal(f.locked(), false);
  assert.equal(mutations(f).length, 0, 'read-only plan');
  assert.ok(plan.referenceCustody.old.every(r => r.image === prior[r.name].Image));
  const result = await runDeployment(f.adapter, options);
  assert.equal(result.ok, true, detail(f, result));
  assert.equal(f.locked(), false);
  assertPreserved(f, prior, jwt); assertV7(f);
  for (const name of services) assert.notEqual(current(f)[name].Id, prior[name].Id, name + ' replaced');
  assert.deepEqual(f.events.filter(e => e.startsWith('build:')).sort(), ['build:api', 'build:openai-egress', 'build:web']);
  assert.deepEqual(f.events.filter(e => e.startsWith('snapshot:')), ['snapshot:fenced', 'snapshot:before-api', 'snapshot:after-api']);
  assert.ok(f.events.indexOf('snapshot:before-api') < f.events.indexOf('up:api'));
  assert.ok(f.events.indexOf('snapshot:after-api') < f.events.indexOf('up:web'));
  assert.equal(f.events.filter(e => e.startsWith('up:')).at(-1), 'up:web');
  const readyCalls = f.calls.filter(c => c[0] === 'container' && c[1] === 'exec' && c[2] === current(f).api.Id && c.at(-1).includes('connectModuleApiGateway'));
  assert.ok(readyCalls.length > 0, 'actual API readiness checks selected ModuleAPI gateway');
  assert.ok(readyCalls.every(c => c.at(-1).includes('moduleapi-egress') && !c.at(-1).includes('connectOpenAiGateway')));
  assert.equal(f.operationNonces.length, 1);
  const firstNonce = f.operationNonces[0];
  const first = assertCompletion(f, prior, firstNonce), firstBytes = fs.readFileSync(join(first, 'complete.json'));
  const nextPrior = current(f), offset = f.events.length;
  const repeated = await runDeployment(f.adapter, options);
  assert.equal(repeated.ok, true, detail(f, repeated));
  assert.equal(f.operationNonces.length, 2); assert.notEqual(f.operationNonces[1], firstNonce);
  assertV7(f); assertPreserved(f, nextPrior, jwt); assertCompletion(f, nextPrior, f.operationNonces[1]);
  assert.equal(f.events.slice(offset).filter(e => e.startsWith('up:')).at(-1), 'up:web');
  assert.deepEqual(fs.readFileSync(join(first, 'complete.json')), firstBytes, 'repeat never rewrites prior receipt');
  assert.deepEqual(fs.readFileSync(join(f.settings, 'moduleapi-deployment.json')), protectedBytes, 'adapter never edits desired settings');
});

test('protected v6 without operations reconciles published v2 through actual first and repeat v7 applies', { timeout: 180000 }, async t => {
  const f = await adapterFixture(t, { protectedOperations: false });
  const path = join(f.settings, 'openai-deployment.json'), before = fs.readFileSync(path);
  assert.equal(Object.hasOwn(read(path), 'operations'), false);
  assert.equal(f.publishedSelection.operations, 'public-images-v2');
  assert.deepEqual(f.desired.openai, f.publishedSelection, 'v7 embeds actual published authority, not raw protected descriptor');
  assert.deepEqual(deployment.selectOpenAiOperations(read(path), f.publishedSelection), f.publishedSelection);
  const jwt = fs.readFileSync(join(f.stand, 'scan-jwt'));
  for (const iteration of [0, 1]) {
    const prior = current(f), result = await runDeployment(f.adapter, options);
    assert.equal(result.ok, true, detail(f, result)); assert.equal(f.locked(), false);
    assert.equal(f.operationNonces.length, iteration + 1);
    assertCompletion(f, prior, f.operationNonces[iteration]); assertPreserved(f, prior, jwt); assertV7(f);
    assert.deepEqual(fs.readFileSync(path), before, 'protected v6 file is never rewritten');
    assert.equal(Object.hasOwn(read(path), 'operations'), false);
  }
});

test('postpublished CVE/status/stop admits only sealed retained OpenAI local image after real v7 replacement', { timeout: 120000 }, async t => {
  const f = await adapterFixture(t), prior = current(f), jwt = fs.readFileSync(join(f.stand, 'scan-jwt'));
  const result = await runDeployment(f.adapter, options);
  assert.equal(result.ok, true, detail(f, result));
  const nonce = f.operationNonces[0], directory = assertCompletion(f, prior, nonce);
  const old = f.images.get(prior['openai-egress'].Image), localTag = 'dip-public-images-openai-egress:local';
  assert.ok(old.RepoTags.includes(localTag));
  assert.deepEqual(old.Config.Cmd, ['python', '-I', 'openai.py', '--serve']);
  const completionBytes = fs.readFileSync(join(directory, 'complete.json'));
  const runtime = await loadCveRuntime(f.root), publicOptions = { root: f.root, env: {}, timeout: 30000 };
  const inspect = () => runtime.inspect(f.publicRun, publicOptions, null);
  const observed = await inspect(); runtime.counts(observed); runtime.membership(observed);
  assert.equal(observed.containers.length, 8); assert.ok(observed.images.includes(localTag));
  assert.ok(f.publicCalls.every(c => ['inspect', 'ls'].includes(c[1])), 'CVE inspection is metadata-only');

  // Valid old provider shape alone is not custody. Retarget the *local* name to
  // another same-command image with no owning completion and require refusal.
  const foreign = structuredClone(old), oldTags = [...old.RepoTags];
  foreign.Id = 'sha256:' + '7'.repeat(64); foreign.RepoTags = [localTag];
  old.RepoTags = oldTags.filter(tag => tag !== localTag); f.images.set(foreign.Id, foreign);
  try { await assert.rejects(inspect, 'same old command without sealed immutable identity is not authority'); }
  finally { old.RepoTags = oldTags; f.images.delete(foreign.Id); }

  // Adapter custody seals immutable content IDs, not a historical image.Config
  // snapshot. Fresh :local/ID/custody-tag observations must nevertheless agree.
  const env = [...old.Config.Env];
  const field = old.Config.Env.findIndex(value => value.startsWith('GPG_KEY=')); assert.ok(field >= 0);
  let localRead = false, configChanged = false;
  const racingRun = async (args, execution) => {
    if (localRead && !configChanged && args[0] === 'image' && args[1] === 'inspect' && args[2] === old.Id) {
      configChanged = true; old.Config.Env[field] = 'GPG_KEY=' + 'B'.repeat(40);
    }
    const value = await f.publicRun(args, execution);
    if (args[0] === 'image' && args[1] === 'inspect' && args[2] === localTag) localRead = true;
    return value;
  };
  try { await assert.rejects(runtime.inspect(racingRun, publicOptions, null), 'retained Config cannot drift between local and custody observations'); }
  finally { old.Config.Env = env; }
  assert.equal(configChanged, true, 'race reached actual custody metadata lookup');

  const custodyPath = join(directory, 'reference-custody.json'), custodyBytes = fs.readFileSync(custodyPath);
  fs.appendFileSync(custodyPath, '\n');
  try { await assert.rejects(inspect, 'same parsed custody without exact completion seal is refused'); }
  finally { fs.writeFileSync(custodyPath, custodyBytes); }

  // Removing the owning completion cannot be compensated by accepting both
  // provider commands. Only test-owned evidence is moved and restored here.
  fs.renameSync(join(directory, 'complete.json'), join(directory, 'complete.hidden'));
  try { await assert.rejects(inspect, 'missing actual completion refuses old local-tag authority'); }
  finally { fs.renameSync(join(directory, 'complete.hidden'), join(directory, 'complete.json')); }
  await inspect();
  const logs = [];
  const status = await publicLlmMainOperation('status', { root: f.root, run: f.publicRun, platform: 'darwin', log: line => logs.push(line) });
  assert.equal(status.containers.length, 8); assert.equal(f.locked(), false);
  const beforeStop = current(f), offset = f.publicCalls.length;
  const stopped = await publicLlmMainOperation('stop', { root: f.root, run: f.publicRun, platform: 'darwin', log: line => logs.push(line) });
  assert.equal(stopped.containers.length, 8); assert.ok(stopped.containers.every(c => !c.State.Running));
  assert.equal(f.publicCalls.slice(offset).filter(c => c[0] === 'container' && c[1] === 'stop').length, 1);
  assert.equal(f.locked(), false);
  for (const [name, c] of Object.entries(current(f))) { assert.equal(c.Id, beforeStop[name].Id); assert.equal(c.Image, beforeStop[name].Image); assert.deepEqual(c.Config, beforeStop[name].Config); }
  const stoppedStatus = await publicLlmMainOperation('status', { root: f.root, run: f.publicRun, platform: 'darwin', log: () => {} });
  assert.ok(stoppedStatus.containers.every(c => !c.State.Running));
  assert.ok(old.RepoTags.includes(localTag)); assert.deepEqual(fs.readFileSync(join(directory, 'complete.json')), completionBytes);
  assert.deepEqual(fs.readFileSync(join(f.stand, 'scan-jwt')), jwt); f.verifyStores();
});

test('initial transition requires the three explicit targets and refuses migration/operations upgrades before writes', { timeout: 30000 }, async t => {
  const f = await adapterFixture(t);
  for (const input of [
    { mode: 'web', services: ['web'] },
    ...services.map(missing => ({ mode: 'app', services: services.filter(n => n !== missing) })),
    { mode: 'app', services, migrate: true },
    { mode: 'app', services, migrateHistoryV4ToV5: true },
    { mode: 'app', services: ['api', 'web', 'worker', 'egress', 'llm-egress', 'openai-egress'], upgradeOperations: true },
    { mode: 'app', services: ['api', 'web', 'moduleapi-egress'] },
  ]) {
    await assert.rejects(f.rawAdapter.prepare(input), error => typeof deployAdapterDiagnostic(error).code === 'string');
    assert.equal(f.locked(), false); assert.equal(attempts(f).length, 0); assert.equal(mutations(f).length, 0);
  }
  f.verifyStores();
});

test('v7 descriptor and transition enforce explicit identity, $5 lifetime, embedded v6 and common quota', () => {
  const prior = deployment.validateOpenAiDeployment(openAiSelection()), next = moduleApiSelection(prior);
  assert.deepEqual(deployment.validateOpenAiDeployment(prior), prior, 'legacy v6 unchanged');
  assert.deepEqual(deployment.validateModuleApiBuildDeployment({ prior, next }).next, next);
  assert.doesNotThrow(() => stand.validatePublicLlmTransition(prior, next));
  assert.doesNotThrow(() => stand.validatePublicLlmTransition(next, next));
  assert.throws(() => stand.validatePublicLlmTransition(next, prior), 'no implicit rollback');
  for (const change of [
    n => { n.provider = 'OpenAI'; }, n => { n.environment.MODULEAPI_MODEL = prior.environment.OPENAI_MODEL; },
    n => { delete n.environment.MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION; },
    n => { n.environment.MODULEAPI_RETENTION = 'no-training'; },
    n => { n.environment.OPENAI_API_KEY = 'synthetic-forbidden'; },
    n => { n.environment.MODULE_API_KEY = 'synthetic-forbidden'; },
    n => { n.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS = '5000001'; },
    n => { delete n.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS; },
    n => { n.environment.LLM_QUOTA_REVISION = 'different'; },
    n => { n.openai.environment.OPENAI_POLICY_REVISION = 'different'; },
    n => { n.openrouter = { version: 2, keyVolume: null, timing: 'public-8081-90s-v1' }; },
    n => { n.credentialVolume = 'openai-secrets'; }, n => { n.operations = 'public-images-v1'; },
    n => { n.unapproved = true; },
  ]) {
    const changed = structuredClone(next); change(changed);
    assert.throws(() => deployment.validateModuleApiBuildDeployment({ prior, next: changed }));
    assert.throws(() => deployment.validateModuleApiBuildDeployment({ prior: next, next: changed }));
  }
});

test('disabled/missing ModuleAPI settings are explicit, ambiguous selectors refuse and absence is fenced', { timeout: 30000 }, async t => {
  const prior = deployment.validateOpenAiDeployment(openAiSelection()), disabled = moduleApiSelection(prior);
  disabled.environment.MODULEAPI_ENABLED = 'false'; disabled.credentialVolume = null;
  assert.deepEqual(deployment.validateModuleApiDeployment(disabled), disabled);
  const enabledWithoutVolume = structuredClone(disabled); enabledWithoutVolume.environment.MODULEAPI_ENABLED = 'true';
  assert.throws(() => deployment.validateModuleApiDeployment(enabledWithoutVolume));
  const f = await adapterFixture(t, { installModuleApi: false });
  const missing = stand.loadPublicLlmSettings(f.home, { moduleapi: true });
  assert.equal(missing.selection.version, 6, 'absence preserves current OpenAI path, never silently activates ModuleAPI');
  missing.verify();
  assert.throws(() => stand.loadPublicLlmSettings(f.home, { moduleapi: true, openai: true }));
  fs.writeFileSync(join(f.settings, 'moduleapi-deployment.json'), JSON.stringify(disabled), { mode: 0o600 });
  assert.throws(missing.verify, 'new selector cannot appear outside captured authority');
  assert.deepEqual(stand.loadPublicLlmSettings(f.home, { moduleapi: true }).selection, disabled);
  assert.equal(mutations(f).length, 0); f.verifyStores();
});

for (const kind of ['missing-price', 'wrong-retention', 'wrong-lifetime', 'wrong-mode', 'symlink']) {
  test('protected desired settings refuse ' + kind + ' before mutation', { timeout: 30000 }, async t => {
    const f = await adapterFixture(t, { configure({ settings, desired, write }) {
      const path = join(settings, 'moduleapi-deployment.json');
      if (kind === 'missing-price') delete desired.environment.MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION;
      if (kind === 'wrong-retention') desired.environment.MODULEAPI_RETENTION = 'no-training';
      if (kind === 'wrong-lifetime') desired.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS = '1';
      write(path, desired);
      if (kind === 'wrong-mode') fs.chmodSync(path, 0o644);
      if (kind === 'symlink') { fs.renameSync(path, path + '.target'); fs.symlinkSync(path + '.target', path); }
    } });
    await assert.rejects(f.rawAdapter.prepare(options));
    assert.equal(mutations(f).length, 0); assert.equal(f.locked(), false); assert.equal(attempts(f).length, 0);
    f.verifyStores();
  });
}

for (const kind of ['foreign-consumer', 'wrong-volume-label', 'missing-volume']) {
  test('new credential namespace refuses ' + kind + ' before mutation', { timeout: 30000 }, async t => {
    let changed = false;
    const f = await adapterFixture(t, { engineHook({ containers, volumes }) {
      if (changed) return; changed = true;
      if (kind === 'wrong-volume-label') volumes.find(v => v.Name === 'moduleapi-secrets').Labels = {};
      if (kind === 'missing-volume') volumes.splice(volumes.findIndex(v => v.Name === 'moduleapi-secrets'), 1);
      if (kind === 'foreign-consumer') {
        const foreign = structuredClone(containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'api'));
        foreign.Id = '9'.repeat(64); foreign.Name = '/synthetic-foreign-consumer'; foreign.Config.Labels = {};
        foreign.Mounts.push({ Type: 'volume', Name: 'moduleapi-secrets', Destination: '/foreign', RW: false });
        containers.push(foreign);
      }
    } });
    await assert.rejects(f.rawAdapter.prepare(options));
    assert.equal(changed, true); assert.equal(mutations(f).length, 0); assert.equal(f.locked(), false); f.verifyStores();
  });
}

for (const fault of ['source', 'settings', 'custody']) {
  test('mid-build ' + fault + ' drift retains HOLD without fence/cleanup', { timeout: 60000 }, async t => {
    let changed = false;
    const f = await adapterFixture(t, { engineHook({ args, events, root, settings, images }) {
      if (changed || !events.includes('build:api') || args[0] !== 'container' || args[1] !== 'inspect') return;
      changed = true;
      if (fault === 'source') fs.appendFileSync(join(root, 'server/deploy/gateway/moduleapi.py'), '\n# synthetic source drift\n');

      if (fault === 'settings') fs.appendFileSync(join(settings, 'moduleapi-deployment.json'), ' ');
      if (fault === 'custody') for (const image of images.values()) image.RepoTags = image.RepoTags.filter(tag => !tag.startsWith('dip-deploy-api:old-'));
    } });
    const result = await runDeployment(f.adapter, options);
    assert.equal(changed, true, detail(f, result)); assert.equal(result.ok, false, detail(f, result)); assert.equal(result.lock, 'retained', detail(f, result));
    assert.equal(f.locked(), true); assert.ok(!f.events.includes('stop:web'));
    assert.ok(!f.calls.some(c => c[0] === 'image' && ['rm', 'prune'].includes(c[1])));
    assert.ok(attempts(f).some(p => !fs.existsSync(join(p, 'complete.json')))); f.verifyStores();
  });
}

test('mid-build JWT drift refuses before writer fencing; old site keeps serving with safe release', { timeout: 60000 }, async t => {
  let changed = false;
  const f = await adapterFixture(t, { engineHook({ args, events, stand: state }) {
    if (changed || !events.includes('build:api') || args[0] !== 'container' || args[1] !== 'inspect') return;
    changed = true; fs.writeFileSync(join(state, 'scan-jwt'), 'cd'.repeat(48));
  } });
  const prior = current(f), result = await runDeployment(f.adapter, options);
  assert.equal(changed, true); assert.equal(result.ok, false, detail(f, result));
  assert.equal(result.phase, 'prepareRecovery', detail(f, result));
  assert.equal(result.lock, 'released', detail(f, result)); assert.equal(f.locked(), false);
  assert.ok(!f.events.some(e => e.startsWith('stop:') || e.startsWith('up:')));
  assert.deepEqual(current(f), prior); assert.equal(stand.readPublicLlmBinding(f.root).version, 6); f.verifyStores();
});

test('post-fence JWT drift retains HOLD before any replacement or publication', { timeout: 60000 }, async t => {
  let changed = false;
  const f = await adapterFixture(t, { engineHook({ args, events, stand: state }) {
    if (changed || !events.includes('stop:web') || args[0] !== 'container' || args[1] !== 'inspect') return;
    changed = true; fs.writeFileSync(join(state, 'scan-jwt'), 'cd'.repeat(48));
  } });
  const result = await runDeployment(f.adapter, options);
  assert.equal(changed, true); assert.equal(result.ok, false, detail(f, result));
  assert.equal(result.lock, 'retained', detail(f, result)); assert.equal(f.locked(), true);
  assert.ok(!f.events.some(e => e.startsWith('up:')));
  assert.equal(stand.readPublicLlmBinding(f.root).version, 6);
  assert.ok(!attempts(f).some(p => fs.existsSync(join(p, 'complete.json')))); f.verifyStores();
});

for (const fault of ['missing-alias', 'uplink-alias', 'worker-private-network', 'foreign-old-secret', 'config-secret']) {
  test('mixed transition rejects ' + fault + ' and never publishes web', { timeout: 90000 }, async t => {
    let changed = false;
    const f = await adapterFixture(t, { engineHook({ args, events, containers }) {
      if (changed || !events.includes('up:openai-egress') || args[0] !== 'container' || args[1] !== 'inspect') return;
      const gateway = containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'openai-egress');
      changed = true;
      if (fault === 'missing-alias') gateway.NetworkSettings.Networks['dip-public-images_openai_internal'].Aliases = [];
      if (fault === 'uplink-alias') gateway.NetworkSettings.Networks['dip-public-images_openai_uplink'].Aliases = ['moduleapi-egress'];
      if (fault === 'worker-private-network') containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'worker').NetworkSettings.Networks['dip-public-images_openai_internal'] = {};
      if (fault === 'foreign-old-secret') containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'web').Mounts.push({ Type: 'volume', Name: 'openai-secrets', Destination: '/foreign', RW: false });
      if (fault === 'config-secret') gateway.Config.Env.push('MODULE_API_KEY=synthetic-forbidden');
    } });
    const result = await runDeployment(f.adapter, options);
    assert.equal(changed, true, detail(f, result)); assert.equal(result.ok, false); assert.equal(result.lock, 'retained');
    assert.equal(f.locked(), true); assert.ok(!f.events.includes('up:web'));
    assert.equal(stand.readPublicLlmBinding(f.root).version, 6);
    assert.ok(!attempts(f).some(p => fs.existsSync(join(p, 'complete.json')))); f.verifyStores();
  });
}

for (const store of ['auth', 'ledger', 'history', 'quota']) {
  test('four-store ' + store + ' drift after baseline holds before API/web publication', { timeout: 90000 }, async t => {
    let changed = false;
    const f = await adapterFixture(t, { tamper({ phase, paths, DB }) {
      if (phase !== 'before-api') return; changed = true;
      const db = new DB(paths[store]);
      try { db.exec('CREATE TABLE synthetic_transition_drift(value TEXT)'); } finally { db.close(); }
    } });
    const result = await runDeployment(f.adapter, options);
    assert.equal(changed, true, detail(f, result)); assert.equal(result.ok, false); assert.equal(result.lock, 'retained');
    assert.ok(!f.events.includes('up:api')); assert.ok(!f.events.includes('up:web'));
    assert.equal(stand.readPublicLlmBinding(f.root).version, 6);
  });
}
