import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { fixture } from './public-refresh-cve-fixtures.mjs';
import { PROJECT, LABEL, STATE } from './public-image-stand.mjs';
import { OPENAI_DEPLOYMENT, MODULEAPI_SLOT_DEPLOYMENT, validateOpenAiDeployment, validateModuleApiDeployment } from './public-llm-source-build.mjs';
import { PUBLIC_LLM_ENV, expectedPublicLlmConfig, expectedModuleApiConfig, validatePublicLlmConfig,
  validatePublicLlmContainer, validatePublicLlmImage, validatePublicLlmRetainedImage, publicLlmEnvironmentOverlay, publicLlmSelectedEnvironment,
  validateLlmSelection, validatePublicLlmTransition, loadPublicLlmSettings, readPublicLlmBinding,
  inspectPublicLlmNamespace, capturePublicLlmSource } from './public-llm-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const clone = value => structuredClone(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const role = c => c.Config.Labels['com.docker.compose.service'];
function selections({ suppliedRouter = false } = {}) {
  const environment = { LLM_PROVIDER: 'openai', OPENAI_ENABLED: 'true', OPENAI_MODEL: OPENAI_DEPLOYMENT.model,
    OPENAI_ROUTING_APPROVED: 'true', OPENAI_RETENTION: 'no-training', OPENAI_POLICY_REVISION: 'topology-synthetic-v1',
    OPENAI_ACCOUNTING_REVISION: 'topology-synthetic-v1', OPENAI_MONETARY_LIMIT: 'uncapped',
    OPENAI_INPUT_PRICE_MICROS_PER_MILLION: '1000000', OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION: '2000000',
    OPENAI_TIMEOUT_MS: '1000', OPENAI_REQUEST_BYTES: '65536', OPENAI_RESPONSE_BYTES: '8192',
    OPENAI_INPUT_TOKENS: '4096', OPENAI_OUTPUT_TOKENS: '256', OPENAI_FINDINGS: '100', OPENAI_MAX_CONCURRENT: '2',
    LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_REVISION: 'topology-synthetic-v1', LLM_QUOTA_WINDOW: 'utc-day', LLM_QUOTA_MONETARY_LIMIT: 'uncapped',
    LLM_QUOTA_USER_INPUT: '100000', LLM_QUOTA_USER_OUTPUT: '10000', LLM_QUOTA_SCAN_INPUT: '100000', LLM_QUOTA_SCAN_OUTPUT: '10000',
    LLM_QUOTA_WARNING_PERCENT: '80', LLM_QUOTA_REQUEST_INPUT: '4096', LLM_QUOTA_OBSERVATION_TOKENS: '65536',
    LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000', LLM_QUOTA_RECEIPT_MS: '30000', LLM_QUOTA_REPLAY_DAYS: '7',
    LLM_QUOTA_MAX_ROWS: '100', LLM_QUOTA_DB_BYTES: '1048576', LLM_QUOTA_DISK_HEADROOM_BYTES: '134217728',
    LLM_QUOTA_BUSY_MS: '10', LLM_QUOTA_CLEANUP_BATCH: '10', LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000' };
  const keyVolume = suppliedRouter ? 'diplom-public-8081-llm-key-' + 'a'.repeat(32) : null;
  const prior = validateOpenAiDeployment({ version: 6, provider: 'OpenAI', keyVolume,
    openrouter: { version: 1, keyVolume }, monetaryLimit: 'uncapped', credentialVolume: 'openai-secrets', environment,
    operations: 'public-images-v2' });
  const moduleEnvironment = Object.fromEntries(Object.entries(environment).map(([key, value]) => [key.replace(/^OPENAI_/, 'MODULEAPI_'), value]));
  Object.assign(moduleEnvironment, { LLM_PROVIDER: 'moduleapi', MODULEAPI_MODEL: 'gpt-5.4-mini', MODULEAPI_RETENTION: 'unknown' });
  const next = validateModuleApiDeployment({ version: 7, provider: 'ModuleAPI', keyVolume, openrouter: prior.openrouter, openai: prior,
    monetaryLimit: 'uncapped', credentialVolume: 'moduleapi-secrets', environment: moduleEnvironment, operations: prior.operations });
  return { prior, next };
}
function temp(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'moduleapi-slot-topology-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root;
}
function materialized(t, options = {}) {
  const f = fixture(t), { next, prior } = selections(options), model = expectedPublicLlmConfig(f.root, null, next);
  for (const [name, command] of [['llm-egress', ['python', '-I', 'openrouter.py']], ['openai-egress', [...MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand]]]) {
    f.images[name] = clone(f.images.egress); f.images[name].Id = 'sha256:' + sha(name);
    f.images[name].RepoTags = [`${PROJECT}-${name}:local`]; f.images[name].Config.Cmd = command;
  }
  f.containers = Object.entries(model.services).map(([name, spec], index) => {
    const c = f.makeContainer(name, spec, index);
    if (name.endsWith('egress')) c.Config.Env = [...f.images[name].Config.Env];
    if (spec.entrypoint) c.Config.Entrypoint = clone(spec.entrypoint);
    if (spec.ulimits) c.HostConfig.Ulimits = [{ Name: 'core', Soft: 0, Hard: 0 }];
    if (spec.logging) c.HostConfig.LogConfig = { Type: spec.logging.driver, Config: clone(spec.logging.options) };
    const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; c.Path = command[0]; c.Args = command.slice(1);
    for (const m of c.Mounts.filter(m => m.Type === 'volume')) {
      const d = c.HostConfig.Mounts.find(d => d.Target === m.Destination);
      const declaration = model.volumes[spec.volumes.find(v => v.target === m.Destination).source];
      if (declaration.external) { d.Source = declaration.name; d.VolumeOptions = { NoCopy: true }; m.Name = declaration.name; }
      m.Driver = 'local'; m.Source = '/fixture/volumes/' + m.Name;
    }
    for (const [name, endpoint] of Object.entries(c.NetworkSettings.Networks)) {
      const aliases = spec.networks?.[name.slice(PROJECT.length + 1)]?.aliases;
      if (aliases) endpoint.Aliases = [c.Name.slice(1), role(c), ...aliases];
    }
    return c;
  });
  f.networks = Object.values(model.networks).map(n => ({ Name: n.name, Id: sha(n.name), Driver: 'bridge',
    Labels: { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT }, Internal: Boolean(n.internal), Options: null, Containers: {} }));
  f.volumes = Object.values(model.volumes).map(v => ({ Name: v.name, Driver: 'local', Scope: 'local', Options: null,
    Mountpoint: '/fixture/volumes/' + v.name, Labels: !v.external ? { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT } :
      v.name === next.keyVolume ? { 'diplom.public-llm': 'key-v1' } :
        { [`org.diplom.${v.name === 'moduleapi-secrets' ? 'moduleapi' : 'openai'}-secret`]: 'v1',
          [`org.diplom.${v.name === 'moduleapi-secrets' ? 'moduleapi' : 'openai'}-secret.claim`]: 'a'.repeat(32) } }));
  f.attachments();
  const calls = [];
  const run = async args => {
    calls.push(args);
    assert.ok(['container', 'image', 'network', 'volume'].includes(args[0]));
    assert.ok(['inspect', 'ls'].includes(args[1]), 'no lifecycle permitted');
    if (args[1] === 'inspect') {
      const group = args[0] === 'image' ? Object.values(f.images) : f[args[0] + 's'];
      const rows = args.slice(2).map(id => group.find(v => v.Id === id || v.Name === id || v.Name === '/' + id || v.RepoTags?.includes(id)));
      assert.ok(rows.every(Boolean), 'unknown fake identity'); return JSON.stringify(rows);
    }
    if (args[0] === 'image') return Object.values(f.images).flatMap(im => im.RepoTags).join('\n');
    if (args[0] === 'container') {
      const filter = args.find(s => s.startsWith('volume='));
      if (filter) return f.containers.filter(c => c.Mounts.some(m => m.Name === filter.slice(7))).map(c => c.Id).join('\n');
      return f.containers.map(c => c.Name.slice(1) + '\t' + PROJECT).join('\n');
    }
    return f[args[0] + 's'].map(v => v.Name + '\t' + (v.Labels['com.docker.compose.project'] ?? '')).join('\n');
  };
  return { ...f, model, next, prior, run, calls };
}

test('v7 keeps eight services/eight networks and replaces only the historical slot', t => {
  const f = materialized(t, { suppliedRouter: true }), old = expectedPublicLlmConfig(f.root, null, f.prior);
  assert.equal(Object.keys(f.model.services).length, 8); assert.equal(Object.keys(f.model.networks).length, 8);
  assert.deepEqual(Object.keys(f.model.services).sort(), Object.keys(old.services).sort());
  assert.deepEqual(f.model.networks, old.networks);
  for (const name of ['web', 'worker', 'llm-egress', 'egress', 'auth-volume-init', 'scan-volume-init']) assert.deepEqual(f.model.services[name], old.services[name]);
  const gateway = f.model.services['openai-egress'];
  assert.equal(gateway.build.dockerfile, 'server/deploy/gateway/moduleapi.Dockerfile');
  assert.deepEqual(gateway.command, ['python', '-I', 'moduleapi.py', '--serve']);
  assert.deepEqual(gateway.networks, { openai_internal: { aliases: ['moduleapi-egress'] }, openai_uplink: null });
  assert.equal(gateway.ports, undefined);
  assert.equal(f.model.services.api.environment.LLM_PROVIDER, 'moduleapi');
  assert.equal(f.model.services.api.environment.MODULEAPI_RETENTION, 'unknown');
  assert.equal(f.model.services.api.environment.OPENAI_RETENTION, undefined);
  assert.deepEqual(f.model.volumes['openai-secrets'], { name: 'openai-secrets', external: true });
  assert.equal(f.containers.filter(c => c.Mounts.some(m => m.Name === 'openai-secrets')).length, 0);
  assert.deepEqual(f.model.services.api.volumes.find(m => m.target === '/run/moduleapi-secrets'), {
    type: 'volume', source: 'moduleapi-secrets', target: '/run/moduleapi-secrets', read_only: true, volume: { nocopy: true },
  });
  assert.doesNotThrow(() => validatePublicLlmConfig(f.model, f.root, null, f.next));
  assert.deepEqual(expectedModuleApiConfig(f.root, null, f.next), f.model);
});

for (const [name, mutate] of Object.entries({
  'wrong slot command': m => { m.services['openai-egress'].command = [...OPENAI_DEPLOYMENT.gatewayCommand]; },
  'arbitrary slot alias': m => { m.services['openai-egress'].networks.openai_internal.aliases.push('evil'); },
  'alias on uplink': m => { m.services['openai-egress'].networks.openai_uplink = { aliases: ['moduleapi-egress'] }; },
  'alias on worker': m => { m.services.worker.networks.scan_internal = { aliases: ['moduleapi-egress'] }; },
  'alias on api': m => { m.services.api.networks.openai_internal = { aliases: ['moduleapi-egress'] }; },
  'extra gateway': m => { m.services['moduleapi-egress'] = clone(m.services['openai-egress']); },
  'extra network': m => { m.networks.moduleapi_internal = { internal: true }; },
  'published gateway': m => { m.services['openai-egress'].ports = ['8080:8080']; },
  'worker secret': m => { m.services.worker.volumes.push(clone(m.services.api.volumes.at(-1))); },
  'writable key': m => { m.services.api.volumes.at(-1).read_only = false; },
  'bind key': m => { m.services.api.volumes.at(-1).type = 'bind'; },
  'copy key': m => { m.services.api.volumes.at(-1).volume.nocopy = false; },
  'old key mounted': m => { m.services.api.volumes.push({ type: 'volume', source: 'openai-secrets', target: '/run/openai-secrets', read_only: true, volume: { nocopy: true } }); },
  'key environment': m => { m.services.api.environment.MODULE_API_KEY = 'synthetic_not_real'; },
  'old provider identity': m => { m.services.api.environment.LLM_PROVIDER = 'openai'; },
  'false retention': m => { m.services.api.environment.MODULEAPI_RETENTION = 'no-training'; },
  'wrong bootstrap': m => { m.services.api.entrypoint = [...OPENAI_DEPLOYMENT.entrypoint]; },
  'wrong retained volume identity': m => { m.volumes['openai-secrets'].name = 'unapproved-old-secret'; },
})) test(`strict v7 Compose rejects ${name}`, t => {
  const f = materialized(t), bad = clone(f.model); mutate(bad);
  assert.throws(() => validatePublicLlmConfig(bad, f.root, null, f.next));
});

test('v7 actual image/container projection validates all roles without mutating observations', t => {
  const f = materialized(t, { suppliedRouter: true });
  for (const c of f.containers) {
    const name = role(c), before = clone(c), image = clone(f.images[name]);
    assert.doesNotThrow(() => validatePublicLlmContainer(c, name, f.model.services[name], f.images[name], f.model, { images: f.images }, f.next));
    assert.deepEqual(c, before); assert.deepEqual(f.images[name], image);
  }
  assert.throws(() => validatePublicLlmImage(f.images['openai-egress'], 'openai-egress', f.prior));
  const old = clone(f.images['openai-egress']); old.Config.Cmd = [...OPENAI_DEPLOYMENT.gatewayCommand];
  assert.doesNotThrow(() => validatePublicLlmImage(old, 'openai-egress', f.prior));
  assert.throws(() => validatePublicLlmImage(old, 'openai-egress', f.next));
});

test('v7 retained-image authority supports exactly embedded legacy and current slot commands', t => {
  const f = materialized(t), moduleImage = clone(f.images['openai-egress']), legacyImage = clone(moduleImage);
  legacyImage.Config.Cmd = [...OPENAI_DEPLOYMENT.gatewayCommand];
  assert.doesNotThrow(() => validatePublicLlmRetainedImage(moduleImage, 'openai-egress', f.next));
  assert.doesNotThrow(() => validatePublicLlmRetainedImage(legacyImage, 'openai-egress', f.next));
  assert.doesNotThrow(() => validatePublicLlmRetainedImage(legacyImage, 'openai-egress', f.prior));
  assert.throws(() => validatePublicLlmRetainedImage(moduleImage, 'openai-egress', f.prior));
  assert.throws(() => validatePublicLlmImage(legacyImage, 'openai-egress', f.next), 'normal v7 slot still rejects legacy command');
  for (const command of [['python', '-I', 'proxy.py'], ['python', '-I', 'openrouter.py'], ['python', '-I', 'moduleapi.py'], ['sh']]) {
    const bad = clone(moduleImage); bad.Config.Cmd = command;
    assert.throws(() => validatePublicLlmRetainedImage(bad, 'openai-egress', f.next));
  }
  for (const image of [moduleImage, legacyImage]) {
    const bad = clone(image); bad.Config.Env.push('MODULE_API_KEY=synthetic_not_real');
    assert.throws(() => validatePublicLlmRetainedImage(bad, 'openai-egress', f.next));
  }
});

for (const [name, mutate] of Object.entries({
  'missing alias': c => { c.NetworkSettings.Networks[PROJECT + '_openai_internal'].Aliases = []; },
  'uplink alias': c => { c.NetworkSettings.Networks[PROJECT + '_openai_uplink'].Aliases = ['moduleapi-egress']; },
  'unknown alias': c => { c.NetworkSettings.Networks[PROJECT + '_openai_internal'].Aliases.push('extra'); },
  'wrong command': c => { c.Config.Cmd = [...OPENAI_DEPLOYMENT.gatewayCommand]; },
  'extra network': c => { c.NetworkSettings.Networks.extra = {}; },
  'published listener': c => { c.HostConfig.PortBindings = { '8080/tcp': [{ HostPort: '8080' }] }; },
})) test(`v7 slot runtime refuses ${name}`, t => {
  const f = materialized(t), gateway = clone(f.containers.find(c => role(c) === 'openai-egress')); mutate(gateway);
  assert.throws(() => validatePublicLlmContainer(gateway, 'openai-egress', f.model.services['openai-egress'], f.images['openai-egress'], f.model, {}, f.next));
});

for (const [name, mutate] of Object.entries({
  'key env': c => { c.Config.Env.push('MODULE_API_KEY=synthetic_not_real'); },
  'old key env': c => { c.Config.Env.push('OPENAI_API_KEY=synthetic_not_real'); },
  'writable secret': c => { c.Mounts.find(m => m.Name === 'moduleapi-secrets').RW = true; },
  'wrong secret': c => { c.HostConfig.Mounts.find(m => m.Target === '/run/moduleapi-secrets').Source = 'openai-secrets'; },
  'wrong exec': c => { c.Path = '/unapproved/node'; },
  'wrong entrypoint': c => { c.Config.Entrypoint = [...OPENAI_DEPLOYMENT.entrypoint]; },
})) test(`v7 API runtime refuses ${name}`, t => {
  const f = materialized(t), api = clone(f.containers.find(c => role(c) === 'api')); mutate(api);
  assert.throws(() => validatePublicLlmContainer(api, 'api', f.model.services.api, f.images.api, f.model, {}, f.next));
});

test('stopped v7 endpoints allow absent live DNS only; running slot still requires alias', t => {
  const f = materialized(t), gateway = clone(f.containers.find(c => role(c) === 'openai-egress'));
  gateway.State.Running = false; gateway.State.Status = 'exited'; gateway.State.Pid = 0;
  for (const endpoint of Object.values(gateway.NetworkSettings.Networks)) { endpoint.Aliases = null; endpoint.DNSNames = null; }
  assert.doesNotThrow(() => validatePublicLlmContainer(gateway, 'openai-egress', f.model.services['openai-egress'], f.images['openai-egress'], f.model, {}, f.next));
  gateway.State.Running = true; assert.throws(() => validatePublicLlmContainer(gateway, 'openai-egress', f.model.services['openai-egress'], f.images['openai-egress'], f.model, {}, f.next));
});

test('v7 Compose normalization accepts only exact harmless defaults', t => {
  const f = materialized(t), model = clone(f.model);
  model.services.api.ulimits = { core: {} };
  model.services.api.networks.openai_internal = { priority: 0 };
  model.services['openai-egress'].networks.openai_internal.priority = 0;
  model.services['openai-egress'].networks.openai_uplink = { priority: 0 };
  for (const dependency of Object.values(model.services.api.depends_on)) { dependency.required = true; dependency.restart = false; }
  assert.doesNotThrow(() => validatePublicLlmConfig(model, f.root, null, f.next));
  for (const bad of [{ core: { soft: 0 } }, { core: { soft: 1, hard: 0 } }, { core: {}, other: {} }]) {
    model.services.api.ulimits = bad; assert.throws(() => validatePublicLlmConfig(model, f.root, null, f.next));
  }
});

test('disabled v7 without new secret keeps old external volume unmounted and never selects old bootstrap', t => {
  const f = materialized(t), disabled = validateModuleApiDeployment({ ...f.next, credentialVolume: null,
    environment: { ...f.next.environment, MODULEAPI_ENABLED: 'false' } });
  const model = expectedPublicLlmConfig(f.root, null, disabled);
  assert.equal(model.services.api.entrypoint, undefined); assert.equal(model.volumes['moduleapi-secrets'], undefined);
  assert.deepEqual(model.volumes['openai-secrets'], { name: 'openai-secrets', external: true });
  assert.ok(!model.services.api.volumes.some(m => m.target.includes('secrets')));
  assert.doesNotThrow(() => validatePublicLlmConfig(model, f.root, null, disabled));
});

test('selection transition is v6 -> distinct v7, repeats v7, never implicit rollback', () => {
  const { prior, next } = selections();
  assert.deepEqual(validateLlmSelection(next), next);
  assert.doesNotThrow(() => validatePublicLlmTransition(prior, next));
  assert.doesNotThrow(() => validatePublicLlmTransition(next, next));
  assert.throws(() => validatePublicLlmTransition(next, prior));
  assert.throws(() => validatePublicLlmTransition(null, next));
  assert.throws(() => validatePublicLlmTransition(prior, { ...next, openai: { ...prior, credentialVolume: null } }));
  assert.equal(publicLlmSelectedEnvironment(next).LLM_PROVIDER, 'moduleapi');
});

function settings(t, { descriptor = true } = {}) {
  const home = temp(t), path = join(home, '.local/state/diplom-public-images/llm'), { prior, next } = selections();
  fs.mkdirSync(path, { recursive: true, mode: 0o700 });
  const write = (name, value) => fs.writeFileSync(join(path, name), typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  write('llm.env', Object.entries(PUBLIC_LLM_ENV).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
  write('openai-deployment.json', prior); if (descriptor) write('moduleapi-deployment.json', next);
  return { home, path, prior, next, write };
}

test('fixed protected settings select v7, absent descriptor remains v6, old path unaffected', t => {
  const x = settings(t);
  const selected = loadPublicLlmSettings(x.home, { moduleapi: true }); assert.deepEqual(selected.selection, x.next); selected.verify();
  assert.deepEqual(loadPublicLlmSettings(x.home, { openai: true }).selection, x.prior);
  assert.deepEqual(loadPublicLlmSettings(x.home).selection, x.prior.openrouter);
  assert.throws(() => loadPublicLlmSettings(x.home, { moduleapi: true, openai: true }));
  const absent = settings(t, { descriptor: false }), fallback = loadPublicLlmSettings(absent.home, { moduleapi: true });
  assert.deepEqual(fallback.selection, absent.prior); fallback.verify();
  absent.write('moduleapi-deployment.json', absent.next); assert.throws(fallback.verify);
});

for (const kind of ['malformed', 'mode', 'symlink', 'wrong-prior', 'mutation']) test(`settings refuse ${kind} descriptor without credential fallback`, t => {
  const x = settings(t);
  if (kind === 'malformed') x.write('moduleapi-deployment.json', '{');
  if (kind === 'mode') fs.chmodSync(join(x.path, 'moduleapi-deployment.json'), 0o644);
  if (kind === 'symlink') { fs.renameSync(join(x.path, 'moduleapi-deployment.json'), join(x.path, 'other')); fs.symlinkSync('other', join(x.path, 'moduleapi-deployment.json')); }
  if (kind === 'wrong-prior') { const bad = clone(x.next); bad.openai.environment.OPENAI_POLICY_REVISION = 'wrong'; x.write('moduleapi-deployment.json', bad); }
  if (kind === 'mutation') { const selected = loadPublicLlmSettings(x.home, { moduleapi: true }); x.write('moduleapi-deployment.json', { ...x.next, environment: { ...x.next.environment, MODULEAPI_POLICY_REVISION: 'changed' } }); assert.throws(selected.verify); }
  else assert.throws(() => loadPublicLlmSettings(x.home, { moduleapi: true }));
});

test('v7 publication round-trip accepts larger embedded descriptor, exact overlay required', t => {
  const root = temp(t), path = join(root, STATE), { next } = selections(); fs.mkdirSync(path, { mode: 0o700 });
  fs.writeFileSync(join(path, 'llm-profile.json'), JSON.stringify(next), { mode: 0o600 });
  fs.writeFileSync(join(path, 'compose.llm-env.json'), JSON.stringify(publicLlmEnvironmentOverlay(next)), { mode: 0o600 });
  assert.deepEqual(readPublicLlmBinding(root), next);
  const overlay = publicLlmEnvironmentOverlay(next); overlay.services.api.environment.MODULEAPI_MODEL = 'other';
  fs.writeFileSync(join(path, 'compose.llm-env.json'), JSON.stringify(overlay)); assert.throws(() => readPublicLlmBinding(root));
});

test('v7 readonly namespace returns eight real peers/networks and validates retired/current secrets', async t => {
  const f = materialized(t, { suppliedRouter: true });
  const observed = await inspectPublicLlmNamespace(f.run, {}, f.root, null, f.next, { images: f.images });
  assert.equal(observed.containers.length, 8); assert.equal(observed.networks.length, 8);
  assert.equal(new Set(observed.containers.map(c => c.Id)).size, 8);
  assert.ok(observed.volumes.some(v => v.Name === 'openai-secrets'));
  assert.ok(observed.volumes.some(v => v.Name === 'moduleapi-secrets'));
  assert.ok(f.calls.every(args => ['inspect', 'ls'].includes(args[1])));
});

test('v7 namespace refuses foreign network members and retired-secret consumers', async t => {
  for (const fault of ['network-member', 'retired-consumer', 'key-label']) {
    const f = materialized(t);
    if (fault === 'network-member') f.networks.find(n => n.Name === PROJECT + '_openai_internal').Containers['f'.repeat(64)] = { Name: 'foreign' };
    if (fault === 'key-label') f.volumes.find(v => v.Name === 'moduleapi-secrets').Labels = { 'org.diplom.openai-secret': 'v1' };
    const run = async args => fault === 'retired-consumer' && args.includes('volume=openai-secrets') ? 'f'.repeat(64) : f.run(args);
    await assert.rejects(inspectPublicLlmNamespace(run, {}, f.root, null, f.next, { images: f.images }));
  }
});

test('moduleapi source capture fences public recipes/bootstrap/init/gateway without private state', t => {
  const initial = capturePublicLlmSource(ROOT, { moduleapi: true });
  const names = new Set(initial.manifest.files.map(f => f.path));
  for (const path of ['server/deploy/moduleapi-api.Dockerfile', 'server/deploy/moduleapi-secret-bootstrap.mjs',
    'server/deploy/moduleapi-secret-init.py', 'server/deploy/moduleapi-secret-init.Dockerfile',
    'scripts/moduleapi-secret-provision.py', 'server/deploy/gateway/moduleapi.py', 'server/deploy/gateway/moduleapi.Dockerfile',
    'scripts/public-llm-source-build.mjs', 'scripts/public-llm-stand.mjs']) assert.ok(names.has(path), path);
  assert.ok(initial.manifest.files.every(f => !f.path.startsWith('.local-') && !f.path.endsWith('server.env')));
  const root = temp(t);
  for (const path of names) { fs.mkdirSync(dirname(join(root, path)), { recursive: true }); fs.copyFileSync(join(ROOT, path), join(root, path)); }
  for (const name of ['src', 'public', 'server/api/src', 'server/runtime/src']) fs.mkdirSync(join(root, name), { recursive: true });
  const captured = capturePublicLlmSource(root, { moduleapi: true }); captured.verify();
  fs.appendFileSync(join(root, 'server/deploy/gateway/moduleapi.py'), '\n# synthetic source drift\n'); assert.throws(captured.verify);
});
