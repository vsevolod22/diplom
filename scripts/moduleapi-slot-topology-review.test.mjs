// Review regressions only: disposable protected metadata + production adapter
// with fake engine/HTTP. No real credentials, Docker or network operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { adapterFixture, openAiSelection, moduleApiSelection } from './moduleapi-slot-transition-fixture.mjs';
import { runDeployment } from './deploy-core.mjs';
import { loadCveRuntime } from './public-cve-bridge-runtime.mjs';
import { PROJECT } from './public-image-stand.mjs';
import { validateOpenAiDeployment, validateModuleApiDeployment, validateModuleApiBuildDeployment } from './public-llm-source-build.mjs';
import { loadPublicLlmSettings, PUBLIC_LLM_ENV, validatePublicLlmTransition, validatePublicLlmImage,
  expectedModuleApiConfig, validateModuleApiConfig } from './public-llm-stand.mjs';

const clone = value => structuredClone(value);
const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

test('Compose pruning normalizes only unused known retired OpenAI external declaration', () => {
  const selection = validateModuleApiDeployment(moduleApiSelection(validateOpenAiDeployment(openAiSelection())));
  const expected = expectedModuleApiConfig(ROOT, null, selection), rendered = clone(expected);
  delete rendered.volumes['openai-secrets']; const original = clone(rendered);
  assert.doesNotThrow(() => validateModuleApiConfig(rendered, ROOT, null, selection));
  assert.deepEqual(rendered, original, 'validation never mutates real render or expected topology');
  assert.deepEqual(expected.volumes['openai-secrets'], { name: selection.openai.credentialVolume, external: true });
  assert.doesNotThrow(() => validateModuleApiConfig(expected, ROOT, null, selection));
  const disabled = validateModuleApiDeployment({ ...selection, credentialVolume: null,
    environment: { ...selection.environment, MODULEAPI_ENABLED: 'false' } });
  const noKey = expectedModuleApiConfig(ROOT, null, disabled); delete noKey.volumes['openai-secrets'];
  assert.doesNotThrow(() => validateModuleApiConfig(noKey, ROOT, null, disabled));
});

test('Compose pruning refuses wrong present declaration, missing other volumes and every old-secret reference', () => {
  const selection = validateModuleApiDeployment(moduleApiSelection(validateOpenAiDeployment(openAiSelection())));
  const expected = expectedModuleApiConfig(ROOT, null, selection), prune = () => {
    const value = clone(expected); delete value.volumes['openai-secrets']; return value;
  };
  for (const declaration of [{ name: 'wrong', external: true }, { name: 'openai-secrets', external: false },
    { name: 'openai-secrets', external: true, driver: 'local' }, null]) {
    const bad = clone(expected); bad.volumes['openai-secrets'] = declaration;
    assert.throws(() => validateModuleApiConfig(bad, ROOT, null, selection));
  }
  for (const key of Object.keys(expected.volumes).filter(key => key !== 'openai-secrets')) {
    const bad = prune(); delete bad.volumes[key]; assert.throws(() => validateModuleApiConfig(bad, ROOT, null, selection), key);
  }
  const extra = prune(); extra.volumes.unapproved = { name: 'unapproved', external: true };
  assert.throws(() => validateModuleApiConfig(extra, ROOT, null, selection));
  const suppliedRouter = 'diplom-public-8081-llm-key-' + 'a'.repeat(32);
  const priorWithRouter = validateOpenAiDeployment({ ...selection.openai, keyVolume: suppliedRouter,
    openrouter: { ...selection.openrouter, keyVolume: suppliedRouter } });
  const withRouter = validateModuleApiDeployment(moduleApiSelection(priorWithRouter));
  const missingRouter = expectedModuleApiConfig(ROOT, null, withRouter);
  delete missingRouter.volumes['openai-secrets']; delete missingRouter.volumes.public_llm_key;
  assert.throws(() => validateModuleApiConfig(missingRouter, ROOT, null, withRouter));
  for (const service of Object.keys(expected.services)) for (const mount of [
    { type: 'volume', source: 'openai-secrets', target: '/run/old', read_only: true, volume: { nocopy: true } },
    { type: 'bind', source: 'openai-secrets', target: '/run/old', read_only: true }, 'openai-secrets:/run/old:ro',
  ]) {
    const bad = prune(); bad.services[service].volumes ??= []; bad.services[service].volumes.push(mount);
    assert.throws(() => validateModuleApiConfig(bad, ROOT, null, selection), service);
  }
});
function protectedSettings(t) {
  const home = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'moduleapi-review-settings-')));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const path = join(home, '.local/state/diplom-public-images/llm'); fs.mkdirSync(path, { recursive: true, mode: 0o700 });
  const published = validateOpenAiDeployment(openAiSelection()), next = validateModuleApiDeployment(moduleApiSelection(published));
  const protectedV6 = clone(published); delete protectedV6.operations;
  const write = (name, value) => fs.writeFileSync(join(path, name), typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  write('llm.env', Object.entries(PUBLIC_LLM_ENV).map(([key, value]) => `${key}=${value}`).join('\n') + '\n');
  write('openai-deployment.json', protectedV6); write('moduleapi-deployment.json', next);
  return { home, path, published, next, protectedV6, write };
}

test('review P2 operations-only publication reconciles protected v6 absence without rewriting settings', t => {
  const x = protectedSettings(t), before = fs.readFileSync(join(x.path, 'openai-deployment.json'));
  const first = loadPublicLlmSettings(x.home, { moduleapi: true });
  assert.deepEqual(first.selection, x.next); first.verify();
  assert.doesNotThrow(() => validateModuleApiBuildDeployment({ prior: x.published, next: first.selection }));
  const repeat = loadPublicLlmSettings(x.home, { moduleapi: true });
  assert.doesNotThrow(() => validatePublicLlmTransition(first.selection, repeat.selection));
  assert.deepEqual(fs.readFileSync(join(x.path, 'openai-deployment.json')), before);
  assert.equal(loadPublicLlmSettings(x.home, { openai: true }).selection.operations, undefined, 'old loader unchanged');
});

for (const [name, mutate] of Object.entries({
  'provider policy': e => { e.environment.OPENAI_POLICY_REVISION = 'unapproved-change'; },
  'price': e => { e.environment.OPENAI_INPUT_PRICE_MICROS_PER_MILLION = '1000001'; },
  'quota revision': e => { e.environment.LLM_QUOTA_REVISION = 'unapproved-change'; },
  'lifetime': e => { e.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS = '5000001'; },
  'secret volume': e => { e.credentialVolume = null; e.environment.OPENAI_ENABLED = 'false'; },
  'router': e => { e.openrouter = { version: 2, keyVolume: null, timing: 'public-8081-90s-v1' }; },
})) test(`operations reconciliation still refuses protected ${name} mismatch`, t => {
  const x = protectedSettings(t), changed = clone(x.protectedV6); mutate(changed); x.write('openai-deployment.json', changed);
  assert.throws(() => loadPublicLlmSettings(x.home, { moduleapi: true }));
});

test('review P2 actual first/repeat adapter publication admits sealed old local tag through CVE/status/stop inspection', { timeout: 180000 }, async t => {
  const f = await adapterFixture(t), options = { mode: 'app', services: ['web', 'api', 'openai-egress'], apply: true };
  const protectedPath = join(f.settings, 'openai-deployment.json'), protectedV6 = JSON.parse(fs.readFileSync(protectedPath));
  delete protectedV6.operations; fs.writeFileSync(protectedPath, JSON.stringify(protectedV6));
  const protectedBytes = fs.readFileSync(protectedPath), oldGateway = clone(f.containers().find(c => f.role(c) === 'openai-egress'));
  const localTag = `${PROJECT}-openai-egress:local`;
  const first = await runDeployment(f.adapter, options);
  assert.equal(first.ok, true, JSON.stringify({ first, diagnostics: f.diagnostics }));
  const nonce = f.operationNonces.at(-1), audit = join(f.stand, 'deploy-adapter-v1', nonce);
  const completePath = join(audit, 'complete.json'), completeBytes = fs.readFileSync(completePath), complete = JSON.parse(completeBytes);
  const custodyPath = join(audit, 'reference-custody.json'), custodyBytes = fs.readFileSync(custodyPath);
  const ownedOld = complete.referenceCustody.old.find(row => row.name === 'openai-egress');
  assert.equal(ownedOld.image, oldGateway.Image);
  const currentGateway = f.containers().find(c => f.role(c) === 'openai-egress');
  assert.notEqual(currentGateway.Image, oldGateway.Image);
  assert.ok(f.images.get(oldGateway.Image).RepoTags.includes(localTag), 'old local tag deliberately retained');
  const inspect = async (run = f.publicRun) => {
    const runtime = await loadCveRuntime(f.root);
    const found = await runtime.inspect(run, {}, null, {}); runtime.counts(found);
    assert.equal(found.containers.length, 8); assert.equal(found.networks.length, 8); return found;
  };
  const found = await inspect();
  assert.equal(found.containers.find(c => f.role(c) === 'openai-egress').Image, currentGateway.Image);
  assert.throws(() => validatePublicLlmImage(f.images.get(oldGateway.Image), 'openai-egress', f.desired), 'current validator never accepts old provider');
  const negative = async (name, change, restore) => {
    try { change(); await assert.rejects(inspect(), name); } finally { restore(); }
  };
  await negative('changed sealed custody rejected', () => fs.appendFileSync(custodyPath, ' '), () => fs.writeFileSync(custodyPath, custodyBytes));
  const ownerPath = join(audit, 'operation.lock/deploy-adapter-owner.json'), ownerBytes = fs.readFileSync(ownerPath);
  await negative('wrong original operation owner rejected', () => fs.writeFileSync(ownerPath, JSON.stringify({ version: 2, nonce: 'f'.repeat(32), kind: 'preserving-deployment' })),
    () => fs.writeFileSync(ownerPath, ownerBytes));
  const oldConfig = clone(f.images.get(oldGateway.Image).Config);
  await negative('sealed old ID cannot authorize arbitrary gateway command', () => { f.images.get(oldGateway.Image).Config.Cmd = ['sh']; },
    () => { f.images.get(oldGateway.Image).Config = clone(oldConfig); });
  await negative('missing original custody rejected', () => fs.renameSync(custodyPath, custodyPath + '.held'), () => fs.renameSync(custodyPath + '.held', custodyPath));
  await negative('completion refs cannot grant another image ID', () => {
    const changed = clone(complete); changed.references = changed.references.filter(ref => ref.name !== 'openai-egress');
    fs.writeFileSync(completePath, JSON.stringify(changed));
  }, () => fs.writeFileSync(completePath, completeBytes));
  for (const fault of ['id', 'config', 'retained-tag']) {
    const run = async args => {
      const text = await f.publicRun(args);
      if (args[0] !== 'image' || args[1] !== 'inspect') return text;
      const rows = JSON.parse(text);
      if (fault === 'id' && args[2] === localTag) rows[0].Id = 'sha256:' + 'f'.repeat(64);
      if (fault === 'config' && args[2] === localTag) rows[0].Config.Cmd = ['python', '-I', 'moduleapi.py', '--serve'];
      if (fault === 'retained-tag' && args[2] === ownedOld.tag) rows[0].RepoTags = rows[0].RepoTags.filter(tag => tag !== ownedOld.tag);
      return JSON.stringify(rows);
    };
    await assert.rejects(inspect(run), fault);
  }
  let drifted = false;
  try {
    await assert.rejects(inspect(async args => {
      const text = await f.publicRun(args);
      if (!drifted && args[0] === 'image' && args[1] === 'inspect' && args[2] === oldGateway.Image) {
        drifted = true; fs.appendFileSync(custodyPath, ' ');
      }
      return text;
    }), 'seal remains fenced across metadata awaits');
    assert.equal(drifted, true);
  } finally { fs.writeFileSync(custodyPath, custodyBytes); }
  await inspect();
  const second = await runDeployment(f.adapter, options);
  assert.equal(second.ok, true, JSON.stringify({ second, diagnostics: f.diagnostics }));
  assert.notEqual(f.operationNonces.at(-1), nonce, 'exact operation nonce, never random directory order');
  await inspect();
  assert.deepEqual(fs.readFileSync(protectedPath), protectedBytes); f.verifyStores();
  // Exercise post-stop admission too: this calls only the fixture's fake engine.
  const running = f.containers().filter(c => c.State.Running).map(c => c.Id);
  await f.publicRun(['container', 'stop', '--time', '60', ...running]);
  const stopped = await inspect(); assert.ok(stopped.containers.every(c => !c.State.Running)); f.verifyStores();
});
