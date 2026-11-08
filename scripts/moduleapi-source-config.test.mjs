import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { MODULEAPI_SLOT_DEPLOYMENT, validateModuleApiDeployment, validateModuleApiBuildDeployment,
  selectModuleApiOperations, moduleApiEnvironment, validateModuleApiVolume, assertNoModuleApiDockerSecret,
  discoverModuleApiExecutionClosure, discoverOpenAiExecutionClosure, moduleApiSourceConfigurationProgram,
  checkPublicLlmSourceBuild, checkModuleApiQuotaSnapshot } from './public-llm-source-build.mjs';
import { normalizeModuleApiConfiguration } from './moduleapi-deployment-descriptor.mjs';
import { syntheticOpenAiDeployment, syntheticModuleApiDeployment } from './moduleapi-source.fixture.mjs';
import * as bootstrap from '../server/deploy/moduleapi-secret-bootstrap.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const next = () => syntheticModuleApiDeployment();

test('fixed v7 source contract uses actual bootstrap and historical infrastructure slot', () => {
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.version, 7);
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.provider, 'ModuleAPI');
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.model, 'gpt-5.4-mini');
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.configName, 'moduleapi-deployment.json');
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.bootstrap, bootstrap.BOOTSTRAP_SOURCE);
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.target, bootstrap.SECRET_PATH);
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.mount, bootstrap.SECRET_DIRECTORY);
  assert.equal(MODULEAPI_SLOT_DEPLOYMENT.volumeKey, bootstrap.SECRET_VOLUME);
  assert.deepEqual(MODULEAPI_SLOT_DEPLOYMENT.entrypoint, bootstrap.API_ENTRYPOINT);
  assert.deepEqual(MODULEAPI_SLOT_DEPLOYMENT.command, bootstrap.API_COMMAND);
  assert.deepEqual(MODULEAPI_SLOT_DEPLOYMENT.networks, ['openai_internal', 'openai_uplink']);
  assert.deepEqual(MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand, ['python', '-I', 'moduleapi.py', '--serve']);
  assert.throws(() => MODULEAPI_SLOT_DEPLOYMENT.networks.push('new-network'));
});

test('first and repeat v7 retain complete v6 identity, shared quota, and fixed secret volume', () => {
  const first = validateModuleApiBuildDeployment({ prior: syntheticOpenAiDeployment(), next: next() });
  assert.equal(first.next.version, 7);
  assert.deepEqual(first.next.openai, first.prior);
  assert.deepEqual(first.next.openrouter, first.prior.openrouter);
  assert.equal(first.next.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS, '5000000');
  assert.deepEqual(selectModuleApiOperations(next(), first.prior), first.next);
  assert.deepEqual(validateModuleApiBuildDeployment({ prior: first.next, next: next() }).next, first.next);
  assert.deepEqual(selectModuleApiOperations(next(), first.next), first.next);
  assert.throws(() => selectModuleApiOperations(next(), first.prior, true));
  assert.throws(() => validateModuleApiBuildDeployment({ prior: first.next, next: first.prior }));
  assert.ok(Object.isFrozen(first.next.environment));
});

for (const key of Object.keys(next())) test(`v7 requires exact top-level field ${key}`, () => {
  const d = next(); delete d[key]; assert.throws(() => validateModuleApiDeployment(d));
});
for (const key of Object.keys(next().environment)) test(`v7 requires explicit environment ${key}`, () => {
  const d = next(); delete d.environment[key]; assert.throws(() => validateModuleApiDeployment(d));
});
for (const [key, value] of Object.entries({ OPENAI_API_KEY: 'synthetic-never-read', MODULE_API_KEY: 'synthetic-never-read',
  OPENAI_MODEL: 'gpt-5.4-mini-2026-03-17', MODULEAPI_BASE_URL: 'https://other.invalid', MODULEAPI_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_QUOTA_OBSERVATION_COST_USD: '0', LLM_QUOTA_USER_COST_USD: '0', MODULEAPI_REQUEST_BUDGET_MICROS: '1' })) {
  test(`v7 rejects unexpected environment ${key}`, () => {
    const d = next(); d.environment[key] = value; assert.throws(() => validateModuleApiDeployment(d));
  });
}
for (const key of Object.keys(next().environment).filter(key => key.startsWith('LLM_QUOTA_'))) {
  test(`v7 preserves exact common setting ${key}`, () => {
    const d = next(); d.environment[key] += '0'; assert.throws(() => validateModuleApiDeployment(d));
  });
}
for (const mutate of [d => d.openai.environment.OPENAI_POLICY_REVISION += '-changed',
  d => d.openai.environment.OPENAI_INPUT_PRICE_MICROS_PER_MILLION = '7',
  d => { d.openai.environment.LLM_QUOTA_REVISION += '-changed'; d.environment.LLM_QUOTA_REVISION += '-changed'; },
  d => { d.openai.credentialVolume = null; d.openai.environment.OPENAI_ENABLED = 'false'; }]) {
  test('build refuses internally valid replacement of preserved embedded prior authority', () => {
    const d = next(); mutate(d); validateModuleApiDeployment(d);
    assert.throws(() => validateModuleApiBuildDeployment({ prior: syntheticOpenAiDeployment(), next: d }));
    assert.throws(() => validateModuleApiBuildDeployment({ prior: next(), next: d }));
  });
}

test('only disabled ModuleAPI may omit volume; current supplied volume cannot be dropped on repeat', () => {
  const d = next(); d.credentialVolume = null;
  assert.throws(() => validateModuleApiDeployment(d));
  d.environment.MODULEAPI_ENABLED = 'false'; validateModuleApiDeployment(d);
  assert.throws(() => validateModuleApiBuildDeployment({ prior: next(), next: d }));
  validateModuleApiBuildDeployment({ prior: d, next: next() });
  d.credentialVolume = 'openai-secrets'; assert.throws(() => validateModuleApiDeployment(d));
});

test('v7 cannot implicitly introduce operations upgrade or lifetime cap', () => {
  const d = next(); delete d.openai.operations; assert.throws(() => validateModuleApiDeployment(d));
  const other = next(); delete other.openai.environment.LLM_QUOTA_LIFETIME_USER_COST_MICROS;
  assert.throws(() => validateModuleApiDeployment(other));
  const old = syntheticOpenAiDeployment(); delete old.operations;
  assert.throws(() => validateModuleApiBuildDeployment({ prior: old, next: next() }));
});

test('environment merge strips old paid provider policy and all three key authorities without changing auxiliary router config', () => {
  const env = moduleApiEnvironment(next(), { OPENAI_API_KEY: 'synthetic', MODULE_API_KEY: 'synthetic', OPENROUTER_API_KEY: 'synthetic',
    OPENAI_ENABLED: 'true', OPENAI_POLICY_REVISION: 'old', MODULEAPI_BASE_URL: 'forbidden', LLM_QUOTA_UNKNOWN: 'old',
    LLM_MODEL: 'existing-free-model', OPENROUTER_API_KEY_FILE: '/run/secrets/public_openrouter_key', LLM_HISTORY_ENABLED: 'true' });
  for (const key of ['OPENAI_API_KEY', 'MODULE_API_KEY', 'OPENROUTER_API_KEY', 'OPENAI_ENABLED', 'OPENAI_POLICY_REVISION', 'MODULEAPI_BASE_URL', 'LLM_QUOTA_UNKNOWN'])
    assert.equal(Object.hasOwn(env, key), false);
  assert.equal(env.LLM_PROVIDER, 'moduleapi');
  assert.equal(env.LLM_MODEL, 'existing-free-model');
  assert.equal(env.OPENROUTER_API_KEY_FILE, '/run/secrets/public_openrouter_key');
  assert.equal(env.LLM_QUOTA_LIFETIME_USER_COST_MICROS, '5000000');
});

test('volume metadata and Docker environment are separate fail-closed authorities', () => {
  const v = { Name: 'moduleapi-secrets', Driver: 'local', Scope: 'local', Mountpoint: '/synthetic/volume', Options: {},
    Labels: { 'org.diplom.moduleapi-secret': 'v1', 'org.diplom.moduleapi-secret.claim': 'b'.repeat(32) } };
  validateModuleApiVolume(v, next());
  for (const patch of [{ Name: 'openai-secrets' }, { Driver: 'remote' }, { Options: { device: '/host' } }, { Labels: {} }])
    assert.throws(() => validateModuleApiVolume({ ...v, ...patch }, next()));
  assertNoModuleApiDockerSecret({ Env: ['LLM_PROVIDER=moduleapi', 'MODULEAPI_MODEL=gpt-5.4-mini'] });
  for (const key of ['MODULE_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY']) {
    assert.throws(() => assertNoModuleApiDockerSecret({ Env: [key] }));
    assert.throws(() => assertNoModuleApiDockerSecret({ Env: [key + '=synthetic'] }));
  }
});

test('normalizer is bounded, nonsecret and delegates actual exact validator', async () => {
  let text = '';
  await normalizeModuleApiConfiguration(Readable.from([JSON.stringify(next())]), { write: value => { text += value; } });
  assert.deepEqual(JSON.parse(text), validateModuleApiDeployment(next()));
  for (const payload of ['', '{', JSON.stringify({ ...next(), secret: 'synthetic' }), 'x'.repeat(16385)])
    await assert.rejects(normalizeModuleApiConfiguration(Readable.from([payload]), { write: () => assert.fail('must not publish') }));
});

test('v7 AST closure discovers actual public modules and fixed bootstrap without execution', () => {
  const closure = discoverModuleApiExecutionClosure(root, path => fs.readFileSync(join(root, path), 'utf8'));
  for (const path of ['scripts/public-llm-stand.mjs', 'scripts/moduleapi-deployment-descriptor.mjs', 'server/deploy/moduleapi-secret-bootstrap.mjs',
    'server/deploy/trust/fetch-db-layer.mjs']) assert.ok(closure.modules.includes(path), path);
  assert.ok(closure.edges.includes('scripts/moduleapi-deployment-descriptor.mjs -> server/deploy/moduleapi-secret-bootstrap.mjs'));
  const old = discoverOpenAiExecutionClosure(root, path => fs.readFileSync(join(root, path), 'utf8'));
  assert.ok(old.modules.includes('server/deploy/openai-secret-bootstrap.mjs'));
});
for (const bad of ["import('./' + name)", "const loader = require; loader(name)", "import('../outside.mjs')",
  "import './unapproved.mjs'", "const r=createRequire(import.meta.url); r.resolve(name)", "export * from './unapproved.mjs'"]) {
  test(`AST closure refuses unknown/computed loader before arbitrary lookup: ${bad}`, () => {
    const reads = [];
    assert.throws(() => discoverModuleApiExecutionClosure(root, name => { reads.push(name); return bad; }));
    assert.deepEqual(reads, ['scripts/public-llm-stand.mjs']);
  });
}

test('actual ModuleAPI factories qualify synthetic explicit rates offline, without provider construction', { timeout: 30000 }, () => {
  const d = validateModuleApiDeployment(next());
  const run = env => spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', moduleApiSourceConfigurationProgram(d)], {
    cwd: join(root, 'server/api'), env: { PATH: process.env.PATH }, input: JSON.stringify(env), encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  const result = run(d.environment);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout, '');
  const env = { ...d.environment }; delete env.MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION;
  assert.notEqual(run(env).status, 0);
});

test('real quota constructor only opens a disposable clone and rejects unsafe snapshot metadata without changing retained bytes', { timeout: 30000 }, t => {
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'moduleapi-source-quota-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'llm-usage.sqlite');
  const d = next();
  const code = `import fs from 'node:fs';
    import {QuotaLedger} from './src/llm/quota-ledger.ts';
    import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';
    const {path,env}=JSON.parse(fs.readFileSync(0,'utf8'));
    const policy=quotaPolicyFromEnvironment(env); if(!policy)throw Error('synthetic-policy');
    const ledger=new QuotaLedger(path,policy,Date.now,true);ledger.close();`;
  const seeded = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
    cwd: join(root, 'server/api'), env: { PATH: process.env.PATH }, input: JSON.stringify({ path, env: d.environment }),
    encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.equal(seeded.status, 0, seeded.stderr);
  fs.chmodSync(path, 0o600);
  const original = fs.readFileSync(path);
  assert.deepEqual(checkModuleApiQuotaSnapshot(root, { selection: d, snapshotPath: path }), { compatible: true });
  assert.deepEqual(fs.readFileSync(path), original);
  fs.chmodSync(path, 0o644);
  assert.throws(() => checkModuleApiQuotaSnapshot(root, { selection: d, snapshotPath: path }));
  fs.chmodSync(path, 0o600);
  fs.writeFileSync(path + '-wal', 'synthetic-sidecar');
  assert.throws(() => checkModuleApiQuotaSnapshot(root, { selection: d, snapshotPath: path }));
  assert.deepEqual(fs.readFileSync(path), original);
});

test('source build refuses ambiguous provider options before filesystem access', () => {
  assert.throws(() => checkPublicLlmSourceBuild('/does-not-exist', { openai: syntheticOpenAiDeployment(), moduleapi: next() }));
});
