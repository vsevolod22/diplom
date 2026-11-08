import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDeployAdapter, deployAdapterDiagnostic, deploymentTargets, assertFourStoreTransition } from './deploy-adapter.mjs';
import { parseArgs } from './deploy.mjs';
import { validateOpenAiDeployment, validateOpenAiBuildDeployment } from './public-llm-source-build.mjs';
import { validatePublicLlmTransition } from './public-llm-stand.mjs';
import { createReferenceCustody, validateReferenceCustody, referenceCustodyDiagnostic } from './deploy-reference-custody.mjs';
import { MODULEAPI_DEPLOYMENT, moduleApiDeploymentSupport } from './moduleapi-deployment-descriptor.mjs';
import { API_ENTRYPOINT, API_COMMAND, SECRET_VOLUME, SECRET_DIRECTORY } from '../server/deploy/moduleapi-secret-bootstrap.mjs';

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

test('ModuleAPI has its own immutable source-only descriptor; never relabels v6 or claims rollout', () => {
  const d = MODULEAPI_DEPLOYMENT;
  assert.equal(d.descriptor, 'moduleapi-preserving-v1'); assert.equal(d.stage, 'source-only');
  assert.equal(d.executable, false); assert.equal(d.activated, false); assert.equal(d.generationVerified, false);
  assert.deepEqual(d.provider, { name: 'ModuleAPI', endpoint: 'https://moduleapi.pro/v1/chat/completions',
    model: 'gpt-5.4-mini', retention: 'unknown', tariff: 'unverified' });
  assert.deepEqual(d.api.entrypoint, API_ENTRYPOINT); assert.deepEqual(d.api.command, API_COMMAND);
  assert.equal(d.secret.volume, SECRET_VOLUME); assert.equal(d.secret.target, SECRET_DIRECTORY);
  assert.equal(d.secret.readOnly, true); assert.equal(d.secret.apiOnly, true); assert.equal(d.secret.dockerEnvironment, false);
  assert.deepEqual(d.gateway.publishedPorts, []); assert.deepEqual(d.gateway.excludedRoles, ['web', 'worker']);
  assert.deepEqual(d.preservation.stores, ['auth', 'ledger', 'history', 'quota']);
  assert.equal(d.preservation.accountLifetimeMicros, 5_000_000);
  assert.equal(d.preservation.liabilities, 'all-retained-including-unknown');
  assert.equal(d.preservation.migrations, false); assert.equal(d.preservation.resets, false);
  assert.ok(d.preservation.requiredOrder.indexOf('web-last') > d.preservation.requiredOrder.indexOf('after-api-four-store-equality'));
  assert.equal(moduleApiDeploymentSupport().executable, false);
  assert.ok(moduleApiDeploymentSupport().blockers.includes('MODULEAPI_PRESERVING_EXECUTOR_NOT_IMPLEMENTED'));
  assert.throws(() => { d.provider.retention = 'no-training'; });
  assert.throws(() => { d.blockers.pop(); });
});

test('real current adapter refuses new ModuleAPI role before config, credentials, engine or source qualification', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'moduleapi-infra-adapter-')));
  try {
    let calls = 0;
    const forbidden = () => { calls++; throw Error('real dependency forbidden'); };
    const adapter = createDeployAdapter({ root, home: root, run: forbidden, http: forbidden, checkSource: forbidden });
    await assert.rejects(adapter.prepare({ mode: 'app', services: ['api', 'web', 'moduleapi-egress'] }), error =>
      deployAdapterDiagnostic(error).code === 'TARGETS_INVALID');
    assert.equal(calls, 0);
    assert.throws(() => deploymentTargets('app', ['api', 'moduleapi-egress']));
    assert.throws(() => parseArgs(['app', '--services', 'api,web', '--provider', 'moduleapi']));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('existing descriptor and transition validators reject source-only ModuleAPI, not reinterpret it as OpenAI', () => {
  for (const candidate of [MODULEAPI_DEPLOYMENT, { ...MODULEAPI_DEPLOYMENT, version: 6 },
    { ...MODULEAPI_DEPLOYMENT, version: 7, provider: 'ModuleAPI' }]) {
    assert.throws(() => validateOpenAiDeployment(candidate));
    assert.throws(() => validateOpenAiBuildDeployment({ prior: { version: 5, keyVolume: null,
      timing: 'public-8081-90s-v1', profile: 'public-8081-remediation-4k-v1' }, next: candidate }));
    assert.throws(() => validatePublicLlmTransition(null, candidate));
  }
});

test('current image custody requires a real old peer and cannot represent a first-added gateway', () => {
  const nonce = 'a'.repeat(32), image = 'sha256:' + 'b'.repeat(64);
  assert.throws(() => createReferenceCustody({ nonce, targets: ['moduleapi-egress'], published: {}, runtime: {}, references: [] }),
    error => referenceCustodyDiagnostic(error) === 'CUSTODY_TARGETS');
  // Even a known role cannot use a fabricated/absent old-image authority.
  assert.throws(() => createReferenceCustody({ nonce, targets: ['api'], published: {}, runtime: { api: image }, references: [] }),
    error => referenceCustodyDiagnostic(error) === 'CUSTODY_OLD_IMAGE_MISMATCH');
  assert.throws(() => validateReferenceCustody({ version: 1, old: [], candidates: [
    { name: 'moduleapi-egress', tag: `dip-public-images-moduleapi-egress:candidate-${nonce}` },
  ] }, nonce), error => referenceCustodyDiagnostic(error) === 'CUSTODY_INVALID');
});

test('retained adapter four-store guard rejects each drift and implicit schema migration', () => {
  const baseline = { historyVersion: 5, core: { auth: { logicalSha256: 'a'.repeat(64) }, ledger: { logicalSha256: 'b'.repeat(64) } },
    llm: { history: 'c'.repeat(64), quota: 'd'.repeat(64) } };
  assert.doesNotThrow(() => assertFourStoreTransition(baseline, structuredClone(baseline)));
  for (const store of ['auth', 'ledger', 'history', 'quota', 'schema']) {
    const changed = structuredClone(baseline);
    if (store === 'schema') changed.historyVersion = 4;
    else if (Object.hasOwn(changed.core, store)) changed.core[store].logicalSha256 = 'e'.repeat(64);
    else changed.llm[store] = 'e'.repeat(64);
    assert.throws(() => assertFourStoreTransition(baseline, changed));
  }
});

test('API recipe adds public ModuleAPI bootstrap only; default command never activates secret/provider', () => {
  const previous = source('server/deploy/openai-api.Dockerfile');
  const actual = source('server/deploy/moduleapi-api.Dockerfile');
  assert.equal(actual, previous.replaceAll('openai-secret-bootstrap', 'moduleapi-secret-bootstrap'));
  assert.ok(!actual.includes('MODULE_API_KEY')); assert.ok(!actual.includes('ENTRYPOINT'));
  const bootstrap = source('server/deploy/moduleapi-secret-bootstrap.mjs');
  assert.ok(!bootstrap.includes('no-training')); assert.ok(!bootstrap.includes('openai-secrets'));
  const gateway = source('server/deploy/gateway/moduleapi.Dockerfile');
  assert.ok(gateway.includes('moduleapi.py')); assert.ok(!gateway.includes('EXPOSE'));
  const init = source('server/deploy/moduleapi-secret-init.Dockerfile');
  assert.ok(init.includes('ARG PYTHON_BASE')); assert.ok(!init.includes('server.env'));
  assert.ok(!init.includes('OPENAI')); assert.ok(!init.includes('MODULE_API_KEY'));
});
