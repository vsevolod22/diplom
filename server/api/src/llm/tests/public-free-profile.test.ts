import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { FREE_MODEL, FREE_PROVIDER, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, disclosure, policyFromEnvironment, publicFreePolicy } from '../policy.js';
import { prepareHistory, prepareSummary, prepareTranslation } from '../prepared-request.js';
import { publicReadiness } from '../public-readiness.js';
import { translationEnabled, translationPolicy } from '../translation-contract.js';
import { createHash } from 'node:crypto';
import { productionProvider } from '../openrouter-provider.js';
import { fixtureEnv, fixtureReport, fakeKey, envelope } from './fixtures.js';
import { LlmRuntime } from '../llm.service.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from '../public-key-file.js';

const env = { ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: PUBLIC_FREE_MODEL, LLM_PROVIDER_ALLOWLIST: PUBLIC_FREE_PROVIDER,
  LLM_RETENTION: 'no-training', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' };

test('explicit Dots3/Atlas no-training profile has no cross-pair/provider/router/paid/privacy fallback', () => {
  const policy = policyFromEnvironment(env)!; assert.ok(policy?.freeOnly);
  assert.equal(policy.model, 'dots-studio/dots-3-note-preview:free');
  assert.deepEqual(policy.providers, ['atlas-cloud/fp8']);
  const wire = JSON.parse(prepareSummary(fixtureReport, policy).body);
  assert.equal(wire.model, PUBLIC_FREE_MODEL); assert.deepEqual(wire.provider.only, [PUBLIC_FREE_PROVIDER]);
  assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
  assert.equal(Object.hasOwn(wire.provider, 'zdr'), false); assert.equal(wire.provider.data_collection, 'deny');
  assert.equal(wire.provider.allow_fallbacks, false); assert.equal(wire.provider.require_parameters, true);
  assert.deepEqual(wire.reasoning, { enabled: false, exclude: true }); assert.equal(wire.models, undefined);
  for (const patch of [{ LLM_MODEL: FREE_MODEL }, { LLM_PROVIDER_ALLOWLIST: FREE_PROVIDER },
    { LLM_MODEL: PUBLIC_FREE_MODEL.replace(':free', '') }, { LLM_MODEL: 'openrouter/free' },
    { LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/fp8,novita/bf16' }, { LLM_RETENTION: 'no-storage' },
    { LLM_RETENTION: undefined }, { LLM_PROVIDER_ALLOWLIST: 'Atlas-Cloud/fp8' }, { LLM_PROVIDER_ALLOWLIST: 'atlas-cloud' },
    { LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/bf16' }, { LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/fp8,atlas-cloud/fp8' },
    { LLM_PROVIDER_ALLOWLIST: ' atlas-cloud/fp8' },
    { LLM_MODEL: 'nvidia/nemotron-3.5-super-vl:free', LLM_PROVIDER_ALLOWLIST: 'nvidia' },
    { LLM_MODEL: 'nvidia/nemotron-3.5-super-vl:free' }, { LLM_PROVIDER_ALLOWLIST: 'nvidia' },
    { LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free', LLM_PROVIDER_ALLOWLIST: 'phala', LLM_RETENTION: 'no-storage' },
    { LLM_ROUTING_APPROVED: 'false' }, { LLM_REQUEST_PRICE_USD: '0.001' }, { LLM_FREE_ONLY: 'false' }])
    assert.equal(policyFromEnvironment({ ...env, ...patch }), null);
  for (const patch of [{ model: FREE_MODEL }, { providers: [FREE_PROVIDER] }, { budgetUsd: 0.01 },
      { retention: 'no-storage' as const }, { region: 'eu' as 'global' }, { inputPricePerMillion: 0.01 },
      { outputPricePerMillion: 0.01 }, { requestPriceUsd: 0.01 }])
    assert.throws(() => prepareSummary(fixtureReport, { ...policy, ...patch }));
});

test('public composition forbids paid policies and env credentials without opening a key; legacy remains explicit', () => {
  const runtime = new LlmRuntime(true);
  assert.equal(runtime.policy(fixtureEnv), null);
  assert.ok(new LlmRuntime().policy(fixtureEnv));
  assert.equal(runtime.policy(env)?.model, PUBLIC_FREE_MODEL);
  for (const config of [{}, { OPENROUTER_API_KEY: fakeKey },
    { OPENROUTER_API_KEY_FILE: 'unapproved-path' },
    { OPENROUTER_API_KEY_FILE: PUBLIC_OPENROUTER_KEY_FILE, OPENROUTER_API_KEY: fakeKey }])
    assert.throws(() => runtime.provider(config));
});

test('public runtime refuses legacy Apodex before credential loading; nonpublic runtime and legacy disclosure stay unchanged', () => {
  const legacyEnv = { ...env, LLM_MODEL: FREE_MODEL, LLM_PROVIDER_ALLOWLIST: FREE_PROVIDER, LLM_RETENTION: 'no-storage' };
  const legacy = policyFromEnvironment(legacyEnv)!;
  assert.ok(legacy?.freeOnly);
  assert.equal(new LlmRuntime(true).policy(legacyEnv), null);
  assert.throws(() => new LlmRuntime(true).provider({ ...legacyEnv, OPENROUTER_API_KEY_FILE: PUBLIC_OPENROUTER_KEY_FILE }));
  assert.deepEqual(new LlmRuntime().policy(legacyEnv), legacy);
  assert.equal(disclosure(legacy).data, 'Sanitized scanner findings and coverage; no raw evidence or credentials.');
  for (const prepared of [prepareSummary(fixtureReport, legacy), prepareHistory({ report: fixtureReport }, legacy)]) {
    const wire = JSON.parse(prepared.body);
    assert.equal(wire.model, FREE_MODEL); assert.deepEqual(wire.provider.only, [FREE_PROVIDER]);
    assert.deepEqual(wire.response_format, { type: 'json_object' });
    assert.doesNotMatch(prepared.body, /packageName|installedVersion|fixedVersion":/);
  }
  assert.equal(new LlmRuntime(true).policy(env)?.model, PUBLIC_FREE_MODEL);
});

test('Dots3 profile uses existing adapter/endpoint, exact response identity, single attempt and zero cost', async () => {
  const policy = policyFromEnvironment(env)!;
  for (const patch of [{ model: PUBLIC_FREE_MODEL }, { model: PUBLIC_FREE_MODEL.replace(':free', '') }, { model: FREE_MODEL },
    { model: 'nvidia/nemotron-3.5-super-vl:free' },
    { model: PUBLIC_FREE_MODEL, usage: { completion_tokens: 32, cost: 0.001 } },
    { model: PUBLIC_FREE_MODEL, usage: { completion_tokens: 32 } },
    { model: PUBLIC_FREE_MODEL, choices: [{ finish_reason: 'length', message: { role: 'assistant', content: '{}' } }] },
    { model: PUBLIC_FREE_MODEL, choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: '{}', reasoning: 'unexpected' } }] }]) {
    let calls = 0;
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async (url, init) => {
      calls++; assert.equal(url, 'https://openrouter.ai/api/v1/chat/completions');
      const wire = JSON.parse(String(init!.body)); assert.equal(wire.model, PUBLIC_FREE_MODEL);
      return new Response(JSON.stringify({ ...envelope(), usage: { completion_tokens: 32, cost: 0 }, ...patch }),
        { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    const result = provider.summarize(fixtureReport, policy, new AbortController().signal);
    if (patch.model === PUBLIC_FREE_MODEL && !('usage' in patch) && !('choices' in patch)) await result;
    else await assert.rejects(result);
    assert.equal(calls, 1);
  }
});

test('Dots3 requires canonical all-zero caps and explicit retention before any provider call', async () => {
  for (const field of ['LLM_REQUEST_BUDGET_USD', 'LLM_INPUT_PRICE_PER_MILLION_USD', 'LLM_OUTPUT_PRICE_PER_MILLION_USD', 'LLM_REQUEST_PRICE_USD']) {
    for (const value of [undefined, '', '0.0', '00', '-0', '0.001', 'NaN', 'Infinity'])
      assert.equal(policyFromEnvironment({ ...env, [field]: value }), null, `${field}=${value}`);
  }
  const policy = policyFromEnvironment(env)!;
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async () => {
    calls++; throw new Error('unexpected synthetic transport');
  }) as typeof fetch);
  for (const patch of [{ retention: 'no-storage' as const }, { providers: ['atlas-cloud/fp8', 'novita/bf16'] },
    { model: 'dots-studio/dots-3-note-preview' },
    { model: 'nvidia/nemotron-3.5-super-vl:free', providers: ['nvidia'] }, { inputPricePerMillion: 0.001 }, { outputPricePerMillion: 0.001 },
    { requestPriceUsd: 0.001 }, { budgetUsd: 0.001 }]) {
    const invalid = { ...policy, ...patch };
    assert.equal(publicFreePolicy(invalid), false); assert.equal(translationEnabled(invalid), false);
    assert.throws(() => prepareHistory({}, invalid));
    assert.throws(() => prepareTranslation({ title: 'Memory flaw', description: null }, invalid));
    await assert.rejects(provider.summarize(fixtureReport, invalid, new AbortController().signal));
  }
  assert.equal(calls, 0);
});

test('gateway wire conditionally requests ZDR only for the separate legacy no-storage profile', () => {
  const current = policyFromEnvironment(env)!;
  const legacy = policyFromEnvironment({ ...env, LLM_MODEL: FREE_MODEL, LLM_PROVIDER_ALLOWLIST: FREE_PROVIDER,
    LLM_RETENTION: 'no-storage' })!;
  for (const policy of [current, legacy]) {
    for (const request of [prepareSummary(fixtureReport, policy), prepareHistory({}, policy)]) {
      const wire = JSON.parse(request.body);
      assert.deepEqual(wire.provider, { only: [...policy.providers], allow_fallbacks: false, require_parameters: true,
        data_collection: 'deny', ...(policy === legacy ? { zdr: true } : {}), max_price: { prompt: 0, completion: 0, request: 0 } });
      assert.equal(wire.models, undefined); assert.equal(wire.tools, undefined); assert.equal(wire.plugins, undefined);
    }
  }
  assert.equal(disclosure(current).retention, 'no-training'); assert.equal(disclosure(legacy).retention, 'no-storage');
  assert.equal(disclosure(current).data, 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.');
  for (const policy of [legacy, policyFromEnvironment(fixtureEnv)!])
    assert.equal(disclosure(policy).data, 'Sanitized scanner findings and coverage; no raw evidence or credentials.');
  const { version, ...settings } = current;
  for (const previous of [
    { model: 'xingchen-agi/xing4.0-29b-a4b:free', providers: ['phala'], retention: 'no-storage' as const },
    { model: 'nvidia/nemotron-3.5-super-vl:free', providers: ['nvidia'], retention: 'no-training' as const },
  ]) {
    const old = { ...current, ...previous, version: createHash('sha256').update(JSON.stringify({
      revision: fixtureEnv.LLM_POLICY_REVISION, responseLanguageRevision: 'russian-prose-v6-cyrillic',
      ...settings, ...previous })).digest('hex') };
    assert.notEqual(version, old.version, 'model/provider/retention invalidate old consent and cache bindings without relying on a revision bump');
    assert.notEqual(translationPolicy(current), translationPolicy(old));
  }
});

test('readiness lists supplied Dots3 catalog facts, never ZDR or product/live qualification', () => {
  const policy = policyFromEnvironment(env)!;
  const ready = publicReadiness(policy, 'metadata-valid', true, true);
  assert.equal(ready.status, 'locally-configured'); assert.equal(ready.localReady, true); assert.deepEqual(ready.blockers, []);
  assert.deepEqual(ready.provider, { checkedOn: '2026-10-29', liveVerified: false, status: 'catalog-listed-unprobed',
    model: PUBLIC_FREE_MODEL, endpoint: PUBLIC_FREE_PROVIDER, zdrListed: false, retention: 'no-training' });
  assert.equal(ready.generationVerified, false); assert.equal(ready.requiresConsent, true); assert.equal(ready.acceptsCredentials, false);
  for (const invalid of [null, { ...policy, retention: 'no-storage' as const }, { ...policy, requestPriceUsd: 0.001 },
    { ...policy, providers: ['atlas-cloud/fp8', 'phala'] }, { ...policy, freeOnly: false },
        { ...policy, model: 'nvidia/nemotron-3.5-super-vl:free', providers: ['nvidia'] },
    { ...policy, model: 'xingchen-agi/xing4.0-29b-a4b:free', providers: ['phala'], retention: 'no-storage' as const }]) {
    const result = publicReadiness(invalid, 'metadata-valid', true, true);
    assert.equal(result.localReady, false); assert.ok(result.blockers.includes('provider-profile-unavailable'));
    assert.equal(result.provider.zdrListed, false); assert.equal(result.generationVerified, false);
  }
  for (const [credential, quota, history, blocker] of [
    ['missing', true, true, 'public-key-required'], ['unsafe', true, true, 'public-key-unsafe'],
    ['metadata-valid', false, true, 'quota-store-unavailable'], ['metadata-valid', true, false, 'history-store-unavailable'],
  ] as const) {
    const result = publicReadiness(policy, credential, quota, history);
    assert.equal(result.localReady, false); assert.deepEqual(result.blockers, [blocker]);
  }
});
