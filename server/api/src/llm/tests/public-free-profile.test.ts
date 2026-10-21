import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { FREE_MODEL, FREE_PROVIDER, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, policyFromEnvironment } from '../policy.js';
import { prepareSummary } from '../prepared-request.js';
import { productionProvider } from '../openrouter-provider.js';
import { fixtureEnv, fixtureReport, fakeKey, envelope } from './fixtures.js';
import { LlmRuntime } from '../llm.service.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from '../public-key-file.js';

const env = { ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: PUBLIC_FREE_MODEL, LLM_PROVIDER_ALLOWLIST: PUBLIC_FREE_PROVIDER,
  LLM_RETENTION: 'no-storage', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' };

test('explicit Xing/Phala profile has no cross-pair/provider/router/paid/privacy fallback', () => {
  const policy = policyFromEnvironment(env)!; assert.ok(policy?.freeOnly);
  const wire = JSON.parse(prepareSummary(fixtureReport, policy).body);
  assert.equal(wire.model, PUBLIC_FREE_MODEL); assert.deepEqual(wire.provider.only, [PUBLIC_FREE_PROVIDER]);
  assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
  assert.equal(wire.provider.zdr, true); assert.equal(wire.provider.data_collection, 'deny');
  assert.equal(wire.provider.allow_fallbacks, false); assert.equal(wire.provider.require_parameters, true);
  assert.deepEqual(wire.reasoning, { enabled: false, exclude: true }); assert.equal(wire.models, undefined);
  for (const patch of [{ LLM_MODEL: FREE_MODEL }, { LLM_PROVIDER_ALLOWLIST: FREE_PROVIDER },
    { LLM_MODEL: PUBLIC_FREE_MODEL.replace(':free', '') }, { LLM_MODEL: 'openrouter/free' },
    { LLM_PROVIDER_ALLOWLIST: 'phala,novita/bf16' }, { LLM_RETENTION: 'no-training' },
    { LLM_ROUTING_APPROVED: 'false' }, { LLM_REQUEST_PRICE_USD: '0.001' }, { LLM_FREE_ONLY: 'false' }])
    assert.equal(policyFromEnvironment({ ...env, ...patch }), null);
  for (const patch of [{ model: FREE_MODEL }, { providers: [FREE_PROVIDER] }, { budgetUsd: 0.01 }])
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

test('Xing profile uses existing adapter/endpoint, exact response identity, single attempt and zero cost', async () => {
  const policy = policyFromEnvironment(env)!;
  for (const model of [PUBLIC_FREE_MODEL, PUBLIC_FREE_MODEL.replace(':free', ''), FREE_MODEL]) {
    let calls = 0;
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async (url, init) => {
      calls++; assert.equal(url, 'https://openrouter.ai/api/v1/chat/completions');
      const wire = JSON.parse(String(init!.body)); assert.equal(wire.model, PUBLIC_FREE_MODEL);
      return new Response(JSON.stringify({ ...envelope(), model, usage: { completion_tokens: 32, cost: 0 } }),
        { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    const result = provider.summarize(fixtureReport, policy, new AbortController().signal);
    if (model === PUBLIC_FREE_MODEL) await result;
    else await assert.rejects(result);
    assert.equal(calls, 1);
  }
});
