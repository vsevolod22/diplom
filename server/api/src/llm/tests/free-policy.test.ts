import assert from 'node:assert/strict';
import test from 'node:test';
import { disclosure, policyFromEnvironment } from '../policy.js';
import { productionProvider } from '../openrouter-provider.js';
import { fixtureEnv, fakeKey, fixtureReport, envelope } from './fixtures.js';

// Fixed identifiers from the parent probe; all transports/replies here are synthetic.
export const freeEnv = { ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
  LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_POLICY_REVISION: 'openrouter-free-apodex-v2',
  LLM_RETENTION: 'no-storage', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' };

test('free mode admits only exact model/endpoint, no-storage and explicit all-zero caps', () => {
  const policy = policyFromEnvironment(freeEnv)!;
  assert.ok(policy); assert.equal(policy.freeOnly, true);
  assert.equal(policy.budgetUsd, 0); assert.equal(policy.requestPriceUsd, 0);
  assert.equal(disclosure(policy).freeOnly, true);
  assert.equal(disclosure(policy).retention, 'no-storage');
  assert.deepEqual(disclosure(policy).providers, ['novita/bf16']);
  assert.notEqual(policy.version, policyFromEnvironment(fixtureEnv)!.version);
  assert.notEqual(policy.version, policyFromEnvironment({ ...freeEnv, LLM_POLICY_REVISION: 'another-revision' })!.version);
  for (const field of ['LLM_REQUEST_BUDGET_USD', 'LLM_INPUT_PRICE_PER_MILLION_USD', 'LLM_OUTPUT_PRICE_PER_MILLION_USD', 'LLM_REQUEST_PRICE_USD']) {
    for (const value of [undefined, '0.1', '-1', 'NaN', ''])
      assert.equal(policyFromEnvironment({ ...freeEnv, [field]: value }), null, field);
  }
  for (const patch of [{ LLM_FREE_ONLY: undefined }, { LLM_FREE_ONLY: 'false' }, { LLM_FREE_ONLY: 'yes' },
    { LLM_MODEL: 'apodex/apodex-1.1-mini' }, { LLM_MODEL: 'liquid/lfm-2.5-2.6b:free' },
    { LLM_MODEL: 'foreign/model:free' }, { LLM_MODEL: 'openrouter/auto' }, { LLM_MODEL: 'openrouter/free' },
    { LLM_MODEL: 'apodex/apodex-1.1-mini:free:online' }, { LLM_PROVIDER_ALLOWLIST: 'novita' },
    { LLM_PROVIDER_ALLOWLIST: 'novita/fp8' }, { LLM_PROVIDER_ALLOWLIST: 'novita/bf16,Other' },
    { LLM_PROVIDER_ALLOWLIST: 'liquid' }, { LLM_ROUTING_APPROVED: 'false' },
    { LLM_RETENTION: undefined }, { LLM_RETENTION: 'no-training' }])
    assert.equal(policyFromEnvironment({ ...freeEnv, ...patch }), null, JSON.stringify(patch));
  // Do not widen slash-containing endpoint names for the separate legacy mode.
  assert.equal(policyFromEnvironment({ ...fixtureEnv, LLM_PROVIDER_ALLOWLIST: 'novita/bf16' }), null);
});

test('free wire request pins endpoint/deny/ZDR/zero prices and disables reasoning without fallback', async () => {
  const policy = policyFromEnvironment(freeEnv)!;
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async (_url, init) => {
    calls++;
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, freeEnv.LLM_MODEL);
    assert.deepEqual(body.provider.only, ['novita/bf16']);
    assert.deepEqual(body.provider.max_price, { prompt: 0, completion: 0, request: 0 });
    assert.equal(body.provider.allow_fallbacks, false); assert.equal(body.provider.require_parameters, true);
    assert.equal(body.provider.data_collection, 'deny'); assert.equal(body.provider.zdr, true);
    assert.deepEqual(body.reasoning, { enabled: false, exclude: true });
    assert.deepEqual(body.response_format, { type: 'json_object' });
    assert.equal(body.models, undefined); assert.equal(body.tools, undefined);
    return new Response(JSON.stringify({ ...envelope(), model: freeEnv.LLM_MODEL, usage: { completion_tokens: 32, cost: 0 } }),
      { headers: { 'content-type': 'application/json' } });
  }) as typeof fetch);
  await provider.summarize(fixtureReport, policy, new AbortController().signal);
  assert.equal(calls, 1);
});

test('free wire boundary rejects injected invalid policies before transport', async () => {
  const policy = policyFromEnvironment(freeEnv)!;
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async () => {
    calls++; throw new Error('unexpected synthetic transport');
  }) as typeof fetch);
  for (const patch of [{ model: 'liquid/lfm-2.5-2.6b:free' }, { providers: ['novita'] },
    { providers: ['novita/bf16', 'Other'] }, { retention: 'no-training' as const },
    { budgetUsd: 0.1 }, { inputPricePerMillion: 0.1 }, { outputPricePerMillion: 0.1 }, { requestPriceUsd: 0.1 }])
    await assert.rejects(provider.summarize(fixtureReport, { ...policy, ...patch }, new AbortController().signal));
  assert.equal(calls, 0);
});

test('response identity is exact with zero reported cost; aliases/truncation/reasoning fail once', async () => {
  const policy = policyFromEnvironment(freeEnv)!;
  for (const patch of [{ model: 'foreign/model' }, { model: 'apodex/apodex-1.1-mini' },
    { model: 'apodex/apodex-1.1-mini:paid' }, { model: 'apodex/apodex-1.1-mini-unknown' },
    { model: 'liquid/lfm-2.5-2.6b' }, { model: 'liquid/lfm-2.5-2.6b:free' },
    { usage: { completion_tokens: 32, cost: 0.0001 } }, { usage: { completion_tokens: 32 } },
    { choices: [{ finish_reason: 'length', message: { role: 'assistant', content: '{}' } }] },
    { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: '{}', reasoning: 'unexpected' } }] },
    { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: 'not JSON' } }] }]) {
    let calls = 0;
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async () => {
      calls++; return new Response(JSON.stringify({ ...envelope(), model: policy.model, usage: { completion_tokens: 32, cost: 0 }, ...patch }),
        { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    await assert.rejects(provider.summarize(fixtureReport, policy, new AbortController().signal));
    assert.equal(calls, 1);
  }
});
