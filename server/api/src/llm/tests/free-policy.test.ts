import assert from 'node:assert/strict';
import test from 'node:test';
import { disclosure, policyFromEnvironment } from '../policy.js';
import { productionProvider } from '../openrouter-provider.js';
import { fixtureEnv, fakeKey, fixtureReport, envelope } from './fixtures.js';

// Catalog identifiers only; transports/replies in this file are synthetic.
export const freeEnv = { ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'liquid/lfm-2.5-2.6b:free',
  LLM_PROVIDER_ALLOWLIST: 'liquid', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' };

test('free mode admits only exact verified model/provider and explicit all-zero caps', () => {
  const policy = policyFromEnvironment(freeEnv)!;
  assert.ok(policy); assert.equal(policy.freeOnly, true);
  assert.equal(policy.budgetUsd, 0); assert.equal(policy.requestPriceUsd, 0);
  assert.equal(disclosure(policy).freeOnly, true);
  assert.notEqual(policy.version, policyFromEnvironment(fixtureEnv)!.version);
  for (const field of ['LLM_REQUEST_BUDGET_USD', 'LLM_INPUT_PRICE_PER_MILLION_USD', 'LLM_OUTPUT_PRICE_PER_MILLION_USD', 'LLM_REQUEST_PRICE_USD']) {
    for (const value of [undefined, '0.1', '-1', 'NaN', ''])
      assert.equal(policyFromEnvironment({ ...freeEnv, [field]: value }), null, field);
  }
  for (const patch of [{ LLM_FREE_ONLY: undefined }, { LLM_FREE_ONLY: 'false' }, { LLM_FREE_ONLY: 'yes' },
    { LLM_MODEL: 'liquid/lfm-2.5-2.6b' }, { LLM_MODEL: 'foreign/model:free' }, { LLM_MODEL: 'openrouter/auto' },
    { LLM_MODEL: 'openrouter/free' }, { LLM_MODEL: 'liquid/lfm-2.5-2.6b:free:online' },
    { LLM_PROVIDER_ALLOWLIST: 'liquid,Other' }, { LLM_PROVIDER_ALLOWLIST: 'liquid/fp8' }, { LLM_ROUTING_APPROVED: 'false' }])
    assert.equal(policyFromEnvironment({ ...freeEnv, ...patch }), null, JSON.stringify(patch));
});

test('free wire request zero-caps all prices, excludes supported reasoning, one call without fallback', async () => {
  const policy = policyFromEnvironment(freeEnv)!;
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async (_url, init) => {
    calls++;
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, freeEnv.LLM_MODEL);
    assert.deepEqual(body.provider.only, ['liquid']);
    assert.deepEqual(body.provider.max_price, { prompt: 0, completion: 0, request: 0 });
    assert.equal(body.provider.allow_fallbacks, false); assert.equal(body.provider.require_parameters, true);
    assert.deepEqual(body.reasoning, { exclude: true });
    assert.equal(body.models, undefined); assert.equal(body.tools, undefined);
    return new Response(JSON.stringify({ ...envelope(), model: 'liquid/lfm-2.5-2.6b', usage: { completion_tokens: 32, cost: 0 } }),
      { headers: { 'content-type': 'application/json' } });
  }) as typeof fetch);
  await provider.summarize(fixtureReport, policy, new AbortController().signal);
  assert.equal(calls, 1);
});

test('canonical response identity is narrow and requires free profile and zero reported cost', async () => {
  const policy = policyFromEnvironment(freeEnv)!;
  for (const model of ['liquid/lfm-2.5-2.6b', 'liquid/lfm-2.5-2.6b:free']) {
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async () => new Response(JSON.stringify({ ...envelope(), model,
      usage: { completion_tokens: 32, cost: 0 } }), { headers: { 'content-type': 'application/json' } })) as typeof fetch);
    await provider.summarize(fixtureReport, policy, new AbortController().signal);
  }
  for (const patch of [{ model: 'foreign/model' }, { model: 'liquid/lfm-2.5-2.6b:paid' }, { model: 'liquid/lfm-2.5-2.6b-unknown' },
    { usage: { completion_tokens: 32, cost: 0.0001 } }, { usage: { completion_tokens: 32 } }]) {
    let calls = 0;
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async () => {
      calls++; return new Response(JSON.stringify({ ...envelope(), model: policy.model, usage: { completion_tokens: 32, cost: 0 }, ...patch }),
        { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    await assert.rejects(provider.summarize(fixtureReport, policy, new AbortController().signal));
    assert.equal(calls, 1);
  }
});
