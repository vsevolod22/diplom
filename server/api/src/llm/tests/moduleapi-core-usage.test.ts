import { openAiSettings as baseSettings, openAiPrompts as moduleApiPrompts } from './openai-core.fixture.js';
import { createModuleApiPolicy, MODULEAPI_MODEL, type ModuleApiSettings } from '../moduleapi-policy.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { estimateModuleApiCost, observeModuleApiUsage, moduleApiReserve } from '../moduleapi-usage.js';

const source = 'moduleapi-server-estimated-configured-rates-not-invoice';

const moduleApiSettings: ModuleApiSettings = { ...baseSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped', requestBudgetMicros: 100_000 };
const makeModuleApiPolicy = (overrides: Partial<ModuleApiSettings> = {}) => {
  const policy = createModuleApiPolicy({ ...moduleApiSettings, ...overrides }, moduleApiPrompts);
  if (!policy) throw new Error('Invalid synthetic ModuleAPI policy fixture');
  return policy;
};

test('configured integer rates use one total BigInt ceiling, no cached discount, estimates never pretend to be provider invoice/cost receipts', () => {
  const policy = makeModuleApiPolicy({ inputPriceMicrosPerMillion: 1, outputPriceMicrosPerMillion: 1 });
  for (const [input, output, expected] of [[0, 0, 0], [1, 0, 1], [0, 1, 1], [1, 1, 1], [499999, 500001, 1], [500000, 500001, 2]])
    assert.equal(estimateModuleApiCost(input, output, policy), expected);
  for (const invalid of [-1, NaN, Infinity, 1.5, 1048577, '1'])
    assert.throws(() => estimateModuleApiCost(invalid as number, 0, policy));
  const paid = makeModuleApiPolicy(), reserve = moduleApiReserve(100, paid);
  const observation = observeModuleApiUsage({ prompt_tokens: 20, completion_tokens: 10, total_tokens: 30,
    prompt_tokens_details: { cached_tokens: 20, audio_tokens: 0 }, completion_tokens_details: { reasoning_tokens: 10, audio_tokens: 0,
      accepted_prediction_tokens: 0, rejected_prediction_tokens: 0 } }, reserve, paid);
  assert.deepEqual(observation, { normal: true, input: 20, output: 10, costMicros: 40, source }); assert.ok(Object.isFrozen(observation));
});

test('unknown/missing/inconsistent usage is abnormal with no fabricated zero estimate; exact positive input with completion0 is paid', () => {
  const policy = makeModuleApiPolicy(), reserve = moduleApiReserve(100, policy);
  for (const value of [null, undefined, {}, [], { prompt_tokens: 20 }, { prompt_tokens: '20', completion_tokens: 10, total_tokens: 30 },
    { prompt_tokens: 20, completion_tokens: 10, total_tokens: 31 }, { prompt_tokens: -1, completion_tokens: 1, total_tokens: 0 },
    { prompt_tokens: NaN, completion_tokens: 10, total_tokens: 30 }]) {
    assert.deepEqual(observeModuleApiUsage(value, reserve, policy), { normal: false, source });
  }
  assert.deepEqual(observeModuleApiUsage({ prompt_tokens: 20, completion_tokens: 0, total_tokens: 20 }, reserve, policy),
    { normal: true, input: 20, output: 0, costMicros: 20, source });
});

test('usage details, reservation input/output/cost and configured budget are strict, never normal overrun or foreign provider cost', () => {
  const policy = makeModuleApiPolicy(), reserve = moduleApiReserve(100, policy), usage = { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 };
  for (const patch of [{ cost: 0 }, { provider: 'OpenRouter' }, { prompt_tokens_details: { cached_tokens: 21 } },
    { prompt_tokens_details: { audio_tokens: 1 } }, { completion_tokens_details: { reasoning_tokens: 11 } },
    { completion_tokens_details: { accepted_prediction_tokens: 1 } }, { completion_tokens_details: { extra: 0 } },
    { prompt_tokens_details: { cached_tokens: -1 } }]) {
    const result = observeModuleApiUsage({ ...usage, ...patch }, reserve, policy);
    assert.equal(result.normal, false); assert.equal(result.costMicros, 40); assert.equal(result.source, source);
  }
  assert.equal(observeModuleApiUsage({ prompt_tokens: 101, completion_tokens: 0, total_tokens: 101 }, reserve, policy).normal, false);
  assert.equal(observeModuleApiUsage({ prompt_tokens: 20, completion_tokens: 257, total_tokens: 277 }, reserve, policy).normal, false);
  assert.equal(observeModuleApiUsage(usage, { ...reserve, costMicros: 39 }, policy).normal, false);
  assert.throws(() => moduleApiReserve(0, policy)); assert.throws(() => moduleApiReserve(65537, policy));
  assert.throws(() => moduleApiReserve(100, makeModuleApiPolicy({ requestBudgetMicros: 1 })));
});
