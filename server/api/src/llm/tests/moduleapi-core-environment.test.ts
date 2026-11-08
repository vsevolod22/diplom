import { openAiPrompts as moduleApiPrompts, syntheticOpenAiKey as syntheticModuleApiKey } from './openai-core.fixture.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { readModuleApiEnvironment, moduleApiEnvironmentReadiness } from '../moduleapi-environment.js';
import { readModuleApiKeyEnvironment, moduleApiKeyEnvironmentReady } from '../moduleapi-key-environment.js';
import { MODULEAPI_MODEL } from '../moduleapi-policy.js';

const environment = (): Record<string, string> => ({ MODULEAPI_ENABLED: 'true', MODULEAPI_MODEL, MODULEAPI_MONETARY_LIMIT: 'capped', MODULEAPI_ACCOUNTING_REVISION: 'moduleapi-accounting-test',
  MODULEAPI_ROUTING_APPROVED: 'true', MODULEAPI_RETENTION: 'unknown', MODULEAPI_POLICY_REVISION: 'independent-tests',
  MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION: '1000000', MODULEAPI_OUTPUT_PRICE_MICROS_PER_MILLION: '2000000',
  MODULEAPI_REQUEST_BUDGET_MICROS: '100000', MODULEAPI_USER_BUDGET_MICROS: '200000', MODULEAPI_SCAN_BUDGET_MICROS: '200000',
  MODULEAPI_TIMEOUT_MS: '1000', MODULEAPI_REQUEST_BYTES: '65536', MODULEAPI_RESPONSE_BYTES: '8192',
  MODULEAPI_INPUT_TOKENS: '65536', MODULEAPI_OUTPUT_TOKENS: '256', MODULEAPI_FINDINGS: '1000', MODULEAPI_MAX_CONCURRENT: '2' });

test('server environment is explicit, strict, immutable and does not read credentials', () => {
  const env = environment(); Object.defineProperty(env, 'MODULE_API_KEY', { get() { assert.fail('parser read credential'); } });
  const config = readModuleApiEnvironment(moduleApiPrompts, env); assert.ok(config); assert.ok(Object.isFrozen(config));
  assert.ok(Object.isFrozen(config.spending));
  for (const name of Object.keys(environment()).filter(name => /(?:MICROS|MS|BYTES|TOKENS|FINDINGS|CONCURRENT)$/.test(name))) {
    for (const value of ['', '0', '-1', '+1', '01', '1.0', '1e2', ' 1', '1 ', 'Infinity', '9007199254740992', '١']) {
      assert.equal(readModuleApiEnvironment(moduleApiPrompts, { ...environment(), [name]: value }), null, `${name}: ${value}`);
    }
  }
  for (const name of Object.keys(environment())) {
    const missing = environment(); delete missing[name]; assert.equal(readModuleApiEnvironment(moduleApiPrompts, missing), null, name);
  }
  for (const patch of [{ MODULEAPI_ENABLED: 'TRUE' }, { MODULEAPI_MAX_CONCURRENT: '9' }, { MODULEAPI_MODEL: 'gpt-4o' },
    { MODULEAPI_ROUTING_APPROVED: '1' }, { MODULEAPI_USER_BUDGET_MICROS: '99999' }]) {
    assert.equal(readModuleApiEnvironment(moduleApiPrompts, { ...environment(), ...patch }), null);
  }
});

test('key never falls back to files, alternate variables, cached values or sensitive errors', () => {
  const fallback = { MODULEAPI_KEY_FILE: '/synthetic/must-not-read', MODULE_API_KEY_FILE: '/synthetic/must-not-read',
    OPENROUTER_API_KEY: syntheticModuleApiKey, API_KEY: syntheticModuleApiKey };
  for (const value of [undefined, '', 'short', ' ' + syntheticModuleApiKey, syntheticModuleApiKey + '\n', 'x'.repeat(513)]) {
    const env = { ...fallback, MODULE_API_KEY: value };
    assert.equal(moduleApiKeyEnvironmentReady(env), false); assert.throws(() => readModuleApiKeyEnvironment(env));
  }
  const env = { MODULE_API_KEY: syntheticModuleApiKey }; assert.equal(readModuleApiKeyEnvironment(env), syntheticModuleApiKey);
  env.MODULE_API_KEY = ''; assert.throws(() => readModuleApiKeyEnvironment(env));
  const throwing = new Proxy({}, { get() { throw new Error(syntheticModuleApiKey); } });
  assert.equal(moduleApiKeyEnvironmentReady(throwing), false);
  assert.throws(() => readModuleApiKeyEnvironment(throwing), error => !String(error).includes(syntheticModuleApiKey));
  assert.equal(moduleApiEnvironmentReadiness(moduleApiPrompts, {}), 'disabled');
  assert.equal(moduleApiEnvironmentReadiness(moduleApiPrompts, environment()), 'configuration-unavailable');
  assert.equal(moduleApiEnvironmentReadiness(moduleApiPrompts, { ...environment(), MODULE_API_KEY: syntheticModuleApiKey }), 'configured-not-activated');
});

test('ModuleAPI configuration has no inherited provider/mode/rate/accounting/privacy defaults, including uncapped mode', () => {
  for (const patch of [{ MODULEAPI_RETENTION: 'no-training' }, { MODULEAPI_RETENTION: 'zero-data-retention' },
    { MODULEAPI_ACCOUNTING_REVISION: 'undecided' }, { MODULEAPI_POLICY_REVISION: 'undecided' },
    { MODULEAPI_ACCOUNTING_REVISION: '' }, { MODULEAPI_MONETARY_LIMIT: undefined },
    { MODULEAPI_MODEL: 'gpt-5.4-mini-2026-03-17' }])
    assert.equal(readModuleApiEnvironment(moduleApiPrompts, { ...environment(), ...patch }), null);
  const uncapped = { ...environment(), MODULEAPI_MONETARY_LIMIT: 'uncapped', MODULEAPI_REQUEST_BUDGET_MICROS: undefined,
    MODULEAPI_USER_BUDGET_MICROS: undefined, MODULEAPI_SCAN_BUDGET_MICROS: undefined };
  const configuration = readModuleApiEnvironment(moduleApiPrompts, uncapped);
  assert.ok(configuration); assert.equal(configuration.policy.requestBudgetMicros, null);
  assert.equal(configuration.policy.retention, 'unknown');
  assert.deepEqual(configuration.spending, { userBudgetMicros: null, scanBudgetMicros: null });
  for (const name of ['MODULEAPI_REQUEST_BUDGET_MICROS', 'MODULEAPI_USER_BUDGET_MICROS', 'MODULEAPI_SCAN_BUDGET_MICROS'])
    assert.equal(readModuleApiEnvironment(moduleApiPrompts, { ...uncapped, [name]: '1' }), null);
  const oldOnly = Object.fromEntries(Object.entries(environment()).map(([key, value]) => [key.replace('MODULEAPI_', 'OPENAI_'), value]));
  assert.equal(readModuleApiEnvironment(moduleApiPrompts, oldOnly), null);
  assert.equal(moduleApiKeyEnvironmentReady({ OPENAI_API_KEY: syntheticModuleApiKey, MODULEAPI_API_KEY: syntheticModuleApiKey }), false);
});
