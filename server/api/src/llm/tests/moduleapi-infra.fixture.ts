import { createModuleApiPolicy, MODULEAPI_MODEL, type ModuleApiSettings } from '../moduleapi-policy.js';

// Synthetic explicit tariff, prompts and key, never operator configuration.
export const syntheticModuleApiKey = 'synthetic_moduleapi_not_a_real_key_12345';
export const makeModuleApiPolicy = (overrides: Partial<ModuleApiSettings> = {}) => {
  const policy = createModuleApiPolicy({
    enabled: true, model: MODULEAPI_MODEL, revision: 'infra-offline-test-v1', routingApproved: true, retention: 'unknown',
    inputPriceMicrosPerMillion: 1_000_000, outputPriceMicrosPerMillion: 2_000_000, monetaryLimit: 'capped', requestBudgetMicros: 100_000,
    timeoutMs: 1000, requestBytes: 65_536, responseBytes: 8192, inputTokens: 65_536, outputTokens: 256, findings: 1000,
    ...overrides,
  }, { summary: 'Write Russian grounded summary.', chat: 'Write Russian grounded reply.' });
  if (!policy) throw new Error('Invalid synthetic ModuleAPI policy fixture');
  return policy;
};
