import assert from 'node:assert/strict';
import { createModuleApiPolicy, MODULEAPI_MODEL, type ModuleApiSettings } from '../moduleapi-policy.js';
import type { ModuleApiServerConfiguration } from '../moduleapi-environment.js';
import { quotaPolicyFromEnvironment } from '../quota-policy.js';
import { quotaEnv } from './quota-fixtures.js';
import { openAiReport, openAiHistory, openAiPrompts, openAiReply } from './openai-core.fixture.js';

// Explicit synthetic policy/rates/key only; never read deployment configuration.
export const moduleApiBackendSettings: ModuleApiSettings = {
  enabled: true, model: MODULEAPI_MODEL, revision: 'moduleapi-backend-offline-v1', routingApproved: true, retention: 'unknown',
  inputPriceMicrosPerMillion: 1_000_000, outputPriceMicrosPerMillion: 2_000_000,
  monetaryLimit: 'uncapped', requestBudgetMicros: null, timeoutMs: 5000,
  requestBytes: 65_536, responseBytes: 8192, inputTokens: 65_536, outputTokens: 256, findings: 1000,
};
export const moduleApiBackendQuota = quotaPolicyFromEnvironment({ ...quotaEnv,
  LLM_QUOTA_MONETARY_LIMIT: 'uncapped', LLM_QUOTA_USER_COST_USD: undefined, LLM_QUOTA_SCAN_COST_USD: undefined,
  LLM_QUOTA_OBSERVATION_COST_USD: undefined, LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000',
  LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000',
})!;
assert.ok(moduleApiBackendQuota);
export function moduleApiBackendConfiguration(revision = 'moduleapi-backend-offline-v1', maxConcurrent = 2): ModuleApiServerConfiguration {
  const policy = createModuleApiPolicy({ ...moduleApiBackendSettings, revision }, openAiPrompts);
  assert.ok(policy);
  return { policy, maxConcurrent, accountingRevision: 'moduleapi-backend-estimates-approved',
    spending: { userBudgetMicros: null, scanBudgetMicros: null } };
}
export const moduleApiBackendReport = openAiReport;
export const moduleApiBackendHistory = openAiHistory;
export const moduleApiBackendKey = 'synthetic_moduleapi_backend_not_real_12345';
export function moduleApiBackendResponse(operation: 'summary' | 'chat' = 'summary', mode: 'valid' | 'unknown' | 'invalid' = 'valid') {
  return new Response(JSON.stringify({ model: MODULEAPI_MODEL, service_tier: 'default',
    ...(mode === 'unknown' ? {} : { usage: { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 } }),
    choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(
      mode === 'invalid' ? { invalid: true } : openAiReply(operation)) } }] }),
  { headers: { 'content-type': 'application/json' } });
}
export function moduleApiBackendDeferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
