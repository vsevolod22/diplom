// Synthetic nonsecret descriptors for source/config qualification only. No IO.
export function syntheticOpenAiDeployment() {
  const openrouter = { version: 5, keyVolume: 'diplom-public-8081-llm-key-' + 'a'.repeat(32),
    timing: 'public-8081-90s-v1', profile: 'public-8081-remediation-4k-v1' };
  return { version: 6, provider: 'OpenAI', keyVolume: openrouter.keyVolume, openrouter, monetaryLimit: 'uncapped',
    credentialVolume: 'openai-secrets', operations: 'public-images-v2', environment: {
      LLM_PROVIDER: 'openai', OPENAI_MODEL: 'gpt-5.4-mini-2026-03-17', OPENAI_ENABLED: 'true',
      OPENAI_ROUTING_APPROVED: 'true', OPENAI_RETENTION: 'no-training', OPENAI_POLICY_REVISION: 'synthetic-openai-policy',
      OPENAI_ACCOUNTING_REVISION: 'synthetic-openai-accounting', OPENAI_MONETARY_LIMIT: 'uncapped',
      OPENAI_INPUT_PRICE_MICROS_PER_MILLION: '1000000', OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION: '2000000',
      OPENAI_TIMEOUT_MS: '90000', OPENAI_REQUEST_BYTES: '262144', OPENAI_RESPONSE_BYTES: '65536',
      OPENAI_INPUT_TOKENS: '65536', OPENAI_OUTPUT_TOKENS: '4096', OPENAI_FINDINGS: '1000', OPENAI_MAX_CONCURRENT: '8',
      LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_REVISION: 'synthetic-shared-quota', LLM_QUOTA_WINDOW: 'utc-day',
      LLM_QUOTA_MONETARY_LIMIT: 'uncapped', LLM_QUOTA_LIFETIME_USER_COST_MICROS: '5000000',
      LLM_QUOTA_USER_INPUT: '1048576', LLM_QUOTA_USER_OUTPUT: '32768', LLM_QUOTA_SCAN_INPUT: '262144', LLM_QUOTA_SCAN_OUTPUT: '16384',
      LLM_QUOTA_WARNING_PERCENT: '80', LLM_QUOTA_REQUEST_INPUT: '65536', LLM_QUOTA_OBSERVATION_TOKENS: '1048576',
      LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000', LLM_QUOTA_RECEIPT_MS: '300000', LLM_QUOTA_REPLAY_DAYS: '7',
      LLM_QUOTA_MAX_ROWS: '100000', LLM_QUOTA_DB_BYTES: '67108864', LLM_QUOTA_DISK_HEADROOM_BYTES: '134217728',
      LLM_QUOTA_BUSY_MS: '1000', LLM_QUOTA_CLEANUP_BATCH: '256',
    } };
}
export function syntheticModuleApiDeployment() {
  const openai = syntheticOpenAiDeployment();
  const environment = Object.fromEntries(Object.entries(openai.environment).filter(([key]) => key.startsWith('LLM_QUOTA_')));
  Object.assign(environment, { LLM_PROVIDER: 'moduleapi', MODULEAPI_MODEL: 'gpt-5.4-mini', MODULEAPI_ENABLED: 'true',
    MODULEAPI_ROUTING_APPROVED: 'true', MODULEAPI_RETENTION: 'unknown', MODULEAPI_POLICY_REVISION: 'synthetic-moduleapi-policy',
    MODULEAPI_ACCOUNTING_REVISION: 'synthetic-moduleapi-accounting', MODULEAPI_MONETARY_LIMIT: 'uncapped',
    // Deliberately distinct synthetic rates, not a provider tariff or approved operator configuration.
    MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION: '3000000', MODULEAPI_OUTPUT_PRICE_MICROS_PER_MILLION: '4000000',
    MODULEAPI_TIMEOUT_MS: '90000', MODULEAPI_REQUEST_BYTES: '262144', MODULEAPI_RESPONSE_BYTES: '65536',
    MODULEAPI_INPUT_TOKENS: '65536', MODULEAPI_OUTPUT_TOKENS: '4096', MODULEAPI_FINDINGS: '1000', MODULEAPI_MAX_CONCURRENT: '8' });
  return { version: 7, provider: 'ModuleAPI', keyVolume: openai.keyVolume, openrouter: structuredClone(openai.openrouter), openai,
    monetaryLimit: 'uncapped', environment, credentialVolume: 'moduleapi-secrets', operations: 'public-images-v2' };
}
