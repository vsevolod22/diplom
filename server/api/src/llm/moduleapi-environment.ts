import { createModuleApiPolicy, MODULEAPI_MODEL, type ModuleApiPolicy, type ModuleApiPrompts } from './moduleapi-policy.js';
import { moduleApiKeyEnvironmentReady, type ModuleApiEnvironment } from './moduleapi-key-environment.js';

export type ModuleApiServerConfiguration = Readonly<{
  policy: ModuleApiPolicy;
  maxConcurrent: number;
  // Explicit and independent from the provider revision; no inherited approval.
  accountingRevision: string;
  // Composition must bind these to the existing durable user/scan windows.
  // Null means explicitly uncapped, not zero cost or disabled usage accounting.
  // Merely parsing limits does not enforce a budget or authorize dispatch.
  spending: Readonly<{ userBudgetMicros: number | null; scanBudgetMicros: number | null }>;
}>;

function positive(env: ModuleApiEnvironment, name: string, max = Number.MAX_SAFE_INTEGER): number {
  const text = env[name];
  if (typeof text !== 'string' || !/^[1-9][0-9]{0,15}$/.test(text)) throw new Error('Invalid ModuleAPI configuration');
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > max) throw new Error('Invalid ModuleAPI configuration');
  return value;
}

// No implicit prices, monetary budgets, prompts, approval or model selection.
// This parses server config only: it never reads the key, creates a provider or dials.
export function readModuleApiEnvironment(prompts: ModuleApiPrompts, env: ModuleApiEnvironment = process.env): ModuleApiServerConfiguration | null {
  try {
    if (env.MODULEAPI_ENABLED !== 'true' || env.MODULEAPI_MODEL !== MODULEAPI_MODEL ||
        env.MODULEAPI_ROUTING_APPROVED !== 'true' || env.MODULEAPI_RETENTION !== 'unknown') return null;
    const monetaryLimit = env.MODULEAPI_MONETARY_LIMIT;
    if (monetaryLimit !== 'capped' && monetaryLimit !== 'uncapped') return null;
    const accountingRevision = env.MODULEAPI_ACCOUNTING_REVISION;
    if (typeof accountingRevision !== 'string' || accountingRevision === 'undecided' ||
        !/^[A-Za-z0-9._-]{1,80}$/.test(accountingRevision)) return null;
    if (monetaryLimit === 'uncapped' && ['MODULEAPI_REQUEST_BUDGET_MICROS', 'MODULEAPI_USER_BUDGET_MICROS',
      'MODULEAPI_SCAN_BUDGET_MICROS'].some(name => env[name] !== undefined)) return null;
    // Monetary mode is explicit; capped requires all three positive budgets.
    const requestBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'MODULEAPI_REQUEST_BUDGET_MICROS');
    const userBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'MODULEAPI_USER_BUDGET_MICROS', 1_000_000);
    const scanBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'MODULEAPI_SCAN_BUDGET_MICROS', 1_000_000);
    if (requestBudgetMicros !== null && (userBudgetMicros === null || scanBudgetMicros === null ||
        Math.min(userBudgetMicros, scanBudgetMicros) < requestBudgetMicros)) return null;
    const policy = createModuleApiPolicy({
      enabled: true, model: MODULEAPI_MODEL, revision: env.MODULEAPI_POLICY_REVISION,
      routingApproved: true, retention: 'unknown',
      inputPriceMicrosPerMillion: positive(env, 'MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION'),
      outputPriceMicrosPerMillion: positive(env, 'MODULEAPI_OUTPUT_PRICE_MICROS_PER_MILLION'),
      monetaryLimit, requestBudgetMicros,
      timeoutMs: positive(env, 'MODULEAPI_TIMEOUT_MS'), requestBytes: positive(env, 'MODULEAPI_REQUEST_BYTES'),
      responseBytes: positive(env, 'MODULEAPI_RESPONSE_BYTES'), inputTokens: positive(env, 'MODULEAPI_INPUT_TOKENS'),
      outputTokens: positive(env, 'MODULEAPI_OUTPUT_TOKENS'), findings: positive(env, 'MODULEAPI_FINDINGS'),
    }, prompts);
    if (!policy) return null;
    return Object.freeze({ policy, maxConcurrent: positive(env, 'MODULEAPI_MAX_CONCURRENT', 8),
      accountingRevision,
      spending: Object.freeze({ userBudgetMicros, scanBudgetMicros }) });
  } catch { return null; }
}

// Configuration readiness only, not runtime consent/admission or live qualification.
export function moduleApiEnvironmentReadiness(prompts: ModuleApiPrompts, env: ModuleApiEnvironment = process.env):
  'disabled' | 'configuration-unavailable' | 'configured-not-activated' {
  try {
    if (env.MODULEAPI_ENABLED !== 'true') return 'disabled';
    return readModuleApiEnvironment(prompts, env) && moduleApiKeyEnvironmentReady(env)
      ? 'configured-not-activated' : 'configuration-unavailable';
  } catch { return 'configuration-unavailable'; }
}
