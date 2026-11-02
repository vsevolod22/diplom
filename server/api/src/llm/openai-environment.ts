import { createOpenAiPolicy, OPENAI_MODEL, type OpenAiPolicy, type OpenAiPrompts } from './openai-policy.js';
import { openAiKeyEnvironmentReady, type OpenAiEnvironment } from './openai-key-environment.js';

export type OpenAiServerConfiguration = Readonly<{
  policy: OpenAiPolicy;
  maxConcurrent: number;
  // Optional for legacy parsing only; runtime must require an explicit revision
  // before creating an accounting approval. Never inherit the provider revision.
  accountingRevision?: string;
  // Future composition must bind these to the existing durable user/scan windows.
  // Null means explicitly uncapped, not zero cost or disabled usage accounting.
  // Merely parsing limits does not enforce a budget or authorize dispatch.
  spending: Readonly<{ userBudgetMicros: number | null; scanBudgetMicros: number | null }>;
}>;

function positive(env: OpenAiEnvironment, name: string, max = Number.MAX_SAFE_INTEGER): number {
  const text = env[name];
  if (typeof text !== 'string' || !/^[1-9][0-9]{0,15}$/.test(text)) throw new Error('Invalid OpenAI configuration');
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > max) throw new Error('Invalid OpenAI configuration');
  return value;
}

// No implicit prices, monetary budgets, prompts, approval or model selection.
// This parses server config only: it never reads the key, creates a provider or dials.
export function readOpenAiEnvironment(prompts: OpenAiPrompts, env: OpenAiEnvironment = process.env): OpenAiServerConfiguration | null {
  try {
    if (env.OPENAI_ENABLED !== 'true' || env.OPENAI_MODEL !== OPENAI_MODEL ||
        env.OPENAI_ROUTING_APPROVED !== 'true' || env.OPENAI_RETENTION !== 'no-training') return null;
    const monetaryLimit = env.OPENAI_MONETARY_LIMIT;
    if (monetaryLimit !== undefined && monetaryLimit !== 'capped' && monetaryLimit !== 'uncapped') return null;
    const accountingRevision = env.OPENAI_ACCOUNTING_REVISION;
    if (accountingRevision !== undefined && (typeof accountingRevision !== 'string' || accountingRevision === 'undecided' ||
        !/^[A-Za-z0-9._-]{1,80}$/.test(accountingRevision))) return null;
    if (monetaryLimit === 'uncapped' && ['OPENAI_REQUEST_BUDGET_MICROS', 'OPENAI_USER_BUDGET_MICROS',
      'OPENAI_SCAN_BUDGET_MICROS'].some(name => env[name] !== undefined)) return null;
    // Missing mode preserves the old capped policy/version only with all three
    // explicit positive budgets; it can never opt into uncapped operation.
    const requestBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'OPENAI_REQUEST_BUDGET_MICROS');
    const userBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'OPENAI_USER_BUDGET_MICROS', 1_000_000);
    const scanBudgetMicros = monetaryLimit === 'uncapped' ? null : positive(env, 'OPENAI_SCAN_BUDGET_MICROS', 1_000_000);
    if (requestBudgetMicros !== null && (userBudgetMicros === null || scanBudgetMicros === null ||
        Math.min(userBudgetMicros, scanBudgetMicros) < requestBudgetMicros)) return null;
    const policy = createOpenAiPolicy({
      enabled: true, model: OPENAI_MODEL, revision: env.OPENAI_POLICY_REVISION,
      routingApproved: true, retention: 'no-training',
      inputPriceMicrosPerMillion: positive(env, 'OPENAI_INPUT_PRICE_MICROS_PER_MILLION'),
      outputPriceMicrosPerMillion: positive(env, 'OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION'),
      ...(monetaryLimit !== undefined ? { monetaryLimit } : {}), requestBudgetMicros,
      timeoutMs: positive(env, 'OPENAI_TIMEOUT_MS'), requestBytes: positive(env, 'OPENAI_REQUEST_BYTES'),
      responseBytes: positive(env, 'OPENAI_RESPONSE_BYTES'), inputTokens: positive(env, 'OPENAI_INPUT_TOKENS'),
      outputTokens: positive(env, 'OPENAI_OUTPUT_TOKENS'), findings: positive(env, 'OPENAI_FINDINGS'),
    }, prompts);
    if (!policy) return null;
    return Object.freeze({ policy, maxConcurrent: positive(env, 'OPENAI_MAX_CONCURRENT', 8),
      ...(accountingRevision !== undefined ? { accountingRevision } : {}),
      spending: Object.freeze({ userBudgetMicros, scanBudgetMicros }) });
  } catch { return null; }
}

// Not operational readiness: runtime accounting/consent wiring is intentionally absent.
export function openAiEnvironmentReadiness(prompts: OpenAiPrompts, env: OpenAiEnvironment = process.env):
  'disabled' | 'configuration-unavailable' | 'configured-not-activated' {
  try {
    if (env.OPENAI_ENABLED !== 'true') return 'disabled';
    return readOpenAiEnvironment(prompts, env) && openAiKeyEnvironmentReady(env)
      ? 'configured-not-activated' : 'configuration-unavailable';
  } catch { return 'configuration-unavailable'; }
}
